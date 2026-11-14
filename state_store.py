"""Where pr-autopilot keeps its state between runs.

Two backends, picked by PR_AUTOPILOT_STATE:
  "file" (the default) - the local ~/.pr-autopilot.json, exactly as before.
  "configmap"          - the key `state.json` of ConfigMap `pr-autopilot-state` in the
                         Datum project, read and written over the Milo API (milo_api).
                         This lets the dispatcher on Datum and the laptop share one state.

The ConfigMap backend never falls back to the local file. A local copy that is older
than the ConfigMap would, once written back, undo another writer's work (split brain).
So when the ConfigMap cannot be written, the caller skips the save and keeps its
changes in a spool file that the next run merges into the state it loads. When it
cannot be read on the first load of a run, the run is skipped. See
reviewer.load_state_configmap and reviewer.save_state_configmap.

Writes are optimistic: each save sends the resourceVersion it last read, and the API
refuses the write (HTTP 409 Conflict) if someone changed the ConfigMap since. The
caller then reloads, re-applies its own changes on top (merge()) and tries again.

State schema (one JSON object):
  reviewed            {"owner/repo#num": head SHA}   last handled commit per PR
  handled_at          {"owner/repo#num": epoch}      when it was handled
  failures            {"owner/repo#num@sha": count}  failed attempts per commit
  skipped, requested_by, rerequest                    caches, pruned to waiting PRs
  notified            {name: epoch}                  throttle for standing warnings
  rescan, last_full_scan, poll_fail_streak, me,
  notif_watermark, notif_last_modified, notif_next_at polling control
  owner               {"id": str, "heartbeat": epoch} single-active lock (reviewer.hold_lock)
  last_poll           epoch                          last good answer from GitHub
  github_401          epoch                          GitHub refused the token since then
  jobs                {"owner/repo#num@sha": record} the dispatcher's reviews on Datum

Job records are described by JOB_FIELDS below. On the laptop they are local files
(reviewer.Job): "running" there means "this PID is alive on this machine". The
dispatcher on Datum keeps them in state["jobs"] (reviewer.StateJob), as it has no
worker processes and must find its jobs again after a restart.
"""
from __future__ import annotations

import json
import os

import milo_api

# The keys each job status adds to a record. A record keeps the keys of its earlier
# statuses (Job.write merges), so a finished record still has pid, reason and audit.
JOB_FIELDS = {
    # The dispatcher only: waiting for a free worker slot.
    "queued": ("queued", "reason", "audit", "plan", "runner", "author", "title", "lost"),
    # pid on the laptop; workload and token_hash (sha256 of the callback token) in the dispatcher.
    # review_floor (dispatcher): the highest id of your reviews on the commit at launch; a
    # review with a higher id is this job's own (reviewer.posted_already).
    "running": ("pid", "started", "reason", "audit", "plan", "runner", "author", "workload", "token_hash",
                "review_floor"),
    # The dispatcher only: the worker called back; the next pass posts the outcome.
    # used_token keeps the hash so a repeated callback gets 409, not 401.
    "result": ("outcome", "result_at", "used_token"),
    "done": ("verdict",),
    "stale": (),
    # Finished, but GitHub did not take the result. Only the post is retried.
    "unposted": ("verdict", "post_event", "post_body", "post_attempts"),
    "auth": ("error",),
    "failed": ("error",),
}
# Every record the dispatcher finishes also gets "finished" (epoch).

BACKEND = os.environ.get("PR_AUTOPILOT_STATE", "file")
NAME = os.environ.get("PR_AUTOPILOT_STATE_CONFIGMAP", "pr-autopilot-state")
KEY = "state.json"
MAX_BYTES = 900 * 1024   # the API refuses a ConfigMap over 1 MiB; stop well before it


class Unavailable(Exception):
    """The store could not be read or written. Nothing is known about its contents."""


class Conflict(Exception):
    """Someone else changed the store since it was read."""


def merge(base: dict, mine: dict, theirs: dict) -> dict:
    """Re-apply the changes from `base` to `mine` on top of `theirs`.

    Dict values (reviewed, failures, ...) merge per entry: an entry this writer
    added, changed or deleted wins, and every other entry keeps the other writer's
    value. Any other value is taken from `mine` only if this writer changed it."""
    out = dict(theirs)
    for key in set(base) | set(mine):
        b, m = base.get(key), mine.get(key)
        if key not in mine:
            if key in base:
                out.pop(key, None)
            continue
        if isinstance(m, dict) and isinstance(b, dict) and isinstance(out.get(key), dict):
            merged = dict(out[key])
            for k in set(b) | set(m):
                if k not in m:
                    merged.pop(k, None)
                elif k not in b or b[k] != m[k]:
                    merged[k] = m[k]
            out[key] = merged
        elif key not in base or b != m:
            out[key] = m
    return out


class ConfigMapStore:
    """One key of one ConfigMap in a Datum project, over the Milo API (milo_api).

    `session` is kept for callers that still pass it; milo_api pins the laptop's
    datumctl login to the same session (PR_AUTOPILOT_DATUM_SESSION). The dispatcher on
    Datum uses its service-account key instead. Errors come from the HTTP status:
    404 NotFound on get, 409 on a create that exists or a patch with an old
    resourceVersion.
    """

    def __init__(self, project: str, session: str | None = None, name: str = NAME, key: str = KEY):
        self.project, self.session, self.name, self.key = project, session, name, key

    def path(self, name: str | None = None) -> str:
        return milo_api.configmaps_path(self.project, name)

    def load(self) -> tuple[dict | None, str | None]:
        """(state, resourceVersion). (None, None) means the ConfigMap does not exist yet;
        any other failure raises Unavailable, never an empty state."""
        try:
            obj = milo_api.get(self.path(self.name))
        except milo_api.NotFound:
            return None, None
        except (milo_api.MiloError, ValueError) as e:
            raise Unavailable(f"reading ConfigMap {self.name}: {e}") from e
        try:
            state = json.loads((obj.get("data") or {}).get(self.key) or "{}")
            version = obj["metadata"]["resourceVersion"]
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            # Unreadable contents are not "nothing reviewed": refuse to run on them.
            raise Unavailable(f"ConfigMap {self.name} does not hold valid state: {e}") from e
        if not isinstance(state, dict):
            raise Unavailable(f"ConfigMap {self.name} does not hold a JSON object")
        return state, version

    def save(self, state: dict, version: str | None) -> str:
        """Write `state` if the ConfigMap is still at `version` (None: create it).
        Returns the new resourceVersion. Raises Conflict or Unavailable."""
        payload = json.dumps(state, separators=(",", ":"), sort_keys=True)
        if len(payload) > MAX_BYTES:
            raise Unavailable(f"{self.name} is {len(payload)} bytes, over the {MAX_BYTES} byte limit")
        try:
            if version is None:
                obj = milo_api.create(self.path(), {
                    "apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"name": self.name, "labels": {"app": "pr-autopilot"}},
                    "data": {self.key: payload}})
            else:
                # A merge patch that names a resourceVersion is refused with 409 Conflict
                # when the object has moved on since.
                obj = milo_api.merge_patch(self.path(self.name), {
                    "metadata": {"resourceVersion": version}, "data": {self.key: payload}})
        except milo_api.Conflict as e:
            raise Conflict(str(e)) from e
        except milo_api.MiloError as e:
            raise Unavailable(f"writing ConfigMap {self.name}: {e}") from e
        try:
            return obj["metadata"]["resourceVersion"]
        except (KeyError, TypeError) as e:
            # Written, but the new version is unknown: the next save will conflict and merge.
            raise Unavailable(f"ConfigMap {self.name} written, but its new version is unknown: {e}") from e
