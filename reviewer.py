#!/usr/bin/env python3
"""PR autopilot: reviews and approves the PRs you are asked to review.

Finds PRs where you personally (not a team) are a requested reviewer, with one
GitHub search across every repo repos.json covers ("owner/repo" entries, plus
"owner/*" for the rest of an organization). If the PR's author, or the person
who asked for your review, is listed in the repo's "authors", it handles the PR
by the repo's "review" mode (other PRs are skipped with one log line):
  "none" - approve unconditionally;
  "full" - tiered. A quick diff review (headless Claude Code, no tools)
           approves low-risk PRs with no comment. A PR goes to a full review
           (a sandboxed, read-only Claude Code agent on real checkouts, see
           full_review.py) when it changes GitHub Actions workflows, touches
           a "full_review_paths" pattern, the quick review flags it, or the
           diff is too large. Full reviews run in the background so polling
           carries on; if nothing blocks they approve, with the non-blocking
           findings in the approval's body (none, no body), otherwise they
           post the blocking findings as a review comment and notify.
           PRs that change CODEOWNERS are always left to you.
           A random AUDIT_RATE share of quick approvals goes to a full review
           instead, which checks how often the quick review misses a blocker.
           With PR_AUTOPILOT_RUNNER=datum, for repos the review VM can read
           (remote_review.vm_can_read), both steps run in ONE Kata VM per PR
           commit instead (pr_worker.py, remote/review-job.py): the quick
           review, then the full review in the same VM if needed. The VM
           returns one outcome; a worker process here posts it. The VM never
           posts and holds no token that can approve.
Any error means "no approval". repos.json is re-read on every run.

To keep API traffic low, each run first makes a conditional request to the
GitHub notifications API (a 304 does not count against the rate limit) and
only searches when a covered repo has new notifications. A search still runs
every FULL_SCAN_SECONDS in case a notification was missed.

Usage:
  DRY_RUN=1 python3 reviewer.py --once   # log only, post nothing
  python3 reviewer.py --once             # one pass (for launchd/cron)
  python3 reviewer.py                    # loop forever
  python3 reviewer.py --test-notify      # send one test notification
  python3 reviewer.py --dashboard        # rebuild the dashboard page and open it

State lives in ~/.pr-autopilot.json. With PR_AUTOPILOT_STATE=configmap it lives in a
ConfigMap in the Datum project instead, so a dispatcher off the laptop can share it
(see state_store.py). That backend never falls back to the local file. It also holds a
single-active lock, so this and the dispatcher on Datum (dispatcher.py, docs/dispatcher.md)
never both run: whichever wrote a heartbeat in the last 5 minutes owns the run.

Anything that needs you (a blocking finding, a CODEOWNERS change, a review it
gave up on, an expired login, GitHub unreachable) is posted to Slack through
an Incoming Webhook whose URL lives in the Keychain (see SLACK_KEYCHAIN_SERVICE),
or shown as a macOS notification when Slack is not set up or fails. With
terminal-notifier installed (brew install terminal-notifier), clicking the
notification opens the PR.
"""
from __future__ import annotations

import calendar
import copy
import json
import os
import pathlib
import random
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import claude_cli
import dashboard
import github_api
import full_review
import pr_worker
import remote_review
import state_store

# Per-repo settings: {"owner/repo" or "owner/*": {"authors": [...], "review": "none"|"full",
# "context": str, "model": str, "full_review_paths": [regex, ...], "strict_workflows": bool}}.
# "strict_workflows" blocks on any change to workflow triggers, permissions, secrets,
# OIDC or third-party actions, for repos whose workflows the whole org reuses. A repo's own entry
# wins over its owner's "owner/*" entry. "authors" lists people whose PRs, or whose requests
# for your review, are handled; ["*"] means anyone.
_HERE = pathlib.Path(__file__).resolve().parent
CONFIG_FILE = pathlib.Path(os.environ.get("PR_AUTOPILOT_CONFIG")
                           or next((f for f in (_HERE / "repos.json", _HERE / "repos.example.json") if f.exists()), _HERE / "repos.json"))
QUICK_MODEL = os.environ.get("MODEL", "sonnet")
POLL_SECONDS = 60
FULL_SCAN_SECONDS = 30 * 60
ERROR_SEARCH_SECONDS = 10 * 60  # when notifications fail, search at most this often instead
MAX_DIFF_CHARS = pr_worker.MAX_DIFF_CHARS
# Share of quick approvals sent to a full review as a spot check, taken only when
# a full review slot is free. A blocker it finds is logged as an AUDIT MISS.
AUDIT_RATE = float(os.environ.get("PR_AUTOPILOT_AUDIT_RATE", "0.10"))
# Kept neutral on purpose: the full review must not learn what the quick review concluded.
AUDIT_FOCUS = pr_worker.AUDIT_FOCUS
DRY_RUN = os.environ.get("DRY_RUN") == "1"
# In "full" mode, a PR changing any of these goes to you: they decide who must approve,
# and this tool approves as you. Workflow changes get a full review instead (full_review.py).
MANUAL_PATHS = (r"(^|/)CODEOWNERS$", r"^\.github/settings\.ya?ml$")
STATE_FILE = pathlib.Path.home() / ".pr-autopilot.json"
# "file" (default): STATE_FILE. "configmap": a ConfigMap in the Datum project, see state_store.py.
STATE_BACKEND = state_store.BACKEND
STATE_SAVE_ATTEMPTS = 3     # writes that hit a conflict: reload, re-apply, try again
STATE_DOWN_ALERT = 15 * 60  # notify once the ConfigMap has been unreachable this long
STATE_DOWN_FILE = full_review.CACHE / "state-store-down.json"
# Changes a run could not save to the ConfigMap, as {"base": ..., "state": ...}. Read back
# only by merging them into the next state loaded from the ConfigMap, so this file never
# replaces the ConfigMap (no split brain). With --once, memory ends with the run.
STATE_SPOOL_FILE = full_review.CACHE / "state-unsaved.json"
# Single-active lock, ConfigMap backend only: state["owner"] = {"id", "heartbeat"}. Whoever
# wrote a heartbeat less than LOCK_SECONDS ago owns the run; anyone else skips theirs. So the
# laptop and the dispatcher on Datum never both review, and either takes over once the
# other has been silent this long.
LOCK_SECONDS = int(os.environ.get("PR_AUTOPILOT_LOCK_SECONDS", str(5 * 60)))
MAX_FAILURES = 3            # per PR commit, then give up and notify
MAX_JOBS = 2                # full reviews running at once on the laptop
# Review VMs running at once on Datum, one per PR commit (quick review, then full if needed).
MAX_DATUM_JOBS = int(os.environ.get("PR_AUTOPILOT_MAX_DATUM_JOBS", "3"))
NOTIFY_EVERY = 6 * 3600     # repeat a standing warning (login, GitHub down) at most this often
POLL_FAIL_ALERT = 15        # consecutive runs where every repo poll failed
JOB_TTL = 7 * 24 * 3600     # finished job records older than this are deleted
JOBS_DIR = full_review.CACHE / ("jobs-dry-run" if DRY_RUN else "jobs")
LOG_FILE = pathlib.Path(os.environ.get(
    "PR_AUTOPILOT_LOG", pathlib.Path.home() / "Library" / "Logs" / "pr-autopilot.log"))
LOG_MAX_BYTES = 5 * 1024 * 1024
# Rebuilt every run. Open it in a browser, or serve its folder with serve_dashboard.py:
# the folder holds only this page, so serving it exposes nothing else from the cache.
DASHBOARD_FILE = full_review.CACHE / "dashboard" / "index.html"
DASHBOARD_PORT = int(os.environ.get("PR_AUTOPILOT_DASHBOARD_PORT", "8787"))  # 0 turns the server off
# Keychain item holding the Slack webhook URL: an app's Incoming Webhook, or a Workflow
# Builder "starts with a webhook" trigger with one text variable named `text`.
# Without it, notifications fall back to macOS ones. Store it with:
#   security add-generic-password -a "$USER" -s pr-autopilot-slack-webhook -U -w
SLACK_KEYCHAIN_SERVICE = "pr-autopilot-slack-webhook"

# The quick review's prompt and schema live in pr_worker, which the review image also runs.
QUICK_SYSTEM, QUICK_SCHEMA = pr_worker.QUICK_SYSTEM, pr_worker.QUICK_SCHEMA


# Log layout: one headline per event, outcome in a fixed column so it can be scanned or
# grepped (`grep -E 'APPROVED|BLOCKED'`), details indented underneath:
#   2026-11-01 12:16:44  BLOCKED   example-org/twins-in-the-loop#103  chore(deps): update node.js to v26
#                                  by renovate[bot], requested by carol · full review
#                                  ...
INDENT = " " * 31


# Every event is also appended here as JSON, for the dashboard; set in main(), not by tests.
EVENTS_FILE: pathlib.Path | None = None


# The dispatcher on Datum has no events file: it collects events here and writes them to a
# ConfigMap (dispatcher.flush_events). None everywhere else.
EVENT_SINK: list | None = None


def event(kind: str, subject: str, *details: str, usage: list | None = None,
          notify: dict | None = None) -> None:
    """Log one event, and keep it as JSON for the dashboard. `usage` (token use of a
    review on Datum) rides along on DONE events, for the stats job's usage log.
    `notify` ({title, text, url}) marks an event the stats job shows as a macOS
    notification: the dispatcher's notify() sets it, since Datum has no macOS."""
    lines = [f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {kind:<9} {subject}"]
    for detail in details:
        lines += [INDENT + line for line in str(detail).strip().splitlines()]
    print("\n".join(lines), flush=True)
    record = {"ts": round(time.time()), "kind": kind, "subject": subject,
              "details": [str(d).strip() for d in details]}
    if usage is not None:
        record["usage"] = usage
    if notify is not None:
        record["notify"] = notify
    if EVENT_SINK is not None:
        EVENT_SINK.append(record)
    if EVENTS_FILE is not None:
        try:
            with EVENTS_FILE.open("a") as f:
                f.write(json.dumps(record) + "\n")
        except OSError:
            pass


def log(msg: str) -> None:
    event("NOTICE", msg)


# A failed GitHub call; its message says what GitHub answered (see github_api).
GhError = github_api.GitHubError


def subject(key: str, title: str = "") -> str:
    return f"{key}  {title}" if title else key


def pr_url(repo: str, num) -> str:
    return f"https://github.com/{repo}/pull/{num}"


def slack_webhook() -> str | None:
    """The Slack Incoming Webhook URL, kept in the login Keychain rather than in files."""
    url = os.environ.get("PR_AUTOPILOT_SLACK_WEBHOOK") or full_review.keychain_secret(SLACK_KEYCHAIN_SERVICE) or ""
    return url if url.startswith("https://hooks.slack.com/") else None


def slack_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def send_slack(webhook: str, title: str, message: str, url: str | None) -> None:
    """Post to an app's Incoming Webhook (/services/), which renders Slack markup, or to
    a Workflow Builder webhook trigger, which fills one `text` variable with plain text."""
    if "/services/" in webhook:
        text = f"*{slack_escape(title)}*\n{slack_escape(message)}"
        if url:
            text += f"\n<{url}|{slack_escape(url.replace('https://github.com/', ''))}>"
    else:
        text = f"{title}\n{message}" + (f"\n{url}" if url else "")
    req = urllib.request.Request(webhook, data=json.dumps({"text": text}).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        resp.read()


def notify(title: str, message: str, url: str | None = None) -> None:
    """Something needs you: post to Slack, or fall back to a macOS notification."""
    webhook = slack_webhook()
    if webhook:
        try:
            send_slack(webhook, title, message, url)
            return
        except Exception as e:
            log(f"Slack notification failed{'' if DISPATCHER else ', using a macOS one instead'}: {e}")
    if DISPATCHER:  # no macOS here, and no subprocesses: the stats job on the laptop shows it
        event("NOTICE", f"notification: {title}: {message}" + (f" {url}" if url else ""),
              notify={"title": title, "text": message, "url": url})
        return
    notifier = shutil.which("terminal-notifier")
    if notifier:
        # Clicking the notification opens the PR. terminal-notifier reads a
        # value that starts with "-" or "[" as an option, so escape it.
        def arg(text: str) -> str:
            return "\\" + text if text[:1] in "-[" else text
        args = [notifier, "-title", arg(title), "-message", arg(message), "-sound", "default"]
        if url:
            args += ["-open", url, "-group", url]
        try:
            if subprocess.run(args, capture_output=True, timeout=30).returncode == 0:
                return
        except subprocess.TimeoutExpired:
            pass
    script = f"display notification {json.dumps(message)} with title {json.dumps(title)}"
    try:
        subprocess.run(["osascript", "-e", script], capture_output=True, timeout=30)
    except subprocess.TimeoutExpired:
        log(f"macOS notification timed out: {title}")


def notify_throttled(state: dict, name: str, title: str, message: str) -> None:
    """Notify about a standing problem at most once per NOTIFY_EVERY."""
    sent = state.setdefault("notified", {})
    if time.time() - sent.get(name, 0) >= NOTIFY_EVERY:
        sent[name] = time.time()
        log(f"{title}: {message}")
        notify(title, message)


class StateUnavailable(Exception):
    """The state could not be loaded, so nothing is known about what was reviewed."""


# ConfigMap backend only, kept for as long as the process lives: one run in production
# (launchd runs --once), longer in loop mode. "base" is the state as last read from or
# written to the ConfigMap, "version" its resourceVersion, "state" the working state.
# "seeded" means the ConfigMap is about to be created from the local file.
STORE_MEMORY = {"state": None, "base": None, "version": None, "seeded": False}


# True in the dispatcher on Datum (dispatcher.py): one process, no fork/exec, no laptop.
DISPATCHER = False
# What the lock last saw, so a waiting run logs a change of owner once, not every minute.
# "lost": another runner took the lock during this process's pass; stop at once.
LOCK_SEEN = {"waiting_for": None, "lost": False}
LOCK_RENEW = 60  # renew the heartbeat during a pass once it is this old
# The dispatcher is long-lived, and two instances can overlap during a rollout with the same
# hostname: each process gets its own id. The laptop runs a new process every minute
# (launchd, --once) and must keep one id, or each run would lock out the next.
_PROCESS = secrets.token_hex(3)


class LockLost(Exception):
    """Another runner took the single-active lock; this one must stop writing."""


def owner_id() -> str:
    base = os.environ.get("PR_AUTOPILOT_OWNER") or \
        f"{'dispatcher' if DISPATCHER else 'laptop'}@{socket.gethostname()}"
    return f"{base}#{_PROCESS}" if DISPATCHER else base


def lock_holder(state: dict, now: float) -> str | None:
    """Who else holds the lock, or None when it is free or ours."""
    owner = state.get("owner") or {}
    if owner.get("id") not in (None, owner_id()) and now - owner.get("heartbeat", 0) < LOCK_SECONDS:
        return owner["id"]
    return None


# A wall-clock step this much larger than the monotonic one means the process was frozen
# in between (a parked unikernel VM): another runner may have taken the lock meanwhile.
CLOCK_JUMP = 60
CLOCK = {"wall": None, "mono": None}


def clock_jumped() -> bool:
    """True if the wall clock moved CLOCK_JUMP seconds more than the monotonic clock
    since the last call."""
    wall, mono = time.time(), time.monotonic()
    last_wall, last_mono = CLOCK["wall"], CLOCK["mono"]
    CLOCK.update(wall=wall, mono=mono)
    return last_wall is not None and (wall - last_wall) - (mono - last_mono) > CLOCK_JUMP


def confirm_lock() -> None:
    """Re-read the lock from the ConfigMap, not from this pass's copy, and raise LockLost
    unless it is still ours. Called before every GitHub write and after a clock jump: a
    pass that was frozen for more than LOCK_SECONDS still has owner = itself in memory,
    while another runner may have taken over. If the lock is ours but the heartbeat
    lapsed, it is renewed with the resourceVersion just read, so a runner taking it at
    the same moment makes this write conflict instead of both going on."""
    if STATE_BACKEND != "configmap":
        return
    store = state_store_client()
    try:
        loaded, version = store.load()
    except state_store.Unavailable as e:
        raise LockLost(f"could not confirm the lock: {e}")
    owner = (loaded or {}).get("owner") or {}
    if owner.get("id") not in (None, owner_id()):
        LOCK_SEEN["lost"] = True
        raise LockLost(f"{owner['id']} holds the lock now")
    if owner.get("id") is None or time.time() - owner.get("heartbeat", 0) < LOCK_SECONDS:
        return
    loaded["owner"] = {"id": owner_id(), "heartbeat": round(time.time())}
    try:
        store.save(loaded, version)
    except (state_store.Conflict, state_store.Unavailable) as e:
        LOCK_SEEN["lost"] = True
        raise LockLost(f"the heartbeat had lapsed and could not be renewed: {e}")


def renew_lock(state: dict) -> None:
    """Renew the heartbeat in the middle of a long pass, so the lock never lapses while
    this runner works. Raises LockLost if someone else took it."""
    if STATE_BACKEND != "configmap":
        return
    if LOCK_SEEN["lost"]:
        raise LockLost("another runner took the lock")
    if clock_jumped():
        confirm_lock()
    owner = state.get("owner") or {}
    if owner.get("id") == owner_id() and time.time() - owner.get("heartbeat", 0) >= LOCK_RENEW:
        owner["heartbeat"] = round(time.time())
        save_state_configmap(state)
        if LOCK_SEEN["lost"]:
            raise LockLost("another runner took the lock")


def hold_lock(state: dict) -> bool:
    """Take or renew the single-active lock. False: someone else holds it, skip this run.
    Taking it is written at once, with the resourceVersion just read: if another writer got
    there first the write conflicts, and this run gives way."""
    now = time.time()
    holder = lock_holder(state, now)
    if holder:
        if LOCK_SEEN["waiting_for"] != holder:
            LOCK_SEEN["waiting_for"] = holder
            # An event, not only a log line: in the dispatcher it reaches the events
            # ConfigMap, so the stats dashboard shows why nothing is reviewed. A restarted
            # dispatcher gets a new id and waits out its old heartbeat this way.
            until = (state.get("owner") or {}).get("heartbeat", now) + LOCK_SECONDS
            event("NOTICE", f"{owner_id()} is waiting for the lock held by {holder} until "
                  f"{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(until))}",
                  f"it takes over if {holder} writes no heartbeat for {LOCK_SECONDS // 60} minutes")
        return False
    LOCK_SEEN["waiting_for"] = None
    LOCK_SEEN["lost"] = False
    before = state.get("owner") or {}
    state["owner"] = {"id": owner_id(), "heartbeat": round(now)}
    if before.get("id") == owner_id():
        return True  # renewed; saved with the rest of the run
    mem, store = STORE_MEMORY, state_store_client()
    try:
        mem["version"] = store.save(state, mem["version"])
    except (state_store.Conflict, state_store.Unavailable) as e:
        state["owner"] = before
        log(f"could not take the lock, trying again next run: {e}")
        return False
    mem["base"] = copy.deepcopy(state)
    if mem["seeded"]:
        retire_state_file()
    gone = f" from {before['id']}, silent for {round(now - before.get('heartbeat', 0))}s" if before.get("id") else ""
    event("NOTICE", f"{owner_id()} took the lock{gone}")
    return True


def normalize_state(state: dict) -> dict:
    state.pop("retry", None)          # replaced by "rescan"
    state.setdefault("reviewed", {})  # "repo#num" -> last handled head SHA
    state.setdefault("rescan", False) # search again next run, whatever the notifications say
    state.setdefault("failures", {})  # "repo#num@sha" -> failed attempts
    return state


def read_state_file() -> dict:
    try:
        return json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    except ValueError:
        broken = STATE_FILE.with_name(f"{STATE_FILE.name}.corrupt-{int(time.time())}")
        STATE_FILE.replace(broken)
        log(f"state file was not valid JSON, moved it to {broken} and started fresh")
        notify("PR autopilot", f"State file was corrupt and has been reset; old copy at {broken}")
        return {}


def state_store_client() -> state_store.ConfigMapStore:
    return state_store.ConfigMapStore(remote_review.PROJECT, remote_review.SESSION)


def load_state() -> dict:
    if STATE_BACKEND == "configmap":
        return load_state_configmap()
    return normalize_state(read_state_file())


def load_state_configmap() -> dict:
    """The state from the ConfigMap, with any changes an earlier run could not save merged
    in. Never falls back to the local file: if the ConfigMap cannot be read, use the state
    already in memory (loop mode), or raise StateUnavailable (--once: the run is skipped)."""
    mem = STORE_MEMORY
    try:
        loaded, version = state_store_client().load()
    except state_store.Unavailable as e:
        if mem["state"] is None:
            raise StateUnavailable(str(e)) from e
        log(f"state ConfigMap unreachable, using the state kept in memory: {e}")
        return mem["state"]
    mem["seeded"] = False
    if loaded is None:
        if STATE_FILE.exists():  # first use: start from the local file, once
            loaded = read_state_file()
            mem["seeded"] = True
            log(f"state ConfigMap {state_store.NAME} not found; creating it from {STATE_FILE}"
                f" ({len(loaded.get('reviewed', {}))} reviewed PRs)")
        else:
            loaded = {}
            event("WARN", f"state ConfigMap {state_store.NAME} not found and no local state to start "
                  "from; starting empty, so PRs waiting on you may be reviewed again")
    theirs = normalize_state(loaded)
    state = copy.deepcopy(theirs)
    unsaved = read_spool()
    if unsaved:
        state = normalize_state(state_store.merge(unsaved["base"], unsaved["state"], state))
    if mem["state"] is not None and mem["state"] != mem["base"]:  # loop mode: a save failed
        state = normalize_state(state_store.merge(mem["base"], mem["state"], state))
    mem.update(state=state, base=theirs, version=version)
    return state


def read_spool() -> dict | None:
    try:
        unsaved = json.loads(STATE_SPOOL_FILE.read_text())
    except FileNotFoundError:
        return None
    except ValueError as e:
        log(f"dropping unreadable {STATE_SPOOL_FILE}: {e}")
        return None
    if not (isinstance(unsaved, dict) and isinstance(unsaved.get("base"), dict)
            and isinstance(unsaved.get("state"), dict)):
        log(f"dropping {STATE_SPOOL_FILE}: not a base/state pair")
        return None
    return unsaved


def spool_unsaved(state: dict) -> None:
    """Keep this run's unsaved changes for the next run, which merges them into the
    ConfigMap. Without this, with --once, a failed save would lose them."""
    try:
        STATE_SPOOL_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATE_SPOOL_FILE.with_name(STATE_SPOOL_FILE.name + ".tmp")
        tmp.write_text(json.dumps({"base": STORE_MEMORY["base"], "state": state}))
        tmp.replace(STATE_SPOOL_FILE)
    except OSError as e:
        log(f"could not keep the unsaved state in {STATE_SPOOL_FILE}: {e}")


def save_state(state: dict) -> None:
    if STATE_BACKEND == "configmap":
        save_state_configmap(state)
        return
    tmp = STATE_FILE.with_name(STATE_FILE.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=1))
    tmp.replace(STATE_FILE)  # atomic, so a crash never leaves half a file


def save_state_configmap(state: dict) -> bool:
    """Write the state if nobody changed the ConfigMap since it was read. On a conflict,
    reload, re-apply this run's changes and try again. If it still fails, keep the changes
    in memory and in STATE_SPOOL_FILE for the next run; never write the local state file."""
    mem, store = STORE_MEMORY, state_store_client()
    mem["state"] = state
    if state == mem["base"] and mem["version"] is not None:
        STATE_SPOOL_FILE.unlink(missing_ok=True)
        return True  # nothing changed: no write, no new resourceVersion
    for _ in range(STATE_SAVE_ATTEMPTS):
        try:
            mem["version"] = store.save(state, mem["version"])
            mem["base"] = copy.deepcopy(state)
            STATE_SPOOL_FILE.unlink(missing_ok=True)
            if mem["seeded"]:
                retire_state_file()
            return True
        except state_store.Conflict:
            try:
                loaded, version = store.load()
            except state_store.Unavailable as e:
                event("WARN", "state not saved: the ConfigMap changed and could not be read again; "
                      "the next run retries", str(e))
                break
            theirs = normalize_state(loaded or {})
            holder = lock_holder(theirs, time.time()) if STATE_BACKEND == "configmap" and state.get("owner") else None
            if holder:
                # Someone else took the lock: their state wins whole. Merging ours in would
                # undo their decisions (reviewed, jobs) with a stale view. Stop here.
                event("WARN", f"{holder} took the lock during this run; dropping this run's unsaved "
                      "changes and standing by")
                LOCK_SEEN["lost"] = True
                state.clear()
                state.update(theirs)
                mem.update(state=state, base=copy.deepcopy(theirs), version=version)
                STATE_SPOOL_FILE.unlink(missing_ok=True)
                return False
            merged = normalize_state(state_store.merge(mem["base"], state, theirs))
            # The lock is one value, not a dict to merge per entry.
            if state.get("owner") is not None:
                merged["owner"] = state["owner"]
            state.clear()
            state.update(merged)  # same object, so the caller sees the merged state
            mem.update(base=theirs, version=version)
        except state_store.Unavailable as e:
            event("WARN", "state not saved; the next run retries", str(e))
            break
    else:
        event("WARN", f"state not saved: the ConfigMap kept changing ({STATE_SAVE_ATTEMPTS} conflicts); "
              "the next run retries")
    spool_unsaved(state)
    return False


def retire_state_file() -> None:
    """After the ConfigMap is created from the local file, rename the file so that a later
    NotFound (the ConfigMap deleted) never brings back state that stopped updating."""
    STORE_MEMORY["seeded"] = False
    retired = STATE_FILE.with_name(STATE_FILE.name + ".migrated")
    try:
        STATE_FILE.replace(retired)
        log(f"state now lives in ConfigMap {state_store.NAME}; moved {STATE_FILE} to {retired}")
    except OSError as e:
        log(f"could not move {STATE_FILE} to {retired}: {e}")


def state_down(error: str) -> None:
    """Record that the state could not be loaded; notify once it has lasted a while."""
    now = time.time()
    try:
        down = json.loads(STATE_DOWN_FILE.read_text())
    except (OSError, ValueError):
        down = {}
    if not down:
        down = {"since": now}
        event("WARN", "state ConfigMap unreachable, skipping runs until it is back", error)
    else:
        log(f"state ConfigMap still unreachable, run skipped: {error}")
    if now - down["since"] >= STATE_DOWN_ALERT and now - down.get("notified", 0) >= NOTIFY_EVERY:
        notify("PR autopilot is paused", f"It cannot read its state from Datum, so it reviews nothing "
               f"until it can: {error[:300]}")
        down["notified"] = now
    STATE_DOWN_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_DOWN_FILE.write_text(json.dumps(down))


def load_config() -> dict:
    return json.loads(CONFIG_FILE.read_text())


def config_for(config: dict, repo: str) -> dict | None:
    """A repo's settings: its own entry, else its owner's "owner/*" entry, else None."""
    return config.get(repo) or config.get(repo.split("/")[0] + "/*")


def search_query(config: dict) -> str:
    owners = sorted(k[:-2] for k in config if k.endswith("/*"))
    repos = sorted(k for k in config if not k.endswith("/*") and k.split("/")[0] not in owners)
    scope = " ".join([f"org:{o}" for o in owners] + [f"repo:{r}" for r in repos])
    # Archived repos are read-only: GitHub refuses any review there (HTTP 422).
    return f"is:pr is:open archived:false user-review-requested:@me {scope}"


def find_prs(config: dict) -> list[tuple[str, dict]]:
    """Open PRs where you personally are a requested reviewer, in every covered repo."""
    global SEARCH_COMPLETE
    found = github_api.search_issues(search_query(config))
    items = found["items"]
    SEARCH_COMPLETE = not found.get("incomplete_results") and found.get("total_count", 0) <= len(items)
    prs = []
    for it in items:
        repo = it["repository_url"].split("/repos/", 1)[1]
        if config_for(config, repo) is not None:
            prs.append((repo, {"number": it["number"], "title": it["title"], "updatedAt": it.get("updated_at", ""),
                               "isDraft": it.get("draft", False), "author": {"login": it["user"]["login"]}}))
    return prs


SEARCH_COMPLETE = False  # the last find_prs() saw every waiting PR (one page, no timeout)


def allowed(cfg: dict, pr: dict) -> bool:
    """Ours to handle: the author, or whoever asked for your review, is in "authors"."""
    people = set(cfg.get("authors", []))
    return "*" in people or pr["author"]["login"] in people or pr.get("requested_by") in people


_ME: list = []


def my_login(state: dict) -> str:
    if not state.get("me"):
        if not _ME:
            _ME.append(github_api.login())
        state["me"] = _ME[0]
    return state["me"]


def last_request(repo: str, num, me: str) -> tuple[str, float] | None:
    """Who most recently asked you personally to review this PR, and when (epoch seconds)."""
    found = [e for e in github_api.timeline(repo, num)
             if e.get("event") == "review_requested" and (e.get("requested_reviewer") or {}).get("login") == me]
    if not found:
        return None
    # A deleted account shows as a null actor; GitHub calls it "ghost".
    return (found[-1].get("actor") or {}).get("login") or "ghost", epoch(found[-1]["created_at"])


def who_requested_me(repo: str, num, me: str) -> str | None:
    found = last_request(repo, num, me)
    return found[0] if found else None


def epoch(iso: str) -> float:
    return calendar.timegm(time.strptime(iso, "%Y-%m-%dT%H:%M:%SZ"))


def my_last_review(repo: str, num, me: str) -> tuple[float, str, str] | None:
    """When you last submitted a review on this PR, its state and commit, if ever."""
    mine = [r for r in github_api.reviews(repo, num)
            if (r.get("user") or {}).get("login") == me and r.get("submitted_at")]
    if not mine:
        return None
    return epoch(mine[-1]["submitted_at"]), mine[-1]["state"], mine[-1]["commit_id"]


def handled(state: dict, key: str, sha: str, at: float | None = None) -> None:
    """Record that this commit is dealt with, and when (a later re-request reopens it)."""
    state["reviewed"][key] = sha
    state.setdefault("handled_at", {})[key] = at or time.time()


def requested_again(repo: str, num, key: str, pr: dict, state: dict) -> str | None:
    """Who asked for your review again after this commit was handled, if anyone.

    Approving or commenting clears the request, so a request newer than that
    means someone wants another look. If your approval of this commit still
    stands, approving again changes nothing, so that is only logged. Cached
    until the PR changes."""
    cache = state.setdefault("rerequest", {})
    ckey = f"{key}@{pr.get('updatedAt', '')}"
    if ckey not in cache:
        me = my_login(state)
        mine = my_last_review(repo, num, me)
        at = state.setdefault("handled_at", {}).get(key) or (mine and mine[0])
        if not at:  # handled before this was tracked, with nothing posted
            state["handled_at"][key] = at = time.time()
        last = last_request(repo, num, me)
        cache[ckey] = last[0] if last and last[1] > at else ""
        if cache[ckey] and mine and mine[1:] == ("APPROVED", pr["headRefOid"]):
            event("NOTICE", subject(key, pr["title"]),
                  f"{cache[ckey]} asked for your review again, but your approval of this commit still "
                  "stands; not approving twice. The merge is likely waiting on someone else, such as a code owner.",
                  pr_url(repo, num))
            cache[ckey] = ""
    return cache[ckey] or None


def rotate_log() -> None:
    try:
        if LOG_FILE.stat().st_size > LOG_MAX_BYTES:
            LOG_FILE.replace(LOG_FILE.with_name(LOG_FILE.name + ".1"))
    except FileNotFoundError:
        pass


def quick_review(repo: str, num: str, context: str, title: str, diff: str) -> dict:
    """The quick review on the laptop, for repos that do not run on Datum."""
    return pr_worker.quick_review(repo, num, context, title, diff, QUICK_MODEL)


def post_review(repo: str, num: str, sha: str, event: str | None, body: str,
                floor: int | None = None) -> None:
    """Pin the review to the commit that was reviewed. No event = pending review,
    visible only to you until you submit it. `floor`: the job's review_floor; only a
    review of yours with a higher id counts as this one already posted. Without it,
    any review of yours in the same state on this commit counts."""
    state = {"APPROVE": "APPROVED", "COMMENT": "COMMENTED"}.get(event or "", "PENDING")
    confirm_lock()  # raises LockLost: only the lock holder writes to GitHub
    if DISPATCHER and posted_already(repo, num, sha, state, floor):
        # A pass that posted, then crashed before saving, runs this again: never post twice.
        log(f"{repo}#{num}: a {state} review of {sha[:8]} is already there; not posting again")
        return
    try:
        github_api.create_review(repo, num, sha, event, body)
    except GhError:
        # A dropped connection can lose GitHub's answer after the review was saved.
        # If it is there, the post worked; otherwise it really failed.
        try:
            found = posted_already(repo, num, sha, state, floor)
        except GhError:
            found = False
        if not found:
            raise


def my_reviews_on(repo: str, num: str, sha: str) -> list[dict]:
    me = my_login({})
    return [r for r in github_api.reviews(repo, num)
            if r.get("commit_id") == sha and (r.get("user") or {}).get("login") == me]


def review_floor(repo: str, num: str, sha: str) -> int:
    """The highest id of your reviews on this commit, 0 if none. Stored in a job at
    launch: any review of yours with a higher id was posted for that job."""
    return max((int(r.get("id") or 0) for r in my_reviews_on(repo, num, sha)), default=0)


def posted_already(repo: str, num: str, sha: str, state: str, floor: int | None = None) -> bool:
    """Whether you already have a review in this state on this commit, with an id above
    `floor` (the job's review_floor) if given. The check exists for a pass that posted
    and crashed before its save: the replay must not post twice. It must not match an
    older review, e.g. your COMMENT on this commit from before someone asked you to
    review it again, or the new review would be dropped. Review ids only grow, so this
    needs no clock."""
    return any(r.get("state") == state and (floor is None or int(r.get("id") or 0) > floor)
               for r in my_reviews_on(repo, num, sha))


def changed_repos(state: dict) -> set[str]:
    """Repos with notifications newer than the last run; empty on 304, and empty without
    asking while GitHub's X-Poll-Interval has not passed since the last call."""
    now = time.time()
    if now < state.get("notif_next_at", 0):
        return set()
    notifications, last_modified, interval = github_api.notifications(state.get("notif_last_modified"))
    state["notif_next_at"] = now + interval if interval > POLL_SECONDS else 0
    if notifications is None:
        return set()
    watermark = state.get("notif_watermark", "")
    fresh = [n for n in notifications if n["updated_at"] > watermark]
    if fresh:
        state["notif_watermark"] = max(n["updated_at"] for n in fresh)
    state["notif_last_modified"] = last_modified
    return {n["repository"]["full_name"] for n in fresh}


def fetch_diff(repo: str, num: str) -> tuple[str | None, list[str]]:
    """The PR diff (None if GitHub refuses it as too large) and the changed paths."""
    diff = github_api.diff(repo, num)
    if diff is None:
        return None, github_api.changed_files(repo, num)
    paths = []
    for m in re.finditer(r"^diff --git a/(.+?) b/(.+)$", diff, re.MULTILINE):
        paths += [m.group(1)] if m.group(1) == m.group(2) else [m.group(1), m.group(2)]
    return diff, paths


class Job:
    """A background full review for one PR commit, tracked by a JSON file."""

    def __init__(self, repo: str, num: str, sha: str):
        self.path = JOBS_DIR / f"{repo.replace('/', '__')}__{num}__{sha[:12]}.json"

    def read(self) -> dict | None:
        try:
            return json.loads(self.path.read_text())
        except (FileNotFoundError, ValueError):
            return None

    def write(self, **fields) -> None:
        data = {**(self.read() or {}), **fields}
        JOBS_DIR.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data))
        tmp.replace(self.path)

    def status(self) -> str | None:
        data = self.read()
        if not data:
            return None
        if data.get("status") == "running" and not pid_alive(data.get("pid", 0)):
            return "died"
        return data.get("status")

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)

    def finished_at(self) -> float:
        return self.path.stat().st_mtime


class StateJob:
    """A review on Datum started by the dispatcher, kept in state["jobs"] under
    "repo#num@sha" instead of a local file: the dispatcher has no worker process to
    track, and a restarted dispatcher must find its jobs again. Same methods as Job.

    Statuses, on top of Job's: "queued" (waiting for a free worker slot) and "result"
    (the worker called back; the next pass posts it). See state_store.JOB_FIELDS."""

    def __init__(self, state: dict, repo: str, num: str, sha: str):
        self.jobs = state.setdefault("jobs", {})
        self.key = f"{repo}#{num}@{sha}"

    def read(self) -> dict | None:
        data = self.jobs.get(self.key)
        return dict(data) if data else None

    def write(self, **fields) -> None:
        if fields.get("status") in ("done", "stale", "unposted", "auth", "failed"):
            fields.setdefault("finished", round(time.time()))
        self.jobs[self.key] = {**self.jobs.get(self.key, {}), **fields}

    def status(self) -> str | None:
        return (self.jobs.get(self.key) or {}).get("status")

    def clear(self) -> None:
        self.jobs.pop(self.key, None)

    def finished_at(self) -> float:
        return (self.jobs.get(self.key) or {}).get("finished") or time.time()


def make_job(repo: str, num: str, sha: str, state: dict):
    return StateJob(state, repo, num, sha) if DISPATCHER else Job(repo, num, sha)


def dispatcher_job_pending(state: dict, key: str, sha: str) -> bool:
    """On the laptop: the dispatcher on Datum queued or ran this commit not long ago (it
    held the lock before), so do not start a second review of it. After a worker's
    lifetime the record is stale and the laptop reviews it itself."""
    data = (state.get("jobs") or {}).get(f"{key}@{sha}") or {}
    started = data.get("started") or data.get("queued") or 0
    return data.get("status") in ("queued", "running", "result") and time.time() - started < WORKER_TTL


WORKER_TTL = 45 * 60  # a worker VM on Datum gets this long to call back, then it is deleted


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return pid > 0
    except (ProcessLookupError, PermissionError):
        return False


def job_files() -> list[tuple[pathlib.Path, dict]]:
    out = []
    for p in JOBS_DIR.glob("*.json") if JOBS_DIR.exists() else []:
        try:
            out.append((p, json.loads(p.read_text())))
        except ValueError:
            continue
    return out


def running_jobs() -> int:
    return sum(d.get("status") == "running" and pid_alive(d.get("pid", 0)) for _, d in job_files())


def datum_jobs() -> int:
    """Running jobs whose review runs in a VM on Datum. The rest run on the laptop."""
    return sum(d.get("status") == "running" and d.get("runner") == "datum" and pid_alive(d.get("pid", 0))
               for _, d in job_files())


def prune_jobs() -> None:
    """Drop finished job records nobody will read: the PR left your review queue."""
    for p, d in job_files():
        if d.get("status") != "running" and time.time() - p.stat().st_mtime > JOB_TTL:
            p.unlink(missing_ok=True)


def review(repo: str, cfg: dict, pr: dict, state: dict) -> bool:
    """Returns False when the PR should be looked at again next run."""
    reviewed = state["reviewed"]
    num, sha = str(pr["number"]), pr["headRefOid"]
    key = f"{repo}#{num}"
    if reviewed.get(key) == sha or pr["isDraft"]:
        return True
    title, url = pr["title"], pr_url(repo, num)
    author = "by " + pr["author"]["login"] + (f", requested by {pr['requested_by']}" if pr.get("requested_by") else "")
    if not allowed(cfg, pr):
        handled(state, key, sha)  # not ours to auto-approve
        return True

    mode = cfg.get("review", "none")
    if mode == "none":
        event("APPROVED", subject(key, title), f"{author} · unconditional for this repo", url)
        if not DRY_RUN:
            post_review(repo, num, sha, "APPROVE", "Auto-approved.")
        handled(state, key, sha)
        return True
    if mode != "full":
        raise ValueError(f"unknown review mode {mode!r} for {repo}")

    if not DISPATCHER and dispatcher_job_pending(state, key, sha):
        return False
    job = make_job(repo, num, sha, state)
    status = job.status()
    if status in ("running", "queued", "result"):
        return False
    if status == "done":
        # The review may have finished days ago: approving clears the request, so the
        # PR left the queue before this record was read. Date it by the job's end, or
        # a re-request that brought the PR back would count as already handled.
        finished = job.finished_at()
        job.clear()
        handled(state, key, sha, at=finished)
        return False  # look again next run, in case someone asked again since
    if status == "stale":  # head moved during the review
        job.clear()
        return False
    if status == "unposted":  # finished, but GitHub did not take the result: post only, no new review
        return post_finished(repo, num, sha, key, title, url, job, state)
    if status == "auth":
        error = (job.read() or {}).get("error") or "Claude Code login expired; run `claude auth login`"
        job.clear()
        raise claude_cli.AuthExpired(error)  # the remote runner names its own fix
    if status in ("failed", "died"):
        error = (job.read() or {}).get("error", "worker exited without a result")
        job.clear()
        raise RuntimeError(f"full review failed: {error}")

    diff, paths = fetch_diff(repo, num)
    manual = [p for p in paths if any(re.search(rx, p) for rx in MANUAL_PATHS)]
    if manual:
        event("MANUAL", subject(key, title), f"{author} · changes {manual[0]}, left to you", url)
        if not DRY_RUN:
            notify("PR needs your review", f"{title}\nIt changes {manual[0]}, which decides who must "
                   "approve, so it was not auto-reviewed.", url)
        handled(state, key, sha)
        return True

    def listed(ps: list[str]) -> str:
        return f"{', '.join(ps[:3])}{' and more' if len(ps) > 3 else ''}"

    workflows = [p for p in paths if full_review.is_workflow(p)]
    hits = [p for p in paths if not p.endswith(".md")
            and any(re.search(rx, p) for rx in cfg.get("full_review_paths", []))]
    reason = (f"changes GitHub Actions workflows: {listed(workflows)}" if workflows
              else f"touches {listed(hits)}" if hits else "")
    if not reason and (diff is None or len(diff) > MAX_DIFF_CHARS):
        reason = pr_worker.DIFF_TOO_LARGE
    if DISPATCHER:
        if not remote_review.vm_can_read(repo):  # no laptop to fall back to
            event("MANUAL", subject(key, title), f"{author} · private repo the review VM cannot read, left to you", url)
            if not DRY_RUN:
                notify("PR needs your review", f"{title}\nThe review VM cannot read this private repo, so it "
                       "was not auto-reviewed.", url)
            handled(state, key, sha)
            return True
        return start_on_datum(repo, num, sha, key, title, url, author, reason, state=state)
    if remote_review.runs_on_datum(repo):
        return start_on_datum(repo, num, sha, key, title, url, author, reason)
    route, audit = "rules", False

    if not reason:
        # If a new commit landed while we fetched the diff, retry next round.
        head = github_api.head_sha(repo, num)
        if head != sha:
            return False
        verdict = quick_review(repo, num, cfg.get("context", ""), title, diff)
        approve = verdict["verdict"] == "approve" and not verdict["needs_full_review"]
        # Roll only when a slot is free, so a sampled PR never waits and gets re-rolled.
        if approve and running_jobs() - datum_jobs() < MAX_JOBS and random.random() < AUDIT_RATE:
            approve, audit = False, True
        if approve:
            event("APPROVED", subject(key, title), f"{author} · quick review", verdict["summary"], url)
            if not DRY_RUN:
                post_review(repo, num, sha, "APPROVE", "")
            handled(state, key, sha)
            return True
        if audit:
            route, reason = "audit", AUDIT_FOCUS
        else:
            route = "quick"
            reason = verdict["full_review_reason"] or "; ".join(verdict["critical"]) or verdict["summary"]

    if running_jobs() - datum_jobs() >= MAX_JOBS:
        return False  # start it once a slot frees up
    start_full_review(repo, num, sha, reason, audit=audit)
    why = "random audit of a quick approval" if audit else reason
    event("REVIEWING", subject(key, title), f"{author} · full review started in the background",
          f"why: {why}", f"route: {route}", url)
    return False


def start_on_datum(repo: str, num: str, sha: str, key: str, title: str, url: str, author: str,
                   reason: str, state: dict | None = None) -> bool:
    """Start one review VM for this PR commit. With a rule's `reason` it runs the full
    review only; without one, the quick review and, if needed, the full review. On the
    laptop a worker process starts it and posts the outcome. In the dispatcher it is
    queued in the state; dispatcher.launch() starts it when a worker slot is free, and
    the worker calls back with the outcome. Either way this run looks again next time."""
    if not DISPATCHER and datum_jobs() >= MAX_DATUM_JOBS:
        return False  # start it once a VM slot frees up
    # Rolled here, as the VM decides after the quick review; it counts only if that approves.
    audit = not reason and random.random() < AUDIT_RATE
    plan = "full" if reason else "quick"
    where = "on Datum"
    if DISPATCHER:
        StateJob(state, repo, num, sha).write(status="queued", queued=round(time.time()), reason=reason,
                                              audit=audit, plan=plan, runner="datum", author=author, title=title)
        where = "queued for Datum"
    else:
        start_pr_review(repo, num, sha, plan, reason, audit, author=author)
    if plan == "full":
        event("REVIEWING", subject(key, title), f"{author} · full review {where}",
              f"why: {reason}", "route: rules", url)
    else:
        event("STARTED", subject(key, title),
              f"{author} · quick review {where}, with a full review in the same VM if needed", url)
    return False


def post_finished(repo: str, num: str, sha: str, key: str, title: str, url: str,
                  job: Job, state: dict) -> bool:
    """Retry posting a full review that finished but could not be posted. A new commit
    leaves the record behind (its key has the old SHA), so the old result is never posted
    on newer code; prune_jobs() deletes it later."""
    data = job.read() or {}
    what = "review comment" if data.get("post_event") == "COMMENT" else "approval"
    try:
        post_review(repo, num, sha, data["post_event"], data.get("post_body", ""), floor=data.get("review_floor"))
    except GhError as e:
        attempts = data.get("post_attempts", 1) + 1
        if attempts < MAX_FAILURES:
            job.write(post_attempts=attempts)
            event("WARN", subject(key, title),
                  f"could not post the finished {what}, attempt {attempts} of {MAX_FAILURES}; retrying next run", str(e))
            return False
        job.clear()
        handled(state, key, sha)
        event("GAVE UP", subject(key, title), f"the full review finished, but its {what} could not be posted "
              f"in {MAX_FAILURES} attempts; post it yourself", data.get("post_body", ""), str(e), url)
        notify("PR autopilot could not post a review",
               f"{title}\nThe full review finished, but GitHub did not take its {what}; the text is in the log.", url)
        return True
    job.clear()
    handled(state, key, sha)
    event("POSTED", subject(key, title), f"the {what} from the earlier full review, after a failed post", url)
    return False  # look again next run, in case someone asked again since


def start_full_review(repo: str, num: str, sha: str, reason: str, audit: bool = False) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a") as out:
        proc = subprocess.Popen(
            [sys.executable, str(pathlib.Path(__file__).resolve()), "--full-review", repo, num, sha, reason],
            stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
            start_new_session=True,  # survive the launchd job ending
        )
    Job(repo, num, sha).write(status="running", pid=proc.pid, started=time.time(), reason=reason, audit=audit)


def run_full_review(repo: str, num: str, sha: str, reason: str) -> None:
    """Worker process: one full review, then post it and record the outcome."""
    job = Job(repo, num, sha)
    job.write(status="running", pid=os.getpid())
    key = f"{repo}#{num}"
    try:
        cfg = config_for(load_config(), repo) or {}
        args = (repo, num, sha, cfg.get("context", ""), cfg.get("model", "opus"))
        opts = {"focus": reason, "strict_workflows": cfg.get("strict_workflows", False)}
        result, runner = None, "laptop"
        if remote_review.runs_on_datum(repo):
            try:
                result, runner = remote_review.review(*args, **opts), "datum"
            except (remote_review.DatumUnavailable, remote_review.ImageNotBuilt) as e:
                event("WARN", key, "reviewing on the laptop instead of Datum", str(e)[:500])
                if isinstance(e, remote_review.TokenExpired):
                    notify("PR autopilot: Datum token expired", f"{e}. Reviews run on the laptop meanwhile.")
        if runner == "laptop":
            result = full_review.review(*args, **opts)
        if result is None:
            job.write(status="stale")
            return
        report_full(job, repo, num, sha, result, runner, audit=bool((job.read() or {}).get("audit")))
    except claude_cli.AuthExpired as e:
        event("ERROR", key, f"full review not run: {e}")
        job.write(status="auth", error=str(e))
    except Exception as e:
        event("ERROR", key, "full review failed", str(e))
        job.write(status="failed", error=str(e)[:500])


def start_pr_review(repo: str, num: str, sha: str, plan: str, reason: str, audit: bool, author: str = "") -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a") as out:
        proc = subprocess.Popen(
            [sys.executable, str(pathlib.Path(__file__).resolve()), "--review-pr", repo, num, sha],
            stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
            start_new_session=True,  # survive the launchd job ending
        )
    Job(repo, num, sha).write(status="running", pid=proc.pid, started=time.time(), reason=reason, audit=audit,
                              plan=plan, runner="datum", author=author)


def run_pr_review(repo: str, num: str, sha: str) -> None:
    """Worker process: one review VM for this PR commit, then post its outcome. If Datum
    is not available, the same quick-then-full review runs on the laptop instead. That
    fallback does not wait for a laptop slot (MAX_JOBS): when Datum fails mid-run, up to
    MAX_DATUM_JOBS workers can fall back at once. mark_down() then sends new PRs down the
    laptop path, which keeps to MAX_JOBS."""
    job = Job(repo, num, sha)
    data = job.read() or {}
    plan, reason, audit = data.get("plan", "quick"), data.get("reason", ""), bool(data.get("audit"))
    job.write(status="running", pid=os.getpid())
    key = f"{repo}#{num}"
    try:
        cfg = config_for(load_config(), repo) or {}
        context, model = cfg.get("context", ""), cfg.get("model", "opus")
        opts = {"plan": plan, "focus": reason, "audit": audit, "quick_model": QUICK_MODEL,
                "strict_workflows": cfg.get("strict_workflows", False)}
        try:
            outcome, runner = remote_review.review_pr(repo, num, sha, context, model, **opts), "datum"
        except (remote_review.DatumUnavailable, remote_review.ImageNotBuilt) as e:
            event("WARN", key, "reviewing on the laptop instead of Datum", str(e)[:500])
            if isinstance(e, remote_review.TokenExpired):
                notify("PR autopilot: Datum token expired", f"{e}. Reviews run on the laptop meanwhile.")
            job.write(runner="laptop")
            outcome = pr_worker.review(repo, num, sha, context=context, model=model, **opts)
            runner = "laptop"
        report_outcome(job, repo, num, sha, outcome, runner)
    except claude_cli.AuthExpired as e:
        event("ERROR", key, f"review not run: {e}")
        job.write(status="auth", error=str(e))
    except Exception as e:
        event("ERROR", key, "review failed", str(e))
        job.write(status="failed", error=str(e)[:500])


def report_outcome(job: Job, repo: str, num: str, sha: str, outcome: dict, runner: str) -> None:
    """Log and post one pr_worker outcome: a quick approval, or a full review's result."""
    if outcome["verdict"] == "moved":
        job.write(status="stale")
        return
    key, url, title = f"{repo}#{num}", pr_url(repo, num), outcome.get("title") or ""
    data = job.read() or {}
    by = f"{data['author']} · " if data.get("author") else ""
    where = " on Datum" if runner == "datum" else ""
    route = outcome["route"]
    if outcome["findings"] is None:  # the quick review approved and nothing else ran
        error = post_or_keep(job, repo, num, sha, ("APPROVE", ""), "approve")
        event("APPROVED", subject(key, title), f"{by}quick review{where}", outcome["quick"]["summary"],
              *([f"could not post the approval, retrying next run without a new review: {error}"]
                if error else []), url)
        return
    if data.get("plan") == "quick":
        # Logged now, as only the VM knew a full review would run (the quick review asked,
        # the audit picked it, or the diff had grown too large: route "rules"). Keeps the
        # dashboard's routing join (REVIEWING, then the decision) the same as on the laptop.
        why = "random audit of a quick approval" if route == "audit" else outcome["focus"]
        event("REVIEWING", subject(key, title), f"{by}full review{where} in the same VM as the quick review",
              f"why: {why}", f"route: {route}", url)
    report_full(job, repo, num, sha, outcome["findings"], runner, audit=route == "audit")


def post_or_keep(job: Job, repo: str, num: str, sha: str, post: tuple[str, str], verdict: str) -> str | None:
    """Post the review and record the job as done. If GitHub does not take it, keep it
    as "unposted" so the next run posts it without a new review; returns the error."""
    if not DRY_RUN:
        try:
            post_review(repo, num, sha, *post, floor=(job.read() or {}).get("review_floor"))
        except GhError as e:  # GitHub unreachable, or you have a pending review there
            job.write(status="unposted", verdict=verdict, post_event=post[0], post_body=post[1],
                      post_attempts=1)
            return str(e)
    job.write(status="done", verdict=verdict)
    return None


def report_full(job: Job, repo: str, num: str, sha: str, result: dict, runner: str, audit: bool) -> None:
    """Log, post and notify one full review's result."""
    key = f"{repo}#{num}"
    result["runner"] = runner
    blocking = result["blocking"]
    verdict = "block" if blocking else "approve"
    details = ["full review on Datum" if runner == "datum" else "full review", result["summary"]]
    # The whole list: the posted comment leaves out minor findings and nits, and an
    # approval carries only the non-blocking ones.
    details += [f"- [{f['severity']}] {f['location'] + ': ' if f['location'] else ''}{f['text']}"
                for f in blocking + result["other"]]
    if result.get("denied"):
        details.append(f"denied tool calls: {'; '.join(result['denied'])[:600]}")
    if audit:
        details.append("audit: the quick review approved this; the full review "
                       + ("found blockers" if blocking else "agrees"))
    post = (("COMMENT", full_review.format_findings(result)) if blocking
            else ("APPROVE", full_review.format_approval(result)))
    error = post_or_keep(job, repo, num, sha, post, verdict)
    posted = not DRY_RUN and error is None
    if error:
        details.append(f"could not post the {'review comment' if blocking else 'approval'}, "
                       f"retrying next run without a new review: {error}")
    if blocking and posted:
        details.append("posted as a review comment")
    elif blocking and not error:
        details.append("not posted, see the log")
    where = "review comment" if posted else "log"
    event("BLOCKED" if blocking else "APPROVED", subject(key, result.get("title", "")),
          *details, pr_url(repo, num))
    if audit and blocking:
        event("AUDIT MISS", subject(key, result.get("title", "")),
              "the quick review approved this PR, the full review found blockers",
              *(f"- {f['text']}" for f in blocking), pr_url(repo, num))
    if blocking and not DRY_RUN:
        found = "\n".join(f"• {f['text']}" for f in blocking[:3])
        notify("PR needs your review",
               f"{len(blocking)} blocking finding(s), not approved; full list in the {where}:\n{found}",
               pr_url(repo, num))


def github_ok(state: dict) -> None:
    """GitHub answered: record the poll time (the stats job alerts when it goes stale)."""
    state["last_poll"] = round(time.time())
    state.pop("github_401", None)


def github_rate_limited(state: dict, e) -> None:
    """403/429 from a rate limit: no GitHub call until GitHub's Retry-After (or reset)."""
    if time.time() >= state.get("github_wait_until", 0):
        event("WARN", f"GitHub rate limit; no GitHub calls for {e.retry_after}s", str(e))
    state["github_wait_until"] = round(time.time() + e.retry_after)


def github_unauthorized(state: dict, e: Exception) -> None:
    """HTTP 401: the token is bad. Nothing works until it is replaced, so say so loudly.
    The stats job on the laptop raises a notification from state["github_401"]."""
    if not state.get("github_401"):
        event("AUTH", "GitHub refused the token (HTTP 401); reviews are paused until it is replaced", str(e))
    state["github_401"] = state.get("github_401") or round(time.time())
    notify_throttled(state, "github_401", "PR autopilot: GitHub token refused",
                     "GitHub answered 401. Replace the token; nothing is reviewed until then.")


def run_once(before_save=None) -> None:
    """One pass: poll GitHub, review what waits on you, save the state. The dispatcher
    passes `before_save(state)` for its own work (results, worker launches), which
    runs under the same lock and is saved with the rest."""
    if not DISPATCHER:
        rotate_log()
    config = load_config()
    try:
        state = load_state()
    except StateUnavailable as e:
        # Not "nothing reviewed": running now would review every waiting PR again.
        state_down(str(e))
        return
    if STATE_BACKEND == "configmap":
        STATE_DOWN_FILE.unlink(missing_ok=True)
        if not hold_lock(state):
            return
    now = time.time()
    if now < state.get("github_wait_until", 0):
        search = False  # rate limited: no GitHub call until the wait is over
    else:
        try:
            search = any(config_for(config, repo) for repo in changed_repos(state))
            github_ok(state)
        except github_api.Unauthorized as e:
            github_unauthorized(state, e)
            search = False  # every other call would fail the same way
        except github_api.RateLimited as e:
            github_rate_limited(state, e)
            search = False
        except Exception as e:  # can't tell what changed: look, but not every minute
            search = now - state.get("error_search_at", 0) >= ERROR_SEARCH_SECONDS
            if search:
                state["error_search_at"] = now
            event("WARN", "GitHub notifications unreachable" + (", searching anyway" if search else ""), str(e))
    if now - state.get("last_full_scan", 0) >= FULL_SCAN_SECONDS and now >= state.get("github_wait_until", 0):
        search = True
        state["last_full_scan"] = now
    if state["rescan"]:
        search = True

    if search:
        state["rescan"] = False
        found = False
        try:
            prs = find_prs(config)
            found = SEARCH_COMPLETE
            state["poll_fail_streak"] = 0
            github_ok(state)
        except github_api.Unauthorized as e:
            github_unauthorized(state, e)
            prs, state["rescan"] = [], True
        except github_api.RateLimited as e:
            github_rate_limited(state, e)
            prs, state["rescan"] = [], True
        except Exception as e:
            event("WARN", "search for review requests failed, retrying next run", str(e))
            prs = []
            state["rescan"] = True
            state["poll_fail_streak"] = state.get("poll_fail_streak", 0) + 1
            if state["poll_fail_streak"] >= POLL_FAIL_ALERT:
                notify_throttled(state, "poll", "PR autopilot can't reach GitHub",
                                 f"Searching for review requests has failed {state['poll_fail_streak']} runs in a row; see the log")
        for repo, pr in prs:
            try:
                if review_one(repo, config_for(config, repo), pr, state) is False:
                    state["rescan"] = True
                renew_lock(state)
            except LockLost as e:
                log(f"lost the lock during this pass ({e}); stopping without a save")
                return
        # Forget skips and requester lookups for PRs no longer waiting on you.
        waiting = {f"{repo}#{pr['number']}" for repo, pr in prs}
        for name in ("skipped", "requested_by", "rerequest"):
            state[name] = {k: v for k, v in state.get(name, {}).items() if k.split("@")[0] in waiting}
        # The ConfigMap must stay small: also forget handled commits and failure counts of
        # PRs that left your queue. Only after a search that saw every waiting PR. A PR that
        # comes back is a new request, and requested_again() would review it again anyway.
        if found and STATE_BACKEND == "configmap":
            for name in ("reviewed", "handled_at", "failures"):
                state[name] = {k: v for k, v in state.get(name, {}).items() if k.split("@")[0] in waiting}

    try:
        if before_save is not None:
            before_save(state)
    except LockLost:
        log("lost the lock during this pass; stopping without a save")
        return
    if DISPATCHER:
        if not DRY_RUN:
            save_state(state)
        return
    prune_jobs()
    if not DRY_RUN:
        save_state(state)
        try:
            dashboard.write(DASHBOARD_FILE, EVENTS_FILE, claude_cli.USAGE_FILE, running_jobs())
        except Exception as e:  # a broken page must never stop reviews
            log(f"could not update the dashboard: {e}")
        ensure_dashboard_server()


def ensure_dashboard_server() -> None:
    """Start serve_dashboard.py in the background unless something already answers on
    its port. Runs exit after each pass, so the server outlives them; if it dies, the
    next run starts it again."""
    if not DASHBOARD_PORT:
        return
    try:
        socket.create_connection(("127.0.0.1", DASHBOARD_PORT), timeout=2).close()
        return
    except OSError:
        pass
    script = pathlib.Path(__file__).resolve().with_name("serve_dashboard.py")
    with open(LOG_FILE, "a") as out:
        subprocess.Popen([sys.executable, str(script)], stdin=subprocess.DEVNULL, stdout=out,
                         stderr=subprocess.STDOUT, start_new_session=True)


def review_one(repo: str, cfg: dict, pr: dict, state: dict) -> bool:
    """Review one PR from the search, counting failures. False means look again next run."""
    if pr["isDraft"]:
        # Marking a PR ready sends you no notification, so keep searching while a
        # listed author's draft waits on you; otherwise it waits for the full scan.
        return pr["author"]["login"] not in cfg.get("authors", [])
    num = pr["number"]
    key = f"{repo}#{num}"
    if not allowed(cfg, pr):
        # The author isn't listed; maybe someone listed asked for your review. The answer
        # is cached until the PR changes, so a waiting PR costs one timeline read.
        cache = state.setdefault("requested_by", {})
        ckey = f"{key}@{pr.get('updatedAt', '')}"
        if ckey not in cache:
            try:
                cache[ckey] = who_requested_me(repo, num, my_login(state)) or ""
            except Exception as e:
                event("WARN", subject(key, pr["title"]), "could not read who requested the review", str(e))
                return False
        pr["requested_by"] = cache[ckey] or None
        if not allowed(cfg, pr):
            why = f"by {pr['author']['login']}, requested by {pr['requested_by'] or 'unknown'}: neither is listed"
            if state.setdefault("skipped", {}).get(key) != why:
                state["skipped"][key] = why
                event("SKIPPED", subject(key, pr["title"]), why, pr_url(repo, num))
            return True
    try:
        pr["headRefOid"] = github_api.head_sha(repo, num)
        if state["reviewed"].get(key) == pr["headRefOid"]:
            again = requested_again(repo, num, key, pr, state)
            if not again:
                return True
            del state["reviewed"][key]
            event("NOTICE", subject(key, pr["title"]),
                  f"{again} asked for your review again on a commit already handled; reviewing it again")
        return review(repo, cfg, pr, state)
    except LockLost:
        raise  # not the PR's fault: the whole pass stops
    except claude_cli.AuthExpired:  # not the PR's fault: retry without counting
        notify_throttled(state, "auth", "PR autopilot: Claude login expired",
                         "Run `claude auth login` to resume reviews")
        return False
    except Exception as e:  # error = no approval; retried next run
        if "headRefOid" not in pr:  # couldn't even read the PR; not a failure of the review
            event("WARN", subject(key, pr["title"]), "could not read the PR, retrying next run", str(e))
            return False
        fkey = f"{key}@{pr['headRefOid']}"
        state["failures"][fkey] = state["failures"].get(fkey, 0) + 1
        attempt = state["failures"][fkey]
        if attempt < MAX_FAILURES:
            event("ERROR", subject(key, pr["title"]), f"attempt {attempt} of {MAX_FAILURES} failed, retrying",
                  str(e))
            return False
        event("GAVE UP", subject(key, pr["title"]), f"all {MAX_FAILURES} attempts failed; review it yourself",
              str(e), pr_url(repo, num))
        handled(state, key, pr["headRefOid"])
        notify("PR autopilot gave up", f"{MAX_FAILURES} attempts failed; last error: {str(e)[:300]}",
               pr_url(repo, num))
        return True


def main() -> None:
    global EVENTS_FILE
    if not DRY_RUN:
        full_review.CACHE.mkdir(parents=True, exist_ok=True)
        EVENTS_FILE = full_review.CACHE / "events.jsonl"
        claude_cli.USAGE_FILE = full_review.CACHE / "usage.jsonl"
    if "--dashboard" in sys.argv:  # rebuild the page now and open it
        dashboard.write(DASHBOARD_FILE, EVENTS_FILE, claude_cli.USAGE_FILE, running_jobs())
        subprocess.run(["open", str(DASHBOARD_FILE)])
        return
    if len(sys.argv) == 6 and sys.argv[1] == "--full-review":
        run_full_review(*sys.argv[2:])
        return
    if len(sys.argv) == 5 and sys.argv[1] == "--review-pr":
        run_pr_review(*sys.argv[2:])
        return
    if "--test-notify" in sys.argv:
        print("Slack webhook:", "found in Keychain" if slack_webhook() else "not set, using macOS notifications",
              "(clickable)" if shutil.which("terminal-notifier") else "(not clickable: terminal-notifier is not installed)")
        notify("PR autopilot test", "If you can read this, notifications work.",
               "https://github.com/example-org/infra/pulls")
        return
    once = "--once" in sys.argv
    while True:
        try:
            run_once()
        except Exception as e:
            event("ERROR", "run failed", str(e))
        if once:
            break
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
