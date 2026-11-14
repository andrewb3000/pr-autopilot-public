#!/usr/bin/env python3
"""Local stats for the dispatcher on Datum: copy its events here, build the dashboard,
serve it on localhost, and raise a macOS notification when something is wrong.

The dispatcher keeps its last ~500 events in ConfigMap pr-autopilot-events (a ring
buffer, see dispatcher.ring). Every minute this script:
  - appends the events it has not seen yet to the local events.jsonl (the same file the
    laptop's reviewer.py writes, so both runners show on one page), and the token use
    on DONE events to usage.jsonl;
  - adds a GAP event ("events lost from X to Y") when the buffer moved on further than
    this copy read, e.g. after the laptop slept for a long time;
  - rebuilds the dashboard (dashboard.py) and serves it on localhost (serve_dashboard.py);
  - shows a macOS notification for each new event the dispatcher marked `notify` (what
    the laptop runner used to notify about: a PR that needs you, an expired token, ...),
    once per event; after a long sleep at most MAX_NOTICES of them, then one summary;
  - notifies when the dispatcher has not polled GitHub for STALE_POLL seconds, or when
    GitHub refused its token (HTTP 401);
  - first of all, if a tick URL is set, calls POST /tick on the dispatcher. A unikernel
    dispatcher is parked between requests and only runs a pass when woken, so this is
    its clock while the Mac is awake. Notifies when ticks have failed for TICK_ALERT
    seconds. No URL means no tick (the Kata dispatcher keeps its own time).

Tick settings, each from the environment or else a file (both optional):
  PR_AUTOPILOT_TICK_URL    or ~/.config/pr-autopilot/tick-url    the dispatcher's public URL
  PR_AUTOPILOT_TICK_TOKEN  or ~/.config/pr-autopilot/tick-token  the same token as its Secret

It only reads from Datum; it never writes the state or the events. Runs under launchd
as com.example.pr-autopilot-stats (KeepAlive), see launchd/.

Usage:
  python3 stats.py           # loop forever (launchd)
  python3 stats.py --once    # one round, no server
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import claude_cli
import dashboard
import full_review
import remote_review
import reviewer
import serve_dashboard
import state_store

EVERY = 60
STALE_POLL = 10 * 60
NOTIFY_EVERY = 60 * 60  # repeat a standing alert at most this often
EVENTS_FILE = full_review.CACHE / "events.jsonl"
USAGE_FILE = full_review.CACHE / "usage.jsonl"
CURSOR_FILE = full_review.CACHE / "stats-cursor.json"
DASHBOARD_FILE = full_review.CACHE / "dashboard" / "index.html"
EVENTS_NAME = "pr-autopilot-events"
STATE_NAME = state_store.NAME
TICK_CONFIG = pathlib.Path.home() / ".config" / "pr-autopilot"
# The dispatcher answers a tick within its TICK_WAIT (5 s); the rest is the wake from
# park and the ALB.
TICK_TIMEOUT = 25
TICK_DEADLINE = 30  # the whole tick, DNS included; the stats round never waits longer
TICK_THREAD: dict = {"thread": None}
TICK_ALERT = 10 * 60
MAX_NOTICES = 3  # dispatcher notifications shown per round; the rest become one summary


def store(name: str, key: str) -> state_store.ConfigMapStore:
    return state_store.ConfigMapStore(remote_review.PROJECT, remote_review.SESSION, name=name, key=key)


def read_json(path: pathlib.Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def write_json(path: pathlib.Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data))
    tmp.replace(path)


def append(path: pathlib.Path, rows: list[dict]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def when(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def new_events(buffer: dict, cursor: dict) -> tuple[list[dict], list[dict], dict]:
    """(events to append, usage rows to append, new cursor). Adds a GAP event when the
    oldest unseen event in the buffer is not the one right after the last one read."""
    events = sorted(buffer.get("events") or [], key=lambda e: e.get("seq", 0))
    last = int(cursor.get("seq") or 0)
    if last >= int(buffer.get("next_seq") or 1):
        last = 0  # the ConfigMap was recreated: start over, it is not a gap
    fresh = [e for e in events if e.get("seq", 0) > last]
    out: list[dict] = []
    if fresh and last and fresh[0]["seq"] > last + 1:
        lost = fresh[0]["seq"] - last - 1
        out.append({"ts": fresh[0]["ts"], "kind": "GAP",
                    "subject": f"gap from {when(cursor.get('ts') or fresh[0]['ts'])} to {when(fresh[0]['ts'])}",
                    "details": [f"{lost} dispatcher events fell off the ring buffer before this copy read them"]})
    usage = []
    for e in fresh:
        # "dseq" goes into events.jsonl with the event, so the file itself says how far
        # this copy got, even if the process stops before it writes the cursor.
        out.append({**{k: v for k, v in e.items() if k not in ("seq", "usage")}, "dseq": e["seq"]})
        usage += [{**u, "runner": "datum"} for u in e.get("usage") or []]
    if fresh:
        cursor = {"seq": fresh[-1]["seq"], "ts": fresh[-1]["ts"]}
    return out, usage, cursor


def last_copied(path: pathlib.Path, tail: int = 256 * 1024) -> dict:
    """The newest dispatcher event already in events.jsonl, as a cursor ({} if none)."""
    try:
        with path.open("rb") as f:
            f.seek(max(0, path.stat().st_size - tail))
            lines = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return {}
    best: dict = {}
    for line in lines:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict) and isinstance(e.get("dseq"), int) and e["dseq"] > best.get("seq", 0):
            best = {"seq": e["dseq"], "ts": e.get("ts")}
    return best


def alerts(state: dict, sent: dict, now: float) -> list[tuple[str, str]]:
    """The notifications due now: (title, message). `sent` remembers what was sent."""
    out = []
    last_poll = state.get("last_poll") or 0
    if now - last_poll > STALE_POLL:
        if now - sent.get("stale", 0) >= NOTIFY_EVERY:
            sent["stale"] = now
            owner = (state.get("owner") or {}).get("id", "the dispatcher")
            out.append(("PR autopilot is not polling",
                        f"{owner} last polled GitHub {round((now - last_poll) / 60)} minutes ago." if last_poll
                        else "The state has no record of any GitHub poll."))
    else:
        sent.pop("stale", None)
    if state.get("github_401"):
        if sent.get("github_401") != state["github_401"]:
            sent["github_401"] = state["github_401"]
            out.append(("PR autopilot: GitHub token refused",
                        "The dispatcher got HTTP 401 from GitHub. Replace the token in its Secret."))
    else:
        sent.pop("github_401", None)
    return out


def tick_settings() -> tuple[str, str]:
    """(url, token); "" for what is not set."""
    def setting(env: str, name: str) -> str:
        if os.environ.get(env):
            return os.environ[env].strip()
        try:
            return (TICK_CONFIG / name).read_text().strip()
        except OSError:
            return ""
    return setting("PR_AUTOPILOT_TICK_URL", "tick-url"), setting("PR_AUTOPILOT_TICK_TOKEN", "tick-token")


def tick_url(url: str) -> str:
    """The /tick endpoint of `url`. HTTPS only, except to this machine: the token must
    not cross the internet in clear text."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" and not (parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1", "::1")):
        raise ValueError(f"the tick URL must be https: {url}")
    path = parts.path.rstrip("/")
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path if path.endswith("/tick") else path + "/tick", "", ""))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an error: the token must never follow one to another host or to
    plain http."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def send_tick(url: str, token: str, timeout: float = TICK_TIMEOUT) -> tuple[int, dict]:
    """POST /tick. (HTTP status, the dispatcher's answer). Raises on any failure,
    a redirect included."""
    req = urllib.request.Request(tick_url(url), data=b"", method="POST",
                                 headers={"Authorization": f"Bearer {token}"})
    with OPENER.open(req, timeout=timeout) as resp:
        if resp.status >= 300:
            raise ValueError(f"HTTP {resp.status}; redirects are not followed")
        body = resp.read(4096)
        try:
            return resp.status, json.loads(body)
        except ValueError:
            return resp.status, {}


def with_deadline(fn, seconds: float):
    """fn() in a daemon thread; its result, or TimeoutError after `seconds`. A thread
    still stuck from an earlier call (a hung DNS lookup) counts as a failure at once,
    so they never pile up."""
    old = TICK_THREAD["thread"]
    if old is not None and old.is_alive():
        raise TimeoutError("the previous tick is still waiting for an answer")
    box: dict = {}

    def run() -> None:
        try:
            box["value"] = fn()
        except BaseException as e:
            box["error"] = e
    thread = threading.Thread(target=run, name="tick", daemon=True)
    TICK_THREAD["thread"] = thread
    thread.start()
    thread.join(seconds)
    if thread.is_alive():
        raise TimeoutError(f"no answer in {seconds:g}s")
    if "error" in box:
        raise box["error"]
    return box["value"]


def tick_round(cursor: dict, now: float, send=send_tick, deadline: float = TICK_DEADLINE) -> list[tuple[str, str]]:
    """Tick the dispatcher if a URL is set. Logs failures and returns the alert due, if
    ticks have failed for TICK_ALERT seconds. Never raises, and never takes longer than
    `deadline`."""
    t = cursor.get("tick") or {}
    try:
        url, token = tick_settings()
        if not url:
            cursor.pop("tick", None)
            return []
        cursor["tick"] = t
        # After a sleep of the Mac the old failure streak says nothing about now.
        if now - t.get("last_try", now) > 3 * EVERY:
            t.pop("failing_since", None)
        t["last_try"] = now
        if not token:
            raise ValueError(f"no tick token: set PR_AUTOPILOT_TICK_TOKEN or {TICK_CONFIG / 'tick-token'}")
        status, answer = with_deadline(lambda: send(url, token), deadline)
        if status == 202:
            print(f"{when(now)} tick: the pass is still running after "
                  f"{answer.get('running_for', '?')}s; the next tick wakes it again", flush=True)
        if t.pop("failing_since", None):
            print(f"{when(now)} tick: works again", flush=True)
        t.pop("alerted", None)
        return []
    except Exception as e:  # anything: the stats loop must go on
        if isinstance(e, urllib.error.HTTPError):
            e = f"HTTP {e.code} {e.reason}"
        print(f"{when(now)} tick failed: {e}", flush=True)
        cursor["tick"] = t
        t["last_try"] = now
        since = t.setdefault("failing_since", now)
        if now - since >= TICK_ALERT and now - t.get("alerted", 0) >= NOTIFY_EVERY:
            t["alerted"] = now
            return [("PR autopilot: the dispatcher is not woken",
                     f"Ticks have failed for {round((now - since) / 60)} minutes: {e}")]
        return []


def dashboard_url() -> str:
    return f"http://localhost:{reviewer.DASHBOARD_PORT}/"


def safe_url(url) -> str | None:
    """A URL a click may open: a GitHub page or the local dashboard, nothing else."""
    if isinstance(url, str) and (url.startswith("https://github.com/") or url == dashboard_url()):
        return url
    return None


def notices(rows: list[dict], limit: int = MAX_NOTICES) -> list[tuple[str, str, str | None]]:
    """The notifications for newly copied events: (title, message, url) for each event
    the dispatcher marked `notify`. More than `limit` (the Mac slept, or the dispatcher
    had a bad hour): the newest `limit`, then one summary that opens the dashboard.
    Events from dispatcher images without the field notify nothing, as before."""
    out = []
    for row in rows:
        n = row.get("notify")
        if isinstance(n, dict) and n.get("title"):
            out.append((str(n["title"])[:200], str(n.get("text") or "")[:1000], safe_url(n.get("url"))))
    if len(out) <= limit:
        return out
    more = len(out) - limit
    return out[-limit:] + [("PR autopilot", f"{more} more notification{'s' if more > 1 else ''} "
                            "in the dashboard.", dashboard_url())]


def mac_notify(title: str, message: str, url: str | None = None) -> None:
    """Like reviewer.notify on the laptop: clicking opens `url` when terminal-notifier
    is installed; osascript otherwise."""
    notifier = shutil.which("terminal-notifier")
    if notifier:
        # terminal-notifier reads a value that starts with "-" or "[" as an option.
        def arg(text: str) -> str:
            return "\\" + text if text[:1] in "-[" else text
        args = [notifier, "-title", arg(title), "-message", arg(message), "-sound", "default"]
        if url:
            args += ["-open", url, "-group", url]
    else:
        args = ["osascript", "-e", f"display notification {json.dumps(message)} with title {json.dumps(title)}"]
    try:
        subprocess.run(args, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        pass


def round_once(now: float | None = None) -> None:
    now = time.time() if now is None else now
    cursor = read_json(CURSOR_FILE)
    running = 0
    # First, so the events of the pass it runs are read in this same round.
    for title, message in tick_round(cursor, now):
        mac_notify(title, message)
    try:
        buffer, _ = store(EVENTS_NAME, "events.json").load()
        copied, saved = last_copied(EVENTS_FILE), cursor.get("events") or {}
        start = copied if copied.get("seq", 0) > saved.get("seq", 0) else saved
        rows, usage, cursor["events"] = new_events(buffer or {}, start)
        append(EVENTS_FILE, rows)
        # Only events copied just now notify, and the copy never reads an event twice, so
        # a restart replays nothing. The very first copy is history: it notifies nothing.
        for title, message, url in (notices(rows) if start else []):
            print(f"{when(now)} notification: {title}: {message}", flush=True)
            mac_notify(title, message, url)
        claude_cli.USAGE_FILE = USAGE_FILE
        for u in usage:
            claude_cli.append_usage(u)
    except state_store.Unavailable as e:
        print(f"{when(now)} events not read: {e}", flush=True)
    try:
        state, _ = store(STATE_NAME, state_store.KEY).load()
        state = state or {}
        running = sum(d.get("status") == "running" for d in (state.get("jobs") or {}).values())
        sent = cursor.setdefault("alerts", {})
        for title, message in alerts(state, sent, now):
            print(f"{when(now)} {title}: {message}", flush=True)
            mac_notify(title, message)
    except state_store.Unavailable as e:
        print(f"{when(now)} state not read: {e}", flush=True)
    write_json(CURSOR_FILE, cursor)
    try:
        dashboard.write(DASHBOARD_FILE, EVENTS_FILE, USAGE_FILE, running)
    except Exception as e:  # a broken page must not stop the alerts
        print(f"{when(now)} dashboard not built: {e}", flush=True)


def serve() -> None:
    """Serve the page unless something already answers on the port (reviewer.py on the
    laptop starts the same server for the same file)."""
    try:
        server = serve_dashboard.server()
    except OSError:
        return
    threading.Thread(target=server.serve_forever, name="dashboard", daemon=True).start()


def main() -> None:
    if "--once" in sys.argv:
        round_once()
        return
    serve()
    while True:
        started = time.time()
        try:
            round_once()
        except Exception as e:
            print(f"{when(started)} round failed: {e}", flush=True)
        time.sleep(max(1.0, EVERY - (time.time() - started)))


if __name__ == "__main__":
    main()
