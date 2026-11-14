#!/usr/bin/env python3
"""The PR autopilot dispatcher for Datum: one process, HTTP calls only.

It runs on a Datum instance, Kata or a unikernel woken through POST /tick, and needs
no fork/exec: nothing here starts a process. GitHub is called over REST (github_api),
Datum over the Milo API (milo_api), and reviews run in worker VMs (Kata, the review
image) that call back with their result. It reuses reviewer.py's rules (who to review, when to escalate, what to post)
with reviewer.DISPATCHER set, which swaps the laptop's parts for these:

  laptop (reviewer.py --once)              dispatcher (this file)
  a Python worker process per review       a job in state["jobs"], queued, then a
                                           worker Workload; at most MAX_WORKERS at once
  result read from the VM's logs           result POSTed to /callback over gVPC
  events.jsonl, dashboard, local server    events in ConfigMap pr-autopilot-events
                                           (stats.py on the laptop builds the page)
  macOS notifications                      Slack (PR_AUTOPILOT_SLACK_WEBHOOK), else an event
                                           marked `notify` that stats.py shows on the Mac

Only the dispatcher writes to GitHub. Workers keep their read-only tokens and get a
one-time bearer token for the callback, generated here; the state keeps only its hash,
and the dispatcher accepts one callback per token.

Passes run one at a time (Passes). The timer starts one every POLL_SECONDS unless a
pass ran in the last TIMER_SKIP seconds; POST /tick starts one (or joins the running one)
and answers when it ends; an accepted callback starts one, so its result is posted at
once. A unikernel instance with a declared port is parked between requests and its
clock stops, so there only /tick and callbacks drive it (docs/dispatcher.md, "Unikernel,
woken by the laptop").

It holds the single-active lock in the state ConfigMap (reviewer.hold_lock), so it and
the laptop never both run. On start it reconciles worker Workloads with the jobs in
the state: Workloads no job knows are deleted, running jobs whose Workload is gone go
back to the queue. A worker that has not called back after WORKER_TTL is deleted and
its job counts as a failed attempt.

Environment:
  PR_AUTOPILOT_GITHUB_TOKEN     classic PAT that can approve (Secret)
  PR_AUTOPILOT_MILO_CREDENTIALS Milo service-account key, JSON (Secret)
  PR_AUTOPILOT_CALLBACK_URL     how workers reach this instance, e.g.
                                http://<instance>.instances.datum.internal:8080/callback
  PR_AUTOPILOT_LISTEN_PORT      port the callback server listens on (default 8080). The Kata
                                Workload does not declare it; the unikernel one does, for
                                its public URL.
  PR_AUTOPILOT_TICK_TOKEN       optional bearer token for POST /tick (Secret); unset means
                                /tick answers 404
  PR_AUTOPILOT_TICK_WAIT        seconds /tick waits for its pass before it answers 202,
                                by the wall clock (default 5, under the ALB's 15 s)
  PR_AUTOPILOT_MAX_WORKERS      worker VMs at once (default 3)
  PR_AUTOPILOT_SLACK_WEBHOOK    optional, for notifications
  PR_AUTOPILOT_CONFIG           optional path to repos.json (a ConfigMap volume on Datum)
"""
from __future__ import annotations

import hashlib
import hmac
import http.server
import json
import os
import secrets
import socket
import threading
import time

import claude_cli
import github_api
import remote_review
import reviewer
import state_store

MAX_WORKERS = int(os.environ.get("PR_AUTOPILOT_MAX_WORKERS", "3"))
WORKER_TTL = reviewer.WORKER_TTL
CALLBACK_URL = os.environ.get("PR_AUTOPILOT_CALLBACK_URL", "")
LISTEN_PORT = int(os.environ.get("PR_AUTOPILOT_LISTEN_PORT", "8080"))
# A parked or busy VM queues new connections; the default backlog of 5 dropped about
# 10% of a burst in the prototype, 128 dropped none.
LISTEN_BACKLOG = 128
# A result is a few KB; the whole state ConfigMap holds at most ~900 KB.
MAX_BODY = 256 * 1024
USAGE_MAX = 50
LOCK_WAIT = 30  # a callback waits this long for a pass to finish, then gets 503 and retries
TICK_TOKEN = os.environ.get("PR_AUTOPILOT_TICK_TOKEN", "")
# /tick answers when its pass ends, or after this many seconds with 202 while the pass goes
# on. It must stay under the ALB's request timeout (15 s), or the edge answers 504 for us.
# The pass itself is not cut: on a unikernel it continues whenever the VM is awake (the
# next tick or callback), on Kata it simply runs on.
#
# Counted on the wall clock from the moment the request arrived, like the ALB counts it.
# A unikernel VM's own clock (time.monotonic, which threading's timeouts use) can fall
# seconds behind during a request: on 2026-11-12 a tick pass took 25.2 s of wall time and
# 18.0 s of VM time, so a 10 s wait on the VM clock answered after 15 s and the ALB gave
# up first. 5 s leaves room for such a lag and for waking the VM.
TICK_WAIT = float(os.environ.get("PR_AUTOPILOT_TICK_WAIT", "5"))
WAIT_SLICE = 0.25  # how often a waiter looks at the wall clock
TIMER_SKIP = 30  # the timer runs no pass if one ended less than this many seconds ago
# The URL is public: a valid tick this soon after the last pass gets that pass's status
# instead of a new pass, so a leaked or looping client cannot run passes back to back.
TICK_MIN_INTERVAL = 20
# Requests handled at once. More connections wait in the listen backlog; past this many
# in progress the answer is 503. Workers retry, ticks come again in a minute.
MAX_HANDLERS = 16

EVENTS_NAME = os.environ.get("PR_AUTOPILOT_EVENTS_CONFIGMAP", "pr-autopilot-events")
EVENTS_KEY = "events.json"
EVENTS_MAX = 500
EVENTS_MAX_BYTES = 900 * 1024
PENDING_MAX = 5000  # events kept in memory while the ConfigMap cannot be written

# One lock for the state: the poll loop holds it for a whole pass, a callback for its write.
STATE_LOCK = threading.Lock()
RECONCILED = {"done": False}
# Hashes of the callback tokens of running jobs ("live") and of results already taken
# ("used"), refreshed every pass. A callback is checked against these before its body is
# read or the state lock is taken. None until the first pass: then the answer is 503, so a
# worker that calls back while the dispatcher restarts tries again.
TOKENS: dict = {"live": None, "used": set()}


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def parse_key(key: str) -> tuple[str, str, str]:
    """"owner/repo#7@sha" -> ("owner/repo", "7", "sha")."""
    head, sha = key.rsplit("@", 1)
    repo, num = head.rsplit("#", 1)
    return repo, num, sha


def jobs(state: dict) -> dict:
    return state.setdefault("jobs", {})


# --- One pass ----------------------------------------------------------------------

def dispatch(state: dict) -> None:
    """The dispatcher's part of a pass, after reviewer.run_once has polled GitHub and
    queued new reviews: reconcile once, post results, expire, launch."""
    steps = ([reconcile] if not RECONCILED["done"] else []) + [process_results, expire, launch, prune,
                                                               refresh_tokens]
    for step in steps:
        try:
            step(state)
            reviewer.renew_lock(state)
        except reviewer.LockLost:
            raise
        except Exception as e:  # one broken step must not stop the save of the others' work
            reviewer.event("ERROR", f"dispatcher step {step.__name__} failed", f"{type(e).__name__}: {e}")


def reconcile(state: dict) -> None:
    """Match worker Workloads with jobs: delete the ones no job owns, requeue running
    jobs whose Workload is gone (it can no longer call back)."""
    try:
        live = set(remote_review.list_workloads(remote_review.WORKER_LABEL))
    except remote_review.DatumUnavailable as e:
        reviewer.event("WARN", "could not list worker Workloads; reconciling next pass", str(e))
        return
    owned = set()
    for key, data in jobs(state).items():
        if data.get("status") not in ("running", "result"):
            continue
        name = data.get("workload")
        if name in live:
            owned.add(name)
        elif data["status"] == "running":
            for field in ("workload", "token_hash", "started"):
                data.pop(field, None)
            data["lost"] = data.get("lost", 0) + 1
            if data["lost"] >= reviewer.MAX_FAILURES:
                # Counts as a failed attempt in review(), like any other.
                data.update(status="failed", finished=round(time.time()),
                             error=f"its worker was lost {data['lost']} times")
                reviewer.event("WARN", key, f"worker {name} is gone, {data['lost']} times; not queued again")
            else:
                data.update(status="queued", queued=round(time.time()))
                reviewer.event("NOTICE", key, f"worker {name} is gone; queued again "
                               f"({data['lost']} of {reviewer.MAX_FAILURES})")
    for name in sorted(live - owned):
        remote_review.delete_workload(name)
        reviewer.event("NOTICE", f"deleted worker {name}", "no job in the state owns it")
    RECONCILED["done"] = True


def process_results(state: dict) -> None:
    """Post each result a worker sent back (reviewer.report_outcome), one at a time:
    each post is saved before the next one starts, and its DONE event is logged only
    after that save. A crash between the post and the save leaves status "result";
    the next pass then finds the review already on GitHub (reviewer.post_review checks
    first in the dispatcher) and does not post it twice."""
    for key, data in list(jobs(state).items()):
        if data.get("status") != "result":
            continue
        repo, num, sha = parse_key(key)
        job = reviewer.StateJob(state, repo, num, sha)
        out = data.get("outcome") or {}
        usage = [{**u, "runner": "datum"} for u in out.get("usage") or []]
        try:
            handle_result(job, repo, num, sha, out)
        except TryAgain as e:
            # GitHub did not answer for sure: keep the result and try on the next pass,
            # without counting a failure. Only a definite answer marks it stale.
            reviewer.event("WARN", f"{repo}#{num}", "could not check the PR before posting; "
                           "the result waits for the next pass", str(e))
            continue
        except reviewer.LockLost:
            raise  # another runner holds the lock: post nothing, save nothing
        except Exception as e:  # a bug here must not lose the other results
            job.write(status="failed", error=f"could not handle the result: {e}"[:500])
        job.write(outcome=None)
        jobs(state)[key] = {k: v for k, v in (job.read() or {}).items() if v is not None}
        saved = reviewer.save_state_configmap(state)
        done = job.read() or {}
        reviewer.event("DONE", reviewer.subject(f"{repo}#{num}", data.get("title", "")),
                       f"worker {data.get('workload', '?')}: {done.get('status')}"
                       + (f", {done.get('verdict')}" if done.get("verdict") else "")
                       + ("" if saved else " (state not saved yet)"),
                       usage_line(usage), usage=usage)
        if data.get("workload"):
            remote_review.delete_workload(data["workload"])
        reviewer.renew_lock(state)


class TryAgain(Exception):
    """A result that cannot be handled now, for a reason that will pass."""


def handle_result(job, repo: str, num: str, sha: str, out: dict) -> None:
    if not out.get("ok"):
        error = str(out.get("error") or "no error given")
        if any(m in error for m in claude_cli.AUTH_MARKERS):
            job.write(status="auth", error="the Claude token in the Datum Secret review-credentials "
                                           "expired; run `claude setup-token` and update the Secret")
        else:
            job.write(status="failed", error=f"review on Datum failed: {error}"[:500])
        return
    if out.get("format") != remote_review.pr_worker.FORMAT:
        job.write(status="failed", error=f"the worker answered in format {out.get('format')!r}")
        return
    # The worker took minutes: the PR may be closed or have a new head by now.
    try:
        pr = github_api.pull(repo, num)
    except github_api.GitHubError as e:  # rate limit, 5xx, network: no answer either way
        raise TryAgain(str(e)) from e
    if pr.get("state") != "open" or (pr.get("head") or {}).get("sha") != sha:
        job.write(status="stale")
        reviewer.event("NOTICE", f"{repo}#{num}", "the PR was closed or got new commits during the review; "
                       "its result is not posted")
        return
    reviewer.report_outcome(job, repo, num, sha, {k: out.get(k) for k in remote_review.OUTCOME_KEYS}, "datum")


def usage_line(usage: list[dict]) -> str:
    if not usage:
        return "no token use reported"
    tokens = sum(u.get("input", 0) + u.get("output", 0) + u.get("cache_read", 0) + u.get("cache_write", 0)
                 for u in usage)
    models = sorted({m for u in usage for m in u.get("models") or []})
    cost = sum(u.get("cost_usd", 0) or 0 for u in usage)
    return f"{len(usage)} Claude runs, {tokens:,} tokens, ${cost:.2f}" + (f", {', '.join(models)}" if models else "")


def expire(state: dict, now: float | None = None) -> None:
    """A worker with no result after WORKER_TTL is deleted; the attempt counts as failed."""
    now = time.time() if now is None else now
    for key, data in jobs(state).items():
        if data.get("status") == "running" and now - data.get("started", now) > WORKER_TTL:
            remote_review.delete_workload(data.get("workload", ""))
            data.update(status="failed", finished=round(now),
                        error=f"worker {data.get('workload')} sent no result in {WORKER_TTL // 60} minutes")
            data.pop("token_hash", None)


def launch(state: dict) -> None:
    """Start queued jobs, oldest first, while fewer than MAX_WORKERS run."""
    running = sum(d.get("status") == "running" for d in jobs(state).values())
    queued = sorted((d.get("queued", 0), k) for k, d in jobs(state).items() if d.get("status") == "queued")
    if not queued or running >= MAX_WORKERS:
        return
    config = reviewer.load_config()
    for _, key in queued[:MAX_WORKERS - running]:
        repo, num, sha = parse_key(key)
        data = jobs(state)[key]
        cfg = reviewer.config_for(config, repo) or {}
        try:
            floor = reviewer.review_floor(repo, num, sha)
        except github_api.GitHubError as e:
            # Without the floor an older review of yours on this commit could hide the new
            # one when it is posted: wait for GitHub rather than launch without it.
            reviewer.event("WARN", key, "could not read your reviews before starting a worker; it stays queued",
                           str(e)[:500])
            continue
        token = secrets.token_urlsafe(32)
        try:
            name = remote_review.start_worker(
                repo, num, sha, cfg.get("context", ""), cfg.get("model", "opus"),
                plan=data.get("plan", "quick"), focus=data.get("reason") or "no specific reason given",
                audit=bool(data.get("audit")), quick_model=reviewer.QUICK_MODEL,
                strict_workflows=cfg.get("strict_workflows", False),
                callback_url=CALLBACK_URL, callback_token=token)
        except (remote_review.DatumUnavailable, remote_review.ImageNotBuilt) as e:
            # Section 7 of the research note: no fallback that runs Claude next to the PAT.
            # The job stays queued; the next pass tries again.
            reviewer.event("WARN", key, "could not start a worker; it stays queued", str(e)[:500])
            reviewer.notify_throttled(state, "worker-start", "PR autopilot cannot start reviews on Datum",
                                      f"{e}"[:300])
            return
        data.update(status="running", workload=name, started=round(time.time()), token_hash=token_hash(token),
                    review_floor=floor)
        if TOKENS["live"] is not None:
            TOKENS["live"].add(data["token_hash"])


def refresh_tokens(state: dict) -> None:
    TOKENS["live"] = {d["token_hash"] for d in jobs(state).values()
                      if d.get("status") == "running" and d.get("token_hash")}
    TOKENS["used"] = {d["used_token"] for d in jobs(state).values() if d.get("used_token")}


def prune(state: dict) -> None:
    """Finished job records nobody will read (review() clears the ones it sees)."""
    now = time.time()
    for key in [k for k, d in jobs(state).items()
                if d.get("status") in ("done", "stale", "failed", "auth")
                and now - d.get("finished", now) > reviewer.JOB_TTL]:
        del jobs(state)[key]


# --- Passes ------------------------------------------------------------------------

class Passes:
    """Runs one pass at a time, in its own thread, and tells waiters when it ends.

    start() begins a pass and returns its number. During a pass it returns that pass,
    or, with rerun=True, asks for one more pass right after it and returns that one's
    number: a callback that lands while a pass is ending must not wait for the next tick
    (the running pass may have read the state before the result was saved). Requests
    for a rerun during one pass make one rerun. Each pass is timed twice: "seconds" by
    the wall clock and "awake" by the monotonic clock, which stops while a unikernel VM
    is parked. A big difference means the VM was parked in the middle."""

    def __init__(self, run=None):
        self.cond = threading.Condition()
        self.run = run  # None: the module's run_pass, looked up at call time
        self.running = False
        self.rerun = False
        self.started = 0  # number of the last pass started
        self.finished = 0  # number of the last pass that ended
        self.last_start = 0.0
        self.last_end = 0.0
        self.last = {}  # {"reason", "seconds", "awake"} of the last pass that ended

    def start(self, reason: str, rerun: bool = False) -> int:
        with self.cond:
            if self.running:
                self.rerun = self.rerun or rerun
                return self.started + 1 if self.rerun else self.started
            self.running = True
            self.started += 1
            self.last_start = time.time()
        threading.Thread(target=self._run, args=(reason,), name=f"pass-{reason}", daemon=True).start()
        return self.started

    def _run(self, reason: str) -> None:
        while True:
            wall, awake = time.time(), time.monotonic()
            try:
                (self.run or run_pass)()
            except Exception as e:  # run_pass logs its own errors; this keeps the loop alive
                print(f"pass failed: {type(e).__name__}: {e}", flush=True)
            took = {"reason": reason, "seconds": round(time.time() - wall, 1),
                    "awake": round(time.monotonic() - awake, 1)}
            if took["seconds"] > TICK_WAIT:
                print(f"{reviewer.owner_id()}: a {reason} pass took {took['seconds']}s "
                      f"({took['awake']}s awake)", flush=True)
            with self.cond:
                self.finished = self.started
                self.last_end = time.time()
                self.last = took
                if self.rerun:
                    self.rerun = False
                    self.started += 1
                    self.last_start = time.time()
                    reason = "rerun"
                else:
                    self.running = False
                self.cond.notify_all()
                if not self.running:
                    return

    def wait(self, number: int, timeout: float | None, since: float | None = None,
             since_awake: float | None = None) -> bool:
        """True once pass `number` has ended; False once `timeout` seconds have passed
        since `since` (wall clock, default now) or since `since_awake` (monotonic clock,
        default now), whichever comes first. Not Condition.wait_for(timeout) alone: the
        monotonic clock can lose time on a unikernel VM, and the wall clock alone could
        be stepped back."""
        if timeout is not None:
            wall_end = (time.time() if since is None else since) + timeout
            awake_end = (time.monotonic() if since_awake is None else since_awake) + timeout
        with self.cond:
            while self.finished < number:
                if timeout is None:
                    self.cond.wait()
                    continue
                left = min(wall_end - time.time(), awake_end - time.monotonic())
                if left <= 0:
                    return False
                self.cond.wait(min(left, WAIT_SLICE))
            return True

    def timer_due(self, now: float) -> bool:
        with self.cond:
            return not self.running and now - self.last_end >= TIMER_SKIP

    def recent(self, now: float) -> bool:
        """A pass started less than TICK_MIN_INTERVAL ago and is over."""
        with self.cond:
            return not self.running and now - self.last_start < TICK_MIN_INTERVAL

    def status(self) -> dict:
        with self.cond:
            out = {"last": dict(self.last)}
            if self.running:
                out["running_for"] = round(time.time() - self.last_start, 1)
            return out


PASSES = Passes()


def timer_step(now: float | None = None) -> bool:
    """The timer's turn: run a pass and wait for it, unless one ran in the last
    TIMER_SKIP seconds or is running. True if it ran one."""
    if not PASSES.timer_due(time.time() if now is None else now):
        return False
    PASSES.wait(PASSES.start("timer"), None)
    return True


def tick_refused(auth: str) -> tuple[int, str] | None:
    """Checked before anything else: no body read, no lock, no pass."""
    if not TICK_TOKEN:
        return 404, "not found"
    token = auth[len("Bearer "):].strip() if auth.startswith("Bearer ") else ""
    if not token or not hmac.compare_digest(token.encode(), TICK_TOKEN.encode()):
        return 401, "bad tick token"
    return None


def tick(received: float | None = None, received_awake: float | None = None) -> tuple[int, str]:
    """Run a pass (or join the running one, and its rerun if one is due) and answer when
    it ends: 200 with its times, or 202 if it is still running TICK_WAIT seconds (wall
    clock) after the request arrived. Within TICK_MIN_INTERVAL of the last pass: 200
    with that pass's times, no new pass. "answered_after" says how long this request
    took inside the VM, by the wall clock and by the VM's own clock."""
    received = time.time() if received is None else received
    received_awake = time.monotonic() if received_awake is None else received_awake
    if PASSES.recent(time.time()):
        status = PASSES.status()
        status["pass"] = "recent"
    else:
        number = PASSES.start("tick")
        done = PASSES.wait(number, TICK_WAIT, since=received, since_awake=received_awake)
        status = PASSES.status()
        status["pass"] = "done" if done else "running"
    took = {"seconds": round(time.time() - received, 1), "awake": round(time.monotonic() - received_awake, 1)}
    status["answered_after"] = took
    if took["seconds"] > TICK_WAIT + 2:
        print(f"{reviewer.owner_id()}: a tick was answered after {took['seconds']}s "
              f"({took['awake']}s awake), over its {TICK_WAIT:g}s wait", flush=True)
    return (200 if status["pass"] != "running" else 202), json.dumps(status)


# --- Callbacks ---------------------------------------------------------------------

def check_token(token: str) -> tuple[int, str] | None:
    """A cheap check before the body is read: None to go on, else (status, message)."""
    if not token:
        return 401, "no token"
    if TOKENS["live"] is None:
        return 503, "starting, try again"
    wanted = token_hash(token)
    if wanted in TOKENS["used"]:
        return 409, "this token was used already"
    if wanted not in TOKENS["live"]:
        return 401, "unknown token"
    return None


def clean_outcome(out) -> dict:
    """Only the fields the dispatcher reads, with their types checked. Raises ValueError."""
    if not isinstance(out, dict) or not isinstance(out.get("ok"), bool):
        raise ValueError("not a result object")
    usage = out.get("usage") or []
    if not isinstance(usage, list):
        raise ValueError("usage is not a list")
    clean = {"ok": out["ok"], "usage": [u for u in usage if isinstance(u, dict)][:USAGE_MAX]}
    if not out["ok"]:
        clean["error"] = str(out.get("error") or "")[:1000]
        return clean
    if out.get("verdict") not in ("approve", "block", "moved") or out.get("route") not in ("rules", "quick", "audit"):
        raise ValueError("unknown verdict or route")
    for key in ("findings", "quick"):
        if out.get(key) is not None and not isinstance(out[key], dict):
            raise ValueError(f"{key} is not an object")
    clean.update({k: out.get(k) for k in remote_review.OUTCOME_KEYS})
    clean["title"] = str(clean.get("title") or "")[:300]
    clean["focus"] = str(clean.get("focus") or "")[:2000]
    return clean


def accept_result(token: str, body: bytes) -> tuple[int, str]:
    """Store one worker's result in the state. Returns (HTTP status, message). Called
    with STATE_LOCK held. 200 only once the result is saved: on a failed save the job
    stays "running" and the worker gets 503, so it sends the result again."""
    refused = check_token(token)
    if refused:
        return refused
    try:
        out = clean_outcome(json.loads(body))
    except ValueError as e:
        return 400, f"bad result: {e}"
    try:
        state = reviewer.load_state()
    except reviewer.StateUnavailable as e:
        return 503, f"state unavailable: {e}"
    wanted = token_hash(token)
    for key, data in jobs(state).items():
        if data.get("token_hash") and secrets.compare_digest(data["token_hash"], wanted):
            break
    else:
        return (409, "this token was used already") if any(
            d.get("used_token") == wanted for d in jobs(state).values()) else (401, "unknown token")
    if data.get("status") != "running":
        return 409, "this job already has a result"
    before = dict(data)
    data.update(status="result", outcome=out, result_at=round(time.time()), used_token=wanted)
    data.pop("token_hash", None)
    if not reviewer.save_state_configmap(state):
        data.clear()
        data.update(before)
        reviewer.spool_unsaved(state)  # the spool must not keep the undone result either
        return 503, "the result could not be saved; send it again"
    TOKENS["live"].discard(wanted)
    TOKENS["used"].add(wanted)
    # The worker is done with the proxy: end its placeholders now, not when its Workload is
    # deleted (delete_workload revokes again). In a thread: STATE_LOCK is held here.
    threading.Thread(target=remote_review.revoke_keyproxy, args=(data.get("workload", ""),),
                     name="revoke", daemon=True).start()
    return 200, "ok"


class CallbackHandler(http.server.BaseHTTPRequestHandler):
    server_version = "pr-autopilot"
    # A client that sends a valid token and then stalls must not hold a thread for ever.
    timeout = 30

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.reply(200, "ok")
        else:
            self.reply(404, "not found")

    def do_POST(self) -> None:
        received, received_awake = time.time(), time.monotonic()
        if self.path == "/tick":
            # The body is never read, so the connection cannot carry another request.
            self.close_connection = True
            refused = tick_refused(self.headers.get("Authorization", ""))
            self.reply(*(refused or tick(received, received_awake)))
            return
        if self.path != "/callback":
            self.reply(404, "not found")
            return
        auth = self.headers.get("Authorization", "")
        token = auth[len("Bearer "):].strip() if auth.startswith("Bearer ") else ""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self.reply(413, "body too large")
            return
        refused = check_token(token)
        if refused:
            self.reply(*refused)
            return
        body = self.rfile.read(length)
        if not STATE_LOCK.acquire(timeout=LOCK_WAIT):
            self.reply(503, "busy, try again")
            return
        try:
            status, message = accept_result(token, body)
        except Exception as e:
            status, message = 500, f"{type(e).__name__}: {e}"
        finally:
            STATE_LOCK.release()
        if status != 200:
            reviewer.log(f"callback refused: HTTP {status} {message}")
        else:
            # Post the result now, not at the next tick. The answer waits for that pass
            # (up to TICK_WAIT): on a unikernel the open request is what keeps the VM awake.
            # Counted from now, after the wait for STATE_LOCK: callbacks come over gVPC, with
            # no ALB timeout, and a callback that waited out a running pass must still hold
            # the VM awake for the rerun that posts its result.
            PASSES.wait(PASSES.start("callback", rerun=True), TICK_WAIT)
        self.reply(status, message)

    def reply(self, status: int, message: str) -> None:
        body = (message + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        pass


class Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6
    request_queue_size = LISTEN_BACKLOG
    daemon_threads = True
    BUSY = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nbusy\n"

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(MAX_HANDLERS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address) -> None:
        if not self.slots.acquire(blocking=False):
            try:
                request.sendall(self.BUSY)
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def server_bind(self) -> None:
        # Both IPv6 (gVPC addresses are IPv6) and IPv4.
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


def serve(port: int = LISTEN_PORT) -> Server:
    server = Server(("::", port), CallbackHandler)
    threading.Thread(target=server.serve_forever, name="callbacks", daemon=True).start()
    return server


# --- Events ring buffer ------------------------------------------------------------

def events_store() -> state_store.ConfigMapStore:
    return state_store.ConfigMapStore(remote_review.PROJECT, remote_review.SESSION, name=EVENTS_NAME,
                                      key=EVENTS_KEY)


def ring(doc: dict, new: list[dict]) -> dict:
    """Append `new` to the buffer, numbering them; keep the last EVENTS_MAX that fit in
    EVENTS_MAX_BYTES. The numbers let the stats job see that events fell off the end
    before it read them."""
    seq = int(doc.get("next_seq") or 1)
    events = list(doc.get("events") or [])
    for e in new:
        events.append({**e, "seq": seq})
        seq += 1
    events = events[-EVENTS_MAX:]
    while events and len(json.dumps({"next_seq": seq, "events": events})) > EVENTS_MAX_BYTES:
        events = events[len(events) // 10 or 1:]
    return {"next_seq": seq, "events": events}


def flush_events(attempts: int = 3) -> None:
    """Write the events collected since the last flush to the ConfigMap. If that fails
    they stay in memory for the next pass (bounded by PENDING_MAX)."""
    pending = reviewer.EVENT_SINK
    if not pending:
        return
    store = events_store()
    batch = list(pending)  # a callback thread may log more while this writes
    for _ in range(attempts):
        try:
            doc, version = store.load()
            store.save(ring(doc or {}, batch), version)
            del pending[:len(batch)]
            return
        except state_store.Conflict:
            continue
        except state_store.Unavailable as e:
            print(f"events not written, kept for the next pass: {e}", flush=True)
            break
    del pending[:-PENDING_MAX]


# --- Main --------------------------------------------------------------------------

def check_environment() -> None:
    missing = [v for v in ("PR_AUTOPILOT_GITHUB_TOKEN", "PR_AUTOPILOT_CALLBACK_URL") if not os.environ.get(v)]
    if reviewer.STATE_BACKEND != "configmap":
        missing.append("PR_AUTOPILOT_STATE=configmap")
    # The image carries no repos.json (it is public, the repo list is not): it comes from a
    # ConfigMap volume. Without it every pass would fail, so refuse to start.
    if not reviewer.CONFIG_FILE.is_file():
        missing.append(f"the repos.json at {reviewer.CONFIG_FILE} (PR_AUTOPILOT_CONFIG)")
    if missing:
        raise SystemExit(f"dispatcher: missing {', '.join(missing)}")


def run_pass() -> None:
    with STATE_LOCK:
        try:
            reviewer.run_once(before_save=dispatch)
        except Exception as e:
            reviewer.event("ERROR", "pass failed", f"{type(e).__name__}: {e}")
        try:
            flush_events()
        except Exception as e:
            print(f"events not written: {e}", flush=True)


def main() -> None:
    reviewer.DISPATCHER = True
    reviewer.EVENT_SINK = []
    check_environment()
    serve()
    reviewer.event("NOTICE", f"dispatcher {reviewer.owner_id()} started",
                   f"at most {MAX_WORKERS} workers; callbacks at {CALLBACK_URL}; "
                   f"/tick {'on' if TICK_TOKEN else 'off'}")
    while True:
        timer_step()
        time.sleep(max(1.0, reviewer.POLL_SECONDS - (time.time() - PASSES.last_start)))


if __name__ == "__main__":
    main()
