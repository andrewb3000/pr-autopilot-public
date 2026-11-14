"""Tests for the dispatcher on Datum and the local stats job. No network: GitHub, Milo
and the worker VMs are faked.

Run: python3 -m unittest -v test_dispatcher
"""
from __future__ import annotations

import json
import http.client
import http.server
import re
import subprocess
import os
import pathlib
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

import dispatcher as d
import github_api
import remote_review
import reviewer as r
import stats
import test_reviewer as tr

REPO, SHA, KEY = tr.REPO, tr.SHA, f"{tr.REPO}#7@{tr.SHA}"
REAL_NOTIFY = r.notify  # Base replaces it in every test
REAL_EVENT = r.event
REAL_POST = r.post_review
REAL_FLOOR = r.review_floor


class DispatcherBase(tr.Base):
    """reviewer in dispatcher mode, with the state in a fake ConfigMap."""

    def setUp(self):
        super().setUp()
        self.store = tr.FakeStore({"reviewed": {}})
        self.events, self.workers, self.deleted = [], [], []
        patches = {
            (r, "DISPATCHER"): True, (r, "STATE_BACKEND"): "configmap",
            (r, "state_store_client"): lambda: self.store,
            (r, "STORE_MEMORY"): {"state": None, "base": None, "version": None, "seeded": False},
            (r, "STATE_SPOOL_FILE"): self.tmp / "spool.json", (r, "STATE_DOWN_FILE"): self.tmp / "down.json",
            (r, "event"): lambda kind, subject, *details, usage=None, notify=None: self.events.append((kind, subject, details, usage)),
            (r, "load_config"): lambda: {REPO: tr.CFG},
            (d, "CALLBACK_URL"): "http://dispatcher.instances.datum.internal:8080/callback",
            (d, "RECONCILED"): {"done": True},
            (d, "TOKENS"): {"live": set(), "used": set()},
            (d, "PASSES"): d.Passes(run=lambda: None),  # a callback starts a pass: none here
            (r, "CLOCK"): {"wall": None, "mono": None},
            (r, "review_floor"): lambda repo, num, sha: self.floor,
            (r, "LOCK_SEEN"): {"waiting_for": None, "lost": False},
            (remote_review, "start_worker"): self.start_worker,
            (remote_review, "delete_workload"): self.deleted.append,
            (remote_review, "vm_can_read"): lambda repo, config=None: True,
            (d.github_api, "pull"): lambda repo, num: dict(self.pr_now),
        }
        self.pr_now = {"state": "open", "head": {"sha": SHA}}
        self.floor = 0  # no review of yours on the commit before the worker starts
        for (mod, name), value in patches.items():
            p = mock.patch.object(mod, name, value)
            p.start()
            self.addCleanup(p.stop)
        env = mock.patch.dict(os.environ, {"PR_AUTOPILOT_OWNER": "dispatcher@test"})
        env.start()
        self.addCleanup(env.stop)

    def start_worker(self, repo, num, sha, context, model, **opts):
        name = f"review-infra-{num}-{sha[:8]}-{len(self.workers)}"
        self.workers.append((name, opts))
        return name

    def queue(self, n=1, plan="quick"):
        state = r.load_state()
        for i in range(n):
            r.StateJob(state, REPO, str(7 + i), SHA).write(status="queued", queued=i, reason="", audit=False,
                                                           plan=plan, runner="datum", author="by alice", title="t")
        r.save_state_configmap(state)
        return state

    def jobs(self):
        return self.store.data.get("jobs", {})

    def kinds(self):
        return [e[0] for e in self.events]


class QueueTest(DispatcherBase):
    def test_review_queues_instead_of_starting_a_process(self):
        state = r.load_state()
        with tr.fake_github(self, diff=tr.diff_for("apps/x/base/a.yaml"), head_sha=SHA), \
             mock.patch.object(r, "start_pr_review", lambda *a, **k: self.fail("no worker process")):
            self.assertFalse(r.review(REPO, tr.CFG, tr.PR, state))
        job = state["jobs"][KEY]
        self.assertEqual((job["status"], job["plan"], job["author"]), ("queued", "quick", "by alice"))
        self.assertEqual(self.kinds(), ["STARTED"])
        # Queued is waiting: the next run does not queue it again.
        with tr.fake_github(self):
            self.assertFalse(r.review(REPO, tr.CFG, tr.PR, state))

    def test_a_private_repo_the_vm_cannot_read_is_left_to_you(self):
        state = r.load_state()
        with tr.fake_github(self, diff=tr.diff_for("a.yaml"), head_sha=SHA), \
             mock.patch.object(remote_review, "vm_can_read", lambda repo, config=None: False):
            self.assertTrue(r.review(REPO, tr.CFG, tr.PR, state))
        self.assertEqual(self.kinds(), ["MANUAL"])
        self.assertFalse(state.get("jobs"))

    def test_launch_keeps_to_max_workers_and_gives_each_a_token(self):
        state = self.queue(5)
        d.launch(state)
        running = [k for k, j in state["jobs"].items() if j["status"] == "running"]
        self.assertEqual(len(running), d.MAX_WORKERS)
        self.assertEqual(len(self.workers), d.MAX_WORKERS)
        tokens = [opts["callback_token"] for _, opts in self.workers]
        self.assertEqual(len(set(tokens)), len(tokens))
        for (name, opts), key in zip(self.workers, sorted(running)):
            job = state["jobs"][key]
            self.assertEqual(job["token_hash"], d.token_hash(opts["callback_token"]))
            self.assertNotIn(opts["callback_token"], json.dumps(state))  # only the hash is kept
            self.assertEqual(opts["callback_url"], d.CALLBACK_URL)
        d.launch(state)  # no free slot: nothing more starts
        self.assertEqual(len(self.workers), d.MAX_WORKERS)

    def test_a_datum_failure_leaves_the_job_queued_and_notifies(self):
        state = self.queue(1)

        def down(*a, **k):
            raise remote_review.DatumUnavailable("deploy refused")
        with mock.patch.object(remote_review, "start_worker", down):
            d.launch(state)
        self.assertEqual(state["jobs"][KEY]["status"], "queued")
        self.assertEqual(self.notified, ["PR autopilot cannot start reviews on Datum"])


class CallbackTest(DispatcherBase):
    def launched(self):
        state = self.queue(1)
        d.launch(state)
        r.save_state_configmap(state)
        return self.workers[0][1]["callback_token"]

    def outcome(self, **over):
        return {"ok": True, "format": 2, "route": "quick", "verdict": "approve", "title": "t",
                "quick": tr.QUICK_OK, "focus": "", "findings": None,
                "usage": [{"kind": "quick", "input": 10, "output": 5, "cost_usd": 0.02, "models": ["claude-sonnet"]}],
                **over}

    def test_one_callback_per_token(self):
        token = self.launched()
        body = json.dumps(self.outcome()).encode()
        self.assertEqual(d.accept_result("wrong", body)[0], 401)
        self.assertEqual(d.accept_result(token, b"not json")[0], 400)
        self.assertEqual(d.accept_result(token, body), (200, "ok"))
        self.assertEqual(self.jobs()[KEY]["status"], "result")  # saved before the 200
        self.assertEqual(d.accept_result(token, body)[0], 409)

    def test_before_the_first_pass_a_callback_is_asked_to_retry(self):
        with mock.patch.object(d, "TOKENS", {"live": None, "used": set()}):
            self.assertEqual(d.accept_result("anything", b"{}")[0], 503)

    def test_a_failed_save_answers_503_and_keeps_the_job_running(self):
        token = self.launched()
        self.store.down = True
        self.assertEqual(d.accept_result(token, json.dumps(self.outcome()).encode())[0], 503)
        self.assertEqual(r.STORE_MEMORY["state"]["jobs"][KEY]["status"], "running")
        self.store.down = False
        self.assertEqual(d.accept_result(token, json.dumps(self.outcome()).encode())[0], 200)  # the retry

    def test_results_are_checked_and_trimmed(self):
        token = self.launched()
        self.assertEqual(d.accept_result(token, json.dumps({"ok": "yes"}).encode())[0], 400)
        self.assertEqual(d.accept_result(token, json.dumps(self.outcome(verdict="lgtm")).encode())[0], 400)
        noisy = self.outcome(extra="x" * 1000, usage=[{"input": 1}] * 500)
        self.assertEqual(d.accept_result(token, json.dumps(noisy).encode())[0], 200)
        stored = self.jobs()[KEY]["outcome"]
        self.assertNotIn("extra", stored)
        self.assertEqual(len(stored["usage"]), d.USAGE_MAX)

    def test_a_result_is_posted_with_its_usage_and_the_worker_deleted(self):
        token = self.launched()
        d.accept_result(token, json.dumps(self.outcome()).encode())
        state = r.load_state()
        d.process_results(state)
        self.assertEqual(self.posted, [("7", "APPROVE", "")])
        job = state["jobs"][KEY]
        self.assertEqual((job["status"], job["verdict"]), ("done", "approve"))
        self.assertNotIn("outcome", job)
        self.assertEqual(self.deleted, [self.workers[0][0]])
        done = [e for e in self.events if e[0] == "DONE"][0]
        self.assertEqual(done[3][0]["runner"], "datum")
        self.assertIn("15 tokens, $0.02, claude-sonnet", done[2][1])
        # The next run records the PR as handled and forgets the job.
        with tr.fake_github(self):
            self.assertFalse(r.review(REPO, tr.CFG, tr.PR, state))
        self.assertEqual(state["reviewed"][f"{REPO}#7"], SHA)
        self.assertNotIn(KEY, state["jobs"])

    def test_a_full_approval_from_the_vm_carries_its_non_blocking_findings(self):
        findings = {**tr.FullReviewPostTest.WITH_NOTES, "title": "t"}
        token = self.launched()
        self.assertEqual(d.accept_result(token, json.dumps(self.outcome(
            route="rules", findings=findings)).encode())[0], 200)
        state = r.load_state()
        d.process_results(state)
        self.assertEqual(self.posted, [("7", "APPROVE", tr.FullReviewPostTest.WITH_NOTES_BODY)])
        self.assertEqual((state["jobs"][KEY]["status"], state["jobs"][KEY]["verdict"]), ("done", "approve"))

    def test_a_full_approval_with_no_findings_has_an_empty_body(self):
        findings = {**tr.FullReviewPostTest.WITH_NOTES, "other": [], "title": "t"}
        token = self.launched()
        d.accept_result(token, json.dumps(self.outcome(route="rules", findings=findings)).encode())
        d.process_results(r.load_state())
        self.assertEqual(self.posted, [("7", "APPROVE", "")])

    def test_a_failed_post_is_kept_and_posted_later_without_a_new_review(self):
        token = self.launched()
        d.accept_result(token, json.dumps(self.outcome()).encode())
        state = r.load_state()

        def failing(*a, **k):
            raise r.GhError("POST", "x", 0, "timed out")
        with mock.patch.object(r, "post_review", failing):
            d.process_results(state)
        self.assertEqual(state["jobs"][KEY]["status"], "unposted")
        with tr.fake_github(self):  # no new diff, no new worker
            self.assertFalse(r.review(REPO, tr.CFG, tr.PR, state))
        self.assertEqual(self.posted, [("7", "APPROVE", "")])
        self.assertEqual(len(self.workers), 1)

    def test_a_github_hiccup_before_posting_keeps_the_result_for_the_next_pass(self):
        token = self.launched()
        d.accept_result(token, json.dumps(self.outcome()).encode())
        state = r.load_state()

        def down(repo, num):
            raise github_api.RateLimited("GET", "pulls/7", 429, "slow down", 60)
        with mock.patch.object(d.github_api, "pull", down):
            d.process_results(state)
        job = state["jobs"][KEY]
        self.assertEqual(job["status"], "result")
        self.assertIn("outcome", job)
        self.assertEqual((self.posted, self.deleted), ([], []))
        self.assertEqual(state["failures"], {})
        self.assertEqual([e[0] for e in self.events if e[0] in ("WARN", "DONE")], ["WARN"])
        d.process_results(state)  # GitHub is back
        self.assertEqual(self.posted, [("7", "APPROVE", "")])
        self.assertEqual(state["jobs"][KEY]["status"], "done")

    def test_a_pr_that_moved_or_closed_during_the_review_is_not_posted(self):
        for now in ({"state": "open", "head": {"sha": "b" * 40}}, {"state": "closed", "head": {"sha": SHA}}):
            self.posted.clear()
            self.store.data = {"reviewed": {}}
            r.STORE_MEMORY.update(state=None, base=None, version=None)
            self.workers.clear()
            token = self.launched()
            d.accept_result(token, json.dumps(self.outcome()).encode())
            self.pr_now = now
            state = r.load_state()
            d.process_results(state)
            self.assertEqual(self.posted, [])
            self.assertEqual(self.jobs()[KEY]["status"], "stale")  # saved right away

    def test_each_post_is_saved_before_the_next_and_never_posted_twice(self):
        token = self.launched()
        d.accept_result(token, json.dumps(self.outcome()).encode())
        state = r.load_state()
        saves = self.store.saves
        d.process_results(state)
        self.assertEqual(self.jobs()[KEY]["status"], "done")
        self.assertGreater(self.store.saves, saves)
        # The pass crashed after posting and before saving: the record still says "result".
        # The real post_review sees the review on GitHub and does not post again.
        created = []
        with mock.patch.object(r, "_ME", []), \
             tr.fake_github(self, login="example-user", create_review=lambda *a: created.append(a),
                            reviews=tr.reviews_of(f"2026-11-11T10:00:00Z APPROVED {SHA}")):
            REAL_POST(REPO, "7", SHA, "APPROVE", "")
        self.assertEqual(created, [])

    def test_an_expired_claude_token_in_the_vm_is_an_auth_status(self):
        token = self.launched()
        d.accept_result(token, json.dumps({"ok": False, "error": "Failed to authenticate", "usage": []}).encode())
        state = r.load_state()
        d.process_results(state)
        self.assertEqual(state["jobs"][KEY]["status"], "auth")
        with tr.fake_github(self), self.assertRaisesRegex(r.claude_cli.AuthExpired, "review-credentials"):
            r.review(REPO, tr.CFG, tr.PR, state)

    def test_a_worker_past_its_ttl_is_deleted_and_counts_as_a_failure(self):
        self.launched()
        state = r.load_state()
        d.expire(state, now=time.time() + d.WORKER_TTL + 1)
        self.assertEqual(state["jobs"][KEY]["status"], "failed")
        self.assertEqual(self.deleted, [self.workers[0][0]])
        with tr.fake_github(self), self.assertRaisesRegex(RuntimeError, "no result in 45 minutes"):
            r.review(REPO, tr.CFG, tr.PR, state)

    def test_the_http_server_takes_a_callback(self):
        token = self.launched()
        server = d.serve(port=0)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]

        def post(path, tok, body):
            req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body, method="POST",
                                         headers={"Authorization": f"Bearer {tok}"})
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return resp.status
            except urllib.error.HTTPError as e:
                return e.code
        body = json.dumps(self.outcome()).encode()
        self.assertEqual(post("/callback", "nope", body), 401)
        self.assertEqual(post("/elsewhere", token, body), 404)
        self.assertEqual(post("/callback", token, body), 200)
        self.assertEqual(post("/callback", token, body), 409)
        self.assertEqual(server.request_queue_size, 128)
        # Too large: refused from the header alone, before the body is read.
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.putrequest("POST", "/callback")
        conn.putheader("Content-Length", str(d.MAX_BODY + 1))
        conn.putheader("Authorization", f"Bearer {token}")
        conn.endheaders()
        self.assertEqual(conn.getresponse().status, 413)
        conn.close()
        # A valid token, then a stalled body: the server drops the connection after its
        # timeout and keeps answering others.
        with mock.patch.object(d.CallbackHandler, "timeout", 0.5), \
             mock.patch.object(d, "check_token", lambda tok: None):  # as if the token were still live
            stalled = socket.create_connection(("127.0.0.1", port), timeout=10)
            stalled.sendall(f"POST /callback HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n"
                            "Content-Length: 100\r\n\r\n".encode())
            started = time.time()
            self.assertEqual(stalled.recv(100), b"")  # closed, no answer
            self.assertLess(time.time() - started, 5)
            stalled.close()
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=10) as resp:
            self.assertEqual(resp.status, 200)


class ReconcileTest(DispatcherBase):
    def test_orphans_are_deleted_and_lost_workers_requeued(self):
        state = self.queue(2)
        d.launch(state)
        mine, lost = self.workers[0][0], self.workers[1][0]
        with mock.patch.object(remote_review, "list_workloads", lambda label: [mine, "review-orphan-1-abc"]):
            d.reconcile(state)
        self.assertEqual(self.deleted, ["review-orphan-1-abc"])
        statuses = {j.get("workload"): j["status"] for j in state["jobs"].values()}
        self.assertEqual(statuses[mine], "running")
        requeued = [j for j in state["jobs"].values() if j["status"] == "queued"]
        self.assertEqual(len(requeued), 1)
        self.assertNotIn("token_hash", requeued[0])
        self.assertNotIn(lost, statuses)

    def test_a_pass_reconciles_once_then_launches(self):
        self.queue(1)
        listed = []
        with mock.patch.object(d, "RECONCILED", {"done": False}), \
             mock.patch.object(remote_review, "list_workloads", lambda label: listed.append(label) or []), \
             tr.fake_github(self, notifications=(None, None, 60), search_issues={"items": []}):
            d.run_pass()
            d.run_pass()
        self.assertEqual(listed, [remote_review.WORKER_LABEL])
        self.assertEqual(self.jobs()[KEY]["status"], "running")
        self.assertTrue(self.store.data["owner"]["id"].startswith("dispatcher@test#"))


class NotifyTest(DispatcherBase):
    def test_the_dispatcher_never_starts_a_process_to_notify(self):
        sink = []
        with mock.patch.object(r, "slack_webhook", lambda: None), \
             mock.patch.object(r, "EVENT_SINK", sink), mock.patch.object(r, "event", REAL_EVENT), \
             mock.patch.object(r.subprocess, "run", lambda *a, **k: self.fail("no subprocess")):
            REAL_NOTIFY("PR needs your review", "x", "https://github.com/a/b/pull/1")
        self.assertEqual(len(sink), 1)
        self.assertEqual(sink[0]["subject"], "notification: PR needs your review: x https://github.com/a/b/pull/1")
        # The stats job on the laptop shows it as a macOS notification.
        self.assertEqual(sink[0]["notify"], {"title": "PR needs your review", "text": "x",
                                             "url": "https://github.com/a/b/pull/1"})

    def test_plain_events_carry_no_notify_mark(self):
        sink = []
        with mock.patch.object(r, "EVENT_SINK", sink):
            REAL_EVENT("NOTICE", "hello")
        self.assertNotIn("notify", sink[0])


class EventsRingTest(unittest.TestCase):
    def test_events_are_numbered_and_the_oldest_drop_off(self):
        doc = d.ring({}, [{"ts": 1, "kind": "NOTICE", "subject": "a", "details": []}])
        self.assertEqual((doc["next_seq"], doc["events"][0]["seq"]), (2, 1))
        many = [{"ts": i, "kind": "NOTICE", "subject": str(i), "details": []} for i in range(600)]
        doc = d.ring(doc, many)
        self.assertEqual(len(doc["events"]), d.EVENTS_MAX)
        self.assertEqual(doc["events"][-1]["seq"], 601)
        self.assertEqual(doc["next_seq"], 602)

    def test_the_buffer_stays_under_the_size_limit(self):
        big = [{"ts": i, "kind": "BLOCKED", "subject": "s", "details": ["x" * 5000]} for i in range(400)]
        doc = d.ring({}, big)
        self.assertLessEqual(len(json.dumps(doc)), d.EVENTS_MAX_BYTES)
        self.assertEqual(doc["events"][-1]["seq"], 400)

    def test_a_failed_flush_keeps_the_events_for_the_next_pass(self):
        store = tr.FakeStore(None)
        store.down = True
        with mock.patch.object(r, "EVENT_SINK", [{"ts": 1, "kind": "NOTICE", "subject": "a", "details": []}]), \
             mock.patch.object(d, "events_store", lambda: store):
            d.flush_events()
            self.assertEqual(len(r.EVENT_SINK), 1)
            store.down = False
            d.flush_events()
            self.assertEqual(r.EVENT_SINK, [])
        self.assertEqual(store.data["events"][0]["seq"], 1)


class StatsTest(unittest.TestCase):
    def buffer(self, first, last):
        return {"next_seq": last + 1, "events": [
            {"seq": s, "ts": 1000 + s, "kind": "DONE" if s == last else "NOTICE", "subject": f"e{s}", "details": [],
             **({"usage": [{"kind": "quick", "input": 1}]} if s == last else {})} for s in range(first, last + 1)]}

    def test_new_events_only_and_usage_from_done(self):
        rows, usage, cursor = stats.new_events(self.buffer(1, 3), {"seq": 1, "ts": 1001})
        self.assertEqual([e["subject"] for e in rows], ["e2", "e3"])
        self.assertNotIn("seq", rows[0])
        self.assertEqual(rows[0]["dseq"], 2)
        self.assertEqual(usage, [{"kind": "quick", "input": 1, "runner": "datum"}])
        self.assertEqual(cursor, {"seq": 3, "ts": 1003})

    def test_a_gap_is_marked(self):
        rows, _, _ = stats.new_events(self.buffer(10, 12), {"seq": 4, "ts": 1004})
        self.assertEqual(rows[0]["kind"], "GAP")
        self.assertTrue(rows[0]["subject"].startswith("gap from "))
        self.assertIn("5 dispatcher events", rows[0]["details"][0])
        # A first read, or a recreated buffer, is not a gap.
        self.assertNotEqual(stats.new_events(self.buffer(10, 12), {})[0][0]["kind"], "GAP")
        self.assertNotEqual(stats.new_events(self.buffer(1, 2), {"seq": 50, "ts": 1})[0][0]["kind"], "GAP")

    def test_the_events_file_itself_says_how_far_the_copy_got(self):
        path = pathlib.Path(tempfile.mkdtemp()) / "events.jsonl"
        self.assertEqual(stats.last_copied(path), {})
        stats.append(path, [{"ts": 1, "kind": "NOTICE"}, {"ts": 5, "kind": "DONE", "dseq": 7}, {"ts": 6, "dseq": 6}])
        self.assertEqual(stats.last_copied(path), {"seq": 7, "ts": 5})

    def test_no_poll_on_record_alerts_too(self):
        self.assertEqual([t for t, _ in stats.alerts({}, {}, 100_000)], ["PR autopilot is not polling"])

    def test_alerts_for_a_stale_poll_and_a_401_once_each(self):
        now, sent = 100_000, {}
        state = {"last_poll": now - stats.STALE_POLL - 1, "github_401": now - 5, "owner": {"id": "dispatcher@vm"}}
        titles = [t for t, _ in stats.alerts(state, sent, now)]
        self.assertEqual(titles, ["PR autopilot is not polling", "PR autopilot: GitHub token refused"])
        self.assertEqual(stats.alerts(state, sent, now + 60), [])  # not again within the hour
        self.assertEqual(stats.alerts({"last_poll": now}, sent, now), [])
        self.assertEqual(sent, {})  # cleared once fixed, so the next problem alerts again


class StatsNotifyTest(unittest.TestCase):
    """Events the dispatcher marked `notify` become macOS notifications on the laptop."""

    def setUp(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.buffer = {"next_seq": 1, "events": []}
        self.shown = []
        stores = {stats.EVENTS_NAME: lambda: tr.FakeStore(self.buffer),
                  stats.STATE_NAME: lambda: tr.FakeStore({"last_poll": 10**12})}
        for patch in (mock.patch.object(stats, "EVENTS_FILE", tmp / "events.jsonl"),
                      mock.patch.object(stats, "USAGE_FILE", tmp / "usage.jsonl"),
                      mock.patch.object(stats, "CURSOR_FILE", tmp / "cursor.json"),
                      mock.patch.object(stats, "DASHBOARD_FILE", tmp / "dashboard" / "index.html"),
                      mock.patch.object(stats, "store", lambda name, key: stores[name]()),
                      mock.patch.object(stats, "tick_settings", lambda: ("", "")),
                      mock.patch.object(stats, "mac_notify", lambda *a: self.shown.append(a))):
            patch.start()
            self.addCleanup(patch.stop)

    def add(self, *events):
        for e in events:
            self.buffer["events"].append({"seq": self.buffer["next_seq"], "ts": 1000, "details": [], **e})
            self.buffer["next_seq"] += 1

    def marked(self, n):
        return {"kind": "NOTICE", "subject": f"notification: {n}",
                "notify": {"title": "PR needs your review", "text": f"pr {n}",
                           "url": f"https://github.com/a/b/pull/{n}"}}

    def round(self):
        self.shown.clear()
        stats.round_once(now=10**12)
        return list(self.shown)

    def test_a_marked_event_notifies_once_and_opens_the_pr(self):
        self.add({"kind": "NOTICE", "subject": "history"})
        self.assertEqual(self.round(), [])  # the first copy is history
        self.add(self.marked(1), {"kind": "DONE", "subject": "a plain event"})
        self.assertEqual(self.round(), [("PR needs your review", "pr 1", "https://github.com/a/b/pull/1")])
        self.assertEqual(self.round(), [])

    def test_a_restart_replays_nothing(self):
        self.add({"kind": "NOTICE", "subject": "history"})
        self.round()
        self.add(self.marked(1))
        self.assertEqual(len(self.round()), 1)
        stats.CURSOR_FILE.unlink()  # a lost cursor: events.jsonl still says how far the copy got
        self.assertEqual(self.round(), [])

    def test_a_burst_is_capped_with_one_summary(self):
        self.add({"kind": "NOTICE", "subject": "history"})
        self.round()
        self.add(*[self.marked(n) for n in range(1, 11)])
        shown = self.round()
        self.assertEqual(len(shown), stats.MAX_NOTICES + 1)
        self.assertEqual([s[1] for s in shown[:-1]], ["pr 8", "pr 9", "pr 10"])  # the newest
        self.assertEqual(shown[-1], ("PR autopilot", "7 more notifications in the dashboard.", stats.dashboard_url()))

    def test_old_dispatcher_events_and_odd_urls(self):
        self.add({"kind": "NOTICE", "subject": "history"})
        self.round()
        self.add({"kind": "NOTICE", "subject": "notification: x: y"},  # an image without the field
                 {"kind": "NOTICE", "subject": "s", "notify": {"title": "t", "text": "m", "url": "file:///etc"}},
                 {"kind": "NOTICE", "subject": "s", "notify": "not a dict"})
        self.assertEqual(self.round(), [("t", "m", None)])


if __name__ == "__main__":
    unittest.main()


class LockIdTest(unittest.TestCase):
    def test_each_dispatcher_process_has_its_own_id_but_the_laptop_keeps_one(self):
        with mock.patch.dict(os.environ, {"PR_AUTOPILOT_OWNER": "x"}):
            with mock.patch.object(r, "DISPATCHER", True):
                self.assertEqual(r.owner_id(), f"x#{r._PROCESS}")
            self.assertEqual(r.owner_id(), "x")


class LostWorkerTest(DispatcherBase):
    def test_a_job_whose_worker_keeps_vanishing_stops_being_requeued(self):
        state = self.queue(1)
        for _ in range(r.MAX_FAILURES):
            d.launch(state)
            with mock.patch.object(remote_review, "list_workloads", lambda label: []):
                d.reconcile(state)
        job = state["jobs"][KEY]
        self.assertEqual((job["status"], job["lost"]), ("failed", r.MAX_FAILURES))
        self.assertIn("lost 3 times", job["error"])


REMOTE = pathlib.Path(__file__).with_name("remote")


def load_yaml(path: pathlib.Path) -> list:
    """Every document in a YAML file. The stdlib has no YAML parser: PyYAML when it is
    installed, else Ruby's (on macOS and on GitHub's Ubuntu runners), else skip."""
    try:
        import yaml
        return list(yaml.safe_load_all(path.read_text()))
    except ImportError:
        pass
    try:
        out = subprocess.run(["ruby", "-ryaml", "-rjson", "-e", "puts JSON.generate(YAML.load_stream(File.read(ARGV[0])))",
                              str(path)], capture_output=True, text=True, timeout=60, check=True)
    except (OSError, subprocess.CalledProcessError) as e:
        raise unittest.SkipTest(f"no YAML parser: {e}")
    return json.loads(out.stdout)


class WorkloadManifestTest(unittest.TestCase):
    """remote/dispatcher-workload.yaml (Kata), parsed."""

    PATH = REMOTE / "dispatcher-workload.yaml"

    @classmethod
    def setUpClass(cls):
        cls.doc = load_yaml(cls.PATH)[0]

    def container(self):
        return self.doc["spec"]["template"]["spec"]["runtime"]["sandbox"]["containers"][0]

    def env(self):
        return {e["name"]: e for e in self.container()["env"]}

    def test_kata_with_no_declared_port(self):
        # Not unikernel: the platform parks it even with no port (docs/dispatcher.md).
        runtime = self.doc["spec"]["template"]["spec"]["runtime"]
        self.assertEqual(runtime["class"], "general-purpose")
        self.assertNotIn("ports", self.container())
        self.assertNotIn("ports", runtime["sandbox"])

    def test_names_fit_and_the_callback_url_is_the_instance(self):
        name = self.doc["metadata"]["name"]
        placement = self.doc["spec"]["placements"][0]
        self.assertLessEqual(len(name), 39)
        self.assertEqual(placement["cityCodes"], [remote_review.CITY])  # DFW is us-central-1
        instance = f"{name}-{placement['name']}-us-central-1-0"
        self.assertLessEqual(len(instance), 63)
        self.assertEqual(self.env()["PR_AUTOPILOT_CALLBACK_URL"]["value"],
                         f"http://{instance}.instances.datum.internal:{self.env()['PR_AUTOPILOT_LISTEN_PORT']['value']}/callback")

    def test_secrets_only_through_secret_refs_and_repos_from_a_volume(self):
        env = self.env()
        for var, key in (("PR_AUTOPILOT_GITHUB_TOKEN", "GITHUB_TOKEN"), ("PR_AUTOPILOT_MILO_CREDENTIALS", "MILO_CREDENTIALS")):
            self.assertEqual(env[var]["valueFrom"]["secretKeyRef"], {"name": "pr-autopilot-dispatcher", "key": key})
            self.assertNotIn("value", env[var])
        mount = self.container()["volumeAttachments"][0]
        volume = self.doc["spec"]["template"]["spec"]["volumes"][0]
        self.assertEqual((mount["name"], volume["configMap"]["name"]), (volume["name"], "pr-autopilot-repos"))
        self.assertEqual(env["PR_AUTOPILOT_CONFIG"]["value"], f"{mount['mountPath']}/repos.json")

    def test_the_image_is_pinned_by_digest_or_still_marked_to_fill_in(self):
        image = self.container()["image"]
        self.assertTrue(image.startswith("ghcr.io/example-user/pr-autopilot-dispatcher@sha256:"))
        digest = image.rsplit(":", 1)[1]
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", digest) or digest == "REPLACE_WITH_THE_DIGEST_CI_PRINTED")

    def test_the_callback_server_backlog_survives_a_resume(self):
        self.assertGreaterEqual(d.LISTEN_BACKLOG, 128)
        self.assertGreaterEqual(d.Server.request_queue_size, 128)


# --- Unikernel, woken by the laptop -------------------------------------------------

class PassesTest(unittest.TestCase):
    """One pass at a time; ticks join the running pass; the timer skips after a recent one."""

    def setUp(self):
        self.calls, self.release = [], threading.Event()
        self.passes = d.Passes(run=self.fake_pass)
        for name, value in (("PASSES", self.passes), ("TICK_WAIT", 5.0)):
            p = mock.patch.object(d, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self.release.set)

    def fake_pass(self):
        self.calls.append(time.time())
        self.release.wait(10)

    def test_ticks_during_a_pass_wait_for_it_instead_of_starting_another(self):
        answers = []
        ticks = [threading.Thread(target=lambda: answers.append(d.tick())) for _ in range(3)]
        for t in ticks:
            t.start()
        time.sleep(0.2)
        self.assertEqual(len(self.calls), 1)
        self.release.set()
        for t in ticks:
            t.join(10)
        self.assertEqual([a[0] for a in answers], [200, 200, 200])
        self.assertEqual(json.loads(answers[0][1])["pass"], "done")
        self.assertEqual(len(self.calls), 1)

    def test_a_long_pass_answers_202_and_keeps_running(self):
        with mock.patch.object(d, "TICK_WAIT", 0.1):
            status, body = d.tick()
        self.assertEqual(status, 202)
        self.assertEqual(json.loads(body)["pass"], "running")
        self.assertIn("running_for", json.loads(body))
        # The next tick joins the same pass and gets its end.
        status, body = [None], [None]

        def second():
            status[0], body[0] = d.tick()
        joined = threading.Thread(target=second)
        joined.start()
        time.sleep(0.2)
        self.release.set()
        joined.join(10)
        self.assertEqual((status[0], len(self.calls)), (200, 1))
        answer = json.loads(body[0])
        self.assertEqual(answer["pass"], "done")
        self.assertEqual(answer["last"]["reason"], "tick")
        self.assertGreaterEqual(answer["last"]["seconds"], answer["last"]["awake"] - 0.1)

    def test_a_tick_soon_after_a_pass_gets_its_status_and_no_new_pass(self):
        self.release.set()
        self.assertEqual(json.loads(d.tick()[1])["pass"], "done")
        status, body = d.tick()
        self.assertEqual((status, json.loads(body)["pass"], len(self.calls)), (200, "recent", 1))
        with mock.patch.object(d, "TICK_MIN_INTERVAL", 0):
            self.assertEqual(json.loads(d.tick()[1])["pass"], "done")
        self.assertEqual(len(self.calls), 2)

    def test_a_rerun_request_during_a_pass_runs_one_more_pass(self):
        first = self.passes.start("timer")
        time.sleep(0.1)
        # Two callbacks land while the pass is ending: one rerun, not two.
        rerun = self.passes.start("callback", rerun=True)
        self.assertEqual(self.passes.start("callback", rerun=True), rerun)
        self.assertEqual(rerun, first + 1)
        # A tick that joins now waits for the rerun too.
        self.assertEqual(self.passes.start("tick"), rerun)
        self.release.set()
        self.assertTrue(self.passes.wait(rerun, 10))
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.passes.last["reason"], "rerun")
        self.assertFalse(self.passes.running)

    def test_a_pass_that_raises_does_not_wedge_the_runner(self):
        self.passes.run = lambda: 1 / 0
        with mock.patch.object(d, "print", lambda *a, **k: None, create=True):
            number = self.passes.start("tick")
            self.assertTrue(self.passes.wait(number, 5))
        self.assertFalse(self.passes.running)

    def test_the_timer_skips_when_a_pass_ran_in_the_last_30_seconds(self):
        self.release.set()
        self.assertEqual(d.tick()[0], 200)
        now = time.time()
        self.assertFalse(d.timer_step(now + d.TIMER_SKIP - 1))
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(d.timer_step(now + d.TIMER_SKIP + 1))
        self.assertEqual(len(self.calls), 2)

    def test_the_timer_skips_while_a_pass_runs(self):
        self.passes.start("tick")
        time.sleep(0.1)
        self.assertFalse(d.timer_step(time.time() + 3600))
        self.assertEqual(len(self.calls), 1)


class TickEndpointTest(unittest.TestCase):
    TOKEN = "t" * 43

    def setUp(self):
        self.calls = []
        for name, value in (("PASSES", d.Passes(run=lambda: self.calls.append(1))), ("TICK_TOKEN", self.TOKEN)):
            p = mock.patch.object(d, name, value)
            p.start()
            self.addCleanup(p.stop)
        server = d.serve(port=0)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.port = server.server_address[1]

    def post(self, token=None, length=0):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest("POST", "/tick")
        conn.putheader("Content-Length", str(length))
        if token is not None:
            conn.putheader("Authorization", f"Bearer {token}")
        conn.endheaders()  # no body sent, whatever Content-Length says
        resp = conn.getresponse()
        out = resp.status, resp.read()
        conn.close()
        return out

    def test_the_token_is_checked_before_the_body_or_a_pass(self):
        self.assertEqual(self.post()[0], 401)
        self.assertEqual(self.post("wrong")[0], 401)
        self.assertEqual(self.post(self.TOKEN[:-1])[0], 401)
        # A claimed body that never comes: refused at once, not after a read timeout.
        started = time.time()
        self.assertEqual(self.post("wrong", length=1000)[0], 401)
        self.assertLess(time.time() - started, 5)
        self.assertEqual(self.calls, [])
        status, body = self.post(self.TOKEN, length=1000)
        self.assertEqual((status, json.loads(body)["pass"]), (200, "done"))
        self.assertEqual(self.calls, [1])

    def test_no_tick_token_means_no_tick_endpoint(self):
        with mock.patch.object(d, "TICK_TOKEN", ""):
            self.assertEqual(self.post("")[0], 404)
            self.assertEqual(self.post(self.TOKEN)[0], 404)
        self.assertEqual(self.calls, [])

    def test_the_stats_job_ticks_this_server(self):
        status, answer = stats.send_tick(f"http://127.0.0.1:{self.port}", self.TOKEN)
        self.assertEqual((status, answer["pass"]), (200, "done"))
        with self.assertRaises(urllib.error.HTTPError):
            stats.send_tick(f"http://127.0.0.1:{self.port}/tick", "wrong")


class CallbackStartsAPassTest(DispatcherBase):
    launched, outcome = CallbackTest.launched, CallbackTest.outcome

    def test_an_accepted_callback_starts_a_pass_so_the_result_is_posted_now(self):
        ran = threading.Event()
        token = self.launched()
        server = d.serve(port=0)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with mock.patch.object(d, "PASSES", d.Passes(run=ran.set)):
            req = urllib.request.Request(f"http://127.0.0.1:{server.server_address[1]}/callback", method="POST",
                                         data=json.dumps(self.outcome()).encode(),
                                         headers={"Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                self.assertEqual(resp.status, 200)
                # The answer came only after the pass: the open request kept the VM awake.
                self.assertTrue(ran.is_set())
            # A refused callback starts nothing.
            ran.clear()
            req.headers["Authorization"] = "Bearer nope"
            with self.assertRaises(urllib.error.HTTPError):
                urllib.request.urlopen(req, timeout=10)
            self.assertFalse(ran.wait(0.3))


class StatsTickTest(unittest.TestCase):
    def setUp(self):
        self.sent = []
        env = mock.patch.dict(os.environ, {"PR_AUTOPILOT_TICK_URL": "https://d.example", "PR_AUTOPILOT_TICK_TOKEN": "tok"})
        env.start()
        self.addCleanup(env.stop)
        for p in (mock.patch.object(stats, "TICK_CONFIG", pathlib.Path(tempfile.mkdtemp())),
                  mock.patch.object(stats, "print", lambda *a, **k: self.printed.append(a), create=True)):
            p.start()
            self.addCleanup(p.stop)
        self.printed = []

    def ok(self, url, token):
        self.sent.append((url, token))
        return 200, {"pass": "done"}

    def fail(self, url, token):
        self.sent.append((url, token))
        raise urllib.error.URLError("timed out")

    def test_no_url_no_tick(self):
        with mock.patch.dict(os.environ, {"PR_AUTOPILOT_TICK_URL": ""}):
            cursor = {"tick": {"failing_since": 1}}
            self.assertEqual(stats.tick_round(cursor, 1000, send=self.ok), [])
        self.assertEqual((self.sent, cursor), ([], {}))

    def test_settings_come_from_files_when_the_env_has_none(self):
        (stats.TICK_CONFIG / "tick-url").write_text("https://from.file\n")
        (stats.TICK_CONFIG / "tick-token").write_text("filetok\n")
        with mock.patch.dict(os.environ, {"PR_AUTOPILOT_TICK_URL": "", "PR_AUTOPILOT_TICK_TOKEN": ""}):
            self.assertEqual(stats.tick_settings(), ("https://from.file", "filetok"))

    def test_failures_alert_after_10_minutes_once_and_clear_on_success(self):
        cursor, alerts = {}, []
        for minute in range(12):
            alerts += stats.tick_round(cursor, 10_000 + 60 * minute, send=self.fail)
        self.assertEqual([t for t, _ in alerts], ["PR autopilot: the dispatcher is not woken"])
        self.assertIn("10 minutes", alerts[0][1])
        self.assertEqual(stats.tick_round(cursor, 10_000 + 60 * 12, send=self.ok), [])
        self.assertNotIn("failing_since", cursor["tick"])

    def test_a_failure_streak_from_before_the_mac_slept_does_not_count(self):
        cursor = {}
        stats.tick_round(cursor, 10_000, send=self.fail)
        # 8 hours asleep, then one failure as the network comes back: no alert yet.
        self.assertEqual(stats.tick_round(cursor, 10_000 + 8 * 3600, send=self.fail), [])
        self.assertEqual(cursor["tick"]["failing_since"], 10_000 + 8 * 3600)

    def test_a_missing_token_counts_as_a_failure_and_sends_nothing(self):
        with mock.patch.dict(os.environ, {"PR_AUTOPILOT_TICK_TOKEN": ""}):
            cursor = {}
            stats.tick_round(cursor, 1000, send=self.ok)
        self.assertEqual(self.sent, [])
        self.assertEqual(cursor["tick"]["failing_since"], 1000)

    def test_the_round_never_raises(self):
        def boom(url, token):
            raise RuntimeError("anything")
        self.assertEqual(stats.tick_round({}, 1000, send=boom), [])

    def test_the_token_only_goes_over_https(self):
        self.assertEqual(stats.tick_url("https://d.example"), "https://d.example/tick")
        self.assertEqual(stats.tick_url("https://d.example/tick/"), "https://d.example/tick")
        self.assertEqual(stats.tick_url("http://127.0.0.1:8080"), "http://127.0.0.1:8080/tick")
        with self.assertRaises(ValueError):
            stats.tick_url("http://d.example")


class UnikernelManifestTest(unittest.TestCase):
    """remote/dispatcher-workload-unikernel.yaml and its URL, remote/dispatcher-url-unikernel.yaml."""

    @classmethod
    def setUpClass(cls):
        cls.doc = load_yaml(REMOTE / "dispatcher-workload-unikernel.yaml")[0]
        cls.kata = load_yaml(REMOTE / "dispatcher-workload.yaml")[0]
        cls.url = {doc["kind"]: doc for doc in load_yaml(REMOTE / "dispatcher-url-unikernel.yaml")}

    def container(self):
        return self.doc["spec"]["template"]["spec"]["runtime"]["sandbox"]["containers"][0]

    def env(self):
        return {e["name"]: e for e in self.container()["env"]}

    def test_unikernel_with_a_declared_http_port(self):
        self.assertEqual(self.doc["spec"]["template"]["spec"]["runtime"]["class"], "unikernel")
        port = self.container()["ports"][0]
        self.assertEqual((port["name"], port["port"]), ("http", int(self.env()["PR_AUTOPILOT_LISTEN_PORT"]["value"])))

    def test_a_name_of_its_own_that_fits_and_a_callback_url_that_matches(self):
        name = self.doc["metadata"]["name"]
        self.assertLessEqual(len(name), 39)
        self.assertNotEqual(name, self.kata["metadata"]["name"])
        self.assertNotEqual(self.env()["PR_AUTOPILOT_OWNER"]["value"],
                            {e["name"]: e for e in self.kata["spec"]["template"]["spec"]["runtime"]["sandbox"]
                             ["containers"][0]["env"]}["PR_AUTOPILOT_OWNER"]["value"])
        placement = self.doc["spec"]["placements"][0]
        instance = f"{name}-{placement['name']}-us-central-1-0"
        self.assertEqual(placement["cityCodes"], [remote_review.CITY])
        self.assertLessEqual(len(instance), 63)
        self.assertEqual(self.env()["PR_AUTOPILOT_CALLBACK_URL"]["value"],
                         f"http://{instance}.instances.datum.internal:8080/callback")

    def test_tokens_only_through_secret_refs(self):
        env = self.env()
        for var, key in (("PR_AUTOPILOT_GITHUB_TOKEN", "GITHUB_TOKEN"), ("PR_AUTOPILOT_MILO_CREDENTIALS", "MILO_CREDENTIALS"),
                         ("PR_AUTOPILOT_TICK_TOKEN", "TICK_TOKEN")):
            self.assertEqual(env[var]["valueFrom"]["secretKeyRef"], {"name": "pr-autopilot-dispatcher", "key": key})
            self.assertNotIn("value", env[var])
        self.assertLess(float(env["PR_AUTOPILOT_TICK_WAIT"]["value"]), stats.TICK_TIMEOUT)

    def test_the_image_is_the_unikernel_copy_pinned_by_digest_or_marked_to_fill_in(self):
        image = self.container()["image"]
        self.assertTrue(image.startswith("ghcr.io/example-user/pr-autopilot-dispatcher@sha256:"))
        digest = image.rsplit(":", 1)[1]
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", digest) or digest == "REPLACE_WITH_THE_UNIKERNEL_DIGEST_CI_PRINTED")
        self.assertNotEqual(image, self.kata["spec"]["template"]["spec"]["runtime"]["sandbox"]["containers"][0]["image"])

    def test_the_url_objects_are_what_datumctl_publishes(self):
        # example-org/compute internal/cmd/compute/url/resources.go: objectMeta,
        # BuildNetworkService, BuildHTTPProxy (no hostnames, no matches, no TLS).
        name = self.doc["metadata"]["name"]
        for kind, doc in self.url.items():
            meta = doc["metadata"]
            self.assertEqual((meta["name"], meta["namespace"]), (name, "default"), kind)
            self.assertEqual(meta["labels"], {"compute.datumapis.com/workload-name": name,
                                              "compute.datumapis.com/workload-uid": "REPLACE_WITH_THE_WORKLOAD_UID"}, kind)
            self.assertEqual(meta["ownerReferences"], [{
                "apiVersion": "compute.datumapis.com/v1alpha", "kind": "Workload", "name": name,
                "uid": "REPLACE_WITH_THE_WORKLOAD_UID", "controller": False, "blockOwnerDeletion": False}], kind)
        self.assertEqual(self.url["NetworkService"]["spec"], {
            "networkInterfaces": {"selector": {"matchLabels": {"compute.datumapis.com/workload-name": name}}},
            "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}]})
        self.assertEqual(self.url["HTTPProxy"]["spec"], {
            "rules": [{"backends": [{"networkService": {"name": name, "port": "http"}}]}]})

    def test_the_url_serves_this_workload_on_its_http_port(self):
        name = self.doc["metadata"]["name"]
        svc, proxy = self.url["NetworkService"], self.url["HTTPProxy"]
        self.assertEqual(svc["spec"]["networkInterfaces"]["selector"]["matchLabels"],
                         {"compute.datumapis.com/workload-name": name})
        self.assertEqual(svc["spec"]["ports"][0]["port"], self.container()["ports"][0]["port"])
        backend = proxy["spec"]["rules"][0]["backends"][0]["networkService"]
        self.assertEqual(backend, {"name": svc["metadata"]["name"], "port": svc["spec"]["ports"][0]["name"]})


class DispatcherConfigTest(unittest.TestCase):
    SCRIPT = REMOTE / "make-dispatcher-config.py"

    def run_script(self, tick: str):
        tmp = pathlib.Path(tempfile.mkdtemp())
        (tmp / "pat").write_text("ghp_" + "x" * 36)
        (tmp / "key.json").write_text(json.dumps({"type": "datum_service_account", "private_key": "k"}))
        (tmp / "tick").write_text(tick + "\n")
        out = subprocess.run([sys.executable, str(self.SCRIPT), "--out", str(tmp / "out"), "--pat-file", str(tmp / "pat"),
                              "--key-file", str(tmp / "key.json"), "--tick-token-file", str(tmp / "tick")],
                             capture_output=True, text=True, timeout=60)
        return out, tmp / "out" / "secret.json"

    def test_the_tick_token_goes_into_the_secret(self):
        import base64
        out, secret = self.run_script("a" * 43)
        self.assertEqual(out.returncode, 0, out.stderr)
        data = json.loads(secret.read_text())["data"]
        self.assertEqual(base64.b64decode(data["TICK_TOKEN"]).decode(), "a" * 43)
        self.assertNotIn("a" * 43, out.stdout + out.stderr)

    def test_a_short_tick_token_is_refused(self):
        out, secret = self.run_script("short")
        self.assertNotEqual(out.returncode, 0)
        self.assertFalse(secret.exists())


class HandlerCapTest(unittest.TestCase):
    def test_past_the_cap_new_requests_get_503(self):
        with mock.patch.object(d, "MAX_HANDLERS", 1):
            server = d.serve(port=0)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        stalled = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.addCleanup(stalled.close)
        stalled.sendall(b"GET /healthz HTTP/1.1\r\n")  # holds the only slot
        time.sleep(0.2)
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", "/healthz")
        self.assertEqual(conn.getresponse().status, 503)
        conn.close()
        stalled.sendall(b"Host: x\r\n\r\n")
        self.assertIn(b"200", stalled.recv(100))
        time.sleep(0.2)
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=10) as resp:
            self.assertEqual(resp.status, 200)


class StaleLockTest(DispatcherBase):
    """A pass frozen for longer than the lock lease must not post once it wakes."""

    launched, outcome = CallbackTest.launched, CallbackTest.outcome

    def take_lock(self, who, age=0):
        self.store.data["owner"] = {"id": who, "heartbeat": round(time.time() - age)}
        self.store.version += 1

    def test_no_post_when_another_runner_holds_the_lock_now(self):
        token = self.launched()
        d.accept_result(token, json.dumps(self.outcome()).encode())
        state = r.load_state()
        self.take_lock("dispatcher@datum#kata")  # while this pass was parked
        created = []
        with mock.patch.object(r, "_ME", []), \
             tr.fake_github(self, login="example-user", create_review=lambda *a: created.append(a),
                            reviews=tr.reviews_of(), pull=lambda repo, num: dict(self.pr_now)), \
             mock.patch.object(r, "post_review", REAL_POST):
            with self.assertRaises(r.LockLost):
                d.process_results(state)
        self.assertEqual(created, [])
        self.assertEqual(self.jobs()[KEY]["status"], "result")  # left for the holder

    def test_a_lapsed_heartbeat_of_our_own_is_renewed_before_the_post(self):
        token = self.launched()
        d.accept_result(token, json.dumps(self.outcome()).encode())
        self.take_lock(r.owner_id(), age=r.LOCK_SECONDS + 60)
        r.confirm_lock()
        self.assertGreater(self.store.data["owner"]["heartbeat"], time.time() - 5)

    def test_a_clock_jump_rereads_the_lock(self):
        state = r.load_state()
        state["owner"] = {"id": r.owner_id(), "heartbeat": round(time.time())}
        r.renew_lock(state)  # first reading of the clocks
        self.take_lock("laptop@mac")
        r.renew_lock(state)  # no jump: the in-memory copy is trusted
        r.CLOCK["wall"] -= r.LOCK_SECONDS + 60  # as if parked for 6 minutes
        with self.assertRaisesRegex(r.LockLost, "laptop@mac"):
            r.renew_lock(state)


class TickDeadlineTest(unittest.TestCase):
    def setUp(self):
        env = mock.patch.dict(os.environ, {"PR_AUTOPILOT_TICK_URL": "https://d.example", "PR_AUTOPILOT_TICK_TOKEN": "tok"})
        env.start()
        self.addCleanup(env.stop)
        self.printed = []
        for p in (mock.patch.object(stats, "TICK_CONFIG", pathlib.Path(tempfile.mkdtemp())),
                  mock.patch.object(stats, "TICK_THREAD", {"thread": None}),
                  mock.patch.object(stats, "print", lambda *a, **k: self.printed.append(a), create=True)):
            p.start()
            self.addCleanup(p.stop)

    def test_a_hung_tick_never_holds_the_stats_round(self):
        release = threading.Event()
        self.addCleanup(release.set)
        hang = lambda url, token: release.wait(10)
        started = time.time()
        cursor = {}
        self.assertEqual(stats.tick_round(cursor, 1000, send=hang, deadline=0.2), [])
        self.assertLess(time.time() - started, 2)
        self.assertIn("no answer in 0.2s", self.printed[-1][0])
        # Still stuck a round later: a failure at once, no second thread.
        stats.tick_round(cursor, 1060, send=hang, deadline=0.2)
        self.assertIn("still waiting", self.printed[-1][0])

    def test_unreadable_settings_are_a_failure_not_a_crash(self):
        (stats.TICK_CONFIG / "tick-url").write_bytes(b"\xff\xfe")
        with mock.patch.dict(os.environ, {"PR_AUTOPILOT_TICK_URL": ""}):
            cursor = {}
            self.assertEqual(stats.tick_round(cursor, 1000, send=lambda u, t: (200, {})), [])
        self.assertEqual(cursor["tick"]["failing_since"], 1000)

    def test_a_redirect_is_not_followed(self):
        hits = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                hits.append((self.path, self.headers.get("Authorization")))
                self.send_response(307)
                self.send_header("Location", "/elsewhere")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass
        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            stats.send_tick(f"http://127.0.0.1:{server.server_address[1]}", "tok")
        self.assertEqual(caught.exception.code, 307)
        self.assertEqual([path for path, _ in hits], ["/tick"])


class TickWallClockTest(unittest.TestCase):
    """The tick's wait counts on the wall clock from the request's arrival, not on the VM's
    monotonic clock, which fell behind during a request on Datum (504 from the ALB)."""

    def setUp(self):
        self.release = threading.Event()
        self.addCleanup(self.release.set)
        self.passes = d.Passes(run=lambda: self.release.wait(10))
        for name, value in (("PASSES", self.passes), ("TICK_WAIT", 5.0)):
            p = mock.patch.object(d, name, value)
            p.start()
            self.addCleanup(p.stop)

    def test_the_wait_ends_by_the_wall_clock_from_its_start(self):
        number = self.passes.start("tick")
        started = time.monotonic()
        # The request arrived 5 s ago by the wall clock; the VM's clock says much less.
        self.assertFalse(self.passes.wait(number, 5, since=time.time() - 5))
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertTrue(self.passes.running)

    def test_a_late_tick_answers_202_at_once_and_says_how_late(self):
        with mock.patch.object(d, "print", lambda *a, **k: None, create=True):
            started = time.monotonic()
            status, body = d.tick(received=time.time() - 6, received_awake=time.monotonic())
        self.assertEqual(status, 202)
        self.assertLess(time.monotonic() - started, 0.5)
        answer = json.loads(body)
        self.assertEqual(answer["pass"], "running")
        self.assertGreaterEqual(answer["answered_after"]["seconds"], 6)
        self.assertLess(answer["answered_after"]["awake"], 1)

    def test_a_pass_that_ends_in_time_still_answers_200(self):
        threading.Timer(0.3, self.release.set).start()
        status, body = d.tick()
        self.assertEqual((status, json.loads(body)["pass"]), (200, "done"))
        self.assertLess(json.loads(body)["answered_after"]["seconds"], 5)

    def test_the_default_wait_leaves_room_under_the_albs_15_seconds(self):
        self.assertLessEqual(float(os.environ.get("PR_AUTOPILOT_TICK_WAIT", "5")), 5)
        doc = load_yaml(REMOTE / "dispatcher-workload-unikernel.yaml")[0]
        env = {e["name"]: e for e in doc["spec"]["template"]["spec"]["runtime"]["sandbox"]["containers"][0]["env"]}
        self.assertLessEqual(float(env["PR_AUTOPILOT_TICK_WAIT"]["value"]), 5)


class RerequestPostTest(DispatcherBase):
    """posted_already guards a replay after a crash, not an older review of the same
    commit: a re-request on a commit you only commented on must get its new comment.
    The job keeps the highest id of your reviews on the commit at launch (review_floor);
    only a higher id is the job's own. No clocks are compared."""

    launched, outcome = CallbackTest.launched, CallbackTest.outcome

    @staticmethod
    def review(rid, state="COMMENTED", sha=SHA):
        return {"id": rid, "user": {"login": "example-user"}, "state": state, "commit_id": sha,
                "submitted_at": "2026-11-12T09:00:00Z"}

    def post_comment(self, reviews, floor=None, drop_floor=False):
        created = []
        if floor is not None:
            self.floor = floor
        with mock.patch.object(r, "_ME", []), \
             tr.fake_github(self, login="example-user", create_review=lambda *a: created.append(a),
                            reviews=reviews, pull=lambda repo, num: dict(self.pr_now)), \
             mock.patch.object(r, "post_review", REAL_POST):
            token = self.launched()
            d.accept_result(token, json.dumps(self.outcome(findings={"blocking": [], "minor": ["m"]})).encode())
            state = r.load_state()
            if drop_floor:  # a job launched before this change
                state["jobs"][KEY].pop("review_floor")
            with mock.patch.object(r, "report_full", lambda job, repo, num, sha, *a, **k:
                                   r.post_or_keep(job, repo, num, sha, ("COMMENT", "body"), "comment")):
                d.process_results(state)
        return created

    def test_launch_stores_the_floor(self):
        self.floor = 41
        self.launched()
        self.assertEqual(self.jobs()[KEY]["review_floor"], 41)

    def test_a_rerequest_on_a_commit_you_commented_on_posts_the_new_comment(self):
        # Your COMMENT (id 41) was there when the worker started: it is not this job's.
        created = self.post_comment([self.review(40, "APPROVED", "b" * 40), self.review(41)], floor=41)
        self.assertEqual([c[3] for c in created], ["COMMENT"])
        self.assertEqual(self.jobs()[KEY]["status"], "done")

    def test_a_replay_after_a_crash_does_not_post_again(self):
        # The job posted id 42, then the pass crashed before its save.
        created = self.post_comment([self.review(41), self.review(42)], floor=41)
        self.assertEqual(created, [])
        self.assertEqual(self.jobs()[KEY]["status"], "done")

    def test_a_job_without_a_floor_keeps_the_old_check(self):
        created = self.post_comment([self.review(41)], floor=41, drop_floor=True)
        self.assertEqual(created, [])  # any COMMENTED review of yours on the commit counts

    def test_the_floor_is_the_highest_id_of_your_reviews_on_the_commit(self):
        reviews = [self.review(7), self.review(9, "APPROVED"), self.review(30, sha="b" * 40),
                   {**self.review(50), "user": {"login": "someone"}}]
        with mock.patch.object(r, "_ME", []), tr.fake_github(self, login="example-user", reviews=reviews), \
             mock.patch.object(r, "review_floor", REAL_FLOOR):
            self.assertEqual(r.review_floor(REPO, "7", SHA), 9)
            self.assertEqual(r.review_floor(REPO, "7", "c" * 40), 0)
            self.assertTrue(r.posted_already(REPO, "7", SHA, "COMMENTED"))
            self.assertFalse(r.posted_already(REPO, "7", SHA, "COMMENTED", floor=9))

    def test_launch_waits_when_github_cannot_list_your_reviews(self):
        def down(repo, num, sha):
            raise github_api.GitHubError("GET", "reviews", 502, "bad gateway")
        state = self.queue(1)
        with mock.patch.object(r, "review_floor", down):
            d.launch(state)
        self.assertEqual(state["jobs"][KEY]["status"], "queued")
        self.assertEqual(self.workers, [])


class CallbackLockWaitTest(DispatcherBase):
    """A callback that first waits for a running pass to release STATE_LOCK still keeps
    its request open for the rerun that posts its result: its deadline starts after the
    lock, not on arrival."""

    launched, outcome = CallbackTest.launched, CallbackTest.outcome

    def test_the_callback_waits_for_its_pass_after_waiting_for_the_lock(self):
        token = self.launched()
        posted = threading.Event()

        def rerun():
            time.sleep(0.4)
            posted.set()
        server = d.serve(port=0)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        held = threading.Event()

        def running_pass():  # holds the state lock for 1 s, longer than TICK_WAIT
            with d.STATE_LOCK:
                held.set()
                time.sleep(1.0)
        with mock.patch.object(d, "PASSES", d.Passes(run=rerun)), mock.patch.object(d, "TICK_WAIT", 0.7):
            threading.Thread(target=running_pass).start()
            held.wait(5)
            req = urllib.request.Request(f"http://127.0.0.1:{server.server_address[1]}/callback", method="POST",
                                         data=json.dumps(self.outcome()).encode(),
                                         headers={"Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                self.assertEqual(resp.status, 200)
                self.assertTrue(posted.is_set())  # answered only after the pass that posts


class BackwardClockTest(unittest.TestCase):
    def test_a_wall_clock_stepped_back_cannot_stretch_the_wait(self):
        release = threading.Event()
        self.addCleanup(release.set)
        passes = d.Passes(run=lambda: release.wait(10))
        number = passes.start("tick")
        started = time.monotonic()
        # Arrived 5 s ago by the VM clock; the wall clock has since been set back an hour.
        self.assertFalse(passes.wait(number, 5, since=time.time() + 3600, since_awake=time.monotonic() - 5))
        self.assertLess(time.monotonic() - started, 0.5)

    def test_a_tick_uses_both_clocks(self):
        release = threading.Event()
        self.addCleanup(release.set)
        with mock.patch.object(d, "PASSES", d.Passes(run=lambda: release.wait(10))), \
             mock.patch.object(d, "TICK_WAIT", 5.0), mock.patch.object(d, "print", lambda *a, **k: None, create=True):
            started = time.monotonic()
            status, _ = d.tick(received=time.time() + 3600, received_awake=time.monotonic() - 5)
        self.assertEqual(status, 202)
        self.assertLess(time.monotonic() - started, 0.5)
