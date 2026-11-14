"""Tests for the PR auto-reviewer. No network, GitHub or Claude calls: those are faked.

Run: python3 -m unittest -v test_reviewer
"""
from __future__ import annotations

import http.server
import json
import threading
import zipfile
import os
import pathlib
import stat
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import claude_cli
import copy
import importlib.util
import io
import contextlib
import base64
import urllib.parse
import urllib.request
import dashboard
import full_review
import github_api
import milo_api
import pr_worker
import remote_review
import reviewer as r
import state_store

REPO = "example-org/infra"
PR = {"number": 7, "title": "t", "headRefOid": "a" * 40, "isDraft": False, "author": {"login": "alice"}}
CFG = {"authors": ["alice"], "review": "full", "full_review_paths": [r"(^|/)production/"]}


def diff_for(*paths: str) -> str:
    return "".join(f"diff --git a/{p} b/{p}\n--- a/{p}\n+++ b/{p}\n@@ -1 +1 @@\n-x\n+y\n" for p in paths)


def isolate_down_file(test: unittest.TestCase) -> pathlib.Path:
    path = pathlib.Path(tempfile.mkdtemp()) / "datum-down-until"
    p = mock.patch.object(remote_review, "DOWN_FILE", path)
    p.start()
    test.addCleanup(p.stop)
    return path


def make_test_rsa_key(bits: int = 1024) -> str:
    """A throwaway RSA key as PKCS#1 PEM, made here with Miller-Rabin primes, so no key
    file sits in the repo. Only for testing milo_api's signer."""
    import random as rnd
    import secrets as sec

    def probable_prime(n: int) -> bool:
        if n % 2 == 0:
            return False
        d, s2 = n - 1, 0
        while d % 2 == 0:
            d, s2 = d // 2, s2 + 1
        for _ in range(32):
            x = pow(rnd.randrange(2, n - 1), d, n)
            if x in (1, n - 1):
                continue
            for _ in range(s2 - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def prime() -> int:
        while True:
            c = sec.randbits(bits // 2) | (3 << (bits // 2 - 2)) | 1
            if all(c % q for q in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31)) and probable_prime(c):
                return c
    e = 65537
    while True:
        p_, q_ = prime(), prime()
        phi = (p_ - 1) * (q_ - 1)
        if p_ != q_ and phi % e:
            break
    n, d = p_ * q_, pow(e, -1, phi)

    def der(tag: int, body: bytes) -> bytes:
        size = len(body)
        head = bytes([size]) if size < 128 else bytes([0x80 | ((size.bit_length() + 7) // 8)]) + \
            size.to_bytes((size.bit_length() + 7) // 8, "big")
        return bytes([tag]) + head + body

    def integer(v: int) -> bytes:
        return der(0x02, v.to_bytes(v.bit_length() // 8 + 1, "big"))
    fields = [0, n, e, d, p_, q_, d % (p_ - 1), d % (q_ - 1), pow(q_, -1, p_)]
    body = base64.b64encode(der(0x30, b"".join(integer(v) for v in fields))).decode()
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END RSA PRIVATE KEY-----\n"


TEST_RSA_KEY = make_test_rsa_key()


def fake_github(test: unittest.TestCase, **answers):
    """Patch github_api's calls for one `with` block. Each answer is a value or a
    function of the call's arguments; a call with no answer fails the test."""
    calls = []
    names = ("login", "search_issues", "head_sha", "pull", "timeline", "reviews", "create_review", "diff",
             "changed_files", "is_private", "notifications")

    def make(name):
        def call(*a, **k):
            calls.append((name, *a))
            if name not in answers:
                test.fail(f"unexpected GitHub call {name}{a}")
            answer = answers[name]
            return answer(*a, **k) if callable(answer) else answer
        return call
    stack = contextlib.ExitStack()
    for name in names:
        stack.enter_context(mock.patch.object(github_api, name, make(name)))
    stack.calls = calls
    return stack


def timeline_of(*requests: str, me: str = "example-user") -> list:
    """Timeline events: each request is "actor iso-time"."""
    out = []
    for line in requests:
        actor, at = line.split()
        out.append({"event": "review_requested", "requested_reviewer": {"login": me},
                    "actor": {"login": actor}, "created_at": at})
    return out


def reviews_of(*lines: str, me: str = "example-user") -> list:
    """Reviews: each line is "iso-time STATE sha"."""
    out = []
    for line in lines:
        at, state, sha = line.split()
        out.append({"user": {"login": me}, "submitted_at": at, "state": state, "commit_id": sha})
    return out


class Base(unittest.TestCase):
    def setUp(self):
        isolate_down_file(self)
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.notified, self.posted, self.started = [], [], []
        patches = {
            "STATE_FILE": self.tmp / "state.json",
            "JOBS_DIR": self.tmp / "jobs",
            "LOG_FILE": self.tmp / "log",
            "DRY_RUN": False,
            "notify": lambda t, m, url=None: self.notified.append(t),
            "post_review": lambda repo, num, sha, event, body, floor=None: self.posted.append((num, event, body)),
            "start_full_review": lambda repo, num, sha, reason, audit=False: self.started.append(
                (reason, "audit") if audit else reason),
            "running_jobs": lambda: 0,
            "ensure_dashboard_server": lambda: None,
            "log": lambda msg: None,
            "event": lambda *a: None,
        }
        for name, value in patches.items():
            p = mock.patch.object(r, name, value)
            p.start()
            self.addCleanup(p.stop)
        # No random audit unless a test asks for one (otherwise 1 run in 10 sends a
        # quick approval to a full review and the test fails by chance).
        p = mock.patch.object(r.random, "random", lambda: 0.99)
        p.start()
        self.addCleanup(p.stop)

    def state(self):
        return {"reviewed": {}, "retry": [], "failures": {}}


class ClaudeCliTest(unittest.TestCase):
    def fake_claude(self, script: str):
        d = pathlib.Path(tempfile.mkdtemp())
        f = d / "claude"
        f.write_text("#!/bin/sh\n" + script)
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
        p = mock.patch.dict(os.environ, {"PATH": f"{d}:{os.environ['PATH']}"})
        p.start()
        self.addCleanup(p.stop)

    def test_success_mentioning_login_is_not_an_auth_error(self):
        self.fake_claude("""echo '{"is_error": false, "result": "Adds a /login route; run claude auth login after"}'""")
        resp = claude_cli.run([], "hi", pathlib.Path.home(), 30)
        self.assertIn("/login", resp["result"])

    def test_expired_login(self):
        self.fake_claude("""echo '{"is_error": true, "result": "Failed to authenticate: OAuth session expired"}'; exit 1""")
        with self.assertRaises(claude_cli.AuthExpired):
            claude_cli.run([], "hi", pathlib.Path.home(), 30)

    def test_other_failure_carries_the_reason(self):
        self.fake_claude("echo 'boom: disk full' >&2; exit 3")
        with self.assertRaisesRegex(RuntimeError, "claude exited 3: boom: disk full"):
            claude_cli.run([], "hi", pathlib.Path.home(), 30)


class ReviewTest(Base):
    def run_review(self, diff: str, quick=None, pr=PR, cfg=CFG):
        with fake_github(self, diff=diff, head_sha=pr["headRefOid"]), \
             mock.patch.object(r, "quick_review", lambda *a: quick or self.fail("quick review not expected")):
            state = self.state()
            done = r.review(REPO, cfg, pr, state)
        return done, state

    def test_production_path_goes_to_full_review(self):
        done, state = self.run_review(diff_for("apps/x/production/kustomization.yaml"))
        self.assertFalse(done)
        self.assertEqual(self.started, ["touches apps/x/production/kustomization.yaml"])
        self.assertEqual(self.posted, [])

    def test_markdown_does_not_trigger_full_review(self):
        quick = {"verdict": "approve", "needs_full_review": False, "summary": "ok", "critical": [],
                 "full_review_reason": ""}
        done, state = self.run_review(diff_for("apps/x/production/README.md"), quick=quick)
        self.assertTrue(done)
        self.assertEqual(self.posted, [("7", "APPROVE", "")])
        self.assertEqual(state["reviewed"][f"{REPO}#7"], PR["headRefOid"])

    def test_quick_review_can_escalate(self):
        quick = {"verdict": "approve", "needs_full_review": True, "summary": "s", "critical": [],
                 "full_review_reason": "shared base"}
        done, _ = self.run_review(diff_for("apps/x/base/a.yaml"), quick=quick)
        self.assertFalse(done)
        self.assertEqual(self.started, ["shared base"])

    APPROVE = {"verdict": "approve", "needs_full_review": False, "summary": "looks fine", "critical": [],
               "full_review_reason": ""}

    def test_a_sampled_quick_approval_goes_to_a_neutral_full_review(self):
        with mock.patch.object(r.random, "random", lambda: 0.01):
            done, state = self.run_review(diff_for("apps/x/base/a.yaml"), quick=self.APPROVE)
        self.assertFalse(done)
        self.assertEqual(self.posted, [])
        self.assertEqual(self.started, [(r.AUDIT_FOCUS, "audit")])
        self.assertNotIn("looks fine", r.AUDIT_FOCUS)
        self.assertNotIn(f"{REPO}#7", state["reviewed"])

    def test_no_audit_roll_when_slots_are_full(self):
        with mock.patch.object(r.random, "random", lambda: 0.0), \
             mock.patch.object(r, "running_jobs", lambda: r.MAX_JOBS):
            done, _ = self.run_review(diff_for("apps/x/base/a.yaml"), quick=self.APPROVE)
        self.assertTrue(done)
        self.assertEqual(self.posted, [("7", "APPROVE", "")])

    def test_unsampled_quick_approval_is_approved(self):
        with mock.patch.object(r.random, "random", lambda: 0.99):
            done, _ = self.run_review(diff_for("apps/x/base/a.yaml"), quick=self.APPROVE)
        self.assertTrue(done)
        self.assertEqual(self.started, [])

    def unposted(self, attempts=1):
        r.Job(REPO, "7", PR["headRefOid"]).write(status="unposted", post_event="COMMENT", post_body="body",
                                                 post_attempts=attempts)

    def test_an_unposted_review_is_posted_without_a_new_review(self):
        self.unposted()
        done, state = self.run_review(diff_for("apps/x/base/a.yaml"))
        self.assertFalse(done)
        self.assertEqual(self.posted, [("7", "COMMENT", "body")])
        self.assertEqual(self.started, [])
        self.assertEqual(state["reviewed"][f"{REPO}#7"], PR["headRefOid"])
        self.assertIsNone(r.Job(REPO, "7", PR["headRefOid"]).read())

    def test_an_unposted_review_gives_up_after_the_last_attempt(self):
        def failing(*a, **k):
            raise r.GhError("POST", "repos/x/pulls/7/reviews", 0, "TLS handshake timeout")
        self.unposted()
        with mock.patch.object(r, "post_review", failing):
            done, state = self.run_review(diff_for("apps/x/base/a.yaml"))
            self.assertFalse(done)
            self.assertEqual(r.Job(REPO, "7", PR["headRefOid"]).read()["post_attempts"], 2)
            done, state = self.run_review(diff_for("apps/x/base/a.yaml"))
        self.assertTrue(done)
        self.assertEqual(self.notified, ["PR autopilot could not post a review"])
        self.assertEqual(state["reviewed"][f"{REPO}#7"], PR["headRefOid"])
        self.assertIsNone(r.Job(REPO, "7", PR["headRefOid"]).read())

    def test_codeowners_changes_are_left_to_you(self):
        for path in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
            self.notified.clear()
            done, state = self.run_review(diff_for("app/main.go", path))
            self.assertTrue(done)
            self.assertEqual(self.notified, ["PR needs your review"])
        self.assertEqual((self.posted, self.started), ([], []))

    def test_workflow_changes_always_get_a_full_review(self):
        for path in (".github/workflows/ci.yaml", ".github/actions/x/action.yml", "tool/action.yaml"):
            self.started.clear()
            done, _ = self.run_review(diff_for(path))
            self.assertFalse(done)
            self.assertEqual(self.started, [f"changes GitHub Actions workflows: {path}"])

    def test_other_github_files_take_the_normal_path(self):
        quick = {"verdict": "approve", "needs_full_review": False, "summary": "ok", "critical": [],
                 "full_review_reason": ""}
        done, _ = self.run_review(diff_for(".github/dependabot.yml"), quick=quick)
        self.assertTrue(done)
        self.assertEqual(self.posted, [("7", "APPROVE", "")])

    def test_other_authors_are_left_alone(self):
        pr = {**PR, "author": {"login": "someone"}}
        done, state = self.run_review(diff_for("x"), pr=pr)
        self.assertTrue(done)
        self.assertEqual((self.posted, self.started), ([], []))

    def test_unconditional_mode(self):
        done, _ = self.run_review("", cfg={"authors": ["*"], "review": "none"})
        self.assertTrue(done)
        self.assertEqual(self.posted, [("7", "APPROVE", "Auto-approved.")])

    def test_finished_job_marks_reviewed_and_failed_job_raises(self):
        job = r.Job(REPO, "7", PR["headRefOid"])
        job.write(status="done", verdict="approve")
        os.utime(job.path, (1000, 1000))  # finished long before this run read it
        state = self.state()
        self.assertFalse(r.review(REPO, CFG, PR, state))  # checked again next run, for re-requests
        self.assertIn(f"{REPO}#7", state["reviewed"])
        self.assertEqual(state["handled_at"][f"{REPO}#7"], 1000)
        job.write(status="failed", error="x")
        with self.assertRaisesRegex(RuntimeError, "full review failed: x"):
            r.review(REPO, CFG, PR, self.state())

    def test_fetch_diff_paths_include_renames(self):
        diff = "diff --git a/old/a.yaml b/new/a.yaml\nsimilarity index 100%\n" + diff_for("c.yaml")
        with fake_github(self, diff=diff):
            _, paths = r.fetch_diff(REPO, "7")
        self.assertEqual(paths, ["old/a.yaml", "new/a.yaml", "c.yaml"])


class DashboardServerTest(unittest.TestCase):
    def spawned(self, port: int, answers: bool) -> list:
        started = []

        def connect(addr, timeout):
            if not answers:
                raise ConnectionRefusedError
            return mock.Mock()
        with mock.patch.object(r, "DASHBOARD_PORT", port), \
             mock.patch.object(r, "LOG_FILE", pathlib.Path(tempfile.mkdtemp()) / "log"), \
             mock.patch.object(r.socket, "create_connection", connect), \
             mock.patch.object(r.subprocess, "Popen", lambda args, **kw: started.append(args[-1])):
            r.ensure_dashboard_server()
        return started

    def test_starts_the_server_only_when_nothing_answers(self):
        self.assertEqual(len(self.spawned(8787, answers=False)), 1)
        self.assertTrue(self.spawned(8787, answers=False)[0].endswith("serve_dashboard.py"))
        self.assertEqual(self.spawned(8787, answers=True), [])
        self.assertEqual(self.spawned(0, answers=False), [])


class GitHubApiTest(unittest.TestCase):
    """github_api's HTTP layer, against a fake urlopen."""

    def setUp(self):
        p = mock.patch.object(github_api, "_TOKEN", "t0ken")
        p.start()
        self.addCleanup(p.stop)
        self.requests = []

    def answer(self, *responses):
        """Each response: (status, headers, body) or an exception to raise."""
        queue = list(responses)

        def urlopen(req, timeout):
            self.requests.append(req)
            resp = queue.pop(0)
            if isinstance(resp, Exception):
                raise resp
            status, headers, body = resp
            if status >= 300:
                raise github_api.urllib.error.HTTPError(req.full_url, status, "x", headers,
                                                        io.BytesIO(body.encode()))
            m = mock.MagicMock()
            m.__enter__.return_value = m
            m.status, m.headers, m.read.return_value = status, headers, body.encode()
            return m
        return mock.patch.object(github_api, "_open", urlopen)

    def test_message_includes_githubs_reason(self):
        body = json.dumps({"message": "Unprocessable Entity", "errors": ["Repository was archived so is read-only."]})
        with self.answer((422, {}, body)), self.assertRaises(r.GhError) as e:
            github_api.create_review(REPO, 7, "a" * 40, "APPROVE", "")
        self.assertIn("Repository was archived so is read-only.", str(e.exception))
        self.assertEqual(e.exception.status, 422)
        self.assertEqual(json.loads(self.requests[0].data),
                         {"commit_id": "a" * 40, "body": "", "event": "APPROVE"})

    def test_a_401_is_unauthorized(self):
        with self.answer((401, {}, '{"message": "Bad credentials"}')), self.assertRaises(github_api.Unauthorized):
            github_api.login()

    def test_no_answer_is_status_0(self):
        with self.answer(OSError("timed out")), self.assertRaises(r.GhError) as e:
            github_api.login()
        self.assertEqual(e.exception.status, 0)
        self.assertIn("no answer", str(e.exception))

    def test_paginate_follows_the_next_link(self):
        nxt = {"Link": '<https://api.github.com/repositories/1/pulls/7/reviews?page=2>; rel="next"'}
        with self.answer((200, nxt, "[1, 2]"), (200, {}, "[3]")):
            self.assertEqual(github_api.reviews(REPO, 7), [1, 2, 3])
        self.assertIn("per_page=100", self.requests[0].full_url)
        self.assertTrue(self.requests[1].full_url.endswith("page=2"))

    def test_rate_limits_say_how_long_to_wait(self):
        with self.answer((429, {"Retry-After": "120"}, "{}")), self.assertRaises(github_api.RateLimited) as e:
            github_api.login()
        self.assertEqual(e.exception.retry_after, 120)
        reset = str(int(time.time()) + 300)
        with self.answer((403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": reset}, "{}")), \
             self.assertRaises(github_api.RateLimited) as e:
            github_api.login()
        self.assertGreater(e.exception.retry_after, 250)
        with self.answer((403, {}, '{"message": "Resource not accessible"}')), self.assertRaises(r.GhError) as e:
            github_api.login()
        self.assertNotIsInstance(e.exception, github_api.RateLimited)  # a plain permission error

    def test_redirects_to_another_host_drop_the_token(self):
        handler = github_api.SameHostRedirects()
        req = urllib.request.Request("https://api.github.com/repos/a/b/pulls/1",
                                     headers={"Authorization": "Bearer t"})
        same = handler.redirect_request(req, None, 302, "Found", {}, "https://api.github.com/repositories/1/pulls/1")
        other = handler.redirect_request(req, None, 302, "Found", {}, "https://codeload.github.com/x")
        self.assertEqual(same.get_header("Authorization"), "Bearer t")
        self.assertIsNone(other.get_header("Authorization"))

    def test_the_token_is_unredirected_and_follows_only_to_the_same_host(self):
        with self.answer((200, {}, "{}")):
            github_api.get("repos/o/r")
        req = self.requests[0]
        self.assertEqual(req.unredirected_hdrs.get("Authorization"), "Bearer t0ken")
        self.assertNotIn("Authorization", req.headers)  # urllib copies these to any redirect
        handler = github_api.SameHostRedirects()
        same = handler.redirect_request(req, None, 301, "Moved", {}, "https://api.github.com/repositories/1")
        blob = handler.redirect_request(req, None, 302, "Found", {}, "https://blob.core.windows.net/a.zip?sig=x")
        self.assertEqual(same.get_header("Authorization"), "Bearer t0ken")
        self.assertIsNone(blob.get_header("Authorization"))

    def test_an_artifact_download_follows_the_redirect_without_the_token(self):
        """End to end through urllib: the API answers 302 to another host."""
        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.headers.get("Host"), self.path, self.headers.get("Authorization")))
                if self.path.startswith("/repos/"):
                    self.send_response(302)
                    self.send_header("Location", f"http://localhost:{self.server.server_address[1]}/blob?sig=x")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", "3")
                self.end_headers()
                self.wfile.write(b"zip")

            def log_message(self, *a):
                pass
        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        with mock.patch.dict(os.environ, {github_api.API_ENV: f"http://127.0.0.1:{port}/", github_api.TOKEN_ENV: "t0ken"}):
            self.assertEqual(github_api.download("repos/o/r/actions/artifacts/1/zip"), b"zip")
        self.assertEqual(seen, [(f"127.0.0.1:{port}", "/repos/o/r/actions/artifacts/1/zip", "Bearer t0ken"),
                                (f"localhost:{port}", "/blob?sig=x", None)])

    def test_the_api_base_and_token_env_are_read_on_each_call(self):
        with mock.patch.dict(os.environ, {github_api.API_ENV: "http://proxy:8080/github",
                                          github_api.TOKEN_ENV: "pap-gh-placeholder"}), \
                self.answer((200, {}, "{}")):
            github_api.get("repos/o/r/pulls/1")
        self.assertEqual(self.requests[0].full_url, "http://proxy:8080/github/repos/o/r/pulls/1")
        self.assertEqual(self.requests[0].get_header("Authorization"), "Bearer pap-gh-placeholder")

    def test_paginate_asks_the_same_path_for_the_next_page(self):
        """GitHub's next link names the repo by id on api.github.com, which the proxy refuses."""
        nxt = {"Link": '<https://api.github.com/repositories/1/issues/7/comments?per_page=100&page=2>; rel="next"'}
        with mock.patch.dict(os.environ, {github_api.API_ENV: "http://proxy/github"}), \
                self.answer((200, nxt, "[1]"), (200, {}, "[2]")):
            self.assertEqual(github_api.issue_comments(REPO, 7), [1, 2])
        self.assertEqual(self.requests[1].full_url,
                         f"http://proxy/github/repos/{REPO}/issues/7/comments?per_page=100&page=2")

    def test_graphql_errors_raise(self):
        with self.answer((200, {}, json.dumps({"errors": [{"message": "Could not resolve"}]}))), \
                self.assertRaises(github_api.GitHubError) as e:
            github_api.graphql(github_api.CHECKS_QUERY, {})
        self.assertIn("Could not resolve", str(e.exception))
        self.assertEqual(json.loads(self.requests[0].data)["query"], github_api.CHECKS_QUERY)

    def test_a_too_large_diff_is_none(self):
        with self.answer((406, {}, '{"message": "Sorry, the diff exceeded the maximum number of lines"}')):
            self.assertIsNone(github_api.diff(REPO, 7))

    def test_changed_files_lists_both_names_of_a_rename(self):
        files = [{"filename": "new/a.yaml", "previous_filename": "old/a.yaml"}, {"filename": "c.yaml"}]
        with self.answer((200, {}, json.dumps(files))):
            self.assertEqual(github_api.changed_files(REPO, 7), ["old/a.yaml", "new/a.yaml", "c.yaml"])

    def test_notifications_send_if_modified_since_and_read_the_poll_interval(self):
        with self.answer((304, {"X-Poll-Interval": "60"}, "")):
            self.assertEqual(github_api.notifications("Tue, 10 Nov 2026 10:00:00 GMT"),
                             (None, "Tue, 10 Nov 2026 10:00:00 GMT", 60))
        self.assertEqual(self.requests[0].get_header("If-modified-since"), "Tue, 10 Nov 2026 10:00:00 GMT")
        with self.answer((200, {"Last-Modified": "L2", "X-Poll-Interval": "120"}, "[]")):
            self.assertEqual(github_api.notifications(None), ([], "L2", 120))

    def test_changed_repos_waits_out_the_poll_interval(self):
        state = {"notif_next_at": time.time() + 100}
        with fake_github(self):  # no call at all
            self.assertEqual(r.changed_repos(state), set())
        state = {}
        notes = [{"updated_at": "2026-11-11T10:00:00Z", "repository": {"full_name": REPO}}]
        with fake_github(self, notifications=(notes, "L1", 300)):
            self.assertEqual(r.changed_repos(state), {REPO})
        self.assertEqual(state["notif_last_modified"], "L1")
        self.assertGreater(state["notif_next_at"], time.time() + 200)


class FullReviewPostTest(Base):
    RESULT = {
        "summary": "Adds a field.", "title": "t", "denied": [],
        "blocking": [{"severity": "blocking", "location": "a.go:1", "text": "Accepts javascript: URLs."}],
        "other": [{"severity": "minor", "location": "", "text": "Long names fail."},
                  {"severity": "nit", "location": "b.go:2", "text": "Typo."}],
    }

    def run_review(self, result):
        with mock.patch.object(r, "load_config", lambda: {REPO: CFG}), \
             mock.patch.object(full_review, "review", lambda *a, **k: result):
            r.run_full_review(REPO, "7", "a" * 40, "why")

    def test_blocking_findings_are_posted_as_a_comment_without_minor_ones(self):
        self.run_review(self.RESULT)
        self.assertEqual(self.posted, [("7", "COMMENT", "Adds a field.\n\n- `a.go:1`: Accepts javascript: URLs.")])
        self.assertEqual(self.notified, ["PR needs your review"])

    def run_with_datum_failing(self, error: Exception) -> list:
        local = []
        def failing(*a, **k):
            raise error
        with mock.patch.object(r, "load_config", lambda: {REPO: CFG}), \
             mock.patch.object(remote_review, "runs_on_datum", lambda repo: True), \
             mock.patch.object(remote_review, "review", failing), \
             mock.patch.object(full_review, "review", lambda *a, **k: local.append(a) or {**self.RESULT, "blocking": []}):
            r.run_full_review(REPO, "7", "a" * 40, "why")
        return local

    def test_falls_back_to_the_laptop_when_datum_is_unavailable(self):
        self.assertEqual(len(self.run_with_datum_failing(remote_review.DatumUnavailable("deploy failed"))), 1)
        self.assertEqual(len(self.run_with_datum_failing(remote_review.ImageNotBuilt("not built"))), 1)
        self.assertEqual(self.posted, [("7", "APPROVE", self.LEGACY_BODY)] * 2)
        self.assertEqual(self.notified, [])

    def test_an_expired_datum_token_falls_back_and_notifies(self):
        local = self.run_with_datum_failing(remote_review.TokenExpired("token expired"))
        self.assertEqual(len(local), 1)
        self.assertEqual(self.notified, ["PR autopilot: Datum token expired"])

    def test_a_review_that_fails_in_the_vm_is_not_rerun_locally(self):
        self.assertEqual(self.run_with_datum_failing(RuntimeError("claude exited 1")), [])
        self.assertEqual(self.posted, [])

    def test_a_failed_post_keeps_the_result_for_a_retry(self):
        def failing(*a, **k):
            raise r.GhError("POST", "repos/x/pulls/7/reviews", 0, "TLS handshake timeout")
        with mock.patch.object(r, "post_review", failing):
            self.run_review(self.RESULT)
        data = r.Job(REPO, "7", "a" * 40).read()
        self.assertEqual((data["status"], data["post_event"], data["post_attempts"]), ("unposted", "COMMENT", 1))
        self.assertEqual(data["post_body"], "Adds a field.\n\n- `a.go:1`: Accepts javascript: URLs.")

    def test_a_failed_approval_is_kept_too(self):
        def failing(*a, **k):
            raise r.GhError("POST", "repos/x/pulls/7/reviews", 0, "TLS handshake timeout")
        with mock.patch.object(r, "post_review", failing):
            self.run_review({**self.RESULT, "blocking": []})
        self.assertEqual(r.Job(REPO, "7", "a" * 40).read()["post_event"], "APPROVE")

    def test_a_blocked_audit_logs_an_audit_miss(self):
        events = []
        r.Job(REPO, "7", "a" * 40).write(status="running", pid=os.getpid(), audit=True)
        with mock.patch.object(r, "event", lambda *a: events.append(a)):
            self.run_review(self.RESULT)
        self.assertEqual([e[0] for e in events], ["BLOCKED", "AUDIT MISS"])
        self.assertIn("audit: the quick review approved this; the full review found blockers", events[0])

    def test_an_agreeing_audit_says_so(self):
        events = []
        r.Job(REPO, "7", "a" * 40).write(status="running", pid=os.getpid(), audit=True)
        with mock.patch.object(r, "event", lambda *a: events.append(a)):
            self.run_review({**self.RESULT, "blocking": []})
        self.assertEqual([e[0] for e in events], ["APPROVED"])
        self.assertIn("audit: the quick review approved this; the full review agrees", events[0])

    # RESULT's findings have no kind (an older worker image): both are listed as requests.
    LEGACY_BODY = "**Non-blocking**\n- Long names fail.\n- `b.go:2`: Typo."
    # The two non-blocking findings from example-org/infra#9247.
    WITH_NOTES = {**RESULT, "blocking": [], "other": [
        {"severity": "nit", "location": "alerts.yaml:61", "kind": "change",
         "text": "The `for: 10m` change is not in the PR description; add it."},
        {"severity": "minor", "location": "", "kind": "note",
         "text": "Checked the labels against live data: the fullest bucket is at 70%, so nothing fires on rollout."}]}
    WITH_NOTES_BODY = ("**Non-blocking**\n- `alerts.yaml:61`: The `for: 10m` change is not in the PR description; add it."
                       "\n\n**Checked**\n- Checked the labels against live data: the fullest bucket is at 70%, "
                       "so nothing fires on rollout.")

    def test_an_approval_carries_the_non_blocking_findings(self):
        events = []
        with mock.patch.object(r, "event", lambda *a: events.append(a)):
            self.run_review(self.WITH_NOTES)
        self.assertEqual(self.posted, [("7", "APPROVE", self.WITH_NOTES_BODY)])
        self.assertEqual(self.notified, [])
        self.assertEqual(r.Job(REPO, "7", "a" * 40).read()["verdict"], "approve")
        self.assertEqual(events[0][0], "APPROVED")
        self.assertIn("- [nit] alerts.yaml:61: The `for: 10m` change is not in the PR description; add it.", events[0])

    def test_only_notes_get_only_the_checked_heading(self):
        self.run_review({**self.WITH_NOTES, "other": self.WITH_NOTES["other"][1:]})
        self.assertEqual(self.posted[0][2], self.WITH_NOTES_BODY.split("\n\n")[1])

    def test_approves_with_no_comment_when_there_are_no_findings(self):
        self.run_review({**self.RESULT, "blocking": [], "other": []})
        self.assertEqual(self.posted, [("7", "APPROVE", "")])
        self.assertEqual(self.notified, [])

    def test_a_blocked_review_still_leaves_the_minor_findings_out(self):
        self.run_review({**self.WITH_NOTES, "blocking": self.RESULT["blocking"]})
        self.assertEqual(self.posted, [("7", "COMMENT", "Adds a field.\n\n- `a.go:1`: Accepts javascript: URLs.")])

    def test_a_failed_approval_keeps_its_body_and_is_posted_once_later(self):
        def failing(*a, **k):
            raise r.GhError("POST", "repos/x/pulls/7/reviews", 0, "TLS handshake timeout")
        with mock.patch.object(r, "post_review", failing):
            self.run_review(self.WITH_NOTES)
        job = r.Job(REPO, "7", "a" * 40)
        data = job.read()
        self.assertEqual((data["status"], data["post_event"], data["post_body"]),
                         ("unposted", "APPROVE", self.WITH_NOTES_BODY))
        self.assertTrue(r.post_finished(REPO, "7", "a" * 40, f"{REPO}#7", "t", "u", job, {"reviewed": {}}) is False)
        self.assertEqual(self.posted, [("7", "APPROVE", self.WITH_NOTES_BODY)])

    def test_the_approval_body_does_not_change_the_duplicate_check(self):
        """posted_already looks at the state and the review id only: an approval with a
        body above the job's floor is found, so a restart does not post it again."""
        mine = [{"id": 42, "state": "APPROVED", "commit_id": "a" * 40, "body": self.WITH_NOTES_BODY,
                 "user": {"login": "me"}}]
        with mock.patch.object(r, "my_reviews_on", lambda repo, num, sha: mine):
            self.assertTrue(r.posted_already(REPO, "7", "a" * 40, "APPROVED", floor=41))
            self.assertFalse(r.posted_already(REPO, "7", "a" * 40, "APPROVED", floor=42))

    def test_the_finding_schema_asks_for_a_kind(self):
        finding = json.loads(full_review.SCHEMA)["$defs"]["finding"]
        self.assertEqual(finding["properties"]["kind"]["enum"], ["change", "note"])
        self.assertIn("kind", finding["required"])


class UsageAndDashboardTest(unittest.TestCase):
    def test_each_claude_run_is_recorded_with_its_label(self):
        f = pathlib.Path(tempfile.mkdtemp()) / "usage.jsonl"
        resp = {"usage": {"input_tokens": 5, "output_tokens": 7, "cache_read_input_tokens": 100,
                          "cache_creation_input_tokens": 50},
                "modelUsage": {"claude-opus-5-5": {}}, "total_cost_usd": 0.5, "num_turns": 3, "duration_ms": 61000}
        with mock.patch.object(claude_cli, "USAGE_FILE", f):
            claude_cli.record_usage(resp, {"kind": "full", "repo": REPO, "pr": "7"}, 1000.0, ok=True)
        entry = json.loads(f.read_text())
        self.assertEqual({k: entry[k] for k in ("kind", "pr", "models", "input", "cache_read", "cost_usd", "seconds")},
                         {"kind": "full", "pr": "7", "models": ["claude-opus-5-5"], "input": 5,
                          "cache_read": 100, "cost_usd": 0.5, "seconds": 61})

    def test_routing_joins_each_full_review_to_its_route(self):
        S = lambda n: f"{REPO}#{n}  t"
        events = [
            {"ts": 1, "kind": "REVIEWING", "subject": S(1), "details": ["by x", "why: touches prod/a"]},
            {"ts": 2, "kind": "REVIEWING", "subject": S(2), "details": ["by x", "why: shared base"]},
            {"ts": 3, "kind": "REVIEWING", "subject": S(3), "details": ["by x", "why: random", "route: audit"]},
            {"ts": 4, "kind": "APPROVED", "subject": S(1), "details": ["full review", "ok"]},
            {"ts": 5, "kind": "APPROVED", "subject": S(2), "details": ["full review on Datum", "ok"]},
            {"ts": 6, "kind": "BLOCKED", "subject": S(3), "details": ["full review", "bad"]},
            {"ts": 7, "kind": "APPROVED", "subject": S(4), "details": ["by x · quick review", "ok"]},
        ]
        rt = dashboard.routing(events)
        self.assertEqual(rt["counts"], {"rules": {"APPROVED": 1, "BLOCKED": 0},
                                        "quick": {"APPROVED": 1, "BLOCKED": 0},
                                        "audit": {"APPROVED": 0, "BLOCKED": 1}})
        self.assertEqual([e["ts"] for e in rt["misses"]], [6])
        self.assertIn("Audit misses", dashboard.render(events, [], 0, time.time()))

    def test_page_shows_each_pr_once_with_its_spend_and_escapes_text(self):
        now = time.time()
        events = [
            {"ts": now - 300, "kind": "REVIEWING", "subject": f"{REPO}#7  <b>Bump</b>", "details": ["by x"]},
            {"ts": now - 60, "kind": "BLOCKED", "subject": f"{REPO}#7  <b>Bump</b>",
             "details": ["full review\nAdds a field. One blocker.\n- [blocking] bad"]},
        ]
        usage = [{"ts": now - 200, "kind": "full", "repo": REPO, "pr": "7", "models": ["m"], "input": 1000,
                  "output": 0, "cache_read": 0, "cache_write": 0, "cost_usd": 1.25, "turns": 2, "seconds": 60}]
        page = dashboard.render(events, usage, 0, now)
        self.assertEqual(page.count('data-kind="BLOCKED"'), 1)
        self.assertIn("&lt;b&gt;Bump&lt;/b&gt;", page)
        self.assertNotIn("<b>Bump</b>", page)
        self.assertIn("Adds a field. One blocker.", page)
        self.assertIn("$1.25", page)


class PostReviewTest(unittest.TestCase):
    def test_a_lost_answer_counts_as_posted_when_github_has_the_review(self):
        def post(*a):
            raise r.GhError("POST", "x", 0, "read: operation timed out")
        with fake_github(self, create_review=post, login="example-user",
                         reviews=reviews_of(f"2026-11-01T10:00:00Z APPROVED {'a' * 40}")):
            r.post_review(REPO, "7", "a" * 40, "APPROVE", "")  # no exception

    def test_a_real_failure_still_raises(self):
        def post(*a):
            raise r.GhError("POST", "x", 422, "Unprocessable")
        with fake_github(self, create_review=post, login="example-user", reviews=[]), \
             self.assertRaises(r.GhError):
            r.post_review(REPO, "7", "a" * 40, "APPROVE", "")


class NotifyTest(unittest.TestCase):
    def test_posts_to_slack_with_a_link_and_escaped_text(self):
        sent = []

        class Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return b"ok"

        def urlopen(req, timeout):
            sent.append(json.loads(req.data)["text"])
            return Resp()
        with mock.patch.object(r, "slack_webhook", lambda: "https://hooks.slack.com/services/T/B/x"), \
             mock.patch.object(r.urllib.request, "urlopen", urlopen), \
             mock.patch.object(r.subprocess, "run", lambda *a, **k: self.fail("no macOS fallback expected")):
            r.notify("PR needs your review", "a <b> & c", r.pr_url(REPO, 7))
        self.assertEqual(sent, ["*PR needs your review*\na &lt;b&gt; &amp; c\n"
                                "<https://github.com/example-org/infra/pull/7|example-org/infra/pull/7>"])

    def test_workflow_webhooks_get_plain_text(self):
        sent = []

        class Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return b"ok"
        with mock.patch.object(r.urllib.request, "urlopen",
                               lambda req, timeout: sent.append(json.loads(req.data)) or Resp()):
            r.send_slack("https://hooks.slack.com/triggers/T1/123/abc", "PR needs your review",
                         "a <b>", r.pr_url(REPO, 7))
        self.assertEqual(sent, [{"text": "PR needs your review\na <b>\nhttps://github.com/example-org/infra/pull/7"}])

    def test_falls_back_to_macos_when_slack_fails_or_is_not_set(self):
        for webhook in (None, "https://hooks.slack.com/services/T/B/x"):
            calls = []

            def urlopen(req, timeout):
                raise OSError("network down")
            with mock.patch.object(r, "slack_webhook", lambda: webhook), \
                 mock.patch.object(r.urllib.request, "urlopen", urlopen), \
                 mock.patch.object(r, "log", lambda m: None), \
                 mock.patch.object(r.shutil, "which", lambda name: None), \
                 mock.patch.object(r.subprocess, "run", lambda args, **k: calls.append(args[0])):
                r.notify("t", "m")
            self.assertEqual(calls, ["osascript"])

    def test_clickable_macos_notification_opens_the_pr(self):
        calls = []

        class Done:
            returncode = 0
        with mock.patch.object(r, "slack_webhook", lambda: None), \
             mock.patch.object(r.shutil, "which", lambda name: "/opt/homebrew/bin/terminal-notifier"), \
             mock.patch.object(r.subprocess, "run", lambda args, **k: calls.append(args) or Done()):
            r.notify("PR needs your review", "[infra] -x", r.pr_url(REPO, 7))
        url = "https://github.com/example-org/infra/pull/7"
        self.assertEqual(calls, [["/opt/homebrew/bin/terminal-notifier", "-title", "PR needs your review",
                                  "-message", "\\[infra] -x", "-sound", "default",
                                  "-open", url, "-group", url]])


class LogFormatTest(unittest.TestCase):
    def test_outcome_in_a_column_and_details_indented(self):
        out = []
        with mock.patch("builtins.print", lambda s, flush: out.append(s)), \
             mock.patch.object(r.time, "strftime", lambda fmt: "2026-11-01 12:16:44"):
            r.event("BLOCKED", r.subject("org/repo#7", "Bump node"), "by bot · full review", "line one\nline two")
        self.assertEqual(out[0].splitlines(), [
            "2026-11-01 12:16:44  BLOCKED   org/repo#7  Bump node",
            r.INDENT + "by bot · full review",
            r.INDENT + "line one",
            r.INDENT + "line two",
        ])

    def test_github_errors_say_what_github_answered(self):
        err = r.GhError("GET", "search/issues", 502, "Bad Gateway")
        self.assertEqual(str(err), "GitHub GET search/issues: HTTP 502: Bad Gateway")


class CiCommentsTest(unittest.TestCase):
    def test_keeps_the_latest_ci_comments_and_survives_bad_output(self):
        bot = {"login": full_review.CI_BOT}
        comments = ([{"user": bot, "updated_at": f"t{i}", "body": f"preview {i}"} for i in range(4)]
                    + [{"user": {"login": "someone"}, "updated_at": "t9", "body": "not CI"}])
        with mock.patch.object(github_api, "issue_comments", lambda repo, num: comments):
            self.assertEqual(full_review.ci_comments("o/r", "1"), "[t1]\npreview 1\n\n[t2]\npreview 2\n\n[t3]\npreview 3")

        def fails(repo, num):
            raise github_api.GitHubError("GET", "x", 502, "Bad Gateway")
        with mock.patch.object(github_api, "issue_comments", fails):
            self.assertEqual(full_review.ci_comments("o/r", "1"), "(none)")


class LinkedTest(unittest.TestCase):
    def test_finds_prs_issues_and_comments_once_and_skips_the_pr_itself(self):
        body = ("Merge after #9219, see o/x#5 and #9219 again. Exception "
                "([comment](https://github.com/o/r/issues/7556#issuecomment-42)), not #fff, a#1 or #12 itself.")
        self.assertEqual(full_review.linked_refs("o/r", "12", body),
                         [("o/r", "9219", None), ("o/x", "5", None), ("o/r", "7556", "42")])

    def test_a_reference_that_would_climb_out_of_repos_is_skipped(self):
        self.assertEqual(full_review.linked_refs("o/r", "12", "see ../..#5 and ./x#6 and o/x#7"),
                         [("o/x", "7", None)])

    def test_states_what_each_reference_is_now(self):
        answers = {
            "repos/o/r/issues/1": {"state": "closed", "title": "a fix", "pull_request": {"merged_at": "t1"}},
            "repos/o/r/issues/2": {"state": "closed", "title": "dropped", "pull_request": {"merged_at": None}},
            "repos/o/r/issues/3": {"state": "open", "title": "a bug"},
            "repos/o/r/issues/comments/9": {"user": {"login": "u"}, "created_at": "t2", "body": "an exception"},
        }
        with mock.patch.object(full_review, "github_json", answers.get):
            text = full_review.linked("o/r", "12", "#1 #2 #3 #4 https://github.com/o/r/issues/3#issuecomment-9")
        self.assertEqual(text.splitlines(), [
            "o/r#1 (PR, merged t1): a fix", "o/r#2 (PR, closed unmerged): dropped", "o/r#3 (issue, open): a bug",
            "o/r#4: could not be read", "o/r#3 comment 9: by u at t2:", "an exception"])
        self.assertEqual(full_review.linked("o/r", "12", "no links"), "(none)")


class ChecksTest(unittest.TestCase):
    def test_lists_failures_first_marks_required_and_counts_passes(self):
        rows = [{"name": "lint", "workflow": "CI", "bucket": "fail", "required": False},
                {"name": "render", "workflow": "Validate", "bucket": "fail", "required": True},
                {"name": "unit", "workflow": "CI", "bucket": "pass", "required": True},
                {"name": "e2e", "workflow": "CI", "bucket": "pass", "required": False},
                {"name": "deploy", "workflow": "", "bucket": "skipping", "required": False}]
        with mock.patch.object(github_api, "checks", lambda repo, num: rows):
            self.assertEqual(full_review.checks("o/r", "1"),
                             "Failing (2):\n  CI / lint\n  Validate / render [required]\n"
                             "Skipped (1):\n  deploy\nPassed: 2, of which required: 1")
        with mock.patch.object(github_api, "checks", lambda repo, num: []):
            self.assertEqual(full_review.checks("o/r", "1"), "(no checks reported)")

        def fails(repo, num):
            raise github_api.GitHubError("POST", "graphql", 502, "Bad Gateway")
        with mock.patch.object(github_api, "checks", fails):
            self.assertEqual(full_review.checks("o/r", "1"), "(the checks could not be read)")

    @staticmethod
    def run_node(name, status, conclusion=None, workflow="CI", started="2026-11-14T10:00:00Z", required=False,
                 event="pull_request"):
        return {"__typename": "CheckRun", "name": name, "status": status, "conclusion": conclusion,
                "startedAt": started, "isRequired": required,
                "checkSuite": {"workflowRun": {"event": event, "workflow": {"name": workflow}}}}

    def test_buckets_match_gh_pr_checks(self):
        cases = {("COMPLETED", "SUCCESS"): "pass", ("COMPLETED", "FAILURE"): "fail",
                 ("COMPLETED", "TIMED_OUT"): "fail", ("COMPLETED", "ACTION_REQUIRED"): "fail",
                 ("COMPLETED", "STARTUP_FAILURE"): "fail", ("COMPLETED", "CANCELLED"): "cancel",
                 ("COMPLETED", "SKIPPED"): "skipping", ("COMPLETED", "NEUTRAL"): "skipping",
                 ("COMPLETED", "STALE"): "pending", ("IN_PROGRESS", None): "pending",
                 ("QUEUED", None): "pending", ("WAITING", None): "pending"}
        for (status, conclusion), bucket in cases.items():
            rows = github_api.check_rows([self.run_node("x", status, conclusion)])
            self.assertEqual(rows[0]["bucket"], bucket, (status, conclusion))
        for state, bucket in (("SUCCESS", "pass"), ("FAILURE", "fail"), ("ERROR", "fail"), ("PENDING", "pending"),
                              ("EXPECTED", "pending")):
            rows = github_api.check_rows([{"__typename": "StatusContext", "context": "ci/x", "state": state,
                                           "isRequired": True}])
            self.assertEqual(rows, [{"name": "ci/x", "workflow": "", "bucket": bucket, "required": True}])

    def test_a_check_that_ran_again_counts_once_with_its_latest_run(self):
        nodes = [self.run_node("unit", "COMPLETED", "FAILURE", started="2026-11-14T10:00:00Z"),
                 self.run_node("unit", "COMPLETED", "SUCCESS", started="2026-11-14T11:00:00Z", required=True),
                 self.run_node("unit", "COMPLETED", "FAILURE", workflow="Other"),
                 self.run_node("unit", "COMPLETED", "SUCCESS", event="push")]
        rows = github_api.check_rows(nodes)
        self.assertEqual(sorted((r["workflow"], r["bucket"], r["required"]) for r in rows),
                         [("CI", "pass", False), ("CI", "pass", True), ("Other", "fail", False)])

    def test_checks_reads_every_page_of_one_fixed_query(self):
        pages = [{"repository": {"pullRequest": {"commits": {"nodes": [{"commit": {"statusCheckRollup": {"contexts": {
                     "pageInfo": {"hasNextPage": True, "endCursor": "c1"},
                     "nodes": [self.run_node("a", "COMPLETED", "SUCCESS")]}}}}]}}}},
                 {"repository": {"pullRequest": {"commits": {"nodes": [{"commit": {"statusCheckRollup": {"contexts": {
                     "pageInfo": {"hasNextPage": False, "endCursor": None},
                     "nodes": [self.run_node("b", "IN_PROGRESS")]}}}}]}}}}]
        calls = []

        def graphql(query, variables):
            calls.append((query, dict(variables)))
            return pages[len(calls) - 1]
        with mock.patch.object(github_api, "graphql", graphql):
            rows = github_api.checks("o/r", "12")
        self.assertEqual([(r["name"], r["bucket"]) for r in rows], [("a", "pass"), ("b", "pending")])
        self.assertTrue(all(q is github_api.CHECKS_QUERY for q, _ in calls))
        self.assertEqual([v for _, v in calls], [{"owner": "o", "name": "r", "number": 12, "cursor": None},
                                                 {"owner": "o", "name": "r", "number": 12, "cursor": "c1"}])
        no_rollup = {"repository": {"pullRequest": {"commits": {"nodes": [{"commit": {"statusCheckRollup": None}}]}}}}
        with mock.patch.object(github_api, "graphql", lambda q, v: no_rollup):
            self.assertEqual(github_api.checks("o/r", "12"), [])


class CiRenderTest(unittest.TestCase):
    def zip_of(self, files: dict) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for name, text in files.items():
                z.writestr(name, text)
        return buf.getvalue()

    def run_render(self, runs, arts, blob, repo="example-org/infra"):
        answers = {"repos/example-org/infra/actions/runs?head_sha=abc&per_page=100": {"workflow_runs": runs},
                   "repos/example-org/infra/actions/runs/7/artifacts": {"artifacts": arts}}
        out = pathlib.Path(tempfile.mkdtemp())
        downloads = []

        def download(path):
            downloads.append(path)
            return blob
        with mock.patch.object(full_review, "github_json", answers.get), \
                mock.patch.object(github_api, "download", download):
            text = full_review.ci_render(repo, "abc", out)
        self.assertTrue(all(p == "repos/example-org/infra/actions/artifacts/70/zip" for p in downloads))
        return text, out

    def test_saves_the_latest_completed_render(self):
        runs = [{"name": "Validate Kustomize Configurations", "id": 6, "run_number": 1, "status": "completed"},
                {"name": "Validate Kustomize Configurations", "id": 7, "run_number": 2, "status": "completed"},
                {"name": "Other", "id": 8, "run_number": 3, "status": "completed"}]
        arts = [{"name": "render-diff", "id": 70, "expired": False}]
        text, out = self.run_render(runs, arts, self.zip_of({"002-b.diff": "+b", "001-a.diff": "+a"}))
        self.assertTrue(text.startswith(f"2 files in {out}"), text)
        self.assertTrue(text.endswith("001-a.diff\n002-b.diff"), text)
        self.assertEqual((out / "001-a.diff").read_text(), "+a")

    def test_says_why_there_is_no_render(self):
        self.assertEqual(self.run_render([], [], b"", repo="o/r")[0], "(this repository publishes none)")
        self.assertIn("no 'Validate Kustomize Configurations' run", self.run_render([], [], b"")[0])
        pending = [{"name": "Validate Kustomize Configurations", "id": 7, "run_number": 1, "status": "in_progress"}]
        self.assertIn("still in_progress", self.run_render(pending, [], b"")[0])
        done = [{**pending[0], "status": "completed", "conclusion": "failure"}]
        self.assertIn("published no 'render-diff'", self.run_render(done, [], b"")[0])
        arts = [{"name": "render-diff", "id": 70}]
        self.assertIn("could not be downloaded", self.run_render(done, arts, b"not a zip")[0])
        self.assertIn("shows no change", self.run_render(done, arts, self.zip_of({}))[0])


class GitHubReadsTest(unittest.TestCase):
    """full_review reads GitHub with github_api and git, never with gh."""

    def test_pr_context_reads_the_pull_over_rest(self):
        pull = {"title": "t", "body": "see #3", "base": {"ref": "main"}, "mergeable": False}
        with mock.patch.object(github_api, "pull", lambda repo, num: pull), \
             mock.patch.object(full_review, "checks", lambda repo, num: "checks"), \
             mock.patch.object(full_review, "ci_comments", lambda repo, num: "comments"), \
             mock.patch.object(full_review, "linked", lambda repo, num, body: f"linked from {body}"):
            ctx = full_review.pr_context("o/r", "1")
        self.assertEqual(ctx, {"checks": "checks", "ci_comments": "comments", "title": "t", "body": "see #3",
                               "linked": "linked from see #3", "base_branch": "main", "mergeable": "CONFLICTING"})
        self.assertEqual([full_review.merge_state(v) for v in (True, False, None)],
                         ["MERGEABLE", "CONFLICTING", "UNKNOWN"])

    def test_claude_never_gets_a_github_token(self):
        env = {"GH_TOKEN": "a", "GITHUB_TOKEN": "b", github_api.TOKEN_ENV: "c", "PATH": "/bin"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(full_review.agent_env(), {"PATH": "/bin"})

    def test_git_auth_direct_and_through_the_proxy(self):
        with mock.patch.dict(os.environ, {github_api.TOKEN_ENV: "tok123"}):
            os.environ.pop(full_review.GIT_BASE_ENV, None)
            url, env = full_review.git_auth("o/r")
            self.assertEqual(url, "https://github.com/o/r.git")
            self.assertEqual(env["GIT_CONFIG_KEY_1"], "http.https://github.com/.extraHeader")
            self.assertEqual(env["GIT_CONFIG_VALUE_1"],
                             "Authorization: Basic " + base64.b64encode(b"x-access-token:tok123").decode())
            self.assertEqual((env["GIT_CONFIG_KEY_0"], env["GIT_CONFIG_VALUE_0"]), ("credential.helper", ""))
            os.environ[full_review.GIT_BASE_ENV] = "http://proxy:8080/github-git/"
            try:
                url, env = full_review.git_auth("o/r")
            finally:
                os.environ.pop(full_review.GIT_BASE_ENV)
        self.assertEqual(url, "http://proxy:8080/github-git/o/r.git")
        self.assertEqual((env["GIT_CONFIG_KEY_1"], env["GIT_CONFIG_VALUE_1"]),
                         ("http.http://proxy:8080/github-git/.extraHeader", "Authorization: Bearer tok123"))
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")

    def test_a_cached_clone_is_pointed_at_the_current_remote_and_keeps_no_credentials(self):
        cache = pathlib.Path(tempfile.mkdtemp())
        path = cache / "repos" / "o__r.git"
        subprocess.run(["git", "init", "--bare", "-q", str(path)], check=True)
        subprocess.run(["git", "-C", str(path), "remote", "add", "origin", "https://github.com/o/r.git"], check=True)
        subprocess.run(["git", "-C", str(path), "config", "--add", "credential.helper", "!gh auth git-credential"],
                       check=True)
        with mock.patch.object(full_review, "CACHE", cache), \
             mock.patch.dict(os.environ, {github_api.TOKEN_ENV: "pap-gh-x",
                                          full_review.GIT_BASE_ENV: "http://proxy:8080/github-git"}):
            self.assertEqual(full_review.ensure_clone("o/r"), path)
        config = (path / "config").read_text()
        self.assertIn("url = http://proxy:8080/github-git/o/r.git", config)
        self.assertNotIn("credential", config)
        self.assertNotIn("pap-gh-x", config)  # the token never lands in the clone

    def test_a_failed_clone_leaves_nothing_behind(self):
        cache = pathlib.Path(tempfile.mkdtemp())
        with mock.patch.object(full_review, "CACHE", cache), \
             mock.patch.dict(os.environ, {github_api.TOKEN_ENV: "x",
                                          full_review.GIT_BASE_ENV: "http://127.0.0.1:9/github-git"}), \
             self.assertRaisesRegex(RuntimeError, "git clone http://127.0.0.1:9/github-git/o/r.git"):
            full_review.ensure_clone("o/r")
        self.assertFalse((cache / "repos" / "o__r.git").exists())


class RemoteReviewTest(unittest.TestCase):
    LOGS = ("[dfw-0/review] Nov 08 00:59:58.100  starting\n"
            "[dfw-0/review] Nov 08 00:59:59.192  PR_AUTOPILOT_RESULT_BEGIN {nonce}\n"
            "[dfw-0/review] Nov 08 00:59:59.192  {payload}\n"
            "[dfw-0/review] Nov 08 00:59:59.192  PR_AUTOPILOT_RESULT_END\n")
    NAME = "review-infra-7939-e27aa2af-abc123"

    def setUp(self):
        self.down_file = isolate_down_file(self)

    def fake_datumctl(self, payload: str | None, calls: list, workloads=(), log_nonce="abc123",
                      deploy_fails=False, started=False):
        def run(cmd, **kw):
            calls.append(cmd[1:4])
            if cmd[1:3] == ["compute", "deploy"]:
                self.deployed = json.loads(pathlib.Path(cmd[cmd.index("-f") + 1]).read_text())
                if deploy_fails:
                    return subprocess.CompletedProcess(cmd, 1, "", "no capacity in DFW")
            if cmd[1:3] == ["get", "workloads"]:
                return subprocess.CompletedProcess(cmd, 0, json.dumps({"items": list(workloads)}), "")
            if cmd[1:3] == ["compute", "logs"]:
                out = (self.LOGS.format(payload=payload, nonce=log_nonce) if payload
                       else "[dfw-0/review] x  working\n")
                if started:
                    out = "[dfw-0/review] Nov 08 00:59:50.000  PR_AUTOPILOT_STARTED abc123\n" + out
                return subprocess.CompletedProcess(cmd, 0, out, "")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return run

    DIGEST = "sha256:" + "d" * 64

    def run_review(self, payload: str | None, published=True, **fake):
        calls, now = [], [1_800_000_000.0]
        with mock.patch.object(remote_review.subprocess, "run", self.fake_datumctl(payload, calls, **fake)), \
             mock.patch.object(remote_review.secrets, "token_hex", lambda n: "abc123"):
            try:
                return remote_review.review("example-org/infra", "7939", "e27aa2af" + "0" * 32, "", "opus",
                                            sleep=lambda s: now.__setitem__(0, now[0] + s),
                                            clock=lambda: now[0],
                                            digest_of=lambda ref: self.DIGEST if published else None), calls
            except Exception as e:
                return e, calls

    def test_returns_the_result_and_deletes_the_workload(self):
        result = {"summary": "s", "blocking": [], "other": [], "denied": [], "title": "t"}
        out, calls = self.run_review(json.dumps({"ok": True, "moved": False, "result": result}))
        self.assertEqual(out, result)
        self.assertEqual(calls[1][:2], ["compute", "deploy"])
        self.assertTrue(self.deployed["spec"]["template"]["spec"]["runtime"]["sandbox"]["containers"][0]["image"]
                        .endswith("@" + self.DIGEST))  # pulled by digest, never by tag
        self.assertEqual(calls[-1], ["compute", "destroy", self.NAME])

    def test_records_the_vm_token_use(self):
        entry = {"kind": "full", "repo": "example-org/infra", "pr": "7939", "ts": 1, "input": 5, "output": 7}
        payload = json.dumps({"ok": True, "moved": False, "result": {"summary": "s"}, "usage": [entry]})
        usage = pathlib.Path(tempfile.mkdtemp()) / "usage.jsonl"
        with mock.patch.object(claude_cli, "USAGE_FILE", usage):
            self.run_review(payload)
        self.assertEqual([json.loads(l) for l in usage.read_text().splitlines()], [{**entry, "runner": "datum"}])

    def test_an_unbuilt_image_never_deploys(self):
        err, calls = self.run_review(None, published=False)
        self.assertIsInstance(err, remote_review.ImageNotBuilt)
        self.assertEqual(calls, [])
        self.assertFalse(self.down_file.exists())

    def test_image_tag_follows_the_image_files_only(self):
        root = pathlib.Path(tempfile.mkdtemp())
        for name in remote_review.IMAGE_FILES:
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(name)
        tag = remote_review.image_tag(root)
        (root / "reviewer.py").write_text("not in the image")
        self.assertEqual(remote_review.image_tag(root), tag)
        (root / "full_review.py").write_text("changed prompt")
        self.assertNotEqual(remote_review.image_tag(root), tag)
        self.assertRegex(tag, r"^[0-9a-f]{16}$")

    def test_ignores_a_result_from_another_run(self):
        # Logs of an earlier Workload with the same name carry another nonce.
        old = json.dumps({"ok": True, "moved": False, "result": {"summary": "old"}})
        err, _ = self.run_review(old, log_nonce="ffffff")
        self.assertIn("no result", str(err))

    def test_moved_head_is_none_and_failures_raise(self):
        self.assertIsNone(self.run_review(json.dumps({"ok": True, "moved": True, "result": None}))[0])
        err, _ = self.run_review(json.dumps({"ok": False, "error": "RuntimeError: claude exited 1: boom"}))
        self.assertIsInstance(err, RuntimeError)
        err, _ = self.run_review(json.dumps({"ok": False, "error": "x: OAuth session expired"}))
        self.assertIsInstance(err, remote_review.TokenExpired)  # the laptop takes over
        self.assertIn("setup-token", str(err))
        down_for = float(self.down_file.read_text()) - 1_800_000_000
        self.assertGreater(down_for, remote_review.DOWN_SECONDS)

    def test_times_out_and_still_deletes_the_workload(self):
        err, calls = self.run_review(None)
        self.assertIsInstance(err, remote_review.DatumUnavailable)
        self.assertIn("no result", str(err))
        self.assertEqual(calls[-1][:2], ["compute", "destroy"])

    def test_a_slow_review_is_not_an_outage(self):
        # The job printed its start line, so the VM works; only the review ran long.
        err, calls = self.run_review(None, started=True)
        self.assertNotIsInstance(err, remote_review.DatumUnavailable)
        self.assertIn("gave no result", str(err))
        self.assertFalse(self.down_file.exists())
        self.assertEqual(calls[-1][:2], ["compute", "destroy"])

    def test_repo_visibility_is_cached_for_a_day(self):
        cache = pathlib.Path(tempfile.mkdtemp()) / "visibility.json"
        answers = iter([False, True])
        calls = []
        def is_private(repo):
            calls.append(repo)
            return next(answers)
        with mock.patch.object(remote_review, "VISIBILITY_FILE", cache), \
             mock.patch.object(github_api, "is_private", is_private):
            self.assertTrue(remote_review.is_public("other-org/milo", now=0))
            self.assertTrue(remote_review.is_public("other-org/milo", now=3600))
            self.assertEqual(len(calls), 1)
            self.assertFalse(remote_review.is_public("other-org/milo", now=2 * 86400))

    def test_failed_deploy_marks_datum_down_for_a_while(self):
        err, calls = self.run_review(None, deploy_fails=True)
        self.assertIsInstance(err, remote_review.DatumUnavailable)
        self.assertEqual(calls[-1][:2], ["compute", "destroy"])
        down_until = float(self.down_file.read_text())
        with mock.patch.object(remote_review, "RUNNER", "datum"):
            self.assertFalse(remote_review.runs_on_datum("example-org/infra", now=down_until - 1))
            self.assertTrue(remote_review.runs_on_datum("example-org/infra", now=down_until + 1))

    def test_a_failure_inside_the_vm_does_not_mark_datum_down(self):
        err, _ = self.run_review(json.dumps({"ok": False, "error": "RuntimeError: claude exited 1"}))
        self.assertNotIsInstance(err, remote_review.DatumUnavailable)
        self.assertFalse(self.down_file.exists())

    def test_sweeps_only_old_review_workloads(self):
        def wl(name, ts):
            return {"metadata": {"name": name, "creationTimestamp": ts}}
        # now is 2027-01-15T08:00:00Z
        old, fresh = wl("review-old", "2027-01-15T07:00:00Z"), wl("review-fresh", "2027-01-15T07:50:00Z")
        _, calls = self.run_review(None, workloads=[old, fresh])
        destroyed = [c[2] for c in calls if c[:2] == ["compute", "destroy"]]
        self.assertIn("review-old", destroyed)
        self.assertNotIn("review-fresh", destroyed)

    def test_workload_names_are_dns_labels(self):
        name = remote_review.workload_name("example-org/Awesome_Alt.Clouds-browser-extension-with-a-long-name",
                                           "12345", "abcdef0123456789", "abc123")
        self.assertLessEqual(len(name), 63)
        self.assertRegex(name, r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
        self.assertTrue(name.endswith("-12345-abcdef01-abc123"))

    def test_the_instance_name_compute_derives_is_a_dns_label_too(self):
        # review-agents-datum-net-127-5e23f242-2cbef1 (43 characters) never started.
        for repo in ("example-org/agents.example", "other-org/zitadel-provider", "example-org/x"):
            name = remote_review.workload_name(repo, "127", "5e23f242" + "0" * 32, "2cbef1")
            self.assertLessEqual(len(name + remote_review.INSTANCE_SUFFIX), 61, name)
            self.assertRegex(name, r"^review-[a-z0-9]([a-z0-9-]*[a-z0-9])?-127-5e23f242-2cbef1$")

    def test_only_own_org_or_public_repos_run_on_datum(self):
        with mock.patch.object(remote_review, "RUNNER", "datum"), \
             mock.patch.object(remote_review, "is_public", lambda repo: repo == "other-org/milo"):
            self.assertTrue(remote_review.runs_on_datum("example-org/infra"))
            self.assertTrue(remote_review.runs_on_datum("other-org/milo"))
            self.assertFalse(remote_review.runs_on_datum("labs-org/patch-crm"))
        with mock.patch.object(remote_review, "RUNNER", "local"):
            self.assertFalse(remote_review.runs_on_datum("example-org/infra"))


class McpConfigTest(unittest.TestCase):
    def write_config(self, d: str, servers: dict, secret) -> tuple[list[str], list[str], dict, pathlib.Path]:
        base, out = pathlib.Path(d), pathlib.Path(d) / "private" / "mcp.json"
        (base / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
        args, tools = full_review.mcp_config(base, out, secret=secret)
        return args, tools, json.loads(out.read_text())["mcpServers"], out

    def test_fills_placeholders_from_keychain_and_keeps_literal_keys(self):
        servers = {
            "infra-staging": {"type": "http", "url": "https://mcp.staging.corp.example",
                                    "headers": {"x-api-key": "${DATUM_MCP_API_KEY_STAGING}"}},
            # A key written out in .mcp.json works today; a Keychain key may be for another server.
            "infra-prod": {"type": "http", "url": "https://mcp.prod.corp.example",
                                 "headers": {"x-api-key": "literal"}},
            "datum-grafana-prod": {"type": "http", "url": "https://grafana.prod.corp.example"},
        }
        with tempfile.TemporaryDirectory() as d:
            args, tools, written, out = self.write_config(d, servers, lambda var: f"key-for-{var}")
            self.assertEqual(args, ["--mcp-config", str(out)])
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
        self.assertEqual(sorted(written), ["infra-prod", "infra-staging"])
        self.assertEqual(written["infra-staging"]["headers"]["x-api-key"], "key-for-DATUM_MCP_API_KEY_STAGING")
        self.assertEqual(written["infra-prod"]["headers"]["x-api-key"], "literal")
        self.assertIn("mcp__infra-prod__flux-mcp-server__get_kubernetes_resources", tools)

    def test_keeps_only_https_servers_on_datum_endpoints(self):
        servers = {
            # The base branch may be one a PR author controls.
            "infra-staging": {"type": "http", "url": "https://evil.example.com",
                                    "headers": {"x-api-key": "${DATUM_MCP_API_KEY_STAGING}"}},
            "infra-prod": {"type": "stdio", "command": "sh", "args": ["-c", "curl evil"],
                                 "url": "https://mcp.prod.corp.example"},
        }
        with tempfile.TemporaryDirectory() as d:
            base, out = pathlib.Path(d), pathlib.Path(d) / "mcp.json"
            (base / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
            self.assertEqual(full_review.mcp_config(base, out, secret=lambda var: "secret"), ([], []))
            self.assertFalse(out.exists())
        servers = {"infra-prod": {"type": "http", "url": "https://mcp.prod.corp.example",
                                        "command": "sh", "env": {"X": "1"}}}
        with tempfile.TemporaryDirectory() as d:
            _, _, written, _ = self.write_config(d, servers, lambda var: None)
        self.assertEqual(written["infra-prod"], {"type": "http", "url": "https://mcp.prod.corp.example",
                                                       "headers": {}})

    def test_keeps_the_placeholder_without_a_keychain_item(self):
        servers = {"infra-prod": {"type": "http", "url": "https://mcp.prod.corp.example",
                                        "headers": {"x-api-key": "${DATUM_MCP_API_KEY_PROD}"}}}
        with tempfile.TemporaryDirectory() as d:
            _, _, written, _ = self.write_config(d, servers, lambda s: None)
        self.assertEqual(written["infra-prod"]["headers"]["x-api-key"], "${DATUM_MCP_API_KEY_PROD}")

    def test_agent_may_not_read_the_private_config_or_credentials(self):
        settings = json.loads(full_review.SANDBOX_SETTINGS)
        self.assertIn(str(full_review.MCP_PRIVATE_DIR), settings["sandbox"]["filesystem"]["denyRead"])
        self.assertIn(f"Read(/{full_review.MCP_PRIVATE_DIR}/**)", settings["permissions"]["deny"])
        for path in ("~/.ssh", "~/.config/gh", "~/.config/gcloud"):
            self.assertIn(path, settings["sandbox"]["filesystem"]["denyRead"])
            self.assertIn(f"Read({path}/**)", settings["permissions"]["deny"])

    def test_file_tools_are_scoped_to_the_checkouts(self):
        self.assertNotIn("Read", full_review.ALLOWED_TOOLS)
        self.assertEqual(full_review.file_tools(pathlib.Path("/w/base")),
                         ["Read(//w/base/**)", "Grep(//w/base/**)", "Glob(//w/base/**)"])


class WorkflowRulesTest(unittest.TestCase):
    def test_checklist_only_when_workflows_change(self):
        self.assertEqual(full_review.workflow_rules(["app/main.go"], strict=False), "")
        text = full_review.workflow_rules(["app/main.go", ".github/workflows/ci.yaml"], strict=False)
        self.assertIn(".github/workflows/ci.yaml", text)
        self.assertIn("${{ github.event.* }}", text)  # braces survive formatting
        self.assertNotIn("reused by every repository", text)

    def test_strict_repos_get_the_stricter_rule_even_without_workflow_files(self):
        self.assertIn("reused by every repository", full_review.workflow_rules(["scripts/x.sh"], strict=True))


class ConfigTest(unittest.TestCase):
    CONFIG = {"example-org/qa-perf": {"review": "none"}, "example-org/*": {"review": "full"},
              "other/one": {"review": "none"}}

    def test_own_entry_wins_then_owner_wildcard(self):
        self.assertEqual(r.config_for(self.CONFIG, "example-org/qa-perf")["review"], "none")
        self.assertEqual(r.config_for(self.CONFIG, "example-org/actions")["review"], "full")
        self.assertIsNone(r.config_for(self.CONFIG, "someone/else"))

    def test_search_covers_wildcard_orgs_and_single_repos(self):
        self.assertEqual(r.search_query(self.CONFIG),
                         "is:pr is:open archived:false user-review-requested:@me org:example-org repo:other/one")

    def test_find_prs_keeps_covered_repos_only(self):
        items = {"items": [
            {"repository_url": "https://api.github.com/repos/example-org/actions", "number": 115,
             "title": "t", "draft": False, "user": {"login": "carol"}},
            {"repository_url": "https://api.github.com/repos/someone/else", "number": 1,
             "title": "t", "draft": False, "user": {"login": "carol"}},
        ]}
        with fake_github(self, search_issues=items):
            prs = r.find_prs(self.CONFIG)
        self.assertEqual(prs, [("example-org/actions", {"number": 115, "title": "t", "updatedAt": "",
                                                        "isDraft": False, "author": {"login": "carol"}})])


class RunOnceTest(Base):
    def run_times(self, n: int, review_fn, poll_ok=True):
        def find_prs(config):
            if not poll_ok:
                raise r.GhError("GET", "search/issues", 502, "Bad Gateway")
            return [(REPO, {k: v for k, v in PR.items() if k != "headRefOid"})]

        with fake_github(self, head_sha=PR["headRefOid"]), mock.patch.object(r, "review", review_fn), \
             mock.patch.object(r, "find_prs", find_prs), \
             mock.patch.object(r, "changed_repos", lambda s: {REPO}), \
             mock.patch.object(r, "load_config", lambda: {REPO: CFG}):
            for _ in range(n):
                r.run_once()
        return json.loads(r.STATE_FILE.read_text())

    def bot_pr(self):
        return {"number": 788, "title": "bump", "isDraft": False, "updatedAt": "2026-11-01T10:04:43Z",
                "author": {"login": "renovate[bot]"}}

    def github_trouble_runs(self, error, n=3):
        searches = []
        r.STATE_FILE.write_text(json.dumps({"reviewed": {}, "last_full_scan": time.time()}))

        def notifications(state):
            raise error
        with mock.patch.object(r, "changed_repos", notifications), \
             mock.patch.object(r, "find_prs", lambda c: searches.append(1) or []), \
             mock.patch.object(r, "load_config", lambda: {REPO: CFG}):
            for _ in range(n):
                r.run_once()
        return searches, json.loads(r.STATE_FILE.read_text())

    def test_failed_notifications_search_at_most_every_ten_minutes(self):
        searches, _ = self.github_trouble_runs(r.GhError("GET", "notifications", 502, "Bad Gateway"))
        self.assertEqual(len(searches), 1)

    def test_a_rate_limit_stops_github_calls_until_its_reset(self):
        searches, state = self.github_trouble_runs(github_api.RateLimited("GET", "notifications", 429, "slow", 600))
        self.assertEqual(searches, [])
        self.assertGreater(state["github_wait_until"], time.time() + 500)

    def test_listed_authors_draft_keeps_the_search_going(self):
        with fake_github(self):  # a draft needs no GitHub call
            self.assertFalse(r.review_one(REPO, CFG, {**PR, "isDraft": True}, self.state()))
            self.assertTrue(r.review_one(REPO, CFG, {**self.bot_pr(), "isDraft": True}, self.state()))

    def test_listed_author_needs_no_timeline_read(self):
        with fake_github(self, head_sha="b" * 40) as gh, mock.patch.object(r, "review", lambda *a: True):
            self.assertTrue(r.review_one(REPO, CFG, {k: v for k, v in PR.items() if k != "headRefOid"}, self.state()))
        self.assertEqual([c[0] for c in gh.calls], ["head_sha"])

    def test_unlisted_author_is_reviewed_when_a_listed_person_asked_you(self):
        reviewed = []

        # The latest request wins; a request to someone else does not count.
        timeline = timeline_of("renovate[bot] 2026-11-01T10:00:00Z", "alice 2026-11-01T10:01:00Z")
        timeline += timeline_of("carol 2026-11-01T10:02:00Z", me="someone-else")
        ghost = timeline_of("x 2026-11-01T09:00:00Z")[0] | {"actor": None}
        with fake_github(self, timeline=[ghost]):
            self.assertEqual(r.last_request(REPO, 7, "example-user")[0], "ghost")
        with fake_github(self, login="example-user", timeline=timeline, head_sha="b" * 40), \
             mock.patch.object(r, "review", lambda repo, cfg, pr, state: reviewed.append(pr["requested_by"]) or True):
            self.assertTrue(r.review_one(REPO, CFG, self.bot_pr(), self.state()))
        self.assertEqual(reviewed, ["alice"])

    def test_unlisted_author_and_requester_is_skipped_with_one_log_line(self):
        logged, timeline_reads = [], []

        def timeline(*a):
            timeline_reads.append(a)
            return timeline_of("someone 2026-11-01T10:00:00Z")
        state = self.state()
        with fake_github(self, login="example-user", timeline=timeline), \
             mock.patch.object(r, "event", lambda *a: logged.append(a)), \
             mock.patch.object(r, "review", lambda *a: self.fail("should be skipped")):
            for _ in range(3):
                self.assertTrue(r.review_one(REPO, CFG, self.bot_pr(), state))
        self.assertEqual(len(logged), 1)
        self.assertEqual(logged[0][0], "SKIPPED")
        self.assertIn("requested by someone: neither is listed", logged[0][2])
        self.assertEqual(len(timeline_reads), 1)  # cached until the PR changes

    def test_a_new_request_on_a_handled_commit_reviews_it_again(self):
        logged, reviewed = [], []
        requests = ["alice 2026-11-01T10:00:00Z"]
        my_reviews = [f"2026-11-01T10:00:30Z COMMENTED {'b' * 40}"]
        gh = fake_github(self, login="example-user", head_sha="b" * 40,
                         reviews=lambda *a: reviews_of(my_reviews[-1]),
                         timeline=lambda *a: timeline_of(requests[-1]))
        state = self.state()
        state["reviewed"] = {f"{REPO}#7": "b" * 40}
        state["handled_at"] = {f"{REPO}#7": r.epoch("2026-11-01T10:00:30Z")}
        pr = {k: v for k, v in PR.items() if k != "headRefOid"}
        with gh, mock.patch.object(r, "event", lambda *a: logged.append(a[0])), \
             mock.patch.object(r, "review", lambda repo, cfg, pr, state: reviewed.append(pr["number"]) or True):
            self.assertTrue(r.review_one(REPO, CFG, {**pr, "updatedAt": "u1"}, state))
            self.assertEqual(reviewed, [])  # the request is older than the review
            requests.append("alice 2026-11-02T20:08:52Z")
            self.assertTrue(r.review_one(REPO, CFG, {**pr, "updatedAt": "u2"}, state))
        self.assertEqual(reviewed, [7])
        self.assertEqual(logged, ["NOTICE"])
        self.assertNotIn(f"{REPO}#7", state["reviewed"])

    def test_a_new_request_after_a_standing_approval_is_only_logged(self):
        logged = []

        gh = fake_github(self, login="example-user", head_sha="b" * 40,
                         reviews=reviews_of(f"2026-11-01T10:00:30Z APPROVED {'b' * 40}"),
                         timeline=timeline_of("carol 2026-11-02T20:08:52Z"))
        state = self.state()
        state["reviewed"] = {f"{REPO}#7": "b" * 40}
        pr = {**{k: v for k, v in PR.items() if k != "headRefOid"}, "updatedAt": "u1"}
        with gh, mock.patch.object(r, "event", lambda *a: logged.append(a[0])), \
             mock.patch.object(r, "review", lambda *a: self.fail("should not approve twice")):
            for _ in range(3):
                self.assertTrue(r.review_one(REPO, CFG, pr, state))
        self.assertEqual(logged, ["NOTICE"])

    def test_expired_login_is_not_counted_and_notifies_once(self):
        def review(*a):
            raise claude_cli.AuthExpired("expired")
        state = self.run_times(5, review)
        self.assertEqual(state["failures"], {})
        self.assertEqual(state["reviewed"], {})
        self.assertEqual(self.notified, ["PR autopilot: Claude login expired"])

    def test_gives_up_after_max_failures(self):
        def review(*a):
            raise RuntimeError("broken")
        state = self.run_times(r.MAX_FAILURES, review)
        self.assertEqual(state["reviewed"], {f"{REPO}#7": PR["headRefOid"]})
        self.assertEqual(self.notified, ["PR autopilot gave up"])

    def test_persistent_poll_failure_notifies(self):
        self.run_times(r.POLL_FAIL_ALERT, lambda *a: True, poll_ok=False)
        self.assertEqual(self.notified, ["PR autopilot can't reach GitHub"])

    def test_corrupt_state_is_moved_aside(self):
        r.STATE_FILE.write_text("{not json")
        state = r.load_state()
        self.assertEqual(state["reviewed"], {})
        self.assertTrue(list(self.tmp.glob("state.json.corrupt-*")))
        self.assertEqual(self.notified, ["PR autopilot"])


class FakeStore:
    """The ConfigMap, in memory: a state, a resourceVersion and an on/off switch."""

    def __init__(self, data=None):
        self.data, self.version, self.down = data, 1, False
        self.saves = 0
        self.other_writer = []  # changes another writer makes just before our next saves

    def current(self):
        return str(self.version) if self.data is not None else None

    def load(self):
        if self.down:
            raise state_store.Unavailable("connection refused")
        return copy.deepcopy(self.data), self.current()

    def save(self, state, version):
        if self.down:
            raise state_store.Unavailable("connection refused")
        if self.other_writer:
            self.other_writer.pop(0)(self.data)
            self.version += 1
        if version != self.current():
            raise state_store.Conflict("the object has been modified")
        self.data, self.version = copy.deepcopy(state), self.version + 1
        self.saves += 1
        return str(self.version)


class ConfigMapStateTest(Base):
    def setUp(self):
        super().setUp()
        self.store = FakeStore()
        self.down_file = self.tmp / "state-store-down.json"
        self.spool = self.tmp / "state-unsaved.json"
        self.events = []
        for name, value in {"STATE_BACKEND": "configmap", "state_store_client": lambda: self.store,
                            "STORE_MEMORY": self.fresh_memory(), "STATE_DOWN_FILE": self.down_file,
                            "STATE_SPOOL_FILE": self.spool, "event": lambda *a: self.events.append(a)}.items():
            p = mock.patch.object(r, name, value)
            p.start()
            self.addCleanup(p.stop)

    @staticmethod
    def fresh_memory():
        return {"state": None, "base": None, "version": None, "seeded": False}

    def new_process(self):
        """launchd runs --once: each run starts with nothing in memory."""
        r.STORE_MEMORY = self.fresh_memory()  # restored by the patch in setUp

    def run_once(self, prs, review_fn=lambda *a: True, complete=True):
        def find_prs(config):
            r.SEARCH_COMPLETE = complete
            return prs
        with fake_github(self, head_sha=PR["headRefOid"]), \
             mock.patch.object(r, "review", review_fn), mock.patch.object(r, "find_prs", find_prs), \
             mock.patch.object(r, "changed_repos", lambda s: {REPO}), \
             mock.patch.object(r, "load_config", lambda: {REPO: CFG}), \
             mock.patch.object(r, "SEARCH_COMPLETE", False):
            r.run_once()

    def test_the_lock_keeps_a_second_owner_out_until_the_heartbeat_is_stale(self):
        self.store.data = {"reviewed": {}, "owner": {"id": "dispatcher@vm", "heartbeat": time.time() - 60}}
        with mock.patch.dict(os.environ, {"PR_AUTOPILOT_OWNER": "laptop@mac"}):
            self.run_once([(REPO, PR)], review_fn=lambda *a: self.fail("the other owner is alive"))
            self.assertEqual(self.store.data["owner"]["id"], "dispatcher@vm")
            self.assertEqual(self.store.saves, 0)
            waiting = [e for e in self.events if e[0] == "NOTICE" and "waiting for the lock" in e[1]]
            self.assertEqual(len(waiting), 1)
            self.assertIn("held by dispatcher@vm until 20", waiting[0][1])
            # Silent for longer than LOCK_SECONDS: this one takes over and reviews.
            self.store.data["owner"]["heartbeat"] = time.time() - r.LOCK_SECONDS - 1
            self.new_process()
            reviewed = []
            self.run_once([(REPO, PR)], review_fn=lambda *a: reviewed.append(1) or True)
        self.assertEqual(reviewed, [1])
        self.assertEqual(self.store.data["owner"]["id"], "laptop@mac")
        self.assertIn(("NOTICE",), [e[:1] for e in self.events])

    def test_taking_the_lock_gives_way_when_someone_else_writes_first(self):
        self.store.data = {"reviewed": {}}
        self.store.other_writer.append(lambda d: d.update(owner={"id": "dispatcher@vm", "heartbeat": time.time()}))
        with mock.patch.dict(os.environ, {"PR_AUTOPILOT_OWNER": "laptop@mac"}):
            self.run_once([(REPO, PR)], review_fn=lambda *a: self.fail("lost the race"))
        self.assertEqual(self.store.data["owner"]["id"], "dispatcher@vm")

    def test_a_conflict_never_merges_two_owners_into_one(self):
        with mock.patch.dict(os.environ, {"PR_AUTOPILOT_OWNER": "laptop@mac"}):
            self.store.data = {"reviewed": {}, "owner": {"id": "laptop@mac", "heartbeat": 1}}
            state = r.load_state()
            self.assertTrue(r.hold_lock(state))
            state["reviewed"]["a#3"] = "s3"
            self.store.other_writer.append(
                lambda d: d.update(owner={"id": "dispatcher@vm", "heartbeat": time.time()}))
            r.save_state(state)
        self.assertEqual(self.store.data["owner"]["id"], "dispatcher@vm")
        self.assertEqual(self.store.data["reviewed"], {})  # the displaced runner writes nothing
        self.assertEqual(state["owner"]["id"], "dispatcher@vm")  # and now sees their state
        self.assertTrue(r.LOCK_SEEN["lost"])
        with self.assertRaises(r.LockLost):
            r.renew_lock(state)
        r.LOCK_SEEN["lost"] = False

    def test_a_good_poll_records_last_poll_and_a_401_is_kept_until_fixed(self):
        self.store.data = {"reviewed": {}}
        self.run_once([])
        self.assertGreater(self.store.data["last_poll"], time.time() - 5)

        def refused(state):
            raise github_api.Unauthorized("GET", "notifications", 401, "Bad credentials")
        self.new_process()
        with mock.patch.object(r, "find_prs", lambda c: self.fail("no search with a bad token")), \
             mock.patch.object(r, "changed_repos", refused), mock.patch.object(r, "load_config", lambda: {REPO: CFG}):
            r.run_once()
        self.assertIn("github_401", self.store.data)
        self.assertEqual([e[0] for e in self.events if e[0] == "AUTH"], ["AUTH"])
        self.assertEqual(self.notified, ["PR autopilot: GitHub token refused"])
        self.new_process()
        self.run_once([])
        self.assertNotIn("github_401", self.store.data)

    def test_a_conflict_reloads_and_reapplies_this_runs_changes(self):
        self.store.data = {"reviewed": {"a#1": "s1", "a#2": "s2"}, "failures": {}, "rescan": False}
        state = r.load_state()
        state["reviewed"]["a#3"] = "s3"     # this run handled a#3
        del state["reviewed"]["a#1"]        # and forgot a#1
        self.store.other_writer.append(lambda d: d["reviewed"].update({"b#9": "s9"}))
        r.save_state(state)
        self.assertEqual(self.store.data["reviewed"], {"a#2": "s2", "a#3": "s3", "b#9": "s9"})
        self.assertEqual(self.store.saves, 1)
        self.assertEqual(state["reviewed"], self.store.data["reviewed"])  # the caller sees the merge

    def test_a_store_that_keeps_changing_is_given_up_on_without_a_local_write(self):
        self.store.data = {"reviewed": {}}
        state = r.load_state()
        state["reviewed"]["a#3"] = "s3"
        self.store.other_writer = [lambda d: None] * 10
        self.assertFalse(r.save_state_configmap(state))
        self.assertEqual(self.store.saves, 0)
        self.assertFalse(r.STATE_FILE.exists())

    def test_an_unreachable_store_skips_the_save_and_never_uses_the_local_file(self):
        self.store.data = {"reviewed": {"a#1": "s1"}}
        state = r.load_state()
        state["reviewed"]["a#3"] = "s3"
        self.store.down = True
        r.save_state(state)  # no exception
        self.assertFalse(r.STATE_FILE.exists())
        self.assertEqual(self.store.data, {"reviewed": {"a#1": "s1"}})
        # Loop mode: the next load also fails, so the run goes on with the state in memory.
        self.assertIs(r.load_state(), state)
        # Once it is back, the change not saved yet is applied on top of the store.
        self.store.down = False
        self.store.data["reviewed"]["b#9"] = "s9"
        self.store.version += 1
        state = r.load_state()
        self.assertEqual(state["reviewed"], {"a#1": "s1", "a#3": "s3", "b#9": "s9"})
        r.save_state(state)
        self.assertEqual(self.store.data["reviewed"], {"a#1": "s1", "a#3": "s3", "b#9": "s9"})
        self.assertFalse(r.STATE_FILE.exists())

    def test_a_failed_first_load_skips_the_run(self):
        r.STATE_FILE.write_text(json.dumps({"reviewed": {}}))  # an old local file is never used
        self.store.down = True
        before = r.STATE_FILE.read_text()
        self.run_once([(REPO, PR)], review_fn=lambda *a: self.fail("nothing may be reviewed"))
        self.assertIsNone(self.store.data)
        self.assertEqual(r.STATE_FILE.read_text(), before)
        self.assertTrue(self.down_file.exists())
        self.assertEqual(self.notified, [])  # not yet: the first runs only log
        # After STATE_DOWN_ALERT the user hears about it, once.
        self.down_file.write_text(json.dumps({"since": time.time() - r.STATE_DOWN_ALERT}))
        self.run_once([(REPO, PR)], review_fn=lambda *a: self.fail("nothing may be reviewed"))
        self.run_once([(REPO, PR)], review_fn=lambda *a: self.fail("nothing may be reviewed"))
        self.assertEqual(self.notified, ["PR autopilot is paused"])
        # Back again: the run goes ahead and the marker is gone.
        self.store.down = False
        self.store.data = {"reviewed": {}}
        self.run_once([(REPO, PR)])
        self.assertFalse(self.down_file.exists())
        self.assertEqual(self.store.saves, 2)  # taking the lock, then the run's state

    def test_first_use_starts_from_the_local_file_then_retires_it(self):
        r.STATE_FILE.write_text(json.dumps({"reviewed": {f"{REPO}#7": PR["headRefOid"]}}))
        self.run_once([(REPO, PR)])
        self.assertEqual(self.store.data["reviewed"], {f"{REPO}#7": PR["headRefOid"]})
        self.assertFalse(r.STATE_FILE.exists())
        self.assertTrue(r.STATE_FILE.with_name("state.json.migrated").exists())
        # The ConfigMap is deleted later: start empty and say so, never from the old file.
        self.new_process()
        self.store.data = None
        state = r.load_state()
        self.assertEqual(state["reviewed"], {})
        self.assertTrue(any("not found" in e[1] for e in self.events if e[0] == "WARN"))

    def test_a_failed_first_create_keeps_the_local_file(self):
        r.STATE_FILE.write_text(json.dumps({"reviewed": {"a#1": "s1"}}))
        state = r.load_state()
        self.store.down = True
        r.save_state(state)
        self.assertTrue(r.STATE_FILE.exists())

    def test_an_unchanged_state_is_not_written(self):
        self.store.data = {"reviewed": {"a#1": "s1"}, "rescan": False, "failures": {}}
        version = self.store.current()
        state = r.load_state()
        self.assertTrue(r.save_state_configmap(state))
        self.assertEqual((self.store.saves, self.store.current()), (0, version))
        state["reviewed"]["a#2"] = "s2"
        r.save_state(state)
        self.assertEqual(self.store.saves, 1)

    def test_a_failed_save_is_spooled_and_merged_by_the_next_run(self):
        self.store.data = {"reviewed": {"a#1": "s1"}, "failures": {}}
        state = r.load_state()
        state["reviewed"]["a#3"] = "s3"
        state["failures"]["a#4@x"] = 2
        self.store.down = True
        r.save_state(state)
        self.assertTrue(self.spool.exists())
        self.assertFalse(r.STATE_FILE.exists())
        # The next run is a new process. Meanwhile another writer changed the ConfigMap.
        self.new_process()
        self.store.down = False
        self.store.data["reviewed"]["b#9"] = "s9"
        self.store.version += 1
        state = r.load_state()
        self.assertEqual(state["reviewed"], {"a#1": "s1", "a#3": "s3", "b#9": "s9"})
        self.assertEqual(state["failures"], {"a#4@x": 2})  # the failure count is not lost
        r.save_state(state)
        self.assertEqual(self.store.data["reviewed"], {"a#1": "s1", "a#3": "s3", "b#9": "s9"})
        self.assertFalse(self.spool.exists())

    def test_a_spool_never_reaches_the_store_without_a_load(self):
        self.spool.write_text(json.dumps({"base": {}, "state": {"reviewed": {"a#3": "s3"}}}))
        self.store.down = True
        with self.assertRaises(r.StateUnavailable):
            r.load_state()
        self.assertIsNone(self.store.data)
        self.assertTrue(self.spool.exists())

    def test_handled_prs_that_left_the_queue_are_pruned(self):
        waiting, gone = f"{REPO}#7", f"{REPO}#8"
        old = "c" * 40  # an older commit of the waiting PR, so the run calls review() (faked)
        self.store.data = {
            "reviewed": {waiting: old, gone: "b" * 40},
            "handled_at": {waiting: 1.0, gone: 2.0},
            "failures": {f"{waiting}@{old}": 1, f"{gone}@{'b' * 40}": 3},
        }
        self.run_once([(REPO, PR)], complete=False)  # a search that missed PRs prunes nothing
        self.assertIn(gone, self.store.data["reviewed"])
        self.run_once([(REPO, PR)])
        self.assertEqual(self.store.data["reviewed"], {waiting: old})
        self.assertEqual(self.store.data["handled_at"], {waiting: 1.0})
        self.assertEqual(self.store.data["failures"], {f"{waiting}@{old}": 1})

    def test_the_local_file_backend_still_prunes_nothing(self):
        r.STATE_BACKEND = "file"  # restored by the patch in setUp
        gone = f"{REPO}#8"
        r.STATE_FILE.write_text(json.dumps({"reviewed": {gone: "b" * 40}, "failures": {}}))
        self.run_once([(REPO, PR)])
        self.assertEqual(json.loads(r.STATE_FILE.read_text())["reviewed"], {gone: "b" * 40})
        self.assertIsNone(self.store.data)

    def test_an_unposted_job_round_trips_and_its_outcome_reaches_the_store(self):
        sha = PR["headRefOid"]
        r.Job(REPO, "7", sha).write(status="running", pid=1, started=1.0, reason="r", audit=True)
        r.Job(REPO, "7", sha).write(status="unposted", verdict="block", post_event="COMMENT",
                                    post_body="body", post_attempts=2)
        job = r.Job(REPO, "7", sha)  # a new object reads it back from disk
        data = job.read()
        self.assertEqual(job.status(), "unposted")
        self.assertEqual({k: data[k] for k in ("audit", "post_event", "post_body", "post_attempts")},
                         {"audit": True, "post_event": "COMMENT", "post_body": "body", "post_attempts": 2})
        known = {"status"} | {k for keys in state_store.JOB_FIELDS.values() for k in keys}
        self.assertLessEqual(set(data), known)
        self.store.data = {"reviewed": {}}
        state = r.load_state()
        with fake_github(self):  # a post retry needs no diff
            self.assertFalse(r.review(REPO, CFG, PR, state))
        self.assertEqual(self.posted, [("7", "COMMENT", "body")])
        r.save_state(state)
        self.assertEqual(self.store.data["reviewed"], {f"{REPO}#7": sha})
        self.assertIsNone(job.read())


class MiloApiTest(unittest.TestCase):
    KEY = TEST_RSA_KEY  # made at import, see make_test_rsa_key

    def test_rs256_signature_checks_out_with_the_public_key(self):
        n, d = milo_api.private_numbers(self.KEY)
        sig = milo_api.rsa_sign(b"hello", self.KEY)
        em = pow(int.from_bytes(sig, "big"), 65537, n).to_bytes(len(sig), "big")
        self.assertTrue(em.startswith(b"\x00\x01\xff"))
        self.assertTrue(em.endswith(milo_api.SHA256_DIGEST_INFO + milo_api.hashlib.sha256(b"hello").digest()))

    def test_the_service_account_login_sends_a_jwt_bearer_grant(self):
        sent = []

        def urlopen(req, timeout):
            sent.append(req)
            return contextlib.nullcontext(io.BytesIO(b'{"access_token": "at", "expires_in": 3600}'))
        key = {"client_id": "123", "private_key_id": "k1", "private_key": self.KEY, "scope": "openid aud"}
        with mock.patch.object(milo_api.urllib.request, "urlopen", urlopen):
            self.assertEqual(milo_api.sa_token(key, now=1000), ("at", 4600))
        form = dict(urllib.parse.parse_qsl(sent[0].data.decode()))
        self.assertEqual(sent[0].full_url, "https://auth.datum.net/oauth/v2/token")
        self.assertEqual((form["grant_type"], form["scope"]), ("urn:ietf:params:oauth:grant-type:jwt-bearer", "openid aud"))
        header, claims, _ = form["assertion"].split(".")
        pad = lambda p: json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
        self.assertEqual(pad(header), {"alg": "RS256", "typ": "JWT", "kid": "k1"})
        c = pad(claims)
        self.assertEqual((c["iss"], c["sub"], c["aud"], c["exp"] - c["iat"]), ("123", "123", "https://auth.datum.net", 60))

    def test_errors_carry_the_kubernetes_reason(self):
        def urlopen(req, timeout):
            raise milo_api.urllib.error.HTTPError(req.full_url, 409, "Conflict", {},
                                                  io.BytesIO(b'{"reason": "Conflict", "message": "modified"}'))
        with mock.patch.dict(milo_api._TOKEN, {"value": "t", "expires": time.time() + 3600}), \
             mock.patch.object(milo_api.urllib.request, "urlopen", urlopen), self.assertRaises(milo_api.Conflict) as e:
            milo_api.merge_patch(milo_api.configmaps_path("p", "cm"), {})
        self.assertEqual(e.exception.reason, "Conflict")


class ConfigMapStoreTest(unittest.TestCase):
    """ConfigMapStore over milo_api, with milo_api's calls faked."""

    def run_with(self, answer=None, error=None):
        calls = []

        def call(method):
            def fake(path, doc=None):
                calls.append((method, path, doc))
                if error:
                    raise error
                return answer
            return fake
        for name in ("get", "create", "merge_patch"):
            p = mock.patch.object(milo_api, name, call(name))
            p.start()
            self.addCleanup(p.stop)
        return calls, state_store.ConfigMapStore("project-x", None, "cm")

    def test_load_reads_the_state_and_its_version(self):
        obj = {"metadata": {"resourceVersion": "42"}, "data": {"state.json": '{"reviewed": {"a#1": "s"}}'}}
        calls, store = self.run_with(obj)
        self.assertEqual(store.load(), ({"reviewed": {"a#1": "s"}}, "42"))
        self.assertEqual(calls[0][:2], ("get", "apis/resourcemanager.miloapis.com/v1alpha1/projects/project-x/"
                                               "control-plane/api/v1/namespaces/default/configmaps/cm"))

    def test_not_found_is_an_empty_store_but_other_errors_are_not(self):
        _, store = self.run_with(error=milo_api.NotFound("GET", "cm", 404, "NotFound", "not found"))
        self.assertEqual(store.load(), (None, None))
        _, store = self.run_with(error=milo_api.MiloError("GET", "cm", 401, "Unauthorized", "token expired"))
        with self.assertRaises(state_store.Unavailable):
            store.load()
        _, store = self.run_with({"metadata": {"resourceVersion": "1"}, "data": {"state.json": "not json"}})
        with self.assertRaises(state_store.Unavailable):
            store.load()

    def test_save_sends_the_version_it_read(self):
        calls, store = self.run_with({"metadata": {"resourceVersion": "43"}})
        self.assertEqual(store.save({"reviewed": {}}, "42"), "43")
        method, path, doc = calls[0]
        self.assertEqual(method, "merge_patch")
        self.assertTrue(path.endswith("/configmaps/cm"))
        self.assertEqual(doc["metadata"], {"resourceVersion": "42"})
        self.assertEqual(json.loads(doc["data"]["state.json"]), {"reviewed": {}})
        self.assertEqual(store.save({}, None), "43")
        self.assertEqual(calls[1][0], "create")
        self.assertTrue(calls[1][1].endswith("/configmaps"))
        self.assertEqual(calls[1][2]["metadata"]["name"], "cm")

    def test_save_conflicts_and_failures(self):
        _, store = self.run_with(error=milo_api.Conflict("PATCH", "cm", 409, "Conflict", "modified"))
        with self.assertRaises(state_store.Conflict):
            store.save({}, "1")
        _, store = self.run_with(error=milo_api.MiloError("PATCH", "cm", 0, "", "i/o timeout"))
        with self.assertRaises(state_store.Unavailable):
            store.save({}, "1")
        with mock.patch.object(state_store, "MAX_BYTES", 10), self.assertRaises(state_store.Unavailable):
            store.save({"reviewed": {"a#1": "x" * 40}}, "1")

    def test_another_key_for_the_events_ring(self):
        obj = {"metadata": {"resourceVersion": "7"}, "data": {"events.json": '{"next_seq": 3}'}}
        _, store = self.run_with(obj)
        store = state_store.ConfigMapStore("project-x", None, "pr-autopilot-events", key="events.json")
        self.assertEqual(store.load(), ({"next_seq": 3}, "7"))

    def test_merge(self):
        base = {"reviewed": {"a": 1, "b": 2}, "rescan": False, "me": "x"}
        mine = {"reviewed": {"a": 1, "c": 3}, "rescan": True, "me": "x"}
        theirs = {"reviewed": {"a": 9, "b": 2, "d": 4}, "rescan": False, "me": "y", "new": 1}
        self.assertEqual(state_store.merge(base, mine, theirs),
                         {"reviewed": {"a": 9, "c": 3, "d": 4}, "rescan": True, "me": "y", "new": 1})


QUICK_OK = {"verdict": "approve", "needs_full_review": False, "summary": "looks fine QUICK-SAID-THIS",
            "critical": [], "full_review_reason": ""}
QUICK_UP = {"verdict": "approve", "needs_full_review": True, "summary": "s", "critical": [],
            "full_review_reason": "shared base"}
FINDINGS = {"summary": "Adds a field.", "title": "t", "denied": [],
            "blocking": [{"severity": "blocking", "location": "a.go:1", "text": "Accepts javascript: URLs."}],
            "other": []}
SHA = "a" * 40


class PrWorkerTest(unittest.TestCase):
    """The quick-then-full logic the review VM runs (and the laptop, when Datum is down)."""

    def run_worker(self, plan="quick", quick=QUICK_OK, audit=False, diff=None, moved=False, findings=FINDINGS):
        calls = {"quick": [], "full": []}

        def read(repo, num, sha):
            return None if moved else ("t", diff if diff is not None else diff_for("a.yaml"))

        def fake_quick(*a):
            calls["quick"].append(a)
            return quick

        def fake_full(*a, **k):
            calls["full"].append((a, k))
            return findings
        out = pr_worker.review(REPO, "7", SHA, plan=plan, focus="rule reason" if plan == "full" else "",
                               audit=audit, context="ctx", model="opus", quick_model="sonnet",
                               read=read, quick=fake_quick, full=fake_full)
        return out, calls

    def test_quick_only_result(self):
        out, calls = self.run_worker()
        self.assertEqual(calls["full"], [])
        self.assertEqual((out["route"], out["verdict"], out["findings"]), ("quick", "approve", None))
        self.assertEqual(out["quick"], QUICK_OK)
        self.assertEqual(out["format"], pr_worker.FORMAT)
        self.assertEqual(calls["quick"][0][-1], "sonnet")  # the quick model, not the full one

    def test_quick_then_full_in_one_run(self):
        out, calls = self.run_worker(quick=QUICK_UP)
        self.assertEqual(len(calls["quick"]), 1)
        self.assertEqual(calls["full"][0][1]["focus"], "shared base")
        self.assertEqual((out["route"], out["verdict"], out["findings"]), ("quick", "block", FINDINGS))
        out, calls = self.run_worker(quick={**QUICK_OK, "verdict": "block", "critical": ["leaks a key"]})
        self.assertEqual(calls["full"][0][1]["focus"], "leaks a key")

    def test_an_audit_full_review_learns_nothing_from_the_quick_review(self):
        out, calls = self.run_worker(audit=True)
        (args, kwargs), = calls["full"]
        self.assertEqual(kwargs["focus"], pr_worker.AUDIT_FOCUS)
        self.assertNotIn("QUICK-SAID-THIS", json.dumps([args, kwargs]))
        self.assertEqual((out["route"], out["verdict"]), ("audit", "block"))
        # An audit only applies to a quick approval: an escalation is not an audit.
        out, _ = self.run_worker(quick=QUICK_UP, audit=True)
        self.assertEqual(out["route"], "quick")

    def test_rules_skip_the_quick_review(self):
        out, calls = self.run_worker(plan="full")
        self.assertEqual(calls["quick"], [])
        self.assertEqual(calls["full"][0][1]["focus"], "rule reason")
        self.assertEqual(out["route"], "rules")

    def test_a_large_diff_skips_the_quick_review(self):
        out, calls = self.run_worker(diff="x" * (pr_worker.MAX_DIFF_CHARS + 1))
        self.assertEqual(calls["quick"], [])
        self.assertEqual(calls["full"][0][1]["focus"], pr_worker.DIFF_TOO_LARGE)
        self.assertEqual(out["route"], "rules")

    def test_a_moved_head_reviews_nothing(self):
        out, calls = self.run_worker(moved=True)
        self.assertEqual((out["verdict"], calls), ("moved", {"quick": [], "full": []}))
        out, _ = self.run_worker(quick=QUICK_UP, findings=None)  # moved during the full review
        self.assertEqual(out["verdict"], "moved")

    def test_read_pr_checks_the_head_around_the_diff(self):
        def fake(heads, diff="the diff"):
            heads = iter(heads)
            return [mock.patch.object(github_api, "pull", lambda repo, num: {"head": {"sha": next(heads)}, "title": "t"}),
                    mock.patch.object(github_api, "head_sha", lambda repo, num: next(heads)),
                    mock.patch.object(github_api, "diff", lambda repo, num: diff)]

        def read(patches):
            with contextlib.ExitStack() as stack:
                for p in patches:
                    stack.enter_context(p)
                return pr_worker.read_pr(REPO, "7", SHA)
        self.assertIsNone(read(fake([SHA, "b" * 40])))  # a commit landed during the diff
        self.assertIsNone(read(fake(["b" * 40])))  # moved before
        self.assertEqual(read(fake([SHA, SHA])), ("t", "the diff"))
        self.assertEqual(read(fake([SHA, SHA], diff=None)), ("t", None))  # too large for GitHub


class DatumRouteTest(Base):
    """The dispatcher starts one VM per PR commit and runs no quick review itself."""

    def setUp(self):
        super().setUp()
        self.vm, self.authors = [], []
        for name, value in {"start_pr_review": lambda *a, **k: self.vm.append(a) or self.authors.append(k["author"]),
                            "datum_jobs": lambda: 0,
                            "quick_review": lambda *a: self.fail("no quick review on the laptop")}.items():
            p = mock.patch.object(r, name, value)
            p.start()
            self.addCleanup(p.stop)

    def run_review(self, diff, on_datum=True):
        with fake_github(self, diff=diff, head_sha=PR["headRefOid"]), \
             mock.patch.object(remote_review, "runs_on_datum", lambda repo: on_datum):
            return r.review(REPO, CFG, PR, self.state())

    def test_a_plain_pr_gets_a_quick_plan(self):
        self.assertFalse(self.run_review(diff_for("apps/x/base/a.yaml")))
        self.assertEqual(self.vm, [(REPO, "7", SHA, "quick", "", False)])
        self.assertEqual(self.authors, ["by alice"])
        self.assertEqual((self.posted, self.started), ([], []))

    def test_a_rule_hit_gets_a_full_plan(self):
        self.run_review(diff_for("apps/x/production/a.yaml"))
        self.assertEqual(self.vm, [(REPO, "7", SHA, "full", "touches apps/x/production/a.yaml", False)])

    def test_the_audit_is_rolled_before_the_vm_starts(self):
        with mock.patch.object(r.random, "random", lambda: 0.01):
            self.run_review(diff_for("apps/x/base/a.yaml"))
            self.run_review(diff_for("apps/x/production/a.yaml"))  # a rule hit is never an audit
        self.assertEqual([v[3:] for v in self.vm], [("quick", "", True),
                                                     ("full", "touches apps/x/production/a.yaml", False)])

    def test_waits_for_a_free_vm_slot(self):
        with mock.patch.object(r, "datum_jobs", lambda: r.MAX_DATUM_JOBS):
            self.assertFalse(self.run_review(diff_for("apps/x/base/a.yaml")))
        self.assertEqual(self.vm, [])

    def test_codeowners_is_still_left_to_you(self):
        self.assertTrue(self.run_review(diff_for("CODEOWNERS")))
        self.assertEqual((self.vm, self.notified), ([], ["PR needs your review"]))

    def test_a_repo_the_vm_cannot_read_keeps_the_laptop_path(self):
        with mock.patch.object(r, "quick_review", lambda *a: QUICK_OK):
            self.assertTrue(self.run_review(diff_for("apps/x/base/a.yaml"), on_datum=False))
        self.assertEqual(self.vm, [])
        self.assertEqual(self.posted, [("7", "APPROVE", "")])


class PrWorkerProcessTest(Base):
    """The worker process on the laptop: one VM outcome in, one post out."""

    def outcome(self, route="quick", findings=None, quick=QUICK_OK):
        return {"format": 2, "route": route, "verdict": "block" if findings and findings["blocking"] else "approve",
                "title": "t", "quick": quick, "focus": "", "findings": findings}

    def run_worker(self, outcome=None, error=None, audit=False, plan="quick"):
        events = []
        r.Job(REPO, "7", SHA).write(status="running", pid=1, reason="", audit=audit, plan=plan, runner="datum",
                                    author="by alice")

        def remote(*a, **k):
            self.remote_opts = k
            if error:
                raise error
            return outcome
        with mock.patch.object(r, "load_config", lambda: {REPO: CFG}), \
             mock.patch.object(r, "event", lambda *a: events.append(a)), \
             mock.patch.object(remote_review, "review_pr", remote):
            r.run_pr_review(REPO, "7", SHA)
        return events

    def test_a_quick_only_outcome_is_approved(self):
        events = self.run_worker(self.outcome())
        self.assertEqual(self.posted, [("7", "APPROVE", "")])
        self.assertEqual([e[0] for e in events], ["APPROVED"])
        self.assertIn("by alice · quick review on Datum", events[0])
        self.assertEqual(r.Job(REPO, "7", SHA).status(), "done")
        self.assertEqual((self.remote_opts["plan"], self.remote_opts["audit"]), ("quick", False))

    def test_a_full_approval_carries_its_non_blocking_findings(self):
        events = self.run_worker(self.outcome(route="rules", findings=FullReviewPostTest.WITH_NOTES), plan="full")
        self.assertEqual(self.posted, [("7", "APPROVE", FullReviewPostTest.WITH_NOTES_BODY)])
        self.assertEqual([e[0] for e in events], ["APPROVED"])

    def test_a_full_approval_with_no_findings_is_bare(self):
        no_findings = {**FullReviewPostTest.WITH_NOTES, "other": []}
        self.run_worker(self.outcome(route="rules", findings=no_findings), plan="full")
        self.assertEqual(self.posted, [("7", "APPROVE", "")])

    def test_quick_then_full_posts_the_full_result(self):
        events = self.run_worker(self.outcome(findings=FINDINGS, quick=QUICK_UP) | {"focus": "shared base"})
        self.assertEqual(self.posted, [("7", "COMMENT", "Adds a field.\n\n- `a.go:1`: Accepts javascript: URLs.")])
        self.assertEqual([e[0] for e in events], ["REVIEWING", "BLOCKED"])
        self.assertIn("route: quick", events[0])
        self.assertIn("why: shared base", events[0])
        self.assertIn("by alice · full review on Datum in the same VM as the quick review", events[0])
        # The dashboard joins the two like a laptop review.
        rows = [{"ts": i, "kind": e[0], "subject": e[1], "details": list(e[2:])} for i, e in enumerate(events)]
        self.assertEqual(dashboard.routing(rows)["counts"]["quick"]["BLOCKED"], 1)

    def test_a_blocked_audit_from_the_vm_is_an_audit_miss(self):
        events = self.run_worker(self.outcome(route="audit", findings=FINDINGS), audit=True)
        self.assertEqual([e[0] for e in events], ["REVIEWING", "BLOCKED", "AUDIT MISS"])
        self.assertIn("why: random audit of a quick approval", events[0])
        self.assertTrue(self.remote_opts["audit"])

    def test_a_diff_that_grew_in_the_vm_still_joins_the_dashboard_as_rules(self):
        events = self.run_worker(self.outcome(route="rules", findings=FINDINGS, quick=None)
                                 | {"focus": pr_worker.DIFF_TOO_LARGE})
        self.assertEqual([e[0] for e in events], ["REVIEWING", "BLOCKED"])
        rows = [{"ts": i, "kind": e[0], "subject": e[1], "details": list(e[2:])} for i, e in enumerate(events)]
        self.assertEqual(dashboard.routing(rows)["counts"]["rules"]["BLOCKED"], 1)
        # A rules plan logged REVIEWING when it started, so the worker adds none.
        events = self.run_worker(self.outcome(route="rules", findings=FINDINGS, quick=None), plan="full")
        self.assertEqual([e[0] for e in events], ["BLOCKED"])

    def test_a_failed_post_is_kept_for_a_retry(self):
        def failing(*a, **k):
            raise r.GhError("POST", "repos/x/pulls/7/reviews", 0, "TLS handshake timeout")
        with mock.patch.object(r, "post_review", failing):
            self.run_worker(self.outcome())
        data = r.Job(REPO, "7", SHA).read()
        self.assertEqual((data["status"], data["post_event"], data["post_body"]), ("unposted", "APPROVE", ""))
        # The next run posts it without a new review (the c4a27e2 retry).
        with fake_github(self):  # a post retry needs no diff
            self.assertFalse(r.review(REPO, CFG, PR, self.state()))
        self.assertEqual(self.posted, [("7", "APPROVE", "")])

    def test_a_moved_head_is_stale(self):
        self.run_worker({**self.outcome(), "verdict": "moved"})
        self.assertEqual((r.Job(REPO, "7", SHA).status(), self.posted), ("stale", []))

    def test_falls_back_to_the_laptop_with_the_same_steps(self):
        full = []
        with mock.patch.object(pr_worker, "read_pr", lambda *a: ("t", diff_for("a.yaml"))), \
             mock.patch.object(pr_worker, "quick_review", lambda *a: QUICK_OK), \
             mock.patch.object(full_review, "review", lambda *a, **k: full.append(k) or {**FINDINGS, "blocking": []}):
            events = self.run_worker(error=remote_review.DatumUnavailable("deploy failed"), audit=True)
        self.assertEqual([f["focus"] for f in full], [pr_worker.AUDIT_FOCUS])
        self.assertEqual(self.posted, [("7", "APPROVE", "")])
        self.assertEqual([e[0] for e in events], ["WARN", "REVIEWING", "APPROVED"])
        self.assertEqual(r.Job(REPO, "7", SHA).read()["runner"], "laptop")

    def test_a_failure_in_the_vm_is_not_rerun_locally(self):
        with mock.patch.object(full_review, "review", lambda *a, **k: self.fail("no local rerun")):
            self.run_worker(error=RuntimeError("review on Datum failed: claude exited 1"))
        self.assertEqual((r.Job(REPO, "7", SHA).status(), self.posted), ("failed", []))

    def test_job_fields_stay_in_the_known_schema(self):
        self.run_worker(self.outcome())
        r.Job(REPO, "7", SHA).write(status="running", pid=1, started=1.0, reason="", audit=False,
                                    plan="quick", runner="datum", author="by x")
        known = {"status"} | {k for keys in state_store.JOB_FIELDS.values() for k in keys}
        self.assertLessEqual(set(r.Job(REPO, "7", SHA).read()), known)


class VmCanReadTest(unittest.TestCase):
    def test_the_vm_reads_private_repos_only_where_config_says_so(self):
        config = {"example-org/infra": {"review": "full"},          # no flag: the owner's applies
                  "example-org/secret": {"vm_can_read": False},     # its own value wins
                  "example-org/*": {"vm_can_read": True},
                  "other-org/*": {"review": "full"}}
        with mock.patch.object(remote_review, "is_public", lambda repo: repo == "other-org/milo"):
            self.assertTrue(remote_review.vm_can_read("example-org/infra", config))
            self.assertTrue(remote_review.vm_can_read("example-org/other", config))
            self.assertFalse(remote_review.vm_can_read("example-org/secret", config))
            self.assertTrue(remote_review.vm_can_read("other-org/milo", config))       # public
            self.assertFalse(remote_review.vm_can_read("other-org/private", config))   # needs the new token
            self.assertFalse(remote_review.vm_can_read("labs-org/x", config))      # no entry at all

    def test_repos_json_marks_only_datum_cloud_for_now(self):
        config = json.loads(remote_review.CONFIG_FILE.with_name("repos.example.json").read_text())
        flagged = sorted(k for k, v in config.items() if v.get("vm_can_read"))
        self.assertEqual(flagged, ["example-org/*"])


def load_review_job():
    spec = importlib.util.spec_from_file_location("review_job", pathlib.Path(__file__).with_name("remote") / "review-job.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ReviewJobTest(unittest.TestCase):
    """What the VM prints: one scrubbed, nonce-tagged result the dispatcher can parse."""

    def run_job(self, env: dict, outcome=None, error=None):
        job = load_review_job()
        seen = {}

        def fake(*a, **k):
            seen.update(k)
            if error:
                raise error
            return outcome
        base = {"REVIEW_REPO": REPO, "REVIEW_PR": "7", "REVIEW_SHA": SHA, "REVIEW_NONCE": "abc123",
                "CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat-SECRETVALUE"}
        out = io.StringIO()
        with mock.patch.dict(os.environ, {**base, **env}), \
             mock.patch.object(job, "wait_for_network", lambda: None), \
             mock.patch.object(job.pr_worker, "review", fake), \
             mock.patch.object(job, "usage", lambda: [{"kind": "quick", "input": 1}]), \
             contextlib.redirect_stdout(out):
            job.run()
        return remote_review.parse_result(out.getvalue(), "abc123"), seen

    def test_a_quick_plan_result_carries_the_outcome_and_the_old_fields(self):
        outcome = {"format": 2, "route": "quick", "verdict": "approve", "title": "t",
                   "quick": {**QUICK_OK, "summary": "token sk-ant-oat-SECRETVALUE"}, "focus": "", "findings": None}
        res, seen = self.run_job({"REVIEW_PLAN": "quick", "REVIEW_AUDIT": "1", "REVIEW_QUICK_MODEL": "haiku"}, outcome)
        self.assertEqual((seen["plan"], seen["audit"], seen["quick_model"]), ("quick", True, "haiku"))
        self.assertEqual((res["ok"], res["format"], res["route"], res["moved"], res["result"]),
                         (True, 2, "quick", False, None))
        self.assertEqual(res["usage"], [{"kind": "quick", "input": 1}])
        self.assertNotIn("SECRETVALUE", json.dumps(res))  # scrubbed as before

    def test_no_plan_means_full_only_as_older_dispatchers_expect(self):
        outcome = {"format": 2, "route": "rules", "verdict": "block", "title": "t", "quick": None,
                   "focus": "why", "findings": FINDINGS}
        res, seen = self.run_job({"REVIEW_FOCUS": "why"}, outcome)
        self.assertEqual((seen["plan"], seen["focus"], seen["audit"]), ("full", "why", False))
        self.assertEqual(res["result"], FINDINGS)

    def test_each_owner_gets_its_own_token_and_no_other_stays_in_the_env(self):
        job = load_review_job()
        seen = {}

        def fake(*a, **k):
            seen.update({k: v for k, v in os.environ.items() if k.startswith("GH_TOKEN")})
            return {"format": 2, "route": "quick", "verdict": "approve", "title": "t", "focus": "",
                    "quick": {**QUICK_OK, "summary": "saw milo-token-123456"}, "findings": None}
        env = {"REVIEW_REPO": "other-org/milo", "REVIEW_PR": "1", "REVIEW_SHA": SHA, "REVIEW_NONCE": "n1",
               "REVIEW_PLAN": "quick", "GH_TOKEN": "example-org-token-1",
               "GH_TOKEN_OTHER_ORG": "milo-token-123456", "GH_TOKEN_LABS_ORG": "labs-token-123456"}
        out = io.StringIO()
        with mock.patch.dict(os.environ, env), \
             mock.patch.object(job, "wait_for_network", lambda: None), \
             mock.patch.object(job.pr_worker, "review", fake), contextlib.redirect_stdout(out):
            job.run()
        self.assertEqual(seen, {"GH_TOKEN": "milo-token-123456"})  # agent_env drops this one too
        self.assertNotIn("milo-token-123456", out.getvalue())
        self.assertEqual(job.owner_token_var("labs-org/x"), "GH_TOKEN_LABS_ORG")
        # An owner with no token of its own keeps the default GH_TOKEN.
        with mock.patch.dict(os.environ, {"GH_TOKEN": "default-token", "GH_TOKEN_OTHER_ORG": "m" * 10}):
            job.pick_github_token("example-org/infra")
            self.assertEqual(os.environ["GH_TOKEN"], "default-token")
            self.assertNotIn("GH_TOKEN_OTHER_ORG", os.environ)

    def test_failures_come_back_through_the_same_channel(self):
        res, _ = self.run_job({"REVIEW_PLAN": "quick"}, error=RuntimeError("claude exited 1"))
        self.assertEqual((res["ok"], res["error"]), (False, "RuntimeError: claude exited 1"))

    def test_the_result_is_also_posted_to_the_callback_and_the_token_leaves_the_env(self):
        job = load_review_job()
        sent, env_seen = [], {}

        def fake(*a, **k):
            env_seen.update({k: v for k, v in os.environ.items() if k.startswith("REVIEW_CALLBACK")})
            return {"format": 2, "route": "quick", "verdict": "approve", "title": "t", "focus": "",
                    "quick": {**QUICK_OK, "summary": "cb-token-1234567"}, "findings": None}
        env = {"REVIEW_REPO": REPO, "REVIEW_PR": "7", "REVIEW_SHA": SHA, "REVIEW_NONCE": "n1",
               "REVIEW_PLAN": "quick", "REVIEW_CALLBACK_URL": "http://d.instances.datum.internal:8080/callback",
               "REVIEW_CALLBACK_TOKEN": "cb-token-1234567"}
        with mock.patch.dict(os.environ, env), \
             mock.patch.object(job, "wait_for_network", lambda: None), \
             mock.patch.object(job.pr_worker, "review", fake), \
             mock.patch.object(job, "callback", lambda url, token, payload: sent.append((url, token, payload))), \
             contextlib.redirect_stdout(io.StringIO()):
            job.run()
        self.assertEqual(env_seen, {})  # the review never sees the callback
        url, token, payload = sent[0]
        self.assertEqual((url, token), (env["REVIEW_CALLBACK_URL"], "cb-token-1234567"))
        self.assertNotIn("cb-token-1234567", payload)
        self.assertEqual(json.loads(payload)["verdict"], "approve")

    def test_the_callback_retries_a_reset_and_stops_on_a_refusal(self):
        job = load_review_job()
        answers, waits = [ConnectionResetError(104, "reset"), None], []

        def urlopen(req, timeout):
            answer = answers.pop(0)
            if answer:
                raise answer
            self.assertEqual(req.get_header("Authorization"), "Bearer tok")
            return contextlib.nullcontext(io.BytesIO(b""))
        with mock.patch.object(job.urllib.request, "urlopen", urlopen), contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(job.callback("http://x/callback", "tok", "{}", sleep=waits.append))
        self.assertEqual(waits, [2.0])

        def refused(req, timeout):
            raise job.urllib.error.HTTPError(req.full_url, 401, "no", {}, io.BytesIO(b""))
        with mock.patch.object(job.urllib.request, "urlopen", refused), contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(job.callback("http://x/callback", "tok", "{}", sleep=self.fail))

        def conflict(req, timeout):
            raise job.urllib.error.HTTPError(req.full_url, 409, "dup", {}, io.BytesIO(b""))
        with mock.patch.object(job.urllib.request, "urlopen", conflict), contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(job.callback("http://x/callback", "tok", "{}", sleep=self.fail))


class RemoteReviewPrTest(unittest.TestCase):
    def setUp(self):
        isolate_down_file(self)

    def run_pr(self, payload: dict, **opts):
        logs = ("[dfw-0/review] x  PR_AUTOPILOT_STARTED abc123\n"
                "[dfw-0/review] x  PR_AUTOPILOT_RESULT_BEGIN abc123\n"
                f"[dfw-0/review] x  {json.dumps(payload)}\n"
                "[dfw-0/review] x  PR_AUTOPILOT_RESULT_END\n")
        deployed = {}

        def run(cmd, **kw):
            if cmd[1:3] == ["compute", "deploy"]:
                deployed.update(json.loads(pathlib.Path(cmd[cmd.index("-f") + 1]).read_text()))
            if cmd[1:3] == ["get", "workloads"]:
                return subprocess.CompletedProcess(cmd, 0, '{"items": []}', "")
            if cmd[1:3] == ["compute", "logs"]:
                return subprocess.CompletedProcess(cmd, 0, logs, "")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        with mock.patch.object(remote_review.subprocess, "run", run), \
             mock.patch.object(remote_review.secrets, "token_hex", lambda n: "abc123"):
            try:
                out = remote_review.review_pr(REPO, "7", SHA, "", "opus", sleep=lambda s: None,
                                              digest_of=lambda ref: "sha256:" + "d" * 64, **opts)
            except Exception as e:
                out = e
        env = {e["name"]: e["value"] for e in
               deployed["spec"]["template"]["spec"]["runtime"]["sandbox"]["containers"][0]["env"]}
        return out, env

    def test_one_vm_returns_the_whole_outcome(self):
        payload = {"ok": True, "format": 2, "route": "audit", "verdict": "approve", "title": "t", "quick": QUICK_OK,
                   "focus": pr_worker.AUDIT_FOCUS, "findings": {**FINDINGS, "blocking": []}, "usage": [],
                   "moved": False, "result": {**FINDINGS, "blocking": []}}
        out, env = self.run_pr(payload, plan="quick", audit=True, quick_model="sonnet")
        self.assertEqual(out, {k: payload[k] for k in remote_review.OUTCOME_KEYS})
        self.assertEqual((env["REVIEW_PLAN"], env["REVIEW_AUDIT"], env["REVIEW_QUICK_MODEL"]),
                         ("quick", "1", "sonnet"))

    def test_a_quick_plan_waits_long_enough_for_quick_plus_full(self):
        quick, full = remote_review.RESULT_TIMEOUTS["quick"], remote_review.RESULT_TIMEOUTS["full"]
        self.assertGreaterEqual(quick, 600 + full_review.TIMEOUT_SECONDS)  # quick timeout, then a full review
        self.assertGreaterEqual(full, full_review.TIMEOUT_SECONDS)
        # The sweep never deletes a VM that may still be working on a quick plan.
        self.assertGreater(remote_review.MAX_AGE, remote_review.DEPLOY_TIMEOUT + quick)
        waited = []
        for plan in ("quick", "full"):
            now = [0.0]
            with mock.patch.object(remote_review.subprocess, "run",
                                   lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "PR_AUTOPILOT_STARTED abc123\n"
                                                                                 if cmd[1:3] == ["compute", "logs"] else '{"items": []}', "")), \
                 mock.patch.object(remote_review.secrets, "token_hex", lambda n: "abc123"):
                with self.assertRaisesRegex(RuntimeError, "gave no result"):
                    remote_review.review_pr(REPO, "7", SHA, "", "opus", plan=plan, sleep=lambda s: now.__setitem__(0, now[0] + s),
                                            clock=lambda: now[0], digest_of=lambda ref: "sha256:" + "d" * 64)
            waited.append(now[0])
        self.assertGreaterEqual(waited[0], quick)
        self.assertLess(waited[1], quick)

    def test_an_image_without_the_worker_falls_back(self):
        out, _ = self.run_pr({"ok": True, "moved": False, "result": FINDINGS}, plan="quick")
        self.assertIsInstance(out, remote_review.DatumUnavailable)

    def test_the_worker_files_are_in_the_image(self):
        self.assertIn("pr_worker.py", remote_review.IMAGE_FILES)
        dockerfile = (pathlib.Path(__file__).with_name("remote") / "Dockerfile").read_text()
        self.assertIn("pr_worker.py", dockerfile)
        workflow = (pathlib.Path(__file__).parent / ".github" / "workflows" / "image.yaml").read_text()
        self.assertIn("- pr_worker.py", workflow)

    def test_the_image_workflow_runs_for_every_file_in_the_tag(self):
        workflow = (pathlib.Path(__file__).parent / ".github" / "workflows" / "image.yaml").read_text()
        for name in remote_review.IMAGE_FILES:
            self.assertIn(f"- {name}\n", workflow)


if __name__ == "__main__":
    unittest.main()
