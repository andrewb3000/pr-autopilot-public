"""Tests for the credential proxy (keyproxy.py) and how workers use it."""
from __future__ import annotations

import base64
import contextlib
import http.client
import http.server
import io
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import full_review
import github_api
import keyproxy
import remote_review
import reviewer
import test_dispatcher as td
from test_dispatcher import load_yaml
from test_reviewer import load_review_job

KEY = "k" * 40
REAL_CLAUDE = "sk-ant-oat01-REAL-CLAUDE-TOKEN-VALUE"
REAL_STAGING = "REAL-MCP-STAGING-KEY-VALUE"
REMOTE = pathlib.Path(__file__).with_name("remote")


class PlaceholderTest(unittest.TestCase):
    def test_a_minted_placeholder_verifies_for_its_route(self):
        token = keyproxy.mint(KEY, "review-x-7-abc", "anthropic", now=1000)
        self.assertTrue(token.startswith("sk-ant-oat01-"))
        self.assertEqual(keyproxy.verify(KEY, token, "anthropic", now=1001), "review-x-7-abc")

    def test_it_expires(self):
        token = keyproxy.mint(KEY, "job", "mcp-prod", now=1000, ttl=60)
        self.assertEqual(keyproxy.verify(KEY, token, "mcp-prod", now=1059), "job")
        self.assertIsNone(keyproxy.verify(KEY, token, "mcp-prod", now=1060))

    def test_the_default_lifetime_covers_a_worker(self):
        token = keyproxy.mint(KEY, "job", "anthropic", now=0)
        self.assertEqual(keyproxy.verify(KEY, token, "anthropic", now=45 * 60 + 60), "job")
        self.assertIsNone(keyproxy.verify(KEY, token, "anthropic", now=keyproxy.TTL))

    def test_a_placeholder_works_only_for_its_route(self):
        staging = keyproxy.mint(KEY, "job", "mcp-staging")
        self.assertIsNone(keyproxy.verify(KEY, staging, "mcp-prod"))  # same prefix, other scope
        self.assertIsNone(keyproxy.verify(KEY, staging, "anthropic"))
        self.assertIsNone(keyproxy.verify(KEY, keyproxy.mint(KEY, "job", "anthropic"), "mcp-staging"))

    def test_tampering_or_another_key_is_refused(self):
        token = keyproxy.mint(KEY, "job", "mcp-staging")
        prefix = keyproxy.ROUTES["mcp-staging"].prefix
        payload, mac = token[len(prefix):].split(".")
        forged = keyproxy._b64(b"other|mcp-staging|9999999999")
        for bad in (f"{prefix}{forged}.{mac}", f"{prefix}{payload}.{mac[:-2]}AA", token + "x",
                    token.replace(".", ""), "", REAL_STAGING, keyproxy.mint("z" * 40, "job", "mcp-staging")):
            self.assertIsNone(keyproxy.verify(KEY, bad, "mcp-staging"), bad)

    def test_a_job_id_or_route_that_would_break_the_format_is_refused(self):
        with self.assertRaises(ValueError):
            keyproxy.mint(KEY, "a|b", "anthropic")
        with self.assertRaises(ValueError):
            keyproxy.mint(KEY, "job", "github")

    def test_a_github_placeholder_carries_its_repo_and_serves_both_github_routes(self):
        token = keyproxy.mint(KEY, "review-x-7-abc", "github", repo="example-org/infra")
        self.assertTrue(token.startswith("pap-gh-"))
        self.assertEqual(keyproxy.claims(KEY, token, "github"), ("review-x-7-abc", "example-org/infra"))
        self.assertEqual(keyproxy.claims(KEY, token, "github-git"), ("review-x-7-abc", "example-org/infra"))
        self.assertIsNone(keyproxy.verify(KEY, token, "anthropic"))
        for bad in (None, "", "noslash", "a/b/c", "../x", "a/..", "a|b/c", "a b/c", "a/%2e"):
            with self.assertRaises(ValueError, msg=bad):
                keyproxy.mint(KEY, "job", "github", repo=bad)
        with self.assertRaises(ValueError):
            keyproxy.mint(KEY, "job", "anthropic", repo="o/r")  # only GitHub placeholders name a repo
        with self.assertRaises(ValueError):
            keyproxy.mint(KEY, "job", "github-git", repo="o/r")  # minted as "github"

    def test_a_github_placeholder_without_a_repo_is_refused(self):
        payload = keyproxy._b64(b"job|github|9999999999")
        token = f"pap-gh-{payload}.{keyproxy._mac(KEY, payload)}"
        self.assertIsNone(keyproxy.claims(KEY, token, "github"))
        self.assertIsNone(keyproxy.claims(KEY, token, "github-git"))

    def test_old_three_field_placeholders_still_verify(self):
        """Minted by a dispatcher from before the GitHub routes: same format as now."""
        payload = keyproxy._b64(b"review-x-7-abc|anthropic|9999999999")
        token = f"sk-ant-oat01-pap-{payload}.{keyproxy._mac(KEY, payload)}"
        self.assertEqual(keyproxy.claims(KEY, token, "anthropic"), ("review-x-7-abc", None))
        self.assertEqual(keyproxy.mint(KEY, "j", "mcp-prod", now=0),
                         "pap-mcp-" + keyproxy._b64(f"j|mcp-prod|{keyproxy.TTL}".encode()) + "."
                         + keyproxy._mac(KEY, keyproxy._b64(f"j|mcp-prod|{keyproxy.TTL}".encode())))
        # A repo field on a route that takes none is refused.
        payload = keyproxy._b64(b"job|anthropic|9999999999|o/r")
        self.assertIsNone(keyproxy.claims(KEY, f"sk-ant-oat01-pap-{payload}.{keyproxy._mac(KEY, payload)}",
                                          "anthropic"))

    def test_owner_token_names_match_review_job(self):
        job = load_review_job()
        for repo in ("other-org/milo", "labs-org/x", "example-org/infra", "Weird.Owner/x"):
            self.assertEqual(keyproxy.owner_token_var(repo), job.owner_token_var(repo))

    def test_the_hmac_key_has_a_minimum_length(self):
        with self.assertRaises(ValueError):
            keyproxy.hmac_key({keyproxy.HMAC_ENV: "short"})
        self.assertEqual(keyproxy.hmac_key({keyproxy.HMAC_ENV: KEY}), KEY)


class PathTest(unittest.TestCase):
    def test_only_the_paths_and_methods_reviews_use(self):
        self.assertEqual(keyproxy.resolve("POST", "/anthropic/v1/messages?beta=true")[::2], (0, "/v1/messages?beta=true"))
        self.assertEqual(keyproxy.resolve("POST", "/anthropic/v1/messages/count_tokens")[::2],
                         (0, "/v1/messages/count_tokens"))
        for method in ("POST", "GET", "DELETE"):  # MCP streamable HTTP, at the host root
            self.assertEqual(keyproxy.resolve(method, "/mcp-staging")[::2], (0, "/"))
            self.assertEqual(keyproxy.resolve(method, "/mcp-prod/")[::2], (0, "/"))

    def test_everything_else_is_refused(self):
        for method, path in [("GET", "/anthropic/v1/messages"), ("POST", "/anthropic/v1/models"),
                             ("POST", "/anthropic/v1/messages/batches"), ("POST", "/anthropic/api/oauth/profile"),
                             ("POST", "/anthropic/v1/messages?other=1"), ("POST", "/anthropic/v1/messages?beta=a%26b"),
                             ("POST", "/anthropic/v1//messages"), ("POST", "/anthropic/v1/messages/"),
                             ("PUT", "/mcp-staging"), ("POST", "/mcp-staging?x=1"),
                             ("POST", "/mcp-staging/logs"), ("POST", "/mcp-prod/logs/x"), ("POST", "/mcp-staging//logs"),
                             ("POST", "/mcp-staging/./logs"), ("POST", "/mcp-staging/LOGS"), ("POST", "/mcp-staging/%2Flogs"),
                             ("POST", "/mcp-staging/%6cogs"), ("POST", "/mcp-staging/%256cogs"), ("POST", "/mcp-staging/;logs"),
                             ("POST", "/mcp-staging/a/../logs")]:
            self.assertEqual(keyproxy.resolve(method, path)[0], 403, (method, path))
        for path in ("/githubx/repos", "/", "/anthropicx/v1/messages", "anthropic/v1/messages", "/.well-known/x", "/register",
                     "/mcp-staging;/logs", "/%61nthropic/v1/messages"):
            self.assertEqual(keyproxy.resolve("POST", path)[0], 404, path)

    def test_github_reads(self):
        ok = [("GET", "/github/repos/o/r", "/repos/o/r", ("repo", "o/r")),
              ("GET", "/github/repos/o/r/pulls/7", "/repos/o/r/pulls/7", ("repo", "o/r")),
              ("GET", "/github/repos/o/r/actions/runs?head_sha=abc123&per_page=100",
               "/repos/o/r/actions/runs?head_sha=abc123&per_page=100", ("repo", "o/r")),
              ("GET", "/github/repos/o/r/issues/7/comments?per_page=100&page=2",
               "/repos/o/r/issues/7/comments?per_page=100&page=2", ("repo", "o/r")),
              ("GET", "/github/repos/x/y/issues/12", "/repos/x/y/issues/12", ("owner", "x")),
              ("GET", "/github/repos/x/y/issues/comments/42", "/repos/x/y/issues/comments/42", ("owner", "x")),
              ("POST", "/github/graphql", "/graphql", ("graphql",)),
              ("GET", "/github-git/o/r.git/info/refs?service=git-upload-pack",
               "/o/r.git/info/refs?service=git-upload-pack", ("repo", "o/r")),
              ("POST", "/github-git/o/r.git/git-upload-pack", "/o/r.git/git-upload-pack", ("repo", "o/r"))]
        for method, path, upstream, target in ok:
            self.assertEqual(keyproxy.resolve(method, path)[::2], (0, upstream), path)
            self.assertEqual(keyproxy.resolve(method, path)[3], target, path)

    def test_github_refuses_everything_else(self):
        for method, path in [
                ("POST", "/github/repos/o/r/pulls/7/reviews"), ("PATCH", "/github/repos/o/r"),
                ("DELETE", "/github/repos/o/r"), ("PUT", "/github/repos/o/r/contents/x"),
                ("GET", "/github/user"), ("GET", "/github/notifications"), ("GET", "/github/search/issues?q=x"),
                ("GET", "/github/repos/o"), ("GET", "/github/repos"), ("GET", "/github/graphql"),
                ("POST", "/github/graphql?x=1"), ("GET", "/github/repositories/1/issues"),
                ("GET", "/github/repos/o/r/../../x/y/pulls"), ("GET", "/github/repos/o/../x/y"),
                ("GET", "/github/repos/o/r/./pulls"), ("GET", "/github/repos/o//r"), ("GET", "/github/repos/o/r/"),
                ("GET", "/github/repos/o/%72"), ("GET", "/github/repos/o/r/pulls%2F7"), ("GET", "/github/repos/o/r;x"),
                ("GET", "/github/repos/o/r?q=secret"), ("GET", "/github/repos/o/r?per_page=1%26q"),
                ("GET", "/github-git/o/r.git/info/refs"), ("GET", "/github-git/o/r.git/info/refs?service=git-receive-pack"),
                ("POST", "/github-git/o/r.git/git-receive-pack"), ("GET", "/github-git/o/r.git/git-upload-pack"),
                ("POST", "/github-git/o/r.git/git-upload-pack?service=git-upload-pack"),
                ("GET", "/github-git/o/r/info/refs?service=git-upload-pack"),
                ("GET", "/github-git/o/r.git/HEAD"), ("GET", "/github-git/o/r.git/objects/info/packs"),
                ("GET", "/github-git/../r.git/info/refs?service=git-upload-pack"),
                ("POST", "/github-git/o/r.git/git-upload-pack/")]:
            self.assertEqual(keyproxy.resolve(method, path)[0], 403, (method, path))

    def test_graphql_only_the_allowlisted_query_on_the_job_repo(self):
        q = github_api.CHECKS_QUERY
        good = {"query": q, "variables": {"owner": "O", "name": "R", "number": 1, "cursor": None}}
        self.assertTrue(keyproxy.graphql_allowed(json.dumps(good).encode(), "o/r"))
        bad = [{"query": q + " ", "variables": good["variables"]},
               {"query": "query { viewer { login } }"},
               {"query": "mutation { addComment(input: {}) { clientMutationId } }"},
               {"query": q, "variables": {**good["variables"], "owner": "other"}},
               {"query": q, "variables": {**good["variables"], "name": "r2"}},
               {"query": q, "variables": {"number": 1}},
               {"query": q, "variables": {**good["variables"], "owner": ["o"]}},
               {**good, "operationName": "x"}, {"query": [q]}, [good]]
        for doc in bad:
            self.assertFalse(keyproxy.graphql_allowed(json.dumps(doc).encode(), "o/r"), doc)
        self.assertFalse(keyproxy.graphql_allowed(b"not json", "o/r"))
        self.assertFalse(keyproxy.graphql_allowed(b"\xff", "o/r"))


class Upstream(http.server.BaseHTTPRequestHandler):
    """A fake upstream: records each request; a GET gets SSE pieces as the test allows."""
    protocol_version = "HTTP/1.1"
    seen: list = []
    release = threading.Event()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        type(self).seen.append({"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body})
        if self.path.endswith("/zip"):  # an artifact download: GitHub sends a signed blob URL
            self.send_response(302)
            self.send_header("Location", "https://blob.example/a.zip?sig=x")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.command == "GET" and self.path == "/":  # the MCP event stream
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i, piece in enumerate((b"data: one\n\n", b"data: two\n\n")):
                if i:
                    type(self).release.wait(10)
                self.wfile.write(b"%x\r\n%s\r\n" % (len(piece), piece))
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            return
        out = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.send_header("Set-Cookie", "upstream=1")
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_DELETE = do_POST

    def log_message(self, *a):
        pass


def local_routes(up: str) -> dict:
    """The real routes, pointed at a local upstream."""
    return {name: r.moved_to(up) for name, r in keyproxy.ROUTES.items()}


class ProxyBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        cls.upstream.daemon_threads = True
        threading.Thread(target=cls.upstream.serve_forever, daemon=True).start()
        cls.patches = [mock.patch.dict(keyproxy.ROUTES, local_routes(f"http://127.0.0.1:{cls.upstream.server_address[1]}"),
                                       clear=True),
                       mock.patch.dict(os.environ, {"CLAUDE_CODE_OAUTH_TOKEN": REAL_CLAUDE,
                                                    "DATUM_MCP_API_KEY_STAGING": REAL_STAGING})]
        for p in cls.patches:
            p.start()
        os.environ.pop("DATUM_MCP_API_KEY_PROD", None)

    @classmethod
    def tearDownClass(cls):
        cls.upstream.shutdown()
        cls.upstream.server_close()
        for p in cls.patches:
            p.stop()

    def setUp(self):
        Upstream.seen = []
        Upstream.release = threading.Event()
        self.server = keyproxy.Server(("::", 0), KEY)  # one per test: connection counts start at zero
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]
        self.logged = io.StringIO()
        out = contextlib.redirect_stdout(self.logged)
        out.__enter__()
        self.addCleanup(out.__exit__, None, None, None)

    def call(self, method, path, headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    def log_lines(self, count: int) -> list[dict]:
        """The log, once it has `count` lines: the proxy logs a request after answering it."""
        deadline = time.monotonic() + 5
        while len(self.logged.getvalue().splitlines()) < count and time.monotonic() < deadline:
            time.sleep(0.02)
        return [json.loads(line) for line in self.logged.getvalue().splitlines()]

    def raw(self, data: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as s:
            s.sendall(data)
            return s.recv(4096)

    def bearer(self, route="anthropic", job="review-x-7-abc"):
        return {"Authorization": f"Bearer {keyproxy.mint(KEY, job, route)}"}

    def mcp(self, job="job"):
        return {"x-api-key": keyproxy.mint(KEY, job, "mcp-staging")}


class ProxyTest(ProxyBase):
    def test_swaps_the_placeholder_for_the_real_token(self):
        resp, data = self.call("POST", "/anthropic/v1/messages?beta=true",
                               {**self.bearer(), "anthropic-beta": "oauth-2025-04-20", "x-stainless-retry-count": "0",
                                "Content-Type": "application/json", "x-api-key": "smuggled", "Cookie": "a=b",
                                "X-Forwarded-For": "1.2.3.4", "Proxy-Authorization": "x"}, b'{"model":"x"}')
        self.assertEqual((resp.status, json.loads(data)), (200, {"ok": True}))
        seen = Upstream.seen[0]
        self.assertEqual((seen["path"], seen["body"]), ("/v1/messages?beta=true", b'{"model":"x"}'))
        headers = {k.lower(): v for k, v in seen["headers"].items()}
        self.assertEqual(headers["authorization"], f"Bearer {REAL_CLAUDE}")
        self.assertEqual((headers["anthropic-beta"], headers["x-stainless-retry-count"], headers["content-type"]),
                         ("oauth-2025-04-20", "0", "application/json"))
        for dropped in ("x-api-key", "cookie", "x-forwarded-for", "proxy-authorization"):
            self.assertNotIn(dropped, headers)  # only allowlisted headers go out
        self.assertIsNone(resp.getheader("Set-Cookie"))

    def test_mcp_gets_its_key_in_x_api_key(self):
        resp, _ = self.call("POST", "/mcp-staging", {**self.mcp(), "Authorization": "Bearer x",
                                                     "mcp-session-id": "s1", "anthropic-beta": "x"}, b"{}")
        self.assertEqual(resp.status, 200)
        headers = {k.lower(): v for k, v in Upstream.seen[0]["headers"].items()}
        self.assertEqual((Upstream.seen[0]["path"], headers["x-api-key"], headers["mcp-session-id"]),
                         ("/", REAL_STAGING, "s1"))
        self.assertNotIn("authorization", headers)
        self.assertNotIn("anthropic-beta", headers)  # the other route's headers stay out

    def test_refuses_requests_without_a_valid_placeholder(self):
        cases = [
            ("/anthropic/v1/messages", {}),  # none
            ("/anthropic/v1/messages", {"Authorization": f"Bearer {REAL_CLAUDE}"}),  # a real key
            ("/anthropic/v1/messages", {"x-api-key": keyproxy.mint(KEY, "job", "anthropic")}),  # wrong header
            ("/anthropic/v1/messages", self.bearer("mcp-staging")),  # another route's placeholder
            ("/mcp-staging", {"x-api-key": REAL_STAGING}),
            ("/mcp-prod", {"x-api-key": keyproxy.mint(KEY, "job", "mcp-staging")}),
        ]
        for path, headers in cases:
            resp, _ = self.call("POST", path, headers, b"{}")
            self.assertEqual((resp.status, resp.getheader("Connection")), (401, "close"), (path, headers))
        self.assertEqual(Upstream.seen, [])

    def test_a_placeholder_with_odd_bytes_is_a_401_not_a_crash(self):
        answer = self.raw(b"POST /mcp-staging HTTP/1.1\r\nHost: x\r\nx-api-key: pap-mcp-\xff\xfe.\xc3\r\n"
                          b"Content-Length: 0\r\n\r\n")
        self.assertTrue(answer.startswith(b"HTTP/1.1 401"), answer)

    def test_a_disallowed_path_is_403_before_any_upstream_call(self):
        resp, _ = self.call("POST", "/mcp-staging/logs", self.mcp(), b"{}")
        self.assertEqual(resp.status, 403)
        resp, _ = self.call("GET", "/anthropic/v1/models", self.bearer())
        self.assertEqual(resp.status, 403)
        resp, _ = self.call("POST", "/mcp-prod", {"x-api-key": keyproxy.mint(KEY, "job", "mcp-prod")}, b"{}")
        self.assertEqual(resp.status, 503)  # no real prod key in this proxy
        self.assertEqual(Upstream.seen, [])

    def test_streams_each_piece_as_it_arrives(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", "/mcp-staging", headers={**self.mcp(), "Accept": "text/event-stream"})
        resp = conn.getresponse()
        self.assertEqual((resp.status, resp.getheader("Content-Type")), (200, "text/event-stream"))
        # The upstream holds the second piece until the first has reached the client.
        self.assertEqual(resp.read1(100), b"data: one\n\n")
        Upstream.release.set()
        self.assertEqual(resp.read(), b"data: two\n\n")
        conn.close()

    def test_a_chunked_request_body_is_forwarded_whole(self):
        def body():
            yield b"part one, "
            yield b"part two"
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/anthropic/v1/messages", body=body(), headers=self.bearer(), encode_chunked=True)
        self.assertEqual(conn.getresponse().status, 200)
        conn.close()
        self.assertEqual(Upstream.seen[0]["body"], b"part one, part two")

    def test_a_body_over_the_cap_is_refused(self):
        self.assertEqual(keyproxy.MAX_BODY, 8 * 1024 * 1024)
        token = keyproxy.mint(KEY, "job", "anthropic")
        answer = self.raw(f"POST /anthropic/v1/messages HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n"
                          f"Content-Length: {keyproxy.MAX_BODY + 1}\r\n\r\n".encode())
        self.assertTrue(answer.startswith(b"HTTP/1.1 413"), answer)
        self.assertEqual(Upstream.seen, [])

    def test_logs_client_route_job_status_and_never_a_credential(self):
        placeholder = keyproxy.mint(KEY, "review-x-7-abc", "anthropic")
        self.call("POST", "/anthropic/v1/messages", {"Authorization": f"Bearer {placeholder}"}, b"{}")
        self.call("POST", "/anthropic/v1/messages", {"Authorization": f"Bearer {REAL_CLAUDE}"}, b"{}")
        lines = self.log_lines(2)
        self.assertEqual([(l["route"], l["job"], l["status"]) for l in lines],
                         [("anthropic", "review-x-7-abc", 200), ("anthropic", None, 401)])
        self.assertTrue(all(l["client"].endswith("127.0.0.1") and "seconds" in l for l in lines))
        for secret in (REAL_CLAUDE, placeholder, KEY):
            self.assertNotIn(secret, self.logged.getvalue())

    def test_healthz(self):
        resp, data = self.call("GET", "/healthz")
        self.assertEqual((resp.status, data), (200, b"ok\n"))

    def test_an_unreachable_upstream_is_a_502(self):
        r = keyproxy.ROUTES["anthropic"]
        dead = keyproxy.Route("anthropic", "http://127.0.0.1:9", r.header, r.secret_env, r.prefix, r.paths,
                              r.query_keys, r.headers, r.header_prefixes)
        with mock.patch.dict(keyproxy.ROUTES, {"anthropic": dead}):
            resp, _ = self.call("POST", "/anthropic/v1/messages", self.bearer(), b"{}")
        self.assertEqual(resp.status, 502)

    def test_main_refuses_to_start_without_the_hmac_key(self):
        out = subprocess.run([sys.executable, str(pathlib.Path(keyproxy.__file__))], capture_output=True, text=True,
                             timeout=30, env={k: v for k, v in os.environ.items() if k != keyproxy.HMAC_ENV})
        self.assertEqual(out.returncode, 2)
        self.assertIn("keyproxy: PR_AUTOPILOT_KEYPROXY_HMAC must be", out.stderr)


REAL_GH = "ghp_REAL-DEFAULT-READ-TOKEN"
REAL_GH_MILO = "github_pat_REAL-OTHER-ORG-TOKEN"


class GitHubProxyTest(ProxyBase):
    """The worker's GitHub reads: the API and git, for its own repo only."""

    def setUp(self):
        super().setUp()
        p = mock.patch.dict(os.environ, {"GH_TOKEN": REAL_GH, "GH_TOKEN_OTHER_ORG": REAL_GH_MILO})
        p.start()
        self.addCleanup(p.stop)

    def gh(self, repo="example-org/infra", job="review-infra-7-abc"):
        return {"Authorization": f"Bearer {keyproxy.mint(KEY, job, 'github', repo=repo)}"}

    def upstream_headers(self, i=0):
        return {k.lower(): v for k, v in Upstream.seen[i]["headers"].items()}

    def test_api_reads_of_its_own_repo_get_the_real_token(self):
        resp, data = self.call("GET", "/github/repos/example-org/infra/pulls/7?per_page=100",
                               {**self.gh(), "Accept": "application/vnd.github.diff", "X-GitHub-Api-Version": "2022-11-28",
                                "User-Agent": "pr-autopilot", "Cookie": "a=b", "X-Forwarded-For": "1.2.3.4"})
        self.assertEqual((resp.status, json.loads(data)), (200, {"ok": True}))
        self.assertEqual(Upstream.seen[0]["path"], "/repos/example-org/infra/pulls/7?per_page=100")
        headers = self.upstream_headers()
        self.assertEqual(headers["authorization"], f"Bearer {REAL_GH}")
        self.assertEqual((headers["accept"], headers["x-github-api-version"], headers["user-agent"]),
                         ("application/vnd.github.diff", "2022-11-28", "pr-autopilot"))
        self.assertNotIn("cookie", headers)
        self.assertNotIn("x-forwarded-for", headers)
        line = self.log_lines(1)[0]
        self.assertEqual((line["route"], line["job"], line["repo"], line["path"], line["status"]),
                         ("github", "review-infra-7-abc", "example-org/infra", "/repos/example-org/infra/pulls/7", 200))
        for secret in (REAL_GH, self.gh()["Authorization"][7:], "per_page"):
            self.assertNotIn(secret, self.logged.getvalue())

    def test_the_repo_check_ignores_case_like_github(self):
        resp, _ = self.call("GET", "/github/repos/Example-Org/Infra", self.gh())
        self.assertEqual(resp.status, 200)

    def test_another_repo_is_refused_except_linked_issues_of_the_same_owner(self):
        for path in ("/github/repos/example-org/other/pulls/7", "/github/repos/other-org/milo",
                     "/github/repos/example-org/other/issues/7/comments",
                     "/github/repos/other-org/milo/issues/12", "/github/repos/other-org/milo/issues/comments/9"):
            resp, _ = self.call("GET", path, self.gh())
            self.assertEqual(resp.status, 403, path)
        self.assertEqual(Upstream.seen, [])
        self.assertTrue(all(l.get("other_repo") for l in self.log_lines(5)))
        for path in ("/github/repos/example-org/other/issues/12", "/github/repos/Example-Org/x/issues/comments/9"):
            resp, _ = self.call("GET", path, self.gh())
            self.assertEqual(resp.status, 200, path)

    def test_the_owners_own_token_is_used_when_there_is_one(self):
        self.call("GET", "/github/repos/other-org/milo/pulls/1", self.gh("other-org/milo"))
        self.call("GET", "/github/repos/labs-org/x/pulls/1", self.gh("labs-org/x"))
        self.assertEqual(self.upstream_headers(0)["authorization"], f"Bearer {REAL_GH_MILO}")
        self.assertEqual(self.upstream_headers(1)["authorization"], f"Bearer {REAL_GH}")  # no token of its own

    def test_no_github_token_is_a_503(self):
        with mock.patch.dict(os.environ, {"GH_TOKEN": ""}):
            resp, _ = self.call("GET", "/github/repos/example-org/infra", self.gh())
        self.assertEqual(resp.status, 503)

    def test_other_placeholders_and_real_tokens_are_refused(self):
        for headers in ({}, {"Authorization": f"Bearer {REAL_GH}"}, self.bearer("anthropic"),
                        {"Authorization": f"token {keyproxy.mint(KEY, 'j', 'github', repo='example-org/infra')}"}):
            resp, _ = self.call("GET", "/github/repos/example-org/infra", headers)
            self.assertEqual(resp.status, 401, headers)
        self.assertEqual(Upstream.seen, [])

    def test_a_revoked_job_loses_github_too(self):
        self.server.revoke("review-infra-7-abc")
        resp, _ = self.call("GET", "/github/repos/example-org/infra", self.gh())
        self.assertEqual(resp.status, 401)

    def test_redirects_are_passed_back_not_followed(self):
        resp, _ = self.call("GET", "/github/repos/example-org/infra/actions/artifacts/70/zip", self.gh())
        self.assertEqual((resp.status, resp.getheader("Location")), (302, "https://blob.example/a.zip?sig=x"))
        self.assertEqual(len(Upstream.seen), 1)

    def test_graphql_goes_through_only_with_the_allowlisted_query(self):
        good = {"query": github_api.CHECKS_QUERY,
                "variables": {"owner": "example-org", "name": "infra", "number": 7, "cursor": None}}
        resp, _ = self.call("POST", "/github/graphql", {**self.gh(), "Content-Type": "application/json"},
                            json.dumps(good).encode())
        self.assertEqual(resp.status, 200)
        self.assertEqual((Upstream.seen[0]["path"], json.loads(Upstream.seen[0]["body"])), ("/graphql", good))
        other_repo = {**good, "variables": {**good["variables"], "name": "other"}}
        for doc in (other_repo, {"query": "query { viewer { login } }"}):
            resp, _ = self.call("POST", "/github/graphql", self.gh(), json.dumps(doc).encode())
            self.assertEqual(resp.status, 403, doc)
        self.assertEqual(len(Upstream.seen), 1)

    def test_git_fetch_gets_basic_auth_and_nothing_else_goes_through(self):
        resp, _ = self.call("GET", "/github-git/example-org/infra.git/info/refs?service=git-upload-pack",
                            {**self.gh(), "Git-Protocol": "version=2", "User-Agent": "git/2.39"})
        self.assertEqual(resp.status, 200)
        resp, _ = self.call("POST", "/github-git/example-org/infra.git/git-upload-pack",
                            {**self.gh(), "Content-Type": "application/x-git-upload-pack-request",
                             "Content-Encoding": "gzip"}, b"0000")
        self.assertEqual(resp.status, 200)
        basic = "Basic " + base64.b64encode(f"x-access-token:{REAL_GH}".encode()).decode()
        self.assertEqual([self.upstream_headers(i)["authorization"] for i in (0, 1)], [basic, basic])
        self.assertEqual(self.upstream_headers(0)["git-protocol"], "version=2")
        self.assertEqual(self.upstream_headers(1)["content-encoding"], "gzip")
        self.assertEqual(Upstream.seen[1]["path"], "/example-org/infra.git/git-upload-pack")
        for method, path in (("POST", "/github-git/example-org/infra.git/git-receive-pack"),
                             ("GET", "/github-git/example-org/infra.git/info/refs?service=git-receive-pack"),
                             ("GET", "/github-git/example-org/other.git/info/refs?service=git-upload-pack")):
            resp, _ = self.call(method, path, self.gh(), b"0000" if method == "POST" else None)
            self.assertEqual(resp.status, 403, path)
        self.assertEqual(len(Upstream.seen), 2)

    def test_the_owner_token_goes_to_git_too(self):
        self.call("GET", "/github-git/other-org/milo.git/info/refs?service=git-upload-pack", self.gh("other-org/milo"))
        self.assertEqual(self.upstream_headers()["authorization"],
                         "Basic " + base64.b64encode(f"x-access-token:{REAL_GH_MILO}".encode()).decode())


class LimitsTest(ProxyBase):
    """One gVPC peer must not be able to lock the workers out."""

    def test_connections_per_client_are_capped(self):
        self.assertGreaterEqual(keyproxy.Server.request_queue_size, 128)
        with mock.patch.object(keyproxy, "PER_CLIENT", 2):
            idle = [socket.create_connection(("127.0.0.1", self.port), timeout=10) for _ in range(2)]
            try:
                time.sleep(0.2)
                answer = self.raw(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
            finally:
                for s in idle:
                    s.close()
        self.assertTrue(answer.startswith(b"HTTP/1.1 503"), answer)
        self.assertIn("too many connections", [l.get("reason") for l in self.log_lines(1)])

    def test_an_idle_connection_is_closed_soon(self):
        with mock.patch.object(keyproxy, "IDLE_TIMEOUT", 0.3):
            with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
                started = time.monotonic()
                self.assertEqual(s.recv(100), b"")  # closed by the proxy, not by our timeout
                self.assertLess(time.monotonic() - started, 3)
        deadline = time.monotonic() + 3
        while self.server.connections and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(dict(self.server.connections), {})  # its slot is free again

    def trickle(self, head: bytes, then: bytes = b"", every: float = 0.1, limit: float = 5) -> float:
        """Send `head`, then `then` one byte every `every` seconds, until the proxy cuts
        the connection off; return how long that took."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=limit) as s:
            started = time.monotonic()
            s.sendall(head)
            try:
                for byte in then:
                    s.sendall(bytes([byte]))
                    time.sleep(every)
                    if time.monotonic() - started > limit:
                        break
                s.settimeout(limit)
                while s.recv(4096):  # a 4xx a slow body may still get, then EOF
                    pass
            except OSError:
                pass  # reset: cut off
            return time.monotonic() - started

    def test_a_client_trickling_its_headers_is_cut_off_at_the_deadline(self):
        # Each byte comes well inside the per-read timeout; only the deadline stops it.
        with mock.patch.object(keyproxy, "HEADER_DEADLINE", 0.6), mock.patch.object(keyproxy, "IDLE_TIMEOUT", 5):
            took = self.trickle(b"", b"POST /anthropic/v1/messages HTTP/1.1\r\nHost: x\r\nX-Slow: " + b"a" * 200)
        self.assertLess(took, 3)
        self.assertIn("cut off", [l.get("event") for l in self.log_lines(1)])
        self.assertEqual(Upstream.seen, [])

    def test_a_trickling_body_is_cut_off_too(self):
        token = keyproxy.mint(KEY, "job", "anthropic")
        head = (f"POST /anthropic/v1/messages HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n"
                f"Content-Length: 1000\r\n\r\n").encode()
        with mock.patch.object(keyproxy, "BODY_BASE", 0.6), mock.patch.object(keyproxy, "BODY_MIN_RATE", 10 ** 9):
            took = self.trickle(head, b"x" * 1000)
        self.assertLess(took, 3)
        self.assertEqual(Upstream.seen, [])

    def test_the_deadline_is_per_request_on_a_kept_alive_connection(self):
        with mock.patch.object(keyproxy, "HEADER_DEADLINE", 0.6):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            for _ in range(3):  # each request well inside its own deadline, together past it
                conn.request("POST", "/anthropic/v1/messages", body=b"{}", headers=self.bearer())
                self.assertEqual(conn.getresponse().read(), b'{"ok": true}')
                time.sleep(0.3)
            conn.close()
        self.assertEqual(len(Upstream.seen), 3)

    def test_the_cap_counts_an_ipv6_64_as_one_client(self):
        self.assertEqual(keyproxy.source("fd20:1:2:3::a"), keyproxy.source("fd20:1:2:3:ffff::b"))
        self.assertNotEqual(keyproxy.source("fd20:1:2:3::a"), keyproxy.source("fd20:1:2:4::a"))
        self.assertEqual(keyproxy.source("fd20:1:2:3::a"), "fd20:1:2:3::/64")
        self.assertEqual(keyproxy.source("::ffff:10.0.0.5"), "10.0.0.5")
        self.assertEqual(keyproxy.source("10.0.0.5"), "10.0.0.5")
        self.assertEqual(keyproxy.source("not-an-ip"), "not-an-ip")

    def test_an_upstream_slot_is_taken_only_after_the_placeholder_checks_out(self):
        for _ in range(keyproxy.MAX_UPSTREAM):
            self.server.upstream.acquire()
        try:
            resp, _ = self.call("POST", "/anthropic/v1/messages", {}, b"{}")
            self.assertEqual(resp.status, 401)  # refused on its own merits, not "busy"
            resp, data = self.call("POST", "/anthropic/v1/messages", self.bearer(), b"{}")
            self.assertEqual((resp.status, data), (503, b"busy\n"))
        finally:
            for _ in range(keyproxy.MAX_UPSTREAM):
                self.server.upstream.release()
        resp, _ = self.call("POST", "/anthropic/v1/messages", self.bearer(), b"{}")
        self.assertEqual(resp.status, 200)  # and slots come back after each request

    def test_memory_worst_case_fits_the_instance(self):
        # Each running request may hold its body twice while reading it.
        self.assertLessEqual(keyproxy.MAX_UPSTREAM * keyproxy.MAX_BODY * 2, 512 * 1024 * 1024)


class RevokeTest(ProxyBase):
    def revoke(self, job, token=None):
        token = token or keyproxy.revoke_token(KEY, job)
        return self.call("POST", "/revoke", {"Authorization": f"Bearer {token}"}, json.dumps({"job": job}).encode())[0]

    def test_a_revoked_job_is_refused_and_others_keep_working(self):
        self.assertEqual(self.revoke("job-a").status, 200)
        resp, _ = self.call("POST", "/mcp-staging", self.mcp("job-a"), b"{}")
        self.assertEqual(resp.status, 401)
        resp, _ = self.call("POST", "/mcp-staging", self.mcp("job-b"), b"{}")
        self.assertEqual(resp.status, 200)
        self.assertIn(True, [l.get("revoked") for l in self.log_lines(3)])

    def test_only_the_dispatcher_can_revoke(self):
        for token in ("", keyproxy.revoke_token("z" * 40, "job-a"), keyproxy.revoke_token(KEY, "job-b"),
                      keyproxy.mint(KEY, "job-a", "anthropic")):
            self.assertEqual(self.revoke("job-a", token or "x").status, 401)
        self.assertFalse(self.server.is_revoked("job-a"))

    def test_the_dispatcher_revokes_through_its_url(self):
        with mock.patch.dict(os.environ, {remote_review.KEYPROXY_URL_ENV: f"http://127.0.0.1:{self.port}",
                                          keyproxy.HMAC_ENV: KEY}):
            self.assertTrue(remote_review.revoke_keyproxy("review-x-7-abc"))
        self.assertTrue(self.server.is_revoked("review-x-7-abc"))

    def test_without_the_proxy_revoking_does_nothing(self):
        os.environ.pop(remote_review.KEYPROXY_URL_ENV, None)
        self.assertFalse(remote_review.revoke_keyproxy("review-x-7-abc"))

    def test_deleting_a_worker_revokes_it_first(self):
        calls = []
        with mock.patch.object(remote_review, "revoke_keyproxy", lambda name: calls.append(("revoke", name))), \
             mock.patch.object(remote_review.milo_api, "delete", lambda path: calls.append(("delete", path))):
            remote_review.delete_workload("review-x-7-abc")
        self.assertEqual([c[0] for c in calls], ["revoke", "delete"])
        self.assertEqual(calls[0][1], "review-x-7-abc")

    def test_the_revoked_set_drops_expired_jobs(self):
        self.server.revoked["old"] = time.time() - 1
        self.server.revoke("new")
        self.assertEqual(set(self.server.revoked), {"new"})


class CallbackRevokesTest(td.DispatcherBase):
    """An accepted callback ends the worker's placeholders at once."""
    launched, outcome = td.CallbackTest.launched, td.CallbackTest.outcome

    def test_an_accepted_result_revokes_its_worker(self):
        revoked = []
        done = threading.Event()
        token = self.launched()
        with mock.patch.object(remote_review, "revoke_keyproxy", lambda name: (revoked.append(name), done.set())):
            self.assertEqual(td.d.accept_result(token, json.dumps(self.outcome()).encode())[0], 200)
            self.assertTrue(done.wait(5))
        self.assertEqual(revoked, [self.workers[0][0]])

    def test_a_refused_result_revokes_nothing(self):
        revoked = []
        self.launched()
        with mock.patch.object(remote_review, "revoke_keyproxy", revoked.append):
            self.assertEqual(td.d.accept_result("wrong-token", json.dumps(self.outcome()).encode())[0], 401)
        self.assertEqual(revoked, [])


class WorkerEnvTest(unittest.TestCase):
    """The dispatcher's side: start_worker hands out placeholders only with the flag."""

    def start(self, env: dict) -> dict:
        created = []
        with mock.patch.dict(os.environ, env), \
             mock.patch.object(remote_review, "image", lambda: "ghcr.io/x/review:tag"), \
             mock.patch.object(remote_review, "image_digest", lambda tagged: "sha256:" + "0" * 64), \
             mock.patch.object(remote_review.milo_api, "create", lambda path, doc: created.append(doc)):
            name = remote_review.start_worker("example-org/infra", "7", "a" * 40, "", "opus", plan="quick", focus="",
                                              audit=False, quick_model="sonnet", strict_workflows=False,
                                              callback_url="http://d/callback", callback_token="t")
        container = created[0]["spec"]["template"]["spec"]["runtime"]["sandbox"]["containers"][0]
        return name, container, {e["name"]: e["value"] for e in container["env"]}

    def test_without_the_flag_nothing_changes(self):
        os.environ.pop(remote_review.KEYPROXY_URL_ENV, None)
        _, container, env = self.start({})
        self.assertFalse([k for k in env if "KEYPROXY" in k or k == "ANTHROPIC_BASE_URL"])
        self.assertEqual(container["envFrom"], [{"secretRef": {"name": remote_review.SECRET}}])

    def test_with_the_flag_the_worker_gets_placeholders_for_its_own_job(self):
        name, container, env = self.start({remote_review.KEYPROXY_URL_ENV: "http://proxy:8080/", keyproxy.HMAC_ENV: KEY})
        self.assertEqual(env["REVIEW_KEYPROXY_URL"], "http://proxy:8080")
        for var, route in (("REVIEW_KEYPROXY_CLAUDE", "anthropic"), ("REVIEW_KEYPROXY_MCP_STAGING", "mcp-staging"),
                           ("REVIEW_KEYPROXY_MCP_PROD", "mcp-prod")):
            self.assertEqual(keyproxy.verify(KEY, env[var], route), name)
        # One GitHub placeholder, for this job and only this PR's repo, for the API and git.
        for route in ("github", "github-git"):
            self.assertEqual(keyproxy.claims(KEY, env["REVIEW_KEYPROXY_GITHUB"], route), (name, "example-org/infra"))
        # Never the real names: review-job.py sets those, whatever env vs envFrom precedence is.
        self.assertFalse({"CLAUDE_CODE_OAUTH_TOKEN", "DATUM_MCP_API_KEY_STAGING", "DATUM_MCP_API_KEY_PROD",
                          "GH_TOKEN", "PR_AUTOPILOT_GITHUB_TOKEN"} & set(env))
        # Placeholders only: no Secret, so review-credentials can be emptied.
        self.assertNotIn("envFrom", container)

    def test_placeholders_outlive_the_worker(self):
        """Minted when start_worker runs (not at queue time), so the hour runs from the
        worker's start and covers its WORKER_TTL."""
        self.assertGreater(keyproxy.TTL, reviewer.WORKER_TTL + remote_review.DEPLOY_TIMEOUT)

    def test_the_flag_without_the_hmac_key_keeps_the_job_queued(self):
        os.environ.pop(keyproxy.HMAC_ENV, None)
        with self.assertRaisesRegex(remote_review.DatumUnavailable, "PR_AUTOPILOT_KEYPROXY_HMAC"):
            self.start({remote_review.KEYPROXY_URL_ENV: "http://proxy:8080"})


class ReviewJobKeyproxyTest(unittest.TestCase):
    """The worker's side: review-job.py puts the placeholders in place of the real keys."""

    def setUp(self):
        self.job = load_review_job()

    def test_with_a_proxy_the_real_keys_leave_the_environment(self):
        env = {"REVIEW_KEYPROXY_URL": "http://proxy:8080/", "REVIEW_KEYPROXY_CLAUDE": "sk-ant-oat01-pap-ph",
               "REVIEW_KEYPROXY_MCP_STAGING": "pap-mcp-s", "REVIEW_KEYPROXY_MCP_PROD": "pap-mcp-p",
               "CLAUDE_CODE_OAUTH_TOKEN": REAL_CLAUDE, "DATUM_MCP_API_KEY_STAGING": REAL_STAGING}
        with mock.patch.dict(os.environ, env, clear=True):
            self.job.take_keyproxy()
            now = dict(os.environ)
        self.assertEqual(now, {"CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat01-pap-ph", "DATUM_MCP_API_KEY_STAGING": "pap-mcp-s",
                               "DATUM_MCP_API_KEY_PROD": "pap-mcp-p", "ANTHROPIC_BASE_URL": "http://proxy:8080/anthropic",
                               "PR_AUTOPILOT_KEYPROXY_URL": "http://proxy:8080"})
        # Kept only so scrub() can still remove them from the result.
        self.assertEqual(self.job.REMOVED_SECRETS["CLAUDE_CODE_OAUTH_TOKEN"], REAL_CLAUDE)
        self.assertEqual(self.job.scrub(f"leaked {REAL_STAGING}"), "leaked [DATUM_MCP_API_KEY_STAGING removed]")

    def test_without_a_proxy_nothing_changes(self):
        env = {"CLAUDE_CODE_OAUTH_TOKEN": REAL_CLAUDE, "REVIEW_KEYPROXY_CLAUDE": "stray"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.job.take_keyproxy()
            now = dict(os.environ)
        self.assertEqual(now, {"CLAUDE_CODE_OAUTH_TOKEN": REAL_CLAUDE})

    def test_with_a_github_placeholder_github_reads_go_through_the_proxy(self):
        env = {"REVIEW_REPO": "other-org/milo", "REVIEW_KEYPROXY_URL": "http://proxy:8080",
               "REVIEW_KEYPROXY_CLAUDE": "sk-ant-oat01-pap-ph", "REVIEW_KEYPROXY_GITHUB": "pap-gh-ph",
               "GH_TOKEN": REAL_GH, "GH_TOKEN_OTHER_ORG": REAL_GH_MILO, "GITHUB_TOKEN": "ghp_stray-real-token"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.job.pick_github_token("other-org/milo")
            self.job.take_keyproxy()
            now = dict(os.environ)
            agent = full_review.agent_env()
            scrubbed = self.job.scrub(f"{REAL_GH} {REAL_GH_MILO} pap-gh-ph")
        self.assertEqual({k: v for k, v in now.items() if "GITHUB" in k or k.startswith("GH_")},
                         {"PR_AUTOPILOT_GITHUB_API": "http://proxy:8080/github",
                          "PR_AUTOPILOT_GITHUB_GIT": "http://proxy:8080/github-git",
                          "PR_AUTOPILOT_GITHUB_TOKEN": "pap-gh-ph"})  # no real token left
        self.assertNotIn("PR_AUTOPILOT_GITHUB_TOKEN", agent)  # nor the placeholder for Claude
        self.assertNotIn("pap-gh-ph", scrubbed)
        self.assertNotIn(REAL_GH, scrubbed)
        self.assertNotIn(REAL_GH_MILO, scrubbed)

    def test_github_api_reads_the_override_after_import(self):
        """review-job imports github_api before take_keyproxy runs."""
        env = {"REVIEW_KEYPROXY_URL": "http://proxy:8080", "REVIEW_KEYPROXY_GITHUB": "pap-gh-ph", "GH_TOKEN": REAL_GH}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(github_api, "_TOKEN", "cached-old"):
            self.job.take_keyproxy()
            self.assertEqual((github_api.api(), github_api.token()), ("http://proxy:8080/github", "pap-gh-ph"))
            self.assertEqual(full_review.git_auth("o/r")[0], "http://proxy:8080/github-git/o/r.git")

    def test_rollback_mode_reads_github_with_the_real_read_token(self):
        for env in ({"GH_TOKEN": REAL_GH},  # no proxy
                    {"GH_TOKEN": REAL_GH, "REVIEW_KEYPROXY_URL": "http://proxy:8080"}):  # an older dispatcher
            with mock.patch.dict(os.environ, env, clear=True):
                self.job.take_keyproxy()
                now = dict(os.environ)
            self.assertEqual(now["PR_AUTOPILOT_GITHUB_TOKEN"], REAL_GH, env)
            self.assertNotIn("PR_AUTOPILOT_GITHUB_API", now)
            self.assertNotIn("PR_AUTOPILOT_GITHUB_GIT", now)


class McpConfigTest(unittest.TestCase):
    def write(self, servers: dict) -> tuple[dict, list]:
        base = pathlib.Path(tempfile.mkdtemp())
        (base / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
        out = base / "private" / "mcp.json"
        args, tools = full_review.mcp_config(base, out, secret=lambda var: f"ph-{var}")
        return (json.loads(out.read_text())["mcpServers"] if args else {}), tools

    SERVERS = {"infra-staging": {"type": "http", "url": "https://mcp.staging.corp.example",
                                       "headers": {"x-api-key": "${DATUM_MCP_API_KEY_STAGING}"}},
               "infra-prod": {"type": "http", "url": "https://other.corp.example/mcp",
                                    "headers": {"x-api-key": "${DATUM_MCP_API_KEY_PROD}"}}}

    def test_through_the_proxy_the_urls_point_at_it(self):
        with mock.patch.dict(os.environ, {full_review.KEYPROXY_ENV: "http://proxy:8080"}):
            servers, tools = self.write(self.SERVERS)
        self.assertEqual(servers, {"infra-staging": {
            "type": "http", "url": "http://proxy:8080/mcp-staging",
            "headers": {"x-api-key": "ph-DATUM_MCP_API_KEY_STAGING"}}})  # a host it does not serve is left out
        self.assertTrue(all(t.startswith("mcp__infra-staging__") for t in tools))

    def test_without_the_proxy_the_urls_stay(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(full_review.KEYPROXY_ENV, None)
            servers, _ = self.write(self.SERVERS)
        self.assertEqual(servers["infra-staging"]["url"], "https://mcp.staging.corp.example")
        self.assertEqual(servers["infra-prod"]["url"], "https://other.corp.example/mcp")


class KeyproxyManifestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docs = load_yaml(REMOTE / "keyproxy-workload.yaml")
        cls.doc = cls.docs[0]
        cls.dispatcher = load_yaml(REMOTE / "dispatcher-workload-unikernel.yaml")[0]

    def test_a_private_unikernel_running_the_proxy(self):
        self.assertEqual([d["kind"] for d in self.docs], ["Workload"])  # no NetworkService or HTTPProxy
        name = self.doc["metadata"]["name"]
        self.assertLessEqual(len(name), 39)
        spec = self.doc["spec"]["template"]["spec"]
        self.assertEqual(spec["runtime"]["class"], "unikernel")
        c = spec["runtime"]["sandbox"]["containers"][0]
        self.assertEqual(c["command"], ["/app/python", "/app/keyproxy.py"])
        self.assertEqual(c["ports"], [{"name": "http", "port": 8080, "protocol": "TCP"}])
        self.assertTrue(c["image"].startswith("ghcr.io/example-user/pr-autopilot-dispatcher@sha256:"))
        refs = {e["name"]: e["valueFrom"]["secretKeyRef"] for e in c["env"] if "valueFrom" in e}
        self.assertEqual({r["name"] for r in refs.values()}, {"pr-autopilot-keyproxy"})
        self.assertEqual(refs[keyproxy.HMAC_ENV]["key"], "KEYPROXY_HMAC")
        self.assertNotIn("envFrom", c)
        # The URL the dispatcher's manifest suggests is this instance's gVPC name.
        self.assertIn(f"http://{name}-main-us-central-1-0.instances.datum.internal:8080",
                      (REMOTE / "dispatcher-workload-unikernel.yaml").read_text())

    def test_the_proxy_gets_a_github_token_for_every_owner_in_repos_json(self):
        c = self.doc["spec"]["template"]["spec"]["runtime"]["sandbox"]["containers"][0]
        refs = {e["name"]: e["valueFrom"]["secretKeyRef"] for e in c["env"] if "valueFrom" in e}
        owners = {k.split("/")[0] for k in json.loads(remote_review.CONFIG_FILE.read_text())}
        for var in ["GH_TOKEN", *(keyproxy.owner_token_var(f"{o}/x") for o in owners)]:
            self.assertEqual((refs[var]["key"], refs[var].get("optional")), (var, True), var)

    def test_the_dispatcher_uses_the_proxy_and_reads_the_shared_key(self):
        c = self.dispatcher["spec"]["template"]["spec"]["runtime"]["sandbox"]["containers"][0]
        env = {e["name"]: e for e in c["env"]}
        self.assertEqual(env[remote_review.KEYPROXY_URL_ENV]["value"],
                         "http://pr-autopilot-keyproxy-main-us-central-1-0.instances.datum.internal:8080")
        ref = env[keyproxy.HMAC_ENV]["valueFrom"]["secretKeyRef"]
        self.assertEqual((ref["name"], ref["key"], ref["optional"]), ("pr-autopilot-dispatcher", "KEYPROXY_HMAC", True))


class KeyproxyConfigTest(unittest.TestCase):
    SCRIPT = REMOTE / "make-dispatcher-config.py"

    def run_script(self, hmac_key: str, claude: str, extra: tuple = ()):
        tmp = pathlib.Path(tempfile.mkdtemp())
        (tmp / "pat").write_text("ghp_" + "x" * 36)
        (tmp / "key.json").write_text(json.dumps({"type": "datum_service_account", "private_key": "k"}))
        (tmp / "hmac").write_text(hmac_key + "\n")
        (tmp / "claude").write_text(claude + "\n")
        (tmp / "staging").write_text(REAL_STAGING)
        out = subprocess.run([sys.executable, str(self.SCRIPT), "--out", str(tmp / "out"), "--pat-file", str(tmp / "pat"),
                              "--key-file", str(tmp / "key.json"), "--keyproxy-hmac-file", str(tmp / "hmac"),
                              "--claude-token-file", str(tmp / "claude"),
                              *[a.replace("@", str(tmp) + "/") for a in extra]],
                             capture_output=True, text=True, timeout=60)
        return out, tmp / "out"

    def test_writes_both_secrets_with_the_same_hmac_key(self):
        out, d = self.run_script(KEY, REAL_CLAUDE, ("--mcp-staging-key-file", "@staging"))
        self.assertEqual(out.returncode, 0, out.stderr)
        mine = json.loads((d / "secret.json").read_text())["data"]
        proxy = json.loads((d / "keyproxy-secret.json").read_text())
        self.assertEqual(proxy["metadata"]["name"], "pr-autopilot-keyproxy")
        self.assertEqual(mine["KEYPROXY_HMAC"], proxy["data"]["KEYPROXY_HMAC"])
        self.assertEqual(sorted(proxy["data"]), ["CLAUDE_CODE_OAUTH_TOKEN", "DATUM_MCP_API_KEY_STAGING", "KEYPROXY_HMAC"])
        self.assertNotIn("CLAUDE_CODE_OAUTH_TOKEN", mine)
        self.assertEqual(oct((d / "keyproxy-secret.json").stat().st_mode & 0o777), "0o600")
        self.assertNotIn(REAL_CLAUDE, out.stdout + out.stderr)

    def test_adds_the_github_read_tokens_to_the_proxy_secret(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        (tmp / "gh").write_text(REAL_GH + "\n")
        (tmp / "milo").write_text(REAL_GH_MILO)
        out, d = self.run_script(KEY, REAL_CLAUDE, ("--github-read-token-file", str(tmp / "gh"),
                                                    "--github-owner-token", f"other-org={tmp / 'milo'}"))
        self.assertEqual(out.returncode, 0, out.stderr)
        proxy = json.loads((d / "keyproxy-secret.json").read_text())["data"]
        self.assertEqual(base64.b64decode(proxy["GH_TOKEN"]).decode(), REAL_GH)
        self.assertEqual(base64.b64decode(proxy["GH_TOKEN_OTHER_ORG"]).decode(), REAL_GH_MILO)
        self.assertNotIn("GH_TOKEN", json.loads((d / "secret.json").read_text())["data"])
        for secret in (REAL_GH, REAL_GH_MILO):
            self.assertNotIn(secret, out.stdout + out.stderr)

    def test_refuses_bad_github_token_flags(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        (tmp / "bad").write_text("not-a-token")
        (tmp / "gh").write_text(REAL_GH)
        self.assertIn("does not look like a GitHub token",
                      self.run_script(KEY, REAL_CLAUDE, ("--github-read-token-file", str(tmp / "bad")))[0].stderr)
        self.assertIn("OWNER=FILE",
                      self.run_script(KEY, REAL_CLAUDE, ("--github-owner-token", str(tmp / "gh")))[0].stderr)
        # Without the proxy flags a GitHub token file has nowhere to go.
        out = subprocess.run([sys.executable, str(self.SCRIPT), "--out", str(tmp / "o"), "--pat-file", str(tmp / "gh"),
                              "--key-file", str(tmp / "gh"), "--github-read-token-file", str(tmp / "gh")],
                             capture_output=True, text=True, timeout=60)
        self.assertIn("add --keyproxy-hmac-file", out.stderr)

    def test_refuses_a_short_key_or_a_token_that_is_not_oauth(self):
        self.assertIn("at least 32", self.run_script("short", REAL_CLAUDE)[0].stderr)
        self.assertIn("OAuth token", self.run_script(KEY, "sk-ant-api03-x")[0].stderr)


if __name__ == "__main__":
    unittest.main()
