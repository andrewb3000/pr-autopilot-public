#!/usr/bin/env python3
"""Credential proxy for the review workers on Datum (docs/dispatcher.md, "Credential proxy").

A worker VM gets placeholder keys instead of real ones, and holds no real credential. It
sends Claude, MCP and GitHub traffic here over plain HTTP inside the project's gVPC;
this process checks the placeholder, puts the real key in its place and forwards the
request over HTTPS. So a prompt injection or a bug in the worker can leak only a
placeholder, which works for one job, one upstream (for GitHub: one repo) and at most
an hour, and stops working once the dispatcher revokes it.

Only what the reviews use gets through (everything else is 403):
  POST /anthropic/v1/messages[?beta=...]              -> https://api.anthropic.com
  POST /anthropic/v1/messages/count_tokens[?beta=...]    (Authorization: Bearer)
  POST, GET, DELETE /mcp-staging   -> https://mcp.staging.corp.example/  (x-api-key)
  POST, GET, DELETE /mcp-prod      -> https://mcp.prod.corp.example/     (x-api-key)
  GET /github/repos/<job repo>/...                    -> https://api.github.com
  GET /github/repos/<owner>/<any>/issues/<n>             (Authorization: Bearer, also
  GET /github/repos/<owner>/<any>/issues/comments/<id>   upstream; <owner> = the job repo's)
  POST /github/graphql   only a query in github_api.GRAPHQL_QUERIES, word for word, whose
                         $owner/$name are the job repo
  GET /github-git/<job repo>.git/info/refs?service=git-upload-pack  -> https://github.com
  POST /github-git/<job repo>.git/git-upload-pack     (Bearer in, Basic x-access-token out)
  POST /revoke     the dispatcher ends a job's placeholders (see revoke_token())
  GET /healthz     200
Paths must match exactly, with no percent-encoding: /mcp-staging/logs (the Grafana MCP)
and any spelling of it never reach an upstream. GitHub paths are matched segment by
segment: plain characters only, no "." or ".." segment, no empty segment. GitHub query
keys: per_page, page, head_sha (API) and service (git), with plain values. Never
receive-pack: the worker cannot push. Only an allowlist of request headers is forwarded.
Redirects are not followed: a 3xx (an artifact download's signed blob URL) goes back
to the worker, which fetches it without any key.

GitHub tokens: GH_TOKEN, or GH_TOKEN_<OWNER> (e.g. GH_TOKEN_OTHER_ORG) for that owner's
repos when it is set, the same names remote/review-job.py used.

A placeholder is "<prefix><payload>.<mac>", payload = base64url("job|route|expiry"),
or "job|route|expiry|owner/name" for GitHub, mac = HMAC-SHA256 over the payload with
PR_AUTOPILOT_KEYPROXY_HMAC, which the dispatcher shares and uses to mint them (mint()).
One GitHub placeholder (route "github") serves both GitHub routes, for its repo only.
The proxy keeps only the set of revoked jobs, in memory; after a restart a revoked
placeholder works again until it expires. A request without a valid placeholder for its
route, in that route's header, is refused and its connection closed: real keys from a
worker are never passed through.

Resources, so one gVPC peer cannot lock out the workers: at most PER_CLIENT connections
per source (an IPv6 /64, or an IPv4 address) and MAX_CONNECTIONS in all. A connection
must deliver its request line and headers within HEADER_DEADLINE of starting to wait for
them, and an authenticated request its body at BODY_MIN_RATE or better; a watchdog shuts
down any connection past its deadline, however slowly it trickles bytes. An upstream slot
(MAX_UPSTREAM) is taken only after the placeholder checks out, and only while that
request runs. Request bodies are capped at MAX_BODY.

Responses stream: each piece the upstream sends is written and flushed at once, so a
Claude answer streamed over SSE for minutes arrives as it is produced, and a git pack of
hundreds of MB passes through CHUNK bytes at a time.

Each request is one JSON log line: client, route, job, status, seconds, and for GitHub
the repo and the path without its query. Never a header value.

This is not an egress fence. A worker can still reach any host directly; it just holds
no real key to use there.

Environment:
  PR_AUTOPILOT_KEYPROXY_HMAC        the shared key, at least 32 characters (required)
  CLAUDE_CODE_OAUTH_TOKEN           the real Claude token
  DATUM_MCP_API_KEY_STAGING, DATUM_MCP_API_KEY_PROD   the real MCP keys
  GH_TOKEN, GH_TOKEN_<OWNER>        the real read-only GitHub tokens
  PR_AUTOPILOT_KEYPROXY_PORT        default 8080
A route whose real key is not set answers 503.
"""
from __future__ import annotations

import base64
import collections
import copy
import hashlib
import hmac
import http.client
import http.server
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse

import github_api  # only for GRAPHQL_QUERIES, the GraphQL a worker may send

HMAC_ENV = "PR_AUTOPILOT_KEYPROXY_HMAC"
HMAC_MIN = 32
PORT = int(os.environ.get("PR_AUTOPILOT_KEYPROXY_PORT", "8080"))
LISTEN_BACKLOG = 128
# A worker holds a few connections at once: a Claude stream, an MCP event stream per
# server, MCP calls, and idle keep-alive ones until IDLE_TIMEOUT closes them.
PER_CLIENT = int(os.environ.get("PR_AUTOPILOT_KEYPROXY_PER_CLIENT", "12"))
MAX_CONNECTIONS = 96
# Requests running upstream at once. Each may hold a body of up to MAX_BODY in memory
# (twice, while it is read), so the worst case is about 16 x 16 MB = 256 MB, well inside
# the 4 GiB of a d1-standard-2.
MAX_UPSTREAM = 16
MAX_BODY = 8 * 1024 * 1024  # a long review context is 1-2 MB of JSON
CONNECT_TIMEOUT = 15
# Longest silence between two pieces of an upstream answer. A streamed Claude answer
# sends pings well inside this; a non-streamed one can take a few minutes.
READ_TIMEOUT = 600
IDLE_TIMEOUT = 10  # longest silence while waiting for the next request on a connection
CLIENT_TIMEOUT = 120  # longest silence from the worker while a request is in flight
# Absolute deadlines: a per-recv timeout alone lets a client that sends one byte every few
# seconds hold a connection for ever. HEADER_DEADLINE runs from when the proxy starts
# waiting for a request (a new or kept-alive connection) to the end of its headers. The
# body deadline is BODY_BASE plus the body's length at BODY_MIN_RATE.
HEADER_DEADLINE = 10
BODY_BASE = 10
BODY_MIN_RATE = 64 * 1024  # bytes a second; an 8 MB body gets 10 + 128 s
WATCH_INTERVAL = 0.25
CHUNK = 64 * 1024
MAX_REVOKED = 10_000

# Placeholders are minted when the dispatcher starts the worker, and the worker must call
# back within reviewer.WORKER_TTL (45 minutes) of that. An hour covers it with a margin.
TTL = 60 * 60

# Query values Claude Code sends (beta=true): plain tokens only.
QUERY_VALUE = re.compile(r"[A-Za-z0-9_.,-]{0,100}")


class Route:
    def __init__(self, name: str, upstream: str, header: str, secret_env: str, prefix: str,
                 paths: dict, query_keys: frozenset, headers: frozenset, header_prefixes: tuple, *,
                 match=None, scope: str | None = None, per_owner: bool = False, basic: bool = False):
        self.name, self.header, self.secret_env, self.prefix = name, header, secret_env, prefix
        u = urllib.parse.urlsplit(upstream)
        self.scheme, self.host, self.port = u.scheme, u.hostname, u.port
        self.paths = paths  # path after the route prefix, as sent -> (upstream path, methods)
        self.query_keys = query_keys
        self.headers, self.header_prefixes = headers, header_prefixes
        # GitHub routes: match(method, rest, query) -> (upstream path, target) or None, where
        # target says which repo the request reads (see github_match). Their placeholders
        # carry a repo, and one placeholder (scope "github") serves both GitHub routes.
        self.match = match
        self.scope = scope or name
        self.needs_repo = match is not None
        self.per_owner, self.basic = per_owner, basic

    def moved_to(self, upstream: str) -> "Route":
        """The same route with another upstream (for tests)."""
        other = copy.copy(self)
        u = urllib.parse.urlsplit(upstream)
        other.scheme, other.host, other.port = u.scheme, u.hostname, u.port
        return other

    def secret(self, repo: str | None = None) -> str | None:
        """The real key: for GitHub, the repo owner's own token if the Secret has one."""
        if self.per_owner and repo:
            key = os.environ.get(owner_token_var(repo), "").strip()
            if key:
                return key
        return os.environ.get(self.secret_env, "").strip() or None

    def real_value(self, repo: str | None = None) -> str | None:
        key = self.secret(repo)
        if not key:
            return None
        if self.basic:  # GitHub's git endpoints take a token as Basic auth
            return "Basic " + base64.b64encode(f"x-access-token:{key}".encode()).decode()
        return f"Bearer {key}" if self.header == "authorization" else key

    def forwards(self, header: str) -> bool:
        h = header.lower()
        return h in self.headers or h.startswith(self.header_prefixes)


OWNER_TOKEN_PREFIX = "GH_TOKEN_"


def owner_token_var(repo: str) -> str:
    """GH_TOKEN_OTHER_ORG for other-org/x, as remote/review-job.py names them."""
    return OWNER_TOKEN_PREFIX + re.sub(r"[^A-Z0-9]", "_", repo.split("/")[0].upper())


# One path segment as sent: no %, ;, space or empty segment. A segment of dots only (".",
# "..") is refused separately.
SEGMENT = re.compile(r"[A-Za-z0-9_.-]{1,200}")


def valid_repo(repo: str) -> bool:
    parts = repo.split("/")
    return len(parts) == 2 and all(SEGMENT.fullmatch(p) and p.strip(".") for p in parts)


def github_match(method: str, rest: str, query: str):
    """What the review worker reads from api.github.com:
      GET /repos/<job repo>/...                       anything in its own repo
      GET /repos/<owner>/<any>/issues/<n>             PRs and issues a PR body links to,
      GET /repos/<owner>/<any>/issues/comments/<id>   and comments, in the job repo's owner
      POST /graphql                                   only GRAPHQL_QUERIES (checked on the body)
    Returns (upstream path, target): ("repo", "<owner>/<name>") when the path must be the
    job's repo, ("owner", "<owner>") for a linked issue or comment, which must be in the
    job repo's owner, ("graphql",) for GraphQL. A linked issue elsewhere is not read: a
    stolen placeholder must not page through issues across every owner the token reaches."""
    if rest == "/graphql":
        return ("/graphql", ("graphql",)) if method == "POST" and not query else None
    parts = rest.split("/")
    if method != "GET" or len(parts) < 4 or parts[:2] != ["", "repos"]:
        return None
    segs = parts[2:]
    if not all(SEGMENT.fullmatch(s) and s.strip(".") for s in segs):
        return None
    repo, tail = f"{segs[0]}/{segs[1]}", segs[2:]
    linked = ((len(tail) == 2 and tail[0] == "issues" and tail[1].isdigit())
              or (len(tail) == 3 and tail[:2] == ["issues", "comments"] and tail[2].isdigit()))
    return rest + (f"?{query}" if query else ""), ("owner", segs[0]) if linked else ("repo", repo)


GIT_PATH = re.compile(r"/([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100})\.git/(info/refs|git-upload-pack)")


def git_match(method: str, rest: str, query: str):
    """Git smart HTTP, fetch only, on the job's repo: GET info/refs for upload-pack and
    POST git-upload-pack. Never receive-pack."""
    m = GIT_PATH.fullmatch(rest)
    if not m or not valid_repo(f"{m[1]}/{m[2]}"):
        return None
    if m[3] == "info/refs" and not (method == "GET" and query == "service=git-upload-pack"):
        return None
    if m[3] == "git-upload-pack" and not (method == "POST" and not query):
        return None
    return rest + (f"?{query}" if query else ""), ("repo", f"{m[1]}/{m[2]}")


GRAPHQL_KEYS = {"query", "variables"}


def graphql_allowed(body: bytes, repo: str) -> bool:
    """A GraphQL body passes only with one of github_api.GRAPHQL_QUERIES word for word,
    and, if that query takes $owner and $name, with the job's repo in them."""
    try:
        doc = json.loads(body.decode("utf-8"))  # GitHub reads UTF-8 only
    except (ValueError, UnicodeDecodeError):
        return False
    if not isinstance(doc, dict) or set(doc) - GRAPHQL_KEYS or not isinstance(doc.get("query"), str):
        return False
    query, variables = doc["query"], doc.get("variables") or {}
    if query not in github_api.GRAPHQL_QUERIES or not isinstance(variables, dict):
        return False
    if "$owner" in query or "$name" in query:
        owner, name = variables.get("owner"), variables.get("name")
        if not (isinstance(owner, str) and isinstance(name, str) and f"{owner}/{name}".lower() == repo.lower()):
            return False
    return True


# Seen from claude -p 2.1.308 with an MCP config (2026-11-13). MCP's streamable HTTP also
# uses GET (the server's event stream) and DELETE (end of session) on the same URL.
ANTHROPIC_HEADERS = frozenset({"accept", "accept-encoding", "content-type", "user-agent", "x-app"})
ANTHROPIC_PREFIXES = ("anthropic-", "x-stainless-", "x-claude-code-")
MCP_HEADERS = frozenset({"accept", "accept-encoding", "content-type", "user-agent", "last-event-id"})
MCP_PREFIXES = ("mcp-",)
MCP_PATHS = {"": ("/", {"POST", "GET", "DELETE"}), "/": ("/", {"POST", "GET", "DELETE"})}
# What urllib (github_api) and git send.
GITHUB_HEADERS = frozenset({"accept", "accept-encoding", "content-type", "user-agent", "x-github-api-version"})
GIT_HEADERS = frozenset({"accept", "accept-encoding", "content-type", "content-encoding", "user-agent",
                         "git-protocol"})

# The prefixes make placeholders look like what each client expects. Claude Code sends
# the token as it is; the shape only helps anyone reading a log see what it stands for.
ROUTES = {
    "anthropic": Route("anthropic", "https://api.anthropic.com", "authorization", "CLAUDE_CODE_OAUTH_TOKEN",
                       "sk-ant-oat01-pap-",
                       {"/v1/messages": ("/v1/messages", {"POST"}),
                        "/v1/messages/count_tokens": ("/v1/messages/count_tokens", {"POST"})},
                       frozenset({"beta"}), ANTHROPIC_HEADERS, ANTHROPIC_PREFIXES),
    "mcp-staging": Route("mcp-staging", "https://mcp.staging.corp.example", "x-api-key",
                         "DATUM_MCP_API_KEY_STAGING", "pap-mcp-", MCP_PATHS, frozenset(), MCP_HEADERS, MCP_PREFIXES),
    "mcp-prod": Route("mcp-prod", "https://mcp.prod.corp.example", "x-api-key",
                      "DATUM_MCP_API_KEY_PROD", "pap-mcp-", MCP_PATHS, frozenset(), MCP_HEADERS, MCP_PREFIXES),
    # The review worker's GitHub reads (github_api from pr_worker and full_review), with a
    # read-only token: GH_TOKEN, or GH_TOKEN_<OWNER> for that owner's repos.
    "github": Route("github", "https://api.github.com", "authorization", "GH_TOKEN", "pap-gh-", {},
                    frozenset({"per_page", "page", "head_sha"}), GITHUB_HEADERS, (),
                    match=github_match, per_owner=True),
    # Its clone and fetches (full_review.ensure_clone). Same placeholder as "github".
    "github-git": Route("github-git", "https://github.com", "authorization", "GH_TOKEN", "pap-gh-", {},
                        frozenset({"service"}), GIT_HEADERS, (),
                        match=git_match, scope="github", per_owner=True, basic=True),
}

# Response headers that describe one connection, not the answer.
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
              "transfer-encoding", "upgrade", "content-length", "set-cookie",
              # They describe the real GitHub token (its scopes and expiry), not the answer.
              "x-oauth-scopes", "x-accepted-oauth-scopes", "x-accepted-github-permissions",
              "github-authentication-token-expiration", "x-oauth-client-id"}


# --- Placeholders --------------------------------------------------------------------

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _mac(key: str, payload: str) -> str:
    return _b64(hmac.new(key.encode(), payload.encode("utf-8", "surrogateescape"), hashlib.sha256).digest())


def _same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8", "surrogateescape"), b.encode("utf-8", "surrogateescape"))


def hmac_key(env: dict | None = None) -> str:
    key = (os.environ if env is None else env).get(HMAC_ENV, "").strip()
    if len(key) < HMAC_MIN:
        raise ValueError(f"{HMAC_ENV} must be at least {HMAC_MIN} characters")
    return key


def mint(key: str, job: str, route: str, now: float | None = None, ttl: int = TTL,
         repo: str | None = None) -> str:
    """A placeholder for one job and one route, valid for `ttl` seconds. A GitHub
    placeholder (route "github", also good for "github-git") also names the job's repo,
    and works only for it: payload "job|route|expiry|repo". The others keep the
    three-field payload, so placeholders minted before the GitHub routes still verify."""
    r = ROUTES.get(route)
    if r is None or r.scope != route:
        raise ValueError(f"unknown route {route}")
    if "|" in job or not job:
        raise ValueError("bad job id")
    if r.needs_repo != bool(repo) or (repo and not valid_repo(repo)):
        raise ValueError(f"route {route} needs a repo" if r.needs_repo else f"route {route} takes no repo")
    expiry = int((time.time() if now is None else now) + ttl)
    payload = _b64("|".join([job, route, str(expiry), *([repo] if repo else [])]).encode())
    return f"{r.prefix}{payload}.{_mac(key, payload)}"


def claims(key: str, token: str, route: str, now: float | None = None) -> tuple[str, str | None] | None:
    """(job, repo or None) if `token` is a live placeholder for `route`, else None."""
    r = ROUTES[route]
    if not token.startswith(r.prefix) or token.count(".") != 1:
        return None
    payload, mac = token[len(r.prefix):].split(".")
    if not _same(_mac(key, payload), mac):
        return None
    try:
        fields = _unb64(payload).decode().split("|")
        job, scope, expiry, repo = fields if len(fields) == 4 else (*fields, None)
        expiry_at = int(expiry)
    except ValueError:
        return None
    if scope != r.scope or (time.time() if now is None else now) >= expiry_at:
        return None
    if r.needs_repo != (repo is not None) or (repo is not None and not valid_repo(repo)):
        return None
    return job, repo


def verify(key: str, token: str, route: str, now: float | None = None) -> str | None:
    """The job id if `token` is a live placeholder for `route`, else None."""
    found = claims(key, token, route, now)
    return found[0] if found else None


def revoke_token(key: str, job: str) -> str:
    """What the dispatcher sends to /revoke a job: only a holder of the key can make it."""
    return "pap-revoke-" + _mac(key, f"revoke|{job}")


def bearer(headers) -> str:
    scheme, _, token = (headers.get("authorization") or "").strip().partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""


def presented(headers, route: Route) -> str:
    """The placeholder in the route's header, or ""."""
    if route.header == "authorization":
        return bearer(headers)
    return (headers.get(route.header) or "").strip()


def resolve(method: str, path: str) -> tuple[int, Route | None, str, tuple | None]:
    """(0, route, upstream path, target) for an allowed request; else (404 or 403, route,
    "", None). `target` is None, or for GitHub what github_match returns: the repo check
    against the placeholder comes once the placeholder is read.

    The path after the route prefix must equal an allowed one (or, for GitHub, match its
    pattern) as sent: no decoding, so no %, ;, dot segment or extra slash gets through.
    The query may hold only the route's keys, with plain values."""
    raw_path, _, query = path.partition("?")
    if not raw_path.startswith("/"):
        return 404, None, "", None
    first, slash, rest = raw_path[1:].partition("/")
    route = ROUTES.get(first)
    if route is None:
        return 404, None, "", None
    if query:
        pairs = [p.partition("=") for p in query.split("&")]
        if any(k not in route.query_keys or not QUERY_VALUE.fullmatch(v) for k, _, v in pairs):
            return 403, route, "", None
    if route.match is not None:
        hit = route.match(method, slash + rest, query)
        return (403, route, "", None) if hit is None else (0, route, hit[0], hit[1])
    allowed = route.paths.get(slash + rest)
    if allowed is None or method not in allowed[1]:
        return 403, route, "", None
    return 0, route, allowed[0] + (f"?{query}" if query else ""), None


# --- Server ---------------------------------------------------------------------------

def log(**fields) -> None:
    """One JSON line per request: client, route, job, status, seconds. Never a header value."""
    print(json.dumps({"ts": round(time.time()), **fields}), flush=True)


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "pr-autopilot-keyproxy"
    timeout = IDLE_TIMEOUT

    def handle_one_request(self) -> None:
        # Between requests a keep-alive connection may sit idle only briefly, and the whole
        # request line and headers must arrive within HEADER_DEADLINE.
        self.connection.settimeout(IDLE_TIMEOUT)
        self.server.set_deadline(self.connection, HEADER_DEADLINE, self.client_address[0])
        super().handle_one_request()

    def parse_request(self) -> bool:
        ok = super().parse_request()  # reads the headers
        self.server.clear_deadline(self.connection)
        return ok

    def finish(self) -> None:
        self.server.clear_deadline(self.connection)
        super().finish()

    def body_deadline(self) -> None:
        """Give the body a deadline that grows with its declared length."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            length = MAX_BODY
        self.server.set_deadline(self.connection, BODY_BASE + min(max(length, 0), MAX_BODY) / BODY_MIN_RATE,
                                 self.client_address[0])

    def reply(self, status: int, message: str) -> None:
        if status >= 400:
            self.close_connection = True  # an unread request body must not become the next request
        body = (message + "\n").encode()
        self.send_response(status)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def read_body(self, limit: int = MAX_BODY) -> bytes | None:
        """The request body, de-chunked; None if it is too large or malformed."""
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            out = bytearray()
            while True:
                line = self.rfile.readline(1024)
                try:
                    size = int(line.split(b";")[0].strip(), 16)
                except ValueError:
                    return None
                if size == 0:
                    while self.rfile.readline(1024) not in (b"\r\n", b"\n", b""):
                        pass  # trailers
                    return bytes(out)
                if size < 0 or len(out) + size > limit:
                    return None
                out += self.rfile.read(size)
                self.rfile.readline(1024)
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length < 0 or length > limit:
            return None
        body = self.rfile.read(length) if length else b""
        return body if len(body) == length else None

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.reply(200, "ok")
            return
        self.proxy()

    def do_POST(self) -> None:
        if self.path == "/revoke":
            self.revoke()
            return
        self.proxy()

    def revoke(self) -> None:
        started, client = time.monotonic(), self.client_address[0]
        self.server.set_deadline(self.connection, BODY_BASE, client)
        body = self.read_body(limit=1024)
        self.server.clear_deadline(self.connection)
        try:
            job = str(json.loads(body or b"").get("job") or "")
        except (ValueError, AttributeError):
            job = ""
        if not job or "|" in job or not _same(revoke_token(self.server.key, job), bearer(self.headers)):
            self.reply(401, "a valid revoke token is required")
            log(method="POST", route="revoke", client=client, job=None, status=401,
                seconds=round(time.monotonic() - started, 2))
            return
        self.server.revoke(job)
        self.reply(200, "revoked")
        log(method="POST", route="revoke", client=client, job=job, status=200,
            seconds=round(time.monotonic() - started, 2))

    def proxy(self) -> None:
        started = time.monotonic()
        refused, route, path, target = resolve(self.command, self.path)
        fields = {"method": self.command, "route": route.name if route else None, "client": self.client_address[0],
                  "job": None}
        if target is not None:
            # A GitHub path that matched: plain characters only. The query is left out.
            fields["path"] = path.partition("?")[0]

        def done(status: int, **extra) -> None:
            log(**fields, status=status, seconds=round(time.monotonic() - started, 2), **extra)

        if refused:
            self.reply(refused, "no such route" if refused == 404 else "not allowed")
            done(refused)
            return
        found = claims(self.server.key, presented(self.headers, route), route.name)
        job, repo = found or (None, None)
        if job is None or self.server.is_revoked(job):
            # Also what a real key gets: it is never passed on.
            self.reply(401, "a placeholder for this route is required")
            done(401, revoked=job is not None)
            return
        fields["job"] = job
        if repo:
            fields["repo"] = repo
        if target is not None and target[0] in ("repo", "owner") and \
                target[1].lower() != (repo if target[0] == "repo" else repo.split("/")[0]).lower():
            self.reply(403, "not allowed for this placeholder's repo")
            done(403, other_repo=True)
            return
        real = route.real_value(repo)
        if real is None:
            self.reply(503, f"no key for {route.name}")
            done(503)
            return
        if not self.server.upstream.acquire(blocking=False):
            self.reply(503, "busy")
            done(503, busy=True)
            return
        try:
            self.connection.settimeout(CLIENT_TIMEOUT)  # a request in flight may be slower
            self.forward(route, path, real, done, graphql_repo=repo if target == ("graphql",) else None)
        finally:
            self.server.upstream.release()

    def forward(self, route: Route, path: str, real: str, done, graphql_repo: str | None = None) -> None:
        self.body_deadline()
        body = self.read_body()
        self.server.clear_deadline(self.connection)
        if body is None:
            self.reply(413, "request body too large or malformed")
            done(413)
            return
        if graphql_repo is not None and not graphql_allowed(body, graphql_repo):
            self.reply(403, "this GraphQL query is not allowed")
            done(403, graphql=False)
            return
        headers = {k: v for k, v in self.headers.items() if route.forwards(k)}
        headers[route.header] = real
        headers["Host"] = route.host if route.port is None else f"{route.host}:{route.port}"
        if body or self.command in ("POST", "PUT", "PATCH"):
            headers["Content-Length"] = str(len(body))
        conn_cls = http.client.HTTPSConnection if route.scheme == "https" else http.client.HTTPConnection
        kwargs = {"context": self.server.tls} if route.scheme == "https" else {}
        conn = conn_cls(route.host, route.port, timeout=CONNECT_TIMEOUT, **kwargs)
        try:
            conn.connect()
            conn.sock.settimeout(READ_TIMEOUT)
            conn.putrequest(self.command, path, skip_host=True, skip_accept_encoding=True)
            for k, v in headers.items():
                conn.putheader(k, v)
            conn.endheaders(body or None)
            resp = conn.getresponse()
        except (OSError, http.client.HTTPException) as e:
            self.reply(502, "upstream unreachable")
            done(502, error=type(e).__name__)
            conn.close()
            return
        except ValueError as e:  # incl. UnicodeError: a header value http.client will not send
            self.reply(400, "bad request header")
            done(400, error=type(e).__name__)
            conn.close()
            return
        try:
            done(resp.status, bytes=stream(self, resp))
        finally:
            conn.close()

    do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = proxy

    def log_message(self, fmt: str, *args) -> None:
        pass


def stream(handler: ProxyHandler, resp: http.client.HTTPResponse) -> int:
    """Send the upstream answer on as it arrives. A known length is kept; otherwise the
    answer goes out chunked. Returns the body bytes sent."""
    length = resp.getheader("Content-Length")
    no_body = handler.command == "HEAD" or resp.status in (204, 304) or 100 <= resp.status < 200
    chunked = not no_body and length is None
    sent = 0
    try:
        handler.send_response_only(resp.status, resp.reason)
        for k, v in resp.getheaders():
            if k.lower() not in HOP_BY_HOP:
                handler.send_header(k, v)
        if chunked:
            handler.send_header("Transfer-Encoding", "chunked")
        elif length is not None:
            handler.send_header("Content-Length", length)
        handler.end_headers()
        handler.wfile.flush()
        while not no_body:
            piece = resp.read1(CHUNK)
            if not piece:
                break
            sent += len(piece)
            handler.wfile.write(b"%x\r\n%s\r\n" % (len(piece), piece) if chunked else piece)
            handler.wfile.flush()
        if chunked:
            handler.wfile.write(b"0\r\n\r\n")
            handler.wfile.flush()
    except (OSError, http.client.HTTPException):
        handler.close_connection = True  # the client sees a cut answer, not a whole one
    return sent


def source(address: str) -> str:
    """What the per-client cap counts: an IPv6 /64 (one peer can use many addresses in it),
    or an IPv4 address, also when it arrives IPv4-mapped."""
    try:
        ip = ipaddress.ip_address(address.split("%")[0])
    except ValueError:
        return address
    if ip.version == 6 and ip.ipv4_mapped:
        return str(ip.ipv4_mapped)
    if ip.version == 6:
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


class Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6
    request_queue_size = LISTEN_BACKLOG
    daemon_threads = True
    BUSY = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nbusy\n"

    def __init__(self, addr, key: str, *args, **kwargs):
        self.key = key
        self.tls = ssl.create_default_context()
        self.upstream = threading.BoundedSemaphore(MAX_UPSTREAM)
        self.guard = threading.Lock()
        self.connections: collections.Counter = collections.Counter()  # per source address
        self.revoked: dict[str, float] = {}  # job -> when its placeholders expire anyway
        self.deadlines: dict = {}  # socket -> (monotonic deadline, client address)
        self.closing = threading.Event()
        super().__init__(addr, ProxyHandler, *args, **kwargs)
        threading.Thread(target=self.watch, name="deadlines", daemon=True).start()

    def set_deadline(self, conn, seconds: float, client: str) -> None:
        with self.guard:
            self.deadlines[conn] = (time.monotonic() + seconds, client)

    def clear_deadline(self, conn) -> None:
        with self.guard:
            self.deadlines.pop(conn, None)

    def watch(self) -> None:
        """Shut down every connection past its deadline: its blocked read then ends."""
        while not self.closing.wait(WATCH_INTERVAL):
            now = time.monotonic()
            with self.guard:
                late = [(c, client) for c, (at, client) in self.deadlines.items() if at <= now]
                for c, _ in late:
                    del self.deadlines[c]
            for conn, client in late:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                log(event="cut off", client=client, reason="too slow to send its request")

    def server_close(self) -> None:
        self.closing.set()
        super().server_close()

    def is_revoked(self, job: str) -> bool:
        with self.guard:
            return job in self.revoked

    def revoke(self, job: str) -> None:
        now = time.time()
        with self.guard:
            for old in [j for j, until in self.revoked.items() if until <= now]:
                del self.revoked[old]
            if len(self.revoked) >= MAX_REVOKED:  # only the dispatcher can add; never expected
                del self.revoked[min(self.revoked, key=self.revoked.get)]
            self.revoked[job] = now + TTL

    def process_request(self, request, client_address) -> None:
        client = source(client_address[0])
        with self.guard:
            full = self.connections[client] >= PER_CLIENT or sum(self.connections.values()) >= MAX_CONNECTIONS
            if not full:
                self.connections[client] += 1
        if full:
            try:
                request.sendall(self.BUSY)
            except OSError:
                pass
            self.shutdown_request(request)
            log(event="refused", client=client_address[0], reason="too many connections")
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.release(client)
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.release(source(client_address[0]))

    def release(self, client: str) -> None:
        with self.guard:
            self.connections[client] -= 1
            if self.connections[client] <= 0:
                del self.connections[client]

    def server_bind(self) -> None:
        # Both IPv6 (gVPC addresses are IPv6) and IPv4.
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


def main() -> int:
    try:
        key = hmac_key()
    except ValueError as e:
        print(f"keyproxy: {e}", file=sys.stderr)
        return 2
    missing = [r.secret_env for r in ROUTES.values() if not os.environ.get(r.secret_env)]
    server = Server(("::", PORT), key)
    owners = sorted(k for k in os.environ if k.startswith(OWNER_TOKEN_PREFIX) and os.environ[k].strip())
    log(event="started", port=PORT, routes=sorted(ROUTES), missing_keys=sorted(set(missing)),
        github_owner_tokens=owners)  # names only
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
