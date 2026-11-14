"""GitHub REST calls over the Python standard library, in place of the `gh` CLI.

The dispatcher on Datum runs as one process with no fork/exec, so it cannot run `gh`.
Everything here is plain HTTPS with urllib.

The token comes from, in this order:
  PR_AUTOPILOT_GITHUB_TOKEN   env (the dispatcher on Datum: a classic PAT from a Secret;
                              a review worker: a credential-proxy placeholder, or its
                              read token in rollback mode)
  Keychain item pr-autopilot-github-token   (the laptop, if you store one there)
  `gh auth token`             (the laptop: the token gh is already logged in with)
The notifications API refuses fine-grained tokens, so use a classic PAT (or gh's own
OAuth token, which works too).

PR_AUTOPILOT_GITHUB_API sets the API base (default https://api.github.com). A review
worker behind the credential proxy sets it to <proxy>/github (keyproxy.py). Both
variables are read on every call, so setting them after import works.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
API_ENV = "PR_AUTOPILOT_GITHUB_API"
TOKEN_ENV = "PR_AUTOPILOT_GITHUB_TOKEN"
KEYCHAIN_SERVICE = "pr-autopilot-github-token"
TIMEOUT = 60
JSON = "application/vnd.github+json"
DIFF = "application/vnd.github.diff"
USER_AGENT = "pr-autopilot"

_TOKEN: str | None = None


class GitHubError(Exception):
    """A GitHub call that failed. `status` is the HTTP status, or 0 when GitHub never
    answered (DNS, TLS, timeout). The message says what GitHub answered."""

    def __init__(self, method: str, path: str, status: int, message: str):
        self.method, self.path, self.status, self.message = method, path, status, message
        super().__init__(f"GitHub {method} {path}: {f'HTTP {status}' if status else 'no answer'}"
                         f"{': ' + message if message else ''}")


class Unauthorized(GitHubError):
    """HTTP 401: the token is wrong, expired or revoked. Nothing works until it is replaced."""


class RateLimited(GitHubError):
    """HTTP 403 or 429 from a rate limit. `retry_after`: seconds to wait before any call."""

    def __init__(self, method: str, path: str, status: int, message: str, retry_after: int):
        super().__init__(method, path, status, message)
        self.retry_after = retry_after


def retry_after(status: int, headers: dict, now: float) -> int | None:
    """Seconds to wait when this answer is a rate limit, else None (see GitHub's docs on
    rate limits: Retry-After, or X-RateLimit-Remaining 0 until X-RateLimit-Reset)."""
    lower = {k.lower(): v for k, v in (headers or {}).items()}
    if status not in (403, 429):
        return None
    if lower.get("retry-after", "").isdigit():
        return max(1, int(lower["retry-after"]))
    if lower.get("x-ratelimit-remaining") == "0" and lower.get("x-ratelimit-reset", "").isdigit():
        return max(1, int(lower["x-ratelimit-reset"]) - int(now))
    return 60 if status == 429 else None


def api() -> str:
    """The API base, read now: a worker sets it after this module is imported."""
    return (os.environ.get(API_ENV) or API).strip().rstrip("/")


class SameHostRedirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but never send the token to another host (artifact downloads
    redirect to a signed blob URL). request() adds Authorization as an unredirected
    header, which urllib never copies to a redirect; this handler puts it back only
    when the redirect stays on the same host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None:
            return None
        old, nxt = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        if (nxt.scheme, nxt.netloc) != (old.scheme, old.netloc):
            new.remove_header("Authorization")
        else:
            auth = req.unredirected_hdrs.get("Authorization") or req.headers.get("Authorization")
            if auth:
                new.add_unredirected_header("Authorization", auth)
        return new


_OPENER = urllib.request.build_opener(SameHostRedirects)


def _open(req: urllib.request.Request, timeout: int):
    return _OPENER.open(req, timeout=timeout)


def token() -> str:
    """The GitHub token, looked up once per process (see the module docstring)."""
    global _TOKEN
    found = os.environ.get(TOKEN_ENV, "").strip()  # read each time: a worker sets it after import
    if found:
        return found
    if _TOKEN:
        return _TOKEN
    if shutil.which("security"):  # laptop only: the dispatcher has no Keychain
        p = subprocess.run(["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"],
                           capture_output=True, text=True, timeout=30)
        found = p.stdout.strip() if p.returncode == 0 else ""
    if not found and shutil.which("gh"):  # laptop only
        p = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=30)
        found = p.stdout.strip() if p.returncode == 0 else ""
    if not found:
        raise Unauthorized("GET", "(token)", 401, f"no GitHub token: set {TOKEN_ENV}")
    _TOKEN = found
    return found


def _message(body: bytes) -> str:
    """GitHub's error message and its `errors` list, which say why (e.g. an archived repo)."""
    text = body.decode("utf-8", "replace").strip()
    try:
        data = json.loads(text)
        parts = [data.get("message", "")] + [str(e) for e in data.get("errors", [])]
        return "; ".join(p for p in parts if p)[:300]
    except (ValueError, AttributeError):
        return text[-300:]


def request(method: str, path: str, *, params: dict | None = None, body: dict | None = None,
            accept: str = JSON, headers: dict | None = None,
            timeout: int = TIMEOUT) -> tuple[int, dict, bytes]:
    """One call. Returns (status, headers, body) for 2xx and 304; raises GitHubError
    (Unauthorized for 401) for anything else."""
    base = api()
    url = path if path.startswith(("https://", "http://")) else f"{base}/{path.lstrip('/')}"
    if params:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Accept": accept,
                                          "User-Agent": USER_AGENT, "X-GitHub-Api-Version": "2022-11-28",
                                          **({"Content-Type": "application/json"} if body is not None else {}),
                                          **(headers or {})})
    # Unredirected: urllib copies normal headers to every redirect, and a redirect to
    # another host (an artifact's signed blob URL) must never get the token.
    req.add_unredirected_header("Authorization", f"Bearer {token()}")
    short = path.replace(base, "").lstrip("/").split("?")[0]
    try:
        with _open(req, timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return 304, dict(e.headers or {}), b""
        wait = retry_after(e.code, dict(e.headers or {}), time.time())
        if wait is not None:
            raise RateLimited(method, short, e.code, _message(e.read() or b""), wait) from None
        error = Unauthorized if e.code == 401 else GitHubError
        raise error(method, short, e.code, _message(e.read() or b"")) from None
    except (urllib.error.URLError, OSError) as e:  # DNS, TLS, timeout, reset
        raise GitHubError(method, short, 0, str(getattr(e, "reason", e))) from None


def get(path: str, **params) -> object:
    return json.loads(request("GET", path, params=params or None)[2] or b"null")


def post(path: str, body: dict) -> object:
    return json.loads(request("POST", path, body=body)[2] or b"null")


def paginate(path: str, **params) -> list:
    """Every item of a list endpoint, following the Link header's rel="next".

    The next page is asked for on the same path, with the query the link gives. GitHub's
    links often name the repo by id (/repositories/123/...) and always point at
    api.github.com, which a worker behind the credential proxy must not call directly;
    the proxy allows only /repos/<owner>/<name>/..."""
    out, query = [], {"per_page": 100, **params}
    while query is not None:
        _, headers, body = request("GET", path, params=query)
        out += json.loads(body or b"[]")
        link = next_link(headers.get("Link") or headers.get("link") or "")
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(link).query)) if link else None
        if query == {}:  # a next link with no query would ask for the same page for ever
            break
    return out


def next_link(link: str) -> str | None:
    m = re.search(r'<([^>]+)>;\s*rel="next"', link)
    return m.group(1) if m else None


# --- The calls pr-autopilot makes -------------------------------------------------

def login() -> str:
    return get("user")["login"]


def search_issues(q: str) -> dict:
    return get("search/issues", q=q, per_page=100)


def pull(repo: str, num) -> dict:
    return get(f"repos/{repo}/pulls/{num}")


def head_sha(repo: str, num) -> str:
    return pull(repo, num)["head"]["sha"]


def timeline(repo: str, num) -> list:
    return paginate(f"repos/{repo}/issues/{num}/timeline")


def reviews(repo: str, num) -> list:
    return paginate(f"repos/{repo}/pulls/{num}/reviews")


def create_review(repo: str, num, sha: str, event: str | None, body: str) -> None:
    payload = {"commit_id": sha, "body": body}
    if event:
        payload["event"] = event
    post(f"repos/{repo}/pulls/{num}/reviews", payload)


def diff(repo: str, num) -> str | None:
    """The PR diff, or None when GitHub refuses it as too large (406)."""
    try:
        return request("GET", f"repos/{repo}/pulls/{num}", accept=DIFF)[2].decode("utf-8", "replace")
    except GitHubError as e:
        if e.status == 406 or "too large" in e.message:
            return None
        raise


def changed_files(repo: str, num) -> list[str]:
    """Changed paths, with both names of a rename (as `gh pr diff --name-only` lists them)."""
    paths = []
    for f in paginate(f"repos/{repo}/pulls/{num}/files"):
        if f.get("previous_filename"):
            paths.append(f["previous_filename"])
        paths.append(f["filename"])
    return paths


def is_private(repo: str) -> bool:
    return bool(get(f"repos/{repo}")["private"])


def notifications(last_modified: str | None) -> tuple[list | None, str | None, int]:
    """Conditional GET /notifications: (notifications or None on 304, Last-Modified,
    X-Poll-Interval seconds). A 304 does not count against the rate limit. The caller
    keeps Last-Modified and waits X-Poll-Interval before asking again."""
    headers = {"If-Modified-Since": last_modified} if last_modified else {}
    status, resp_headers, body = request("GET", "notifications", params={"all": "true", "per_page": 50},
                                         headers=headers, timeout=30)
    lower = {k.lower(): v for k, v in resp_headers.items()}
    try:
        interval = int(lower.get("x-poll-interval") or 0)
    except ValueError:
        interval = 0
    if status == 304:
        return None, last_modified, interval
    return json.loads(body or b"[]"), lower.get("last-modified") or last_modified, interval


# --- What a review worker reads (pr_worker, full_review) ----------------------------
# A worker behind the credential proxy may only read its own repo, plus the issues and
# comments a PR body links to (keyproxy.py checks each path).

def issue_comments(repo: str, num) -> list:
    return paginate(f"repos/{repo}/issues/{num}/comments")


def download(path: str, timeout: int = 300) -> bytes:
    """A binary download such as an artifact zip. GitHub answers 302 to a signed URL on
    another host; urllib follows it, without the token (SameHostRedirects)."""
    return request("GET", path, accept=JSON, timeout=timeout)[2]


def graphql(query: str, variables: dict) -> dict:
    """One GraphQL call; its `data`. GraphQL errors come back as HTTP 200 with `errors`."""
    out = json.loads(request("POST", "graphql", body={"query": query, "variables": variables})[2] or b"{}")
    if out.get("errors"):
        raise GitHubError("POST", "graphql", 200, "; ".join(str(e.get("message", e)) for e in out["errors"])[:300])
    return out.get("data") or {}


# The CI checks of a PR's head commit, as `gh pr checks` reads them. A worker behind the
# credential proxy sends it there, and the proxy forwards a GraphQL call only when its
# query is one of GRAPHQL_QUERIES, word for word, and $owner/$name are the job's repo.
CHECKS_QUERY = """query PrChecks($owner: String!, $name: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      commits(last: 1) {
        nodes {
          commit {
            statusCheckRollup {
              contexts(first: 100, after: $cursor) {
                pageInfo { hasNextPage endCursor }
                nodes {
                  __typename
                  ... on CheckRun {
                    name
                    status
                    conclusion
                    startedAt
                    isRequired(pullRequestNumber: $number)
                    checkSuite { workflowRun { event workflow { name } } }
                  }
                  ... on StatusContext {
                    context
                    state
                    isRequired(pullRequestNumber: $number)
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}"""
GRAPHQL_QUERIES = (CHECKS_QUERY,)
CHECKS_PAGES = 10  # 1000 checks; a busy repo runs about 100


def check_bucket(state: str) -> str:
    """gh's bucket for a check state (gh pr checks, pkg/cmd/pr/checks/aggregate.go)."""
    if state == "SUCCESS":
        return "pass"
    if state in ("SKIPPED", "NEUTRAL"):
        return "skipping"
    if state in ("ERROR", "FAILURE", "TIMED_OUT", "ACTION_REQUIRED", "STARTUP_FAILURE"):
        return "fail"
    if state == "CANCELLED":
        return "cancel"
    return "pending"  # EXPECTED, REQUESTED, WAITING, QUEUED, PENDING, IN_PROGRESS, STALE


def check_rows(nodes: list) -> list[dict]:
    """{name, workflow, bucket, required} per check, as `gh pr checks --json` gives them.
    Like gh, a check run that ran again counts once: the latest by start time for each
    name, workflow and event."""
    runs = [n for n in nodes if n.get("__typename") == "CheckRun"]
    runs.sort(key=lambda n: n.get("startedAt") or "", reverse=True)
    rows, seen = [], set()
    for n in runs:
        run = (n.get("checkSuite") or {}).get("workflowRun") or {}
        workflow = (run.get("workflow") or {}).get("name") or ""
        key = (n.get("name"), workflow, run.get("event") or "")
        if key in seen:
            continue
        seen.add(key)
        state = n.get("conclusion") if n.get("status") == "COMPLETED" else n.get("status")
        rows.append({"name": n.get("name") or "", "workflow": workflow, "bucket": check_bucket(state or ""),
                     "required": bool(n.get("isRequired"))})
    for n in nodes:
        if n.get("__typename") == "StatusContext":
            rows.append({"name": n.get("context") or "", "workflow": "", "bucket": check_bucket(n.get("state") or ""),
                         "required": bool(n.get("isRequired"))})
    return rows


def checks(repo: str, num) -> list[dict]:
    """The PR head's checks (check_rows), from one fixed GraphQL query, page by page."""
    owner, name = repo.split("/", 1)
    nodes, cursor = [], None
    for _ in range(CHECKS_PAGES):
        data = graphql(CHECKS_QUERY, {"owner": owner, "name": name, "number": int(num), "cursor": cursor})
        pr = (data.get("repository") or {}).get("pullRequest") or {}
        commits = (pr.get("commits") or {}).get("nodes") or []
        rollup = (commits[0].get("commit") or {}).get("statusCheckRollup") if commits else None
        contexts = (rollup or {}).get("contexts") or {}
        nodes += contexts.get("nodes") or []
        page = contexts.get("pageInfo") or {}
        if not page.get("hasNextPage"):
            break
        cursor = page.get("endCursor")
    return check_rows(nodes)
