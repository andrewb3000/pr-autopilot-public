#!/usr/bin/env python3
"""Run one review of one PR commit inside the review container and print the result.

With REVIEW_PLAN=quick it runs the quick review first and, if that escalates (or
REVIEW_AUDIT picks it for a spot check), the full review in the same VM. With
REVIEW_PLAN=full (or no REVIEW_PLAN, as older dispatchers send) it runs only the
full review. Either way it prints one result (pr_worker.review's outcome, plus
"ok" and "usage"): one JSON line between the two markers below, which the
dispatcher reads from the container's logs (`datumctl compute logs`). This job
never posts anything to GitHub.

Environment:
  REVIEW_REPO, REVIEW_PR, REVIEW_SHA   the PR and the commit to review (required)
  REVIEW_PLAN                          "quick" or "full" (default "full")
  REVIEW_FOCUS                         why the dispatcher's rules asked for a full review
  REVIEW_AUDIT                         "1": a quick approval still gets a neutral full review
  REVIEW_CONTEXT, REVIEW_MODEL         as in repos.json ("context", "model")
  REVIEW_QUICK_MODEL                   the quick review's model
  REVIEW_STRICT_WORKFLOWS              "1" for repos with strict_workflows
  REVIEW_SELF_TEST                     "1" to check the sandbox only, with no review
  REVIEW_NONCE                         printed after the BEGIN marker, to tell runs apart
  REVIEW_SLEEP                         "1" to sleep after printing, since Compute
                                       restarts a container that exits
  REVIEW_CALLBACK_URL                  optional: also POST the result here (the dispatcher
                                       on Datum, over gVPC), with
  REVIEW_CALLBACK_TOKEN                this one-time bearer token. Retried on connection
                                       errors, as a parked or restarting dispatcher can
                                       reset a connection.
  REVIEW_KEYPROXY_URL                  optional: the credential proxy (keyproxy.py). Then
  REVIEW_KEYPROXY_CLAUDE,              these placeholders replace CLAUDE_CODE_OAUTH_TOKEN and
  REVIEW_KEYPROXY_MCP_STAGING,         DATUM_MCP_API_KEY_*, and Claude and MCP traffic goes
  REVIEW_KEYPROXY_MCP_PROD             to the proxy, which adds the real keys.
  REVIEW_KEYPROXY_GITHUB               with the URL: the GitHub placeholder, for this PR's
                                       repo only. github_api then calls <proxy>/github with
                                       it, and git clones and fetches from <proxy>/github-git.
                                       With all four, the worker holds no real credential:
                                       the dispatcher gives it no Secret at all.
  Rollback mode (no REVIEW_KEYPROXY_URL), from the Secret review-credentials:
  CLAUDE_CODE_OAUTH_TOKEN, GH_TOKEN    credentials; DATUM_MCP_API_KEY_* optional.
                                       GH_TOKEN only reads: nothing here can approve.
                                       github_api and git get it as PR_AUTOPILOT_GITHUB_TOKEN.
  GH_TOKEN_<OWNER>                     optional read-only token for one GitHub owner,
                                       e.g. GH_TOKEN_OTHER_ORG (a fine-grained token covers
                                       one owner only). Used as GH_TOKEN for that owner's
                                       repos; every GH_TOKEN_* is removed before review.
Claude never gets a GitHub token or placeholder in its environment (full_review.agent_env).
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import full_review
import github_api
import pr_worker

BEGIN, END = "PR_AUTOPILOT_RESULT_BEGIN", "PR_AUTOPILOT_RESULT_END"
STARTED = "PR_AUTOPILOT_STARTED"
SECRET_VARS = ("CLAUDE_CODE_OAUTH_TOKEN", *full_review.MCP_KEYCHAIN, *full_review.AGENT_ENV_DROP)
CALLBACK_DEADLINE = 15 * 60  # keep retrying the callback this long
OWNER_TOKEN_PREFIX = "GH_TOKEN_"
# Values of the per-owner tokens, kept for scrub() after they leave the environment.
REMOVED_SECRETS: dict[str, str] = {}
# Where to send the result, taken out of the environment before any review runs: Claude
# with tools must never hold a token that lets it report a result of its own.
CALLBACK = {"url": "", "token": ""}


def take_callback() -> None:
    CALLBACK["url"] = os.environ.pop("REVIEW_CALLBACK_URL", "")
    CALLBACK["token"] = os.environ.pop("REVIEW_CALLBACK_TOKEN", "")
    if CALLBACK["token"]:
        REMOVED_SECRETS["REVIEW_CALLBACK_TOKEN"] = CALLBACK["token"]


# Placeholder env (from the dispatcher) -> the variable it replaces.
KEYPROXY_VARS = {"REVIEW_KEYPROXY_CLAUDE": "CLAUDE_CODE_OAUTH_TOKEN",
                 "REVIEW_KEYPROXY_MCP_STAGING": "DATUM_MCP_API_KEY_STAGING",
                 "REVIEW_KEYPROXY_MCP_PROD": "DATUM_MCP_API_KEY_PROD"}
KEYPROXY_GITHUB = "REVIEW_KEYPROXY_GITHUB"
# The real GitHub read tokens a Secret may still hold (pick_github_token already took the
# GH_TOKEN_<OWNER> ones out).
GITHUB_TOKEN_VARS = ("GH_TOKEN", "GITHUB_TOKEN")


def take_keyproxy() -> None:
    """With a proxy URL, put each placeholder where the real key would be and point
    Claude, the MCP config and the GitHub reads (github_api, git) at the proxy. A real
    key the Secret still holds is removed (and kept only for scrub()), so the review
    never runs next to one.

    Without a URL (rollback), or from a dispatcher that sends no GitHub placeholder,
    github_api and git use the real read token: GH_TOKEN, as pick_github_token chose it."""
    url = os.environ.pop("REVIEW_KEYPROXY_URL", "").strip().rstrip("/")
    placeholders = {var: os.environ.pop(ph, "") for ph, var in KEYPROXY_VARS.items()}
    github = os.environ.pop(KEYPROXY_GITHUB, "").strip()
    if url:
        for var, placeholder in placeholders.items():
            real = os.environ.pop(var, "")
            if real and real != placeholder:
                REMOVED_SECRETS[var] = real
            if placeholder:
                os.environ[var] = placeholder
        os.environ["ANTHROPIC_BASE_URL"] = f"{url}/anthropic"
        os.environ[full_review.KEYPROXY_ENV] = url
    if url and github:
        for var in GITHUB_TOKEN_VARS:
            real = os.environ.pop(var, "")
            if real:
                REMOVED_SECRETS[var] = real
        os.environ[github_api.API_ENV] = f"{url}/github"
        os.environ[full_review.GIT_BASE_ENV] = f"{url}/github-git"
        os.environ[github_api.TOKEN_ENV] = github
    elif os.environ.get("GH_TOKEN"):
        os.environ[github_api.TOKEN_ENV] = os.environ["GH_TOKEN"]


def owner_token_var(repo: str) -> str:
    """GH_TOKEN_OTHER_ORG for other-org/x: the Secret key of that owner's read-only token."""
    return OWNER_TOKEN_PREFIX + re.sub(r"[^A-Z0-9]", "_", repo.split("/")[0].upper())


def pick_github_token(repo: str) -> None:
    """Use the repo owner's own token as GH_TOKEN when the Secret has one, then remove
    every GH_TOKEN_* from the environment. Claude's Bash inherits the environment
    minus GH_TOKEN (full_review.agent_env), so no other owner's token may stay in it."""
    chosen = os.environ.get(owner_token_var(repo))
    for var in [v for v in os.environ if v.startswith(OWNER_TOKEN_PREFIX)]:
        REMOVED_SECRETS[var] = os.environ.pop(var)
    if chosen:
        default = os.environ.get("GH_TOKEN", "")
        if default and default != chosen:
            REMOVED_SECRETS["GH_TOKEN (default)"] = default  # for scrub() only
        os.environ["GH_TOKEN"] = chosen


def scrub(text: str) -> str:
    """Remove any credential value the review might have picked up and repeated;
    the result ends up in logs and, through the dispatcher, on GitHub."""
    values = {**{var: os.environ.get(var, "") for var in SECRET_VARS}, **REMOVED_SECRETS}
    for var, value in values.items():
        if len(value) >= 8:
            text = text.replace(value, f"[{var} removed]")
    return text


def emit(result: dict) -> None:
    # The nonce ties the result to this run: logs of an earlier Workload with
    # the same name must never be read as this review's answer.
    nonce = os.environ.get("REVIEW_NONCE", "")
    payload = scrub(json.dumps(result))
    print(f"{BEGIN} {nonce}".rstrip(), payload, END, sep="\n", flush=True)
    if CALLBACK["url"]:
        callback(CALLBACK["url"], CALLBACK["token"], payload)


def callback(url: str, token: str, payload: str, sleep=time.sleep, clock=time.time,
             deadline: float = CALLBACK_DEADLINE) -> bool:
    """POST the result to the dispatcher until it answers 2xx, or 409 (it already has a
    result for this token), or the deadline passes. 401/404 are final: a token the
    dispatcher does not know will not become known. Returns True when delivered."""
    end, wait = clock() + deadline, 2.0
    while True:
        req = urllib.request.Request(url, data=payload.encode(), method="POST",
                                     headers={"Authorization": f"Bearer {token}",
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                resp.read()
            print("PR_AUTOPILOT_CALLBACK delivered", flush=True)
            return True
        except urllib.error.HTTPError as e:
            if e.code == 409:
                print("PR_AUTOPILOT_CALLBACK already delivered", flush=True)
                return True
            if e.code in (400, 401, 403, 404):
                print(f"PR_AUTOPILOT_CALLBACK refused: HTTP {e.code}", flush=True)
                return False
            why = f"HTTP {e.code}"
        except (urllib.error.URLError, OSError) as e:  # reset while the dispatcher resumes
            why = str(getattr(e, "reason", e))
        if clock() + wait > end:
            print(f"PR_AUTOPILOT_CALLBACK gave up: {why}", flush=True)
            return False
        print(f"PR_AUTOPILOT_CALLBACK retrying in {wait:.0f}s: {why}", flush=True)
        sleep(wait)
        wait = min(wait * 2, 60)


def wait_for_network(host: str = "github.com", seconds: int = 90) -> None:
    """On Compute the network comes up a few seconds after the container starts."""
    deadline = time.time() + seconds
    while True:
        try:
            socket.getaddrinfo(host, 443)
            return
        except OSError:
            if time.time() > deadline:
                raise
            time.sleep(2)


def sh(*cmd: str) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return f"exit {p.returncode}: {(p.stdout + p.stderr).strip()[-300:]}"


def claude_sandbox_test() -> dict:
    """Ask claude to reach GitHub from its sandboxed Bash; the call must fail."""
    import claude_cli
    try:
        resp = claude_cli.run(
            ["--model", "haiku", "--setting-sources", "", "--settings", full_review.SANDBOX_SETTINGS,
             "--strict-mcp-config", "--no-session-persistence", "--permission-mode", "dontAsk",
             "--allowedTools", "Bash(git ls-remote:*)", "Bash(head:*)", "Bash(git diff:*)", "Bash(printenv:*)",
             "Read"],
            "This is a sandbox test. Do five things and report each result on its own line:\n"
            "1. Run with Bash: git ls-remote https://github.com/example-org/compute HEAD "
            "and give its output.\n"
            "2. Use the Read tool on /proc/self/environ and say only whether the read was allowed.\n"
            "3. Run with Bash: head -c 200 /proc/1/cmdline and give its output or its error.\n"
            "4. Run with Bash: git diff --no-index /dev/null /proc/1/cmdline and give its "
            "output or its error.\n"
            "5. Run with Bash: printenv CLAUDE_CODE_OAUTH_TOKEN and report only its exit code "
            "(1 means the variable is not set). Do not repeat its output.",
            cwd=pathlib.Path("/tmp"), timeout=300,
            env=full_review.agent_env())
        return {"reply": str(resp.get("result"))[-1500:], "denied": claude_cli.denied_calls(resp)}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"[-600:]}


def self_test() -> dict:
    """What the sandbox needs on this kernel, checked with bubblewrap directly, then
    with claude itself when a token is set."""
    bwrap = ["bwrap", "--unshare-all", "--ro-bind", "/", "/", "--dev", "/dev", "--tmpfs", "/tmp"]
    out = {
        "kernel": os.uname().release, "arch": os.uname().machine, "uid": os.getuid(),
        "bwrap_proc_mount": sh(*bwrap, "--proc", "/proc", "true"),
        "bwrap_proc_bind": sh(*bwrap, "--bind", "/proc", "/proc", "true"),
        "bwrap_no_network": sh(*bwrap, "--bind", "/proc", "/proc", "git", "ls-remote",
                               "https://github.com/example-org/compute", "HEAD"),
        "claude": sh("claude", "--version"),
    }
    if os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"):
        out["claude_sandbox"] = claude_sandbox_test()
    return out


def main() -> int:
    try:
        return run()
    finally:
        if os.environ.get("REVIEW_SLEEP") == "1":
            while True:
                time.sleep(3600)


def run() -> int:
    pick_github_token(os.environ.get("REVIEW_REPO", ""))  # first: nothing below may see the others
    take_callback()
    take_keyproxy()
    if os.environ.get("REVIEW_SELF_TEST") == "1":
        emit({"ok": True, "self_test": self_test()})
        return 0
    import claude_cli
    # Tells the laptop the VM is up, so a review that runs long is not taken for an outage.
    print(f"{STARTED} {os.environ.get('REVIEW_NONCE', '')}", flush=True)
    # Token use goes back with the result, for the laptop's usage log and dashboard.
    claude_cli.USAGE_FILE = pathlib.Path("/tmp/usage.jsonl")
    try:
        wait_for_network()
        outcome = pr_worker.review(
            os.environ["REVIEW_REPO"], os.environ["REVIEW_PR"], os.environ["REVIEW_SHA"],
            plan=os.environ.get("REVIEW_PLAN") or "full",
            focus=os.environ.get("REVIEW_FOCUS") or "no specific reason given",
            audit=os.environ.get("REVIEW_AUDIT") == "1",
            context=os.environ.get("REVIEW_CONTEXT", ""), model=os.environ.get("REVIEW_MODEL", "opus"),
            quick_model=os.environ.get("REVIEW_QUICK_MODEL") or "sonnet",
            strict_workflows=os.environ.get("REVIEW_STRICT_WORKFLOWS") == "1",
        )
        # "moved" and "result" keep the shape older dispatchers read for a full review.
        emit({"ok": True, **outcome, "moved": outcome["verdict"] == "moved",
              "result": outcome["findings"], "usage": usage()})
        return 0
    except Exception as e:  # report every failure through the same channel
        emit({"ok": False, "error": f"{type(e).__name__}: {e}"[-1000:], "usage": usage()})
        return 1


def usage() -> list[dict]:
    try:
        return [json.loads(line) for line in pathlib.Path("/tmp/usage.jsonl").read_text().splitlines()]
    except (OSError, ValueError):
        return []


if __name__ == "__main__":
    sys.exit(main())
