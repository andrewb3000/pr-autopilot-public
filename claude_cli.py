"""Running headless Claude Code (`claude -p`) and making sense of its failures."""
from __future__ import annotations

import json
import pathlib
import subprocess
import time

# Text Claude Code prints when its login has lapsed. Only looked for in failed runs,
# so a review that merely mentions a /login route is not mistaken for one.
AUTH_MARKERS = ("Failed to authenticate", "OAuth session expired", "Please run /login", "claude auth login")


# Where each run's token use is appended as one JSON line; set by the running tool, not by tests.
USAGE_FILE: pathlib.Path | None = None


class AuthExpired(RuntimeError):
    """Claude Code is logged out; run `claude auth login`."""


def run(args: list[str], prompt: str, cwd: pathlib.Path, timeout: int, label: dict | None = None,
        env: dict | None = None) -> dict:
    """Run `claude -p ... --output-format json` and return the parsed response.

    Raises AuthExpired when the login has lapsed, and RuntimeError with the tail
    of Claude's own output for any other failure, so the log shows the reason.
    Token use is recorded in USAGE_FILE, tagged with `label` (kind, repo, pr).
    """
    started = time.time()
    p = subprocess.run(["claude", "-p", *args, "--output-format", "json"], input=prompt,
                       capture_output=True, text=True, timeout=timeout, cwd=cwd, env=env)
    try:
        resp = json.loads(p.stdout)
    except ValueError:
        resp = {}
    record_usage(resp, label or {}, started, ok=p.returncode == 0 and not resp.get("is_error"))
    if p.returncode == 0 and resp and not resp.get("is_error"):
        return resp

    text = "\n".join(s for s in (str(resp.get("result") or ""), p.stdout, p.stderr) if s)
    if any(m in text for m in AUTH_MARKERS):
        raise AuthExpired("Claude Code login expired; run `claude auth login`")
    tail = (str(resp.get("result") or "") or p.stderr or p.stdout).strip()[-400:]
    raise RuntimeError(f"claude exited {p.returncode}: {tail}")


def record_usage(resp: dict, label: dict, started: float, ok: bool) -> None:
    if USAGE_FILE is None or not resp:
        return
    usage = resp.get("usage") or {}
    entry = {
        **label, "ts": round(started), "ok": ok,
        "models": sorted(resp.get("modelUsage") or {}),
        "input": usage.get("input_tokens", 0), "output": usage.get("output_tokens", 0),
        "cache_read": usage.get("cache_read_input_tokens", 0),
        "cache_write": usage.get("cache_creation_input_tokens", 0),
        "cost_usd": resp.get("total_cost_usd", 0), "turns": resp.get("num_turns", 0),
        "seconds": round((resp.get("duration_ms") or (time.time() - started) * 1000) / 1000),
    }
    append_usage(entry)


def append_usage(entry: dict) -> None:
    """Add one run to USAGE_FILE; also used for runs recorded on another machine."""
    if USAGE_FILE is None:
        return
    try:
        USAGE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with USAGE_FILE.open("a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # accounting must never fail a review


def denied_calls(resp: dict) -> list[str]:
    """Short descriptions of tool calls the permission rules refused."""
    out = []
    for d in resp.get("permission_denials", []):
        inp = d.get("tool_input") or {}
        out.append(f"{d.get('tool_name')}: {inp.get('command') or json.dumps(inp)[:150]}")
    return out
