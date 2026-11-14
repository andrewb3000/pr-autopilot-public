#!/usr/bin/env python3
"""Write the Secret and the ConfigMap the dispatcher Workload needs, as manifests for
`datumctl apply -f`. Values are read from files, never from the command line (which
lands in shell history and `ps`), and never printed.

  python3 remote/make-dispatcher-config.py --out ~/pr-autopilot-deploy \\
      --pat-file <file with the classic PAT> --key-file <service-account key JSON> \\
      [--slack-file <file with the webhook URL>] [--tick-token-file <file with the /tick token>] \\
      [--keyproxy-hmac-file <file> --claude-token-file <file> \\
       [--mcp-staging-key-file <file>] [--mcp-prod-key-file <file>] \\
       [--github-read-token-file <file>] [--github-owner-token OWNER=<file> ...]]

--tick-token-file is for the unikernel dispatcher, which the laptop wakes with POST /tick
(docs/dispatcher.md). Use the same file stats.py reads, ~/.config/pr-autopilot/tick-token.

--keyproxy-hmac-file is for the credential proxy (keyproxy.py, docs/dispatcher.md). It adds
KEYPROXY_HMAC to the dispatcher's Secret and writes <out>/keyproxy-secret.json, the Secret
pr-autopilot-keyproxy with the same HMAC key and the real Claude token and MCP keys.
--github-read-token-file adds the review workers' read-only GitHub token to it as GH_TOKEN,
and each --github-owner-token other-org=<file> one owner's own token as GH_TOKEN_OTHER_ORG
(the names remote/review-job.py and keyproxy.py use).

Writes <out>/secret.json (mode 0600) and <out>/repos-configmap.json. Keep <out> outside
the repository and delete the secret files once applied.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent.parent


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def write_secret(path: pathlib.Path, name: str, data: dict) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                   "metadata": {"name": name, "labels": {"app": "pr-autopilot"}}, "data": data}, f)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--pat-file", required=True, type=pathlib.Path)
    ap.add_argument("--key-file", required=True, type=pathlib.Path)
    ap.add_argument("--slack-file", type=pathlib.Path)
    ap.add_argument("--tick-token-file", type=pathlib.Path)
    ap.add_argument("--keyproxy-hmac-file", type=pathlib.Path)
    ap.add_argument("--claude-token-file", type=pathlib.Path)
    ap.add_argument("--mcp-staging-key-file", type=pathlib.Path)
    ap.add_argument("--mcp-prod-key-file", type=pathlib.Path)
    ap.add_argument("--github-read-token-file", type=pathlib.Path)
    ap.add_argument("--github-owner-token", action="append", default=[], metavar="OWNER=FILE")
    args = ap.parse_args()
    proxy_files = (args.claude_token_file, args.mcp_staging_key_file, args.mcp_prod_key_file,
                   args.github_read_token_file, *args.github_owner_token)
    if any(proxy_files) and not args.keyproxy_hmac_file:
        raise SystemExit("--claude-token-file, the MCP key files and the GitHub token files are for the proxy: "
                         "add --keyproxy-hmac-file")
    github = {}
    if args.github_read_token_file:
        github["GH_TOKEN"] = args.github_read_token_file
    for spec in args.github_owner_token:
        owner, sep, f = spec.partition("=")
        if not sep or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", owner) or not f:
            raise SystemExit("--github-owner-token takes OWNER=FILE, e.g. other-org=<file>")
        github["GH_TOKEN_" + re.sub(r"[^A-Z0-9]", "_", owner.upper())] = pathlib.Path(f)
    if args.keyproxy_hmac_file and not args.claude_token_file:
        raise SystemExit("--keyproxy-hmac-file needs --claude-token-file: the proxy holds the Claude token")

    pat = args.pat_file.read_text().strip()
    if not pat.startswith("ghp_"):
        raise SystemExit("the PAT does not look like a classic token (ghp_...); the notifications API needs one")
    key = json.loads(args.key_file.read_text())
    if key.get("type") != "datum_service_account" or not key.get("private_key"):
        raise SystemExit("the key file is not a Datum service-account key")
    data = {"GITHUB_TOKEN": b64(pat), "MILO_CREDENTIALS": b64(json.dumps(key))}
    if args.slack_file:
        data["SLACK_WEBHOOK"] = b64(args.slack_file.read_text().strip())
    if args.tick_token_file:
        tick = args.tick_token_file.read_text().strip()
        # The /tick URL is public: the token is all that stands in front of it.
        if len(tick) < 32 or any(c.isspace() for c in tick):
            raise SystemExit("the tick token must be at least 32 characters with no spaces; "
                             "make one with: python3 -c 'import secrets; print(secrets.token_urlsafe(32))'")
        data["TICK_TOKEN"] = b64(tick)
    proxy = {}
    if args.keyproxy_hmac_file:
        hmac_key = args.keyproxy_hmac_file.read_text().strip()
        if len(hmac_key) < 32 or any(c.isspace() for c in hmac_key):
            raise SystemExit("the proxy HMAC key must be at least 32 characters with no spaces; "
                             "make one with: python3 -c 'import secrets; print(secrets.token_urlsafe(32))'")
        claude = args.claude_token_file.read_text().strip()
        if not claude.startswith("sk-ant-oat"):
            raise SystemExit("the Claude token does not look like an OAuth token (sk-ant-oat...); "
                             "the proxy sends it as a Bearer token")
        data["KEYPROXY_HMAC"] = b64(hmac_key)
        proxy = {"KEYPROXY_HMAC": b64(hmac_key), "CLAUDE_CODE_OAUTH_TOKEN": b64(claude)}
        for var, f in (("DATUM_MCP_API_KEY_STAGING", args.mcp_staging_key_file),
                       ("DATUM_MCP_API_KEY_PROD", args.mcp_prod_key_file)):
            if f:
                proxy[var] = b64(f.read_text().strip())
        for var, f in github.items():
            token = f.read_text().strip()
            # Classic, fine-grained and OAuth tokens. The proxy sends it as a Bearer token
            # (API) and as Basic auth (git).
            if not token.startswith(("ghp_", "github_pat_", "gho_")) or any(c.isspace() for c in token):
                raise SystemExit(f"the token for {var} does not look like a GitHub token "
                                 "(ghp_..., github_pat_... or gho_...)")
            proxy[var] = b64(token)

    if HERE in args.out.resolve().parents or args.out.resolve() == HERE:
        raise SystemExit("--out must be outside the repository")
    args.out.mkdir(parents=True, exist_ok=True)
    secret = args.out / "secret.json"
    write_secret(secret, "pr-autopilot-dispatcher", data)
    if proxy:
        write_secret(args.out / "keyproxy-secret.json", "pr-autopilot-keyproxy", proxy)
        print(f"wrote {args.out / 'keyproxy-secret.json'} (keys: {', '.join(sorted(proxy))})")
    (args.out / "repos-configmap.json").write_text(json.dumps({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "pr-autopilot-repos", "labels": {"app": "pr-autopilot"}},
        "data": {"repos.json": next(f for f in (HERE / "repos.json", HERE / "repos.example.json") if f.exists()).read_text()}}))
    print(f"wrote {secret} (keys: {', '.join(sorted(data))}) and {args.out / 'repos-configmap.json'}")


if __name__ == "__main__":
    main()
