# pr-autopilot

A PR review bot that runs every review in its own throwaway VM on
[Datum Cloud](https://www.datum.net) compute. It reviews pull requests where it is a
requested reviewer, approves the safe ones and blocks or comments on the rest.

This is a trimmed copy of an internal tool, shared as an example. Organization names,
project ids and the repo list are replaced with placeholders, and the internal docs are
left out. It is not packaged for reuse as is.

## How it works

```
GitHub ──notifications──▶ dispatcher (unikernel) ──creates──▶ review VM (Kata), one per PR commit
                              ▲   │                               │ placeholder tokens only
                              │   └──revoke──▶ credential proxy ◀─┘
                              │                (unikernel, holds the real keys)
                              │                 │ GitHub (read), Claude, MCP (read-only)
                              └──── result over gVPC, one-time token ──── review VM
```

1. **Dispatcher** (`dispatcher.py`, unikernel instance). Polls GitHub, picks up review
   requests, and starts one review VM per PR commit (at most 3 at once). It is the only
   part that holds a GitHub token that can approve or comment.
2. **Review VM** (`remote/review-job.py`, `full_review.py`, Kata `general-purpose` class).
   It holds no real credential. A Python wrapper clones the PR, collects the description,
   linked issues, CI checks and CI's render through the credential proxy, and hands all
   of it to Claude Code. The agent works on local checkouts
   and read-only MCP servers, and returns only the verdict text. A quick review
   (Sonnet) runs first. A full review (Opus) follows when paths or risk call for it.
3. **Result.** The wrapper sends the verdict back over the project's private network with
   a one-time token. The dispatcher accepts one result per token, posts the review and
   deletes the VM.

## Security model

| Layer | What it does |
|---|---|
| Dispatcher only | Holds the GitHub token that can approve. Never enters a review VM. |
| One-time callback token | Each VM can report a result for its own job only, once. |
| Wrapper, not agent, talks to GitHub | The agent has no GitHub access at all. A prompt injection in the PR cannot read other repos or act on GitHub. |
| Claude Code sandbox | Tool allowlist, Bash with no network (bubblewrap), secret paths denied, tokens dropped from the agent's environment. |
| Credential proxy (`keyproxy.py`) | A separate unikernel instance that holds every real key the reviews use: GitHub read, Claude and MCP. Each VM gets placeholder tokens signed for one job, one upstream and one hour; the GitHub one also for one repo. The proxy forwards only the exact requests a review needs (for GitHub: reads and git fetch of that repo, never push), swaps in the real key, and never sends a key back. The dispatcher revokes the placeholders when the job ends. |
| Throwaway Kata VM | If the agent escapes the sandbox, it lands in a VM with no real key at all: only one job's placeholders and its one-time callback token. The VM is deleted afterwards. |

Not covered yet: there is no per-instance identity, so the proxy can only check bearer
placeholders, and there is no egress policy for the VMs. A compromised VM cannot steal a
key, but it could still send the PR's code somewhere.

## Layout

| Path | What |
|---|---|
| `reviewer.py` | Finds PRs to review, routes quick and full reviews, posts results |
| `pr_worker.py`, `full_review.py` | Quick and full review prompts and agent runs |
| `dispatcher.py` | The always-on dispatcher |
| `remote_review.py`, `milo_api.py` | Starting and deleting review VMs through the Datum API |
| `keyproxy.py` | The credential proxy |
| `remote/` | Dockerfiles, Workload manifests, IAM and the in-VM job |
| `repos.example.json` | Per-repo settings: authors, review depth, model, context |

## Tests

```bash
python3 -m unittest test_reviewer test_dispatcher test_keyproxy
```
