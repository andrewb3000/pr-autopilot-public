# Image for one review on Datum Compute (quick, then full if needed) (see docs/remote-review.md).
# Holds no secrets: the Claude token, GitHub token and MCP keys (or, with the credential
# proxy, placeholders for them) come from env.
#
# CI builds and pushes it (.github/workflows/image.yaml). By hand, from the repository root:
#   docker build --platform linux/amd64 -f remote/Dockerfile -t pr-autopilot-review .
# Base images are pinned by digest, so one image tag always means the same layers.
FROM node:22-bookworm-slim@sha256:5ec23b7c622b00547753bc6ffd78085dd868a68aeb41c8e0a1418f033e13d96d

ARG CLAUDE_CODE_VERSION=2.1.308

# bubblewrap and socat are what Claude Code's sandbox uses on Linux. kustomize comes
# from its image: GitHub release downloads failed with 504 for hours on 2026-11-08.
# No gh: the review reads GitHub with github_api (urllib) and git, which also work
# through the credential proxy.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bubblewrap socat git python3 ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

COPY --from=registry.k8s.io/kustomize/kustomize:v5.8.0@sha256:98424842862ed35fa666dbaac02159623567e1e9e184d91382fa665e89023258 /app/kustomize /usr/local/bin/kustomize

RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" && npm cache clean --force

# bubblewrap creates an unprivileged user namespace, so the review runs as a normal user.
RUN useradd --create-home --uid 1001 review
WORKDIR /app
COPY claude_cli.py full_review.py github_api.py pr_worker.py render-diff remote/review-job.py ./
RUN chmod 0755 render-diff review-job.py

USER review
# Not CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: it runs Bash in its own bubblewrap with a fresh
# /proc, which the VM refuses, so no Bash command could start (tested 2026-11-08).
ENV PR_AUTOPILOT_CACHE=/home/review/cache \
    PR_AUTOPILOT_WEAKER_NESTED_SANDBOX=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DISABLE_AUTOUPDATER=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
ENTRYPOINT ["python3", "/app/review-job.py"]
