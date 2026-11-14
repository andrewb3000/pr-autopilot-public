"""Reviews on Datum Compute (see docs/remote-review.md).

review_pr() runs one PR commit's review in its own Workload, a Kata VM built from
the review image: the quick review and, if needed, the full review in the same
VM. It returns pr_worker.review's outcome. review() is the full review alone, with
the same contract as full_review.review. The result comes back through the
container's logs and the Workload is deleted afterwards. Nothing
here posts to GitHub: the dispatcher does that. start_worker() is the dispatcher on
Datum's variant: it creates the Workload over the Milo API (milo_api) and returns at
once, and the worker calls back with its result (dispatcher.py). The laptop path
keeps using datumctl until the dispatcher on Datum takes over.

PR_AUTOPILOT_RUNNER=datum turns it on; anything else keeps reviews local.
Private repos stay local too unless repos.json says the VM's GitHub token reads
them ("vm_can_read", see vm_can_read()).
"""
from __future__ import annotations

import calendar
import hashlib
import json
import os
import pathlib
import re
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

import claude_cli
import full_review
import github_api
import keyproxy
import milo_api
import pr_worker

RUNNER = os.environ.get("PR_AUTOPILOT_RUNNER", "local")
ORG = os.environ.get("PR_AUTOPILOT_DATUM_ORG", "my-org")
PROJECT = os.environ.get("PR_AUTOPILOT_DATUM_PROJECT", "my-project")
# Pinned so that signing in to another endpoint, such as staging, never moves the
# reviews there: without it datumctl acts as whichever session is active.
SESSION = os.environ.get("PR_AUTOPILOT_DATUM_SESSION", "you@example.com@api.datum.net")
REGISTRY_REPO = "example-user/pr-autopilot-review"
# The files the review image is built from. Its tag is a hash of their contents,
# computed the same way here and in CI (.github/workflows/image.yaml), so the
# laptop always asks for the image that matches its own code.
IMAGE_FILES = ("remote/Dockerfile", "remote/review-job.py", "full_review.py", "pr_worker.py", "claude_cli.py",
               "github_api.py", "render-diff")
HERE = pathlib.Path(__file__).resolve().parent
CITY = "DFW"
INSTANCE_TYPE = "datumcloud-d1-standard-2"
# CLAUDE_CODE_OAUTH_TOKEN, GH_TOKEN[_<OWNER>], DATUM_MCP_API_KEY_*. Workers get it only
# without the credential proxy (laptop-started VMs, and the dispatcher in rollback mode).
SECRET = "review-credentials"
# The class defaults plus what bubblewrap needs; this list replaces the defaults.
CAPABILITIES = ["CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "NET_BIND_SERVICE",
                "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_ADMIN", "NET_ADMIN"]
CONFIG_FILE = pathlib.Path(os.environ.get("PR_AUTOPILOT_CONFIG")
                           or next((f for f in (HERE / "repos.json", HERE / "repos.example.json") if f.exists()), HERE / "repos.json"))

DEPLOY_TIMEOUT = 300
POLL_SECONDS = 15
# How long to wait for a VM's result, by plan. A full review stops at 15 minutes
# (full_review.TIMEOUT_SECONDS). A quick plan can run the quick review (up to 10
# minutes) and then a full review in the same VM.
RESULT_TIMEOUTS = {"full": 20 * 60, "quick": 30 * 60}
RESULT_TIMEOUT = RESULT_TIMEOUTS["full"]
MAX_AGE = DEPLOY_TIMEOUT + max(RESULT_TIMEOUTS.values()) + 10 * 60  # older review Workloads are leftovers
BEGIN, END = "PR_AUTOPILOT_RESULT_BEGIN", "PR_AUTOPILOT_RESULT_END"
STARTED = "PR_AUTOPILOT_STARTED"
# After Datum fails, reviews go to the laptop for this long without trying it,
# so an outage does not cost every review a failed deploy or a 20-minute wait.
DOWN_SECONDS = 15 * 60
DOWN_FILE = full_review.CACHE / "datum-down-until"
TOKEN_DOWN_SECONDS = 6 * 3600  # an expired token in the Secret stays expired until you replace it
VISIBILITY_FILE = full_review.CACHE / "repo-visibility.json"
VISIBILITY_TTL = 24 * 3600


class DatumUnavailable(RuntimeError):
    """Datum itself failed (deploy, API, no result in time), not the review in the VM:
    the same review can run on the laptop instead."""


class TokenExpired(DatumUnavailable):
    """The Claude token in the Datum Secret expired; the laptop's own login still works."""


class ImageNotBuilt(RuntimeError):
    """CI has not yet published the image for this code: review on the laptop."""


def image_tag(root: pathlib.Path = HERE) -> str:
    h = hashlib.sha256()
    for name in IMAGE_FILES:
        h.update(name.encode() + b"\0" + (root / name).read_bytes() + b"\0")
    return h.hexdigest()[:16]


def image() -> str:
    return os.environ.get("PR_AUTOPILOT_IMAGE") or f"ghcr.io/{REGISTRY_REPO}:{image_tag()}"


def image_digest(ref: str) -> str | None:
    """The digest the public registry serves for this tag, or None if there is no such
    tag (anonymous pull token, then a HEAD). The Workload pulls by this digest."""
    repo, _, tag = ref.removeprefix("ghcr.io/").rpartition(":")
    try:
        with urllib.request.urlopen(f"https://ghcr.io/token?scope=repository:{repo}:pull", timeout=30) as r:
            token = json.load(r)["token"]
        req = urllib.request.Request(
            f"https://ghcr.io/v2/{repo}/manifests/{tag}", method="HEAD",
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/vnd.oci.image.index.v1+json, "
                               "application/vnd.oci.image.manifest.v1+json, "
                               "application/vnd.docker.distribution.manifest.v2+json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            digest = resp.headers.get("Docker-Content-Digest", "")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise DatumUnavailable(f"ghcr.io gave no digest for {ref}")
        return digest
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise DatumUnavailable(f"ghcr.io answered {e.code} for {ref}") from e
    except (OSError, ValueError, KeyError) as e:
        raise DatumUnavailable(f"could not check {ref}: {e}") from e


def mark_down(now: float, seconds: int = DOWN_SECONDS) -> None:
    try:
        DOWN_FILE.parent.mkdir(parents=True, exist_ok=True)
        DOWN_FILE.write_text(str(now + seconds))
    except OSError:
        pass


def is_down(now: float) -> bool:
    try:
        return now < float(DOWN_FILE.read_text())
    except (OSError, ValueError):
        return False


def datumctl_env() -> dict:
    # DATUM_SESSION, unlike --session, also reaches plugins such as compute.
    return {**os.environ, "DATUM_SESSION": SESSION}


def datumctl(*args: str, timeout: int = 120) -> str:
    p = subprocess.run(["datumctl", *args, "--org", ORG, "--project", PROJECT],
                       capture_output=True, text=True, timeout=timeout, env=datumctl_env())
    if p.returncode != 0:
        raise RuntimeError(f"datumctl {' '.join(args[:2])}: {(p.stderr or p.stdout).strip()[-400:]}")
    return p.stdout


def is_public(repo: str, now: float | None = None) -> bool:
    """Whether GitHub says the repo is public, cached for a day. A failed lookup
    counts as private (the review runs on the laptop) and is not cached."""
    now = time.time() if now is None else now
    try:
        cache = json.loads(VISIBILITY_FILE.read_text())
    except (OSError, ValueError):
        cache = {}
    if repo in cache and now - cache[repo]["at"] < VISIBILITY_TTL:
        return cache[repo]["public"]
    try:
        public = not github_api.is_private(repo)
    except (github_api.GitHubError, KeyError, TypeError):
        return False
    cache[repo] = {"public": public, "at": now}
    try:
        VISIBILITY_FILE.write_text(json.dumps(cache))
    except OSError:
        pass
    return cache[repo]["public"]


def vm_can_read(repo: str, config: dict | None = None) -> bool:
    """Whether the VM's GitHub token can read this repo: GH_TOKEN, or GH_TOKEN_<OWNER>
    (such as GH_TOKEN_OTHER_ORG) when there is one for the owner. Those live in the Secret
    pr-autopilot-keyproxy when the credential proxy is on, else in review-credentials.
    Nothing here reads either Secret: repos.json says what the tokens can read.

    Public repos, always. Private ones when repos.json sets "vm_can_read": true on the
    repo's own entry or, if that entry does not set it, on its "owner/*" entry. It is a
    property of the token, not of how the repo is reviewed, so it is looked up key by
    key: a repo's own entry for other settings does not hide its owner's value."""
    if config is None:
        try:
            config = json.loads(CONFIG_FILE.read_text())
        except (OSError, ValueError):
            config = {}
    own, owner = config.get(repo) or {}, config.get(repo.split("/")[0] + "/*") or {}
    if own.get("vm_can_read", owner.get("vm_can_read")):
        return True
    return is_public(repo)


def runs_on_datum(repo: str, now: float | None = None) -> bool:
    if RUNNER != "datum" or is_down(time.time() if now is None else now):
        return False
    return vm_can_read(repo)


# Compute names each instance <workload>-<placement>-<location>-<index>, and that name must
# be a DNS label too (63 characters). A longer one is accepted but never starts: the location
# reports a ConfigurationError about "Linux capabilities" and retries forever, and the
# deploy waits out DEPLOY_TIMEOUT (seen 2026-11-10/11, a 42-character name failed, 41 ran).
# "review" is the placement below; the location for CITY is "us-central-1". Two characters
# of slack cover a two-digit index.
INSTANCE_SUFFIX = "-review-us-central-1-0"
NAME_MAX = 63 - len(INSTANCE_SUFFIX) - 2


def workload_name(repo: str, num: str, sha: str, nonce: str) -> str:
    """A DNS label: review-<repo>-<num>-<sha8>-<nonce>, at most NAME_MAX characters.
    The nonce makes each attempt's name new, so its logs are its own."""
    tail = f"-{num}-{sha[:8]}-{nonce}"
    name = re.sub(r"[^a-z0-9-]+", "-", repo.split("/")[1].lower()).strip("-")
    return f"review-{name[:NAME_MAX - len('review-') - len(tail)].rstrip('-')}{tail}"


def manifest(ref: str, name: str, nonce: str, repo: str, num: str, sha: str, context: str, model: str,
             focus: str, strict_workflows: bool, plan: str = "full", audit: bool = False,
             quick_model: str = "sonnet", labels: dict | None = None, extra_env: dict | None = None,
             credentials: bool = True) -> dict:
    """The worker Workload. `credentials` False leaves out SECRET: a worker behind the
    credential proxy holds placeholders only, so the Secret can be emptied."""
    env = {**(extra_env or {}), "REVIEW_REPO": repo, "REVIEW_PR": num, "REVIEW_SHA": sha, "REVIEW_FOCUS": focus,
           "REVIEW_NONCE": nonce, "REVIEW_PLAN": plan, "REVIEW_AUDIT": "1" if audit else "0",
           "REVIEW_CONTEXT": context, "REVIEW_MODEL": model, "REVIEW_QUICK_MODEL": quick_model,
           "REVIEW_STRICT_WORKFLOWS": "1" if strict_workflows else "0",
           # Compute restarts a container that exits, which would run the review again.
           "REVIEW_SLEEP": "1"}
    return {
        "apiVersion": "compute.datumapis.com/v1alpha", "kind": "Workload",
        "metadata": {"name": name, "labels": labels or {"app": "pr-autopilot"}},
        "spec": {
            "template": {"spec": {
                "runtime": {
                    "class": "general-purpose",
                    "resources": {"instanceType": INSTANCE_TYPE},
                    "sandbox": {"containers": [{
                        "name": "review", "image": ref,
                        "securityContext": {"capabilities": {"add": CAPABILITIES}},
                        **({"envFrom": [{"secretRef": {"name": SECRET}}]} if credentials else {}),
                        "env": [{"name": k, "value": v} for k, v in env.items()],
                    }]},
                },
                "networkInterfaces": [{"network": {"name": "default"}}],
            }},
            "placements": [{"name": "review", "cityCodes": [CITY], "scaleSettings": {"minReplicas": 1}}],
        },
    }


# Workers the dispatcher on Datum starts carry this label, not app=pr-autopilot: the laptop's
# sweep() and the dispatcher's reconcile each clean up only their own.
WORKER_LABEL = "app=pr-autopilot-worker"


# With the credential proxy (keyproxy.py) deployed, the dispatcher sets this to its gVPC URL,
# e.g. http://pr-autopilot-keyproxy-main-us-central-1-0.instances.datum.internal:8080, and
# each worker gets placeholders instead of the real Claude token, MCP keys and GitHub read
# token, and no Secret at all. Unset, the worker uses the keys in SECRET, as before.
KEYPROXY_URL_ENV = "PR_AUTOPILOT_KEYPROXY_URL"


def keyproxy_env(job: str, repo: str) -> dict:
    """The worker env that sends Claude, MCP and GitHub through the proxy: its URL and
    one placeholder per upstream, each for this job only (the GitHub one also only for
    `repo`, for both the API and git). Empty when the proxy is not in use.
    Under REVIEW_KEYPROXY_* names, not the real ones: review-job.py swaps them in itself,
    so it does not matter whether the platform lets env or envFrom win."""
    url = os.environ.get(KEYPROXY_URL_ENV, "").strip().rstrip("/")
    if not url:
        return {}
    try:
        key = keyproxy.hmac_key()
    except ValueError as e:
        raise DatumUnavailable(f"{KEYPROXY_URL_ENV} is set, but {e}") from e
    return {"REVIEW_KEYPROXY_URL": url,
            "REVIEW_KEYPROXY_CLAUDE": keyproxy.mint(key, job, "anthropic"),
            "REVIEW_KEYPROXY_MCP_STAGING": keyproxy.mint(key, job, "mcp-staging"),
            "REVIEW_KEYPROXY_MCP_PROD": keyproxy.mint(key, job, "mcp-prod"),
            "REVIEW_KEYPROXY_GITHUB": keyproxy.mint(key, job, "github", repo=repo)}


def start_worker(repo: str, num: str, sha: str, context: str, model: str, *, plan: str, focus: str,
                 audit: bool, quick_model: str, strict_workflows: bool, callback_url: str,
                 callback_token: str) -> str:
    """Create one worker Workload for the dispatcher and return its name, without
    waiting for it: the worker calls back with its result. Raises ImageNotBuilt or
    DatumUnavailable."""
    tagged = image()
    digest = image_digest(tagged)
    if digest is None:
        raise ImageNotBuilt(f"{tagged} is not published yet")
    ref = f"{tagged.rpartition(':')[0]}@{digest}"
    nonce = secrets.token_hex(3)
    name = workload_name(repo, num, sha, nonce)
    key, value = WORKER_LABEL.split("=")
    proxied = keyproxy_env(name, repo)
    doc = manifest(ref, name, nonce, repo, num, sha, context, model, focus, strict_workflows, plan=plan,
                   audit=audit, quick_model=quick_model, labels={key: value},
                   extra_env={"REVIEW_CALLBACK_URL": callback_url, "REVIEW_CALLBACK_TOKEN": callback_token,
                              **proxied},
                   credentials=not proxied)  # behind the proxy the worker needs no Secret
    try:
        milo_api.create(milo_api.workloads_path(PROJECT), doc)
    except milo_api.MiloError as e:
        raise DatumUnavailable(f"creating worker {name} failed: {e}") from e
    return name


def list_workloads(selector: str) -> list[str]:
    """Names of the Workloads with this label selector. Raises DatumUnavailable."""
    try:
        return [w["metadata"]["name"] for w in milo_api.list_items(milo_api.workloads_path(PROJECT), selector)]
    except (milo_api.MiloError, KeyError, TypeError) as e:
        raise DatumUnavailable(f"listing Workloads {selector}: {e}") from e


KEYPROXY_REVOKE_TIMEOUT = 5


def revoke_keyproxy(job: str) -> bool:
    """Tell the proxy that this worker's placeholders are done, so a copy of one stops
    working before it expires. Best effort: on failure they still expire within
    keyproxy.TTL. False if the proxy is not in use or did not confirm."""
    url = os.environ.get(KEYPROXY_URL_ENV, "").strip().rstrip("/")
    if not url or not job:
        return False
    try:
        token = keyproxy.revoke_token(keyproxy.hmac_key(), job)
    except ValueError:
        return False
    req = urllib.request.Request(f"{url}/revoke", data=json.dumps({"job": job}).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                req, timeout=KEYPROXY_REVOKE_TIMEOUT) as resp:
            return resp.status == 200
    except (OSError, ValueError):
        return False


def delete_workload(name: str) -> None:
    """Delete a Workload; already gone is fine, and any other failure is left for the
    next reconcile or sweep. Its proxy placeholders are revoked first."""
    if not name:
        return
    revoke_keyproxy(name)
    try:
        milo_api.delete(milo_api.workloads_path(PROJECT, name))
    except milo_api.MiloError:
        pass


def started(logs: str, nonce: str) -> bool:
    """Whether this run's job printed its start line, so the VM is up and working."""
    return any(line.rstrip().endswith(f"{STARTED} {nonce}") for line in logs.splitlines())


def parse_result(logs: str, nonce: str) -> dict | None:
    """The JSON line after this run's BEGIN marker, once the END marker has arrived."""
    lines = logs.splitlines()
    for i, line in enumerate(lines):
        if (line.rstrip().endswith(f"{BEGIN} {nonce}") and i + 2 < len(lines)
                and lines[i + 2].rstrip().endswith(END)):
            payload = lines[i + 1]
            return json.loads(payload[payload.index("{"):])
    return None


def destroy(name: str) -> None:
    try:
        datumctl("compute", "destroy", name, "--yes")
    except (RuntimeError, subprocess.TimeoutExpired):
        pass  # already gone, or sweep() removes it later


def sweep(now: float) -> None:
    """Delete review Workloads older than any review can take: left by a worker that
    died (the laptop slept or restarted) or by a destroy that failed. Each one keeps
    a VM up, since the container sleeps after it prints its result."""
    p = subprocess.run(["datumctl", "get", "workloads", "-l", "app=pr-autopilot", "-o", "json",
                        "--project", PROJECT], capture_output=True, text=True, timeout=120,
                       env=datumctl_env())
    if p.returncode != 0:
        return
    try:
        items = json.loads(p.stdout).get("items", [])
    except ValueError:
        return
    for w in items:
        created = w.get("metadata", {}).get("creationTimestamp", "")
        try:
            age = now - calendar.timegm(time.strptime(created, "%Y-%m-%dT%H:%M:%SZ"))
        except ValueError:
            continue
        if age > MAX_AGE:
            destroy(w["metadata"]["name"])


def review(repo: str, num: str, sha: str, context: str, model: str,
           focus: str = "no specific reason given", strict_workflows: bool = False,
           sleep=time.sleep, clock=time.time, digest_of=image_digest) -> dict | None:
    """The full review alone: its findings, or None when the PR head moved."""
    out = run_job(repo, num, sha, context, model, focus=focus, strict_workflows=strict_workflows,
                  sleep=sleep, clock=clock, digest_of=digest_of)
    return None if out.get("moved") else out["result"]


OUTCOME_KEYS = ("format", "route", "verdict", "title", "quick", "focus", "findings")


def review_pr(repo: str, num: str, sha: str, context: str, model: str, *, plan: str,
              focus: str = "", audit: bool = False, quick_model: str = "sonnet",
              strict_workflows: bool = False, sleep=time.sleep, clock=time.time,
              digest_of=image_digest) -> dict:
    """One VM for the whole PR: pr_worker.review's outcome (see pr_worker)."""
    out = run_job(repo, num, sha, context, model, focus=focus or "no specific reason given",
                  strict_workflows=strict_workflows, plan=plan, audit=audit, quick_model=quick_model,
                  sleep=sleep, clock=clock, digest_of=digest_of)
    if out.get("format") != pr_worker.FORMAT:
        # An image from before pr_worker (only with PR_AUTOPILOT_IMAGE set by hand: the
        # tag otherwise follows this checkout). It ran a full review only; redo it here.
        raise DatumUnavailable(f"the review image answered in format {out.get('format')!r}, "
                               f"not {pr_worker.FORMAT}; set PR_AUTOPILOT_IMAGE to a newer image")
    return {k: out.get(k) for k in OUTCOME_KEYS}


def run_job(repo: str, num: str, sha: str, context: str, model: str, *, focus: str,
            strict_workflows: bool, plan: str = "full", audit: bool = False, quick_model: str = "sonnet",
            sleep=time.sleep, clock=time.time, digest_of=image_digest) -> dict:
    """Deploy one review Workload, wait for its result, delete it. Returns the result
    the VM printed when it says "ok"; raises otherwise."""
    tagged = image()
    digest = digest_of(tagged)
    if digest is None:
        raise ImageNotBuilt(f"{tagged} is not published yet; push the code so CI builds it")
    ref = f"{tagged.rpartition(':')[0]}@{digest}"
    sweep(clock())
    nonce = secrets.token_hex(3)
    name = workload_name(repo, num, sha, nonce)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(manifest(ref, name, nonce, repo, num, sha, context, model, focus, strict_workflows,
                           plan=plan, audit=audit, quick_model=quick_model), f)
    try:
        try:
            datumctl("compute", "deploy", "-f", f.name, "--yes", timeout=DEPLOY_TIMEOUT)
        except (RuntimeError, subprocess.TimeoutExpired) as e:
            mark_down(clock())
            raise DatumUnavailable(f"deploy of {name} failed: {e}") from e
        timeout = RESULT_TIMEOUTS.get(plan, max(RESULT_TIMEOUTS.values()))
        deadline = clock() + timeout
        logs = ""
        while clock() < deadline:
            sleep(POLL_SECONDS)
            try:
                logs = datumctl("compute", "logs", name, "--current")
            except (RuntimeError, subprocess.TimeoutExpired):
                continue  # logs can lag the instance for a moment
            out = parse_result(logs, nonce)
            if out is None:
                continue
            for entry in out.get("usage") or []:  # token use in the VM, for the dashboard
                claude_cli.append_usage({**entry, "runner": "datum"})
            if not out.get("ok"):
                error = out.get("error", "no error given")
                if any(m in error for m in claude_cli.AUTH_MARKERS):
                    mark_down(clock(), TOKEN_DOWN_SECONDS)
                    raise TokenExpired("the Claude token in the Datum Secret review-credentials expired; "
                                       "run `claude setup-token` and update the Secret")
                raise RuntimeError(f"review on Datum failed: {error}")
            return out
        tail = "\n".join(logs.splitlines()[-5:])
        if started(logs, nonce):  # the VM works; the review itself ran too long
            raise RuntimeError(f"the review in {name} gave no result in {timeout // 60} minutes; "
                               f"last logs: {tail[-400:]}")
        mark_down(clock())
        raise DatumUnavailable(f"no result from {name} in {timeout // 60} minutes; last logs: {tail[-400:]}")
    finally:
        os.unlink(f.name)
        destroy(name)
