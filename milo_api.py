"""Milo (Datum Cloud) API calls over the Python standard library, in place of datumctl.

The dispatcher on Datum runs as one process with no fork/exec, so it cannot run
datumctl. A project's resources live in its control plane, which speaks the
Kubernetes API under a per-project prefix (see project_base()).

Credentials, in this order:
  PR_AUTOPILOT_MILO_CREDENTIALS   a service-account key (JSON, from a Secret): the
                                  dispatcher. Exchanged for an access token, see sa_token().
  `datumctl auth get-token`       the laptop: your own login, pinned to SESSION.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

API = os.environ.get("PR_AUTOPILOT_MILO_API", "https://api.datum.net")
SESSION = os.environ.get("PR_AUTOPILOT_DATUM_SESSION", "you@example.com@api.datum.net")
CREDENTIALS_ENV = "PR_AUTOPILOT_MILO_CREDENTIALS"
ISSUER = os.environ.get("PR_AUTOPILOT_MILO_ISSUER", "https://auth.datum.net")
TOKEN_URL = f"{ISSUER}/oauth/v2/token"
TIMEOUT = 60
REFRESH_BEFORE = 120  # renew a token this many seconds before it expires
JSON = "application/json"
MERGE_PATCH = "application/merge-patch+json"

_TOKEN = {"value": "", "expires": 0.0}


class MiloError(Exception):
    """A failed call. `status` is the HTTP status (0: no answer), `reason` the
    Kubernetes Status reason such as NotFound, Conflict or AlreadyExists."""

    def __init__(self, method: str, path: str, status: int, reason: str, message: str):
        self.method, self.path, self.status, self.reason, self.message = method, path, status, reason, message
        super().__init__(f"Milo {method} {path}: {f'HTTP {status}' if status else 'no answer'}"
                         f"{f' ({reason})' if reason else ''}{': ' + message if message else ''}")


class NotFound(MiloError):
    pass


class Conflict(MiloError):
    """409: an old resourceVersion, or the object already exists."""


def project_base(project: str) -> str:
    return f"apis/resourcemanager.miloapis.com/v1alpha1/projects/{project}/control-plane"


def configmaps_path(project: str, name: str | None = None, namespace: str = "default") -> str:
    path = f"{project_base(project)}/api/v1/namespaces/{namespace}/configmaps"
    return f"{path}/{name}" if name else path


def workloads_path(project: str, name: str | None = None, namespace: str = "default") -> str:
    path = f"{project_base(project)}/apis/compute.datumapis.com/v1alpha/namespaces/{namespace}/workloads"
    return f"{path}/{name}" if name else path


# --- Tokens ------------------------------------------------------------------------

def token() -> str:
    now = time.time()
    if _TOKEN["value"] and now < _TOKEN["expires"] - REFRESH_BEFORE:
        return _TOKEN["value"]
    raw = os.environ.get(CREDENTIALS_ENV, "").strip()
    value, expires = sa_token(json.loads(raw)) if raw else user_token()
    _TOKEN.update(value=value, expires=expires)
    return value


def user_token() -> tuple[str, float]:
    """The laptop: your datumctl login. Not available in the dispatcher (no exec)."""
    if not shutil.which("datumctl"):
        raise MiloError("GET", "(token)", 401, "Unauthorized", f"no credentials: set {CREDENTIALS_ENV}")
    try:
        p = subprocess.run(["datumctl", "auth", "get-token"], capture_output=True, text=True, timeout=60,
                           env={**os.environ, "DATUM_SESSION": SESSION})
    except subprocess.TimeoutExpired as e:
        raise MiloError("GET", "(token)", 0, "", f"datumctl auth get-token: {e}") from None
    if p.returncode != 0 or not p.stdout.strip():
        raise MiloError("GET", "(token)", 401, "Unauthorized",
                        f"datumctl auth get-token: {(p.stderr or p.stdout).strip()[-300:]}")
    # It refreshes the login itself; asking again every few minutes costs one fork.
    return p.stdout.strip(), time.time() + 10 * 60


def sa_token(key: dict, now: float | None = None) -> tuple[str, float]:
    """Exchange a service-account key for an access token, as `datumctl login
    --credentials` does: a JWT signed with the key (RS256), sent with the JWT-bearer
    grant. There is no refresh token; a new JWT is signed when the token runs out."""
    now = time.time() if now is None else now
    for field in ("client_id", "private_key_id", "private_key"):
        if not key.get(field):
            raise MiloError("POST", "(token)", 401, "Unauthorized", f"service-account key has no {field}")
    claims = {"iss": key["client_id"], "sub": key["client_id"], "aud": ISSUER,
              "iat": int(now), "exp": int(now) + 60, "jti": uuid.uuid4().hex}
    assertion = sign_jwt(claims, key["private_key"], key["private_key_id"])
    form = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                   "assertion": assertion,
                                   "scope": key.get("scope") or "openid profile email offline_access"}).encode()
    req = urllib.request.Request(TOKEN_URL, data=form, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": JSON})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise MiloError("POST", "(token)", e.code, "Unauthorized",
                        (e.read() or b"").decode("utf-8", "replace")[-300:]) from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise MiloError("POST", "(token)", 0, "", str(getattr(e, "reason", e))) from None
    if not body.get("access_token"):
        raise MiloError("POST", "(token)", 401, "Unauthorized", "no access_token in the answer")
    return body["access_token"], now + int(body.get("expires_in") or 300)


# --- RS256 with the standard library ------------------------------------------------
# Python has no RSA in its standard library, and the dispatcher cannot run openssl.
# Signing is RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017, section 8.2): small enough to
# write out. Only signing is needed, and the key never leaves this process.

SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sign_jwt(claims: dict, pem: str, kid: str) -> str:
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    signing_input = (b64url(json.dumps(header, separators=(",", ":")).encode()) + "."
                     + b64url(json.dumps(claims, separators=(",", ":")).encode()))
    return signing_input + "." + b64url(rsa_sign(signing_input.encode(), pem))


def rsa_sign(message: bytes, pem: str) -> bytes:
    n, d = private_numbers(pem)
    k = (n.bit_length() + 7) // 8
    t = SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    if k < len(t) + 11:
        raise ValueError("RSA key too short")
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


def private_numbers(pem: str) -> tuple[int, int]:
    """(n, d) from a PEM private key: PKCS#1 ("RSA PRIVATE KEY") or PKCS#8 ("PRIVATE KEY")."""
    body = "".join(line for line in pem.strip().splitlines() if not line.startswith("-----"))
    der = base64.b64decode(body)
    seq, _ = der_read(der, 0x30)
    if "BEGIN RSA PRIVATE KEY" not in pem:  # PKCS#8: version, algorithm, OCTET STRING(PKCS#1)
        _, pos = der_read(seq, 0x02)
        _, pos = der_read(seq, 0x30, pos)
        inner, _ = der_read(seq, 0x04, pos)
        seq, _ = der_read(inner, 0x30)
    numbers, pos = [], 0
    for _ in range(4):  # version, n, e, d
        value, pos = der_read(seq, 0x02, pos)
        numbers.append(int.from_bytes(value, "big"))
    return numbers[1], numbers[3]


def der_read(data: bytes, tag: int, pos: int = 0) -> tuple[bytes, int]:
    """One DER element with this tag at `pos`: (its contents, the position after it)."""
    if data[pos] != tag:
        raise ValueError(f"DER: expected tag {tag:#x} at {pos}, found {data[pos]:#x}")
    length, pos = data[pos + 1], pos + 2
    if length & 0x80:
        count = length & 0x7F
        length, pos = int.from_bytes(data[pos:pos + count], "big"), pos + count
    return data[pos:pos + length], pos + length


# --- Calls -------------------------------------------------------------------------

def request(method: str, path: str, *, body: dict | None = None, params: dict | None = None,
            content_type: str = JSON, timeout: int = TIMEOUT) -> bytes:
    url = f"{API}/{path.lstrip('/')}" + (f"?{urllib.parse.urlencode(params)}" if params else "")
    req = urllib.request.Request(url, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": f"Bearer {token()}", "Accept": JSON,
                                          **({"Content-Type": content_type} if body is not None else {})})
    short = path.split("/control-plane/", 1)[-1]
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        raw = e.read() or b""
        try:
            status = json.loads(raw)
            reason, message = status.get("reason", ""), status.get("message", "")
        except (ValueError, AttributeError):
            reason, message = "", raw.decode("utf-8", "replace")[-300:]
        if e.code == 401:
            _TOKEN.update(value="", expires=0)  # fetch a fresh one next time
        error = NotFound if e.code == 404 else Conflict if e.code == 409 else MiloError
        raise error(method, short, e.code, reason, message[:300]) from None
    except (urllib.error.URLError, OSError) as e:
        raise MiloError(method, short, 0, "", str(getattr(e, "reason", e))) from None


def get(path: str) -> dict:
    return json.loads(request("GET", path))


def create(path: str, doc: dict) -> dict:
    """POST to a collection path."""
    return json.loads(request("POST", path, body=doc))


def merge_patch(path: str, patch: dict) -> dict:
    """A JSON merge patch. With metadata.resourceVersion set, a stale version gets 409."""
    return json.loads(request("PATCH", path, body=patch, content_type=MERGE_PATCH))


def delete(path: str) -> None:
    try:
        request("DELETE", path)
    except NotFound:
        pass


def list_items(path: str, selector: str | None = None) -> list[dict]:
    return get_list(path, {"labelSelector": selector} if selector else None)


def get_list(path: str, params: dict | None) -> list[dict]:
    return json.loads(request("GET", path, params=params)).get("items") or []

