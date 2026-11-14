# Image for the PR autopilot dispatcher on a Datum `unikernel` instance (docs/dispatcher.md).
# The same image runs the credential proxy (keyproxy.py, remote/keyproxy-workload.yaml) with
# its own command.
# One process, stdlib Python only, no shell and no other programs: a unikernel cannot start
# them. Holds no secrets: the GitHub PAT and the Milo service-account key come from Secrets,
# repos.json from a ConfigMap volume.
#
# CI builds and pushes it (.github/workflows/dispatcher-image.yaml). By hand, from the
# repository root:
#   docker build --platform linux/amd64 -f remote/dispatcher.Dockerfile -t pr-autopilot-dispatcher .
#
# The final stage is `scratch` with the interpreter, its stdlib and the few shared libraries
# it loads (libssl/libcrypto for HTTPS and hashlib, libz). Shape taken from the unikernel
# prototype (research note, "Prototype B results"): 41.5 MB there.
FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df AS build
RUN cd /usr/local/lib/python3.12 \
 && rm -rf test idlelib tkinter turtledemo ensurepip lib2to3 pydoc_data site-packages \
           config-3.12-x86_64-linux-gnu unittest/test sqlite3 \
 && find . -name '__pycache__' -prune -exec rm -rf {} + \
 && (python3 -m compileall -q -b . >/dev/null 2>&1 || true)
RUN mkdir -p /out/app /out/tmp && cp /usr/local/bin/python3.12 /out/app/python
# The review image's files are copied too: remote_review.image_tag() hashes them to pick
# the review image built from the same commit.
COPY claude_cli.py dashboard.py dispatcher.py full_review.py github_api.py keyproxy.py milo_api.py pr_worker.py \
     remote_review.py reviewer.py state_store.py render-diff /out/app/
COPY remote/Dockerfile remote/review-job.py /out/app/remote/
RUN cd /out/app && /usr/local/bin/python3.12 -c "import dispatcher, keyproxy" \
 && /usr/local/bin/python3.12 -c "import remote_review; print('review image tag', remote_review.image_tag())"

FROM scratch
COPY --from=build /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=build /usr/local/lib/libpython3.12.so.1.0 /lib/x86_64-linux-gnu/libpython3.12.so.1.0
COPY --from=build /lib64/ld-linux-x86-64.so.2 /lib64/ld-linux-x86-64.so.2
COPY --from=build /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/libm.so.6 \
     /lib/x86_64-linux-gnu/libssl.so.3 /lib/x86_64-linux-gnu/libcrypto.so.3 /lib/x86_64-linux-gnu/libz.so.1 \
     /lib/x86_64-linux-gnu/
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/app /app
COPY --from=build /out/tmp /tmp
# No WORKDIR: the unikernel runtime emulates it with a shell, and this image has none
# (datumctl compute build --analyze). Python finds the modules next to /app/dispatcher.py.
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    PYTHONHOME=/usr/local \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    PR_AUTOPILOT_CACHE=/tmp/pr-autopilot \
    PR_AUTOPILOT_STATE=configmap \
    PR_AUTOPILOT_RUNNER=datum
ENTRYPOINT ["/app/python", "/app/dispatcher.py"]
