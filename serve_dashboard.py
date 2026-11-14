#!/usr/bin/env python3
"""Serve the PR autopilot dashboard page on localhost, for a Datum Connect tunnel.

Answers only / and /index.html with the page reviewer.py rebuilds every run;
every other path gets 404, so nothing else in the cache can leak through it.
Binds to 127.0.0.1 only: `datumctl connect serve localhost:PORT` reaches it
from the device itself. reviewer.py starts it in the background when nothing
answers on the port; stats.py runs it in a thread.
"""
from __future__ import annotations

import http.server

import reviewer


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.split("?", 1)[0] not in ("/", "/index.html"):
            self.send_error(404)
            return
        try:
            body = reviewer.DASHBOARD_FILE.read_bytes()
        except OSError:
            self.send_error(503, "the dashboard has not been built yet")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:  # keep the shared log readable
        pass


def server(port: int | None = None) -> http.server.ThreadingHTTPServer:
    """Bound to 127.0.0.1; raises OSError when the port is taken. stats.py runs it in a thread."""
    return http.server.ThreadingHTTPServer(("127.0.0.1", port or reviewer.DASHBOARD_PORT), Handler)


if __name__ == "__main__":
    server().serve_forever()
