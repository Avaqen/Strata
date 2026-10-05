#!/usr/bin/env python3
"""Public, synthetic-data-only web entry point for the Strata demo."""

from __future__ import annotations

import argparse
import json
import os
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import app


ROOT = Path(__file__).resolve().parent
MAX_REQUEST_BYTES = 32 * 1024
ASSETS = {"/", "/index.html", "/app.js", "/styles.css", "/demo.css"}


class DemoHandler(app.Handler):
    def _is_local_request(self) -> bool:
        host = self.headers.get("Host", "").lower()
        origin = self.headers.get("Origin")
        return bool(host) and (
            origin is None or origin in {f"http://{host}", f"https://{host}"}
        )

    def _read_payload(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length", "")
        if not raw_length.isascii() or not raw_length.isdecimal():
            raise ValueError("A valid Content-Length header is required.")
        length = int(raw_length)
        if length > MAX_REQUEST_BYTES:
            raise OverflowError("Demo requests must be smaller than 32 KB.")
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError("Request body was incomplete.")
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ValueError("Send data as application/json.")
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object.")
        return payload

    def do_GET(self) -> None:
        if not self._is_local_request():
            self._json(403, {"error": "Cross-origin requests are not allowed."})
            return
        path = urlparse(self.path).path
        if path == "/api/health":
            self._json(200, {"status": "ok", "service": "Strata demo"})
        elif path == "/api/config":
            self._json(200, {"demo_mode": True})
        elif path == "/api/demo":
            self._json(200, {"rows": app.demo_rows()})
        elif path.startswith("/api/live/"):
            self._json(404, {"error": "Live capture is disabled in the public demo."})
        elif path in ASSETS:
            target = ROOT / ("index.html" if path in {"/", "/index.html"} else path[1:])
            body = target.read_bytes()
            if path in {"/", "/index.html"}:
                page = body.decode("utf-8")
                page = page.replace(
                    '<link rel="stylesheet" href="/styles.css">',
                    '<link rel="stylesheet" href="/styles.css">\n'
                    '  <link rel="stylesheet" href="/demo.css">',
                    1,
                )
                page = page.replace(
                    '<div class="content">',
                    '<div class="content">\n'
                    '        <aside class="public-demo-notice">'
                    '<strong>Public demo</strong> Synthetic sample traffic only. '
                    'Live capture and CSV imports are disabled.</aside>',
                    1,
                )
                page = page.replace("LOCAL PROCESSING", "SYNTHETIC DATA ONLY", 1)
                page = page.replace(
                    "All processing stays on this device",
                    "Demo uses synthetic traffic only",
                    1,
                )
                body = page.encode("utf-8")
            suffix = target.suffix
            content_type = {
                ".html": "text/html; charset=utf-8",
                ".js": "text/javascript; charset=utf-8",
                ".css": "text/css; charset=utf-8",
            }[suffix]
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'self'; script-src 'self'; "
                "img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
            )
            self.end_headers()
            self.wfile.write(body)
        else:
            self._json(404, {"error": "Endpoint not found."})

    def do_POST(self) -> None:
        if not self._is_local_request():
            self._json(403, {"error": "Cross-origin requests are not allowed."})
            return
        if urlparse(self.path).path != "/api/analyze":
            self._json(404, {"error": "Live capture is disabled in the public demo."})
            return
        try:
            payload = self._read_payload()
            if "csv" in payload or set(payload) - {"rows", "threshold", "features"}:
                raise ValueError("The public demo only analyzes its synthetic sample traffic.")
            result = app.analyze(
                app.demo_rows(),
                payload.get("threshold", 72),
                payload.get("features"),
            )
            self._json(200, result)
        except OverflowError as error:
            self._json(413, {"error": str(error)})
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
            self._json(400, {"error": str(error)})


class ThreadedDemoServer(ThreadingHTTPServer):
    daemon_threads = True


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the public Strata synthetic-data demo.")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    server = ThreadedDemoServer(("0.0.0.0", args.port), DemoHandler)
    print(f"Strata public demo listening on port {args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Strata demo.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
