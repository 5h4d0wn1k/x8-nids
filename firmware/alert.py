"""Alert output handling for X8 NIDS.

Alerts are written as a JSONL stream to stdout and to a file, and optionally
forwarded to a simple built-in HTTP/JSON listener endpoint that saves arriving
records to the same alert stream file. The HTTP listener is a tiny
threaded HTTP server used for downstream SIEM-style ingestion.

This module only *sends/collects* alerts (blue-team telemetry); it contains no
attack or injection primitives.
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

from .rules import Alert


class AlertFormatter:
    """Serializes an :class:`Alert` to a stable JSON line."""

    @staticmethod
    def format(alert: Alert) -> str:
        return json.dumps(alert.as_dict(), sort_keys=True)

    @staticmethod
    def to_dict(alert: Alert) -> Dict[str, Any]:
        return alert.as_dict()


class AlertSink:
    """Writes alert records to stdout (JSONL), a file, and an optional local
    HTTP endpoint for downstream consumption.

    The built-in HTTP listener (``api_host:api_port``) accepts ``POST``
    requests carrying a JSON alert object (or a JSON array of them) and appends
    each to the alert stream file, so external producers can feed the same
    detection log.
    """

    def __init__(
        self,
        stream_path: str,
        api_enabled: bool = True,
        api_host: str = "127.0.0.1",
        api_port: int = 8488,
        to_stdout: bool = True,
    ) -> None:
        self.stream_path = stream_path
        self.api_enabled = api_enabled
        self.api_host = api_host
        self.api_port = int(api_port)
        self.to_stdout = to_stdout
        self._file: Optional[Any] = None
        self._count = 0
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._http_dump: Optional[str] = None

    # -- file/stdout ---------------------------------------------------------

    def open(self) -> None:
        parent = os.path.dirname(self.stream_path) or "."
        os.makedirs(parent, exist_ok=True)
        self._file = open(self.stream_path, "a", encoding="utf-8")

    def close(self) -> None:
        self.stop_listener()
        if self._file is not None:
            self._file.close()
            self._file = None

    def _append_line(self, line: str) -> None:
        with self._write_lock:
            if self._file is not None:
                self._file.write(line + "\n")
                self._file.flush()

    def emit(self, alert: Alert) -> None:
        """Emit one alert to stdout and the stream file."""
        line = AlertFormatter.format(alert)
        if self.to_stdout:
            print(line, flush=True)
        with self._lock:
            self._count += 1
        self._append_line(line)

    def emit_record(self, record: Dict[str, Any]) -> None:
        """Emit an already-dict alert record (used by the HTTP listener)."""
        line = json.dumps(record, sort_keys=True)
        if self.to_stdout:
            print(line, flush=True)
        with self._lock:
            self._count += 1
        self._append_line(line)

    @property
    def count(self) -> int:
        with self._lock:
            return self._count

    # -- built-in HTTP/JSON listener ----------------------------------------

    def start_listener(self) -> None:
        """Start the threaded HTTP listener if enabled and port is free."""
        if not self.api_enabled:
            return
        self._http_dump = self.stream_path

        class _Handler(BaseHTTPRequestHandler):
            sink = self

            def log_message(self, *args: Any) -> None:
                pass

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length) if length else b"{}"
                try:
                    payload = json.loads(body.decode("utf-8"))
                except Exception:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b'{"error":"bad json"}')
                    return
                records = payload if isinstance(payload, list) else [payload]
                for rec in records:
                    if isinstance(rec, dict):
                        self.sink.emit_record(rec)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok":true}')

        try:
            self._server = ThreadingHTTPServer((self.api_host, self.api_port), _Handler)
        except OSError as exc:
            self._server = None
            return
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop_listener(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
            except Exception:
                pass
            self._server.server_close()
            self._server = None
        self._thread = None

    def listener_url(self) -> Optional[str]:
        if self._server is None:
            return None
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    def status(self) -> Dict[str, Any]:
        return {
            "stream_path": self.stream_path,
            "alerts_written": self.count,
            "api_enabled": self.api_enabled and self._server is not None,
            "api_url": self.listener_url(),
        }
