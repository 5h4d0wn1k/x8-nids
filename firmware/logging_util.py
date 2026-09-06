"""Structured logging for X8 NIDS.

Writes a consistent machine/JSON-friendly log to a file (``logs/nids.log``)
and a readable stream to stdout. Level comes from config.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any, Dict, Optional


class JsonFormatter(logging.Formatter):
    """Format log records as single-line JSON objects for the file sink."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        payload: Dict[str, Any] = {
            "ts": record.created,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0] is not None:
            payload["exc"] = self.formatException(record.exc_info)
        extra = getattr(record, "nids_extra", None)
        if extra:
            payload["data"] = extra
        return json.dumps(payload, sort_keys=True)


class StreamFormatter(logging.Formatter):
    """Human-readable formatter for stdout."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        base = f"[{record.levelname}] {record.getMessage()}"
        extra = getattr(record, "nids_extra", None)
        if extra:
            base += f" {json.dumps(extra, sort_keys=True)}"
        return base


class Logger:
    """Small wrapper exposing a configured logging.Logger with extra helpers."""

    def __init__(self, level: str = "INFO", file_path: Optional[str] = None) -> None:
        self.logger = logging.getLogger("nids")
        self.logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        self.logger.propagate = False
        self.logger.handlers = []

        if file_path:
            parent = os.path.dirname(file_path) or "."
            os.makedirs(parent, exist_ok=True)
            fh = logging.FileHandler(file_path, encoding="utf-8")
            fh.setFormatter(JsonFormatter())
            self.logger.addHandler(fh)

        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(StreamFormatter())
        self.logger.addHandler(sh)

    def _extra(self, data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        return {"nids_extra": data or {}}

    def info(self, msg: str, data: Optional[Dict[str, Any]] = None) -> None:
        self.logger.info(msg, extra=self._extra(data))

    def warning(self, msg: str, data: Optional[Dict[str, Any]] = None) -> None:
        self.logger.warning(msg, extra=self._extra(data))

    def error(self, msg: str, data: Optional[Dict[str, Any]] = None) -> None:
        self.logger.error(msg, extra=self._extra(data))

    def debug(self, msg: str, data: Optional[Dict[str, Any]] = None) -> None:
        self.logger.debug(msg, extra=self._extra(data))

    def critical(self, msg: str, data: Optional[Dict[str, Any]] = None) -> None:
        self.logger.critical(msg, extra=self._extra(data))


def get_logger(level: str = "INFO", file_path: Optional[str] = None) -> Logger:
    return Logger(level=level, file_path=file_path)
