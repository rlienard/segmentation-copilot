"""Structured-logging helper.

Switching between JSON and plain text via `SCOPILOT_LOG_FORMAT`. JSON is
the production default — feeds straight into Loki / CloudWatch / etc.
without an exporter.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from typing import Any


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        for k, v in record.__dict__.items():
            if k in ("args", "msg", "name", "pathname", "filename", "module",
                     "exc_info", "exc_text", "stack_info", "lineno", "funcName",
                     "created", "msecs", "relativeCreated", "thread", "threadName",
                     "processName", "process", "levelname", "levelno"):
                continue
            payload[k] = v
        return json.dumps(payload, default=str)


def configure_logging(*, level: str | None = None, fmt: str | None = None,
                      stream=None) -> None:
    """Configure root logging once per process.

    `level` and `fmt` default to `SCOPILOT_LOG_LEVEL` / `SCOPILOT_LOG_FORMAT`.
    `stream` defaults to stderr (stdio MCP transport must keep stdout clean).
    """
    level = (level or os.environ.get("SCOPILOT_LOG_LEVEL") or "INFO").upper()
    fmt = (fmt or os.environ.get("SCOPILOT_LOG_FORMAT") or "text").lower()
    stream = stream or sys.stderr

    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(stream)
    if fmt == "json":
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s"
        ))
    root.addHandler(handler)
    root.setLevel(getattr(logging, level, logging.INFO))
