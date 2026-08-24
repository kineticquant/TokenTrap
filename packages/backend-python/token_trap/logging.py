"""Structured JSON logging + optional webhook delivery.

Note: module intentionally named ``logging`` per the architecture spec; it is
imported as ``token_trap.logging`` and never shadows the stdlib inside this
package (absolute imports are the Python 3 default).
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import urllib.request
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    """One JSON object per log line - ready for `wrangler tail`-style ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("event_data",):
            value = getattr(record, key, None)
            if value is not None:
                payload.update(value if isinstance(value, dict) else {"event_data": value})
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def get_logger(name: str = "token_trap") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


def post_webhook(url: str, payload: dict, timeout: float = 4.0) -> None:
    """Fire-and-forget webhook delivery on a daemon thread; never raises."""

    def _post() -> None:
        try:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            request = urllib.request.Request(
                url,
                data=data,
                headers={"content-type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=timeout):  # noqa: S310
                pass
        except Exception:  # noqa: BLE001 - honeypot logging must never break serving
            pass

    threading.Thread(target=_post, daemon=True).start()
