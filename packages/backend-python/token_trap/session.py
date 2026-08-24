"""Session storage for the TokenTrap backend.

In-memory store with TTL by default; swap in a Redis-backed implementation of
``SessionStore`` for multi-process deployments (see docs/deployment/python-backend.md).
"""

from __future__ import annotations

import threading
import time
from typing import Dict, Optional


class SessionRecord:
    __slots__ = ("session_id", "turns", "created_at", "last_meta")

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.turns = 0
        self.created_at = time.time()
        self.last_meta: Optional[dict] = None


class InMemorySessionStore:
    """Thread-safe, TTL-expiring session store (mirrors widget TtlMap)."""

    def __init__(self, ttl_seconds: int = 86_400, sweep_at: int = 10_000) -> None:
        self._ttl = ttl_seconds
        self._sweep_at = sweep_at
        self._sessions: Dict[str, SessionRecord] = {}
        self._lock = threading.Lock()

    def get(self, session_id: str) -> Optional[SessionRecord]:
        now = time.time()
        with self._lock:
            rec = self._sessions.get(session_id)
            if rec is None:
                return None
            if now - rec.created_at > self._ttl:
                del self._sessions[session_id]
                return None
            return rec

    def get_or_create(self, session_id: str) -> SessionRecord:
        rec = self.get(session_id)
        if rec is not None:
            return rec
        with self._lock:
            # Double-check after acquiring the lock.
            rec = self._sessions.get(session_id)
            if rec is not None and time.time() - rec.created_at <= self._ttl:
                return rec
            fresh = SessionRecord(session_id)
            self._sessions[session_id] = fresh
            if len(self._sessions) > self._sweep_at:
                self.sweep()
            return fresh

    def increment_turns(self, session_id: str) -> int:
        """Advance the exchange counter; returns the new count."""
        rec = self.get_or_create(session_id)
        with self._lock:
            rec.turns += 1
            return rec.turns

    def set_last_meta(self, session_id: str, meta: dict) -> None:
        rec = self.get_or_create(session_id)
        with self._lock:
            rec.last_meta = meta

    def sweep(self, now: Optional[float] = None) -> int:
        now = now if now is not None else time.time()
        removed = 0
        for sid, rec in list(self._sessions.items()):
            if now - rec.created_at > self._ttl:
                del self._sessions[sid]
                removed += 1
        return removed

    def __len__(self) -> int:
        return len(self._sessions)


class SlidingWindowRateLimiter:
    """Per-key rate limiter (mirrors the Worker's in-isolate limiter)."""

    def __init__(self, limit_per_minute: int) -> None:
        self.limit = limit_per_minute
        self._hits: Dict[str, list] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        if self.limit <= 0:
            return True
        now = time.time()
        window_start = now - 60.0
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if t >= window_start]
            allowed = len(hits) < self.limit
            if allowed:
                hits.append(now)
            self._hits[key] = hits
            if len(self._hits) > 5_000:
                stale = [k for k, v in self._hits.items() if all(t < window_start for t in v)]
                for k in stale:
                    del self._hits[k]
            return allowed
