"""Session state and TTL storage for the PHP2Shell decoy."""

from __future__ import annotations

import threading
import time
from typing import Callable, Dict, Optional, Tuple

from ..traps import fnv1a32
from .types import DetectionResult, Php2ShellState


def session_key(client_ip: str, user_agent: str) -> str:
    return f"p2s-{fnv1a32(f'{client_ip}|{user_agent}'):x}"


def initial_state(session_id: str, now: float) -> Php2ShellState:
    return Php2ShellState(
        session_id=session_id,
        created_at=now,
        last_seen=now,
        request_count=0,
        max_score=0,
        phase="recon",
        pressure_seen=False,
        upload_progress_seen=False,
        issued_canaries=(),
        canary_echoed=False,
    )


def apply_detection(
    prior: Optional[Php2ShellState],
    detection: DetectionResult,
    now: float,
) -> Php2ShellState:
    state = prior or initial_state("p2s-unknown", now)
    return Php2ShellState(
        session_id=state.session_id,
        created_at=state.created_at,
        last_seen=now,
        request_count=state.request_count + 1,
        max_score=max(state.max_score, detection.score),
        phase=detection.phase,
        pressure_seen=state.pressure_seen or detection.phase != "recon",
        upload_progress_seen=state.upload_progress_seen
        or "upload_progress_field" in detection.signals,
        issued_canaries=tuple(state.issued_canaries),
        canary_echoed=state.canary_echoed or detection.canary_echo,
    )


class InMemoryPhp2ShellStore:
    """Thread-safe TTL store; intentionally small and dependency-free."""

    def __init__(
        self,
        ttl_seconds: int = 86_400,
        now: Callable[[], float] = time.time,
        max_entries: int = 10_000,
    ) -> None:
        self._ttl = ttl_seconds
        self._now = now
        self._max_entries = max_entries
        self._entries: Dict[str, Tuple[Php2ShellState, float]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Php2ShellState]:
        now = self._now()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            state, expires_at = entry
            if expires_at <= now:
                del self._entries[key]
                return None
            return state

    def set(self, key: str, state: Php2ShellState, ttl_seconds: Optional[int] = None) -> None:
        ttl = self._ttl if ttl_seconds is None else ttl_seconds
        now = self._now()
        with self._lock:
            self._entries[key] = (state, now + ttl)
            if len(self._entries) > self._max_entries:
                expired = [k for k, (_, expires) in self._entries.items() if expires <= now]
                for k in expired:
                    del self._entries[k]

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)
