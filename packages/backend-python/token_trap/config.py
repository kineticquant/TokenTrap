"""Runtime configuration for the TokenTrap backend.

Mirrors the widget's ``TokenTrapConfig`` surface. Defaults match the shared
escalation spec so all three deployment levels behave identically.
"""

from __future__ import annotations

import dataclasses
from typing import Optional, Tuple

DEFAULT_PERSONA = "Internal AI Assistant"

STRENGTHS = ("moderate", "aggressive", "maximum")


@dataclasses.dataclass
class TrapConfig:
    """All knobs for one honeypot instance. Safe to construct with no args."""

    persona: str = DEFAULT_PERSONA
    strength: str = "aggressive"
    extra_keywords: Tuple[str, ...] = ()
    override_keywords: bool = False
    canary_tokens: Tuple[str, ...] = ()
    session_ttl_seconds: int = 86_400
    rate_limit_per_minute: int = 30
    log_webhook: Optional[str] = None
    # Optional real-LLM dressing for turn 0 (requires the `llm` extra).
    llm_model: Optional[str] = None

    def __post_init__(self) -> None:
        if self.strength not in STRENGTHS:
            raise ValueError(
                f"strength must be one of {STRENGTHS}, got {self.strength!r}"
            )

    def effective_keywords(self) -> Tuple[str, ...]:
        """Keyword list actually used for detection."""
        from .detection import DEFAULT_INJECTION_KEYWORDS

        if self.override_keywords:
            return tuple(self.extra_keywords)
        return tuple(DEFAULT_INJECTION_KEYWORDS) + tuple(self.extra_keywords)

    @classmethod
    def from_env_prefix(cls, env, prefix: str = "TOKENTRAP_") -> "TrapConfig":
        """Build a config from environment variables (TOKENTRAP_*)."""
        import os

        source = env if env is not None else os.environ
        kwargs = {}
        mapping = {
            "PERSONA": ("persona", str),
            "STRENGTH": ("strength", str),
            "CANARY_TOKENS": ("canary_tokens", "csv"),
            "EXTRA_KEYWORDS": ("extra_keywords", "csv"),
            "LOG_WEBHOOK": ("log_webhook", str),
            "RATE_LIMIT": ("rate_limit_per_minute", int),
            "SESSION_TTL": ("session_ttl_seconds", int),
            "OVERRIDE_KEYWORDS": ("override_keywords", bool),
            "LLM_MODEL": ("llm_model", str),
        }
        for env_key, (field, kind) in mapping.items():
            raw = source.get(prefix + env_key)
            if raw is None or raw == "":
                continue
            if kind == "csv":
                kwargs[field] = tuple(s.strip() for s in raw.split(",") if s.strip())
            elif kind == int:
                kwargs[field] = int(raw)
            elif kind == bool:
                kwargs[field] = raw.lower() in {"1", "true", "yes"}
            else:
                kwargs[field] = raw
        return cls(**kwargs)
