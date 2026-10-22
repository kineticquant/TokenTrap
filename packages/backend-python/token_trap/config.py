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
    # ---------------------------------------------------- PHP2Shell decoy --
    php2shell_enabled: bool = False
    php2shell_profile: str = "generic"
    php2shell_mode: str = "tripwire"
    php2shell_path_prefix: str = ""
    php2shell_strength: str = "aggressive"
    php2shell_canary_tokens: Tuple[str, ...] = ()
    php2shell_max_scan_bytes: int = 2 * 1024 * 1024
    php2shell_pressure_bytes: int = 1024 * 1024
    php2shell_session_ttl_seconds: int = 86_400
    php2shell_rate_limit_per_minute: int = 120
    php2shell_max_preview_bytes: int = 2048
    php2shell_webhook: Optional[str] = None

    def __post_init__(self) -> None:
        if self.strength not in STRENGTHS:
            raise ValueError(
                f"strength must be one of {STRENGTHS}, got {self.strength!r}"
            )
        if self.php2shell_profile not in ("generic", "wordpress", "drupal", "joomla"):
            raise ValueError(
                "php2shell_profile must be one of "
                "('generic', 'wordpress', 'drupal', 'joomla')"
            )
        if self.php2shell_mode not in ("tripwire", "scanner"):
            raise ValueError(
                "php2shell_mode must be one of ('tripwire', 'scanner')"
            )
        if self.php2shell_strength not in STRENGTHS:
            raise ValueError(
                f"php2shell_strength must be one of {STRENGTHS}, "
                f"got {self.php2shell_strength!r}"
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
            "PHP2SHELL": ("php2shell_enabled", bool),
            "PHP2SHELL_PROFILE": ("php2shell_profile", str),
            "PHP2SHELL_MODE": ("php2shell_mode", str),
            "PHP2SHELL_PATH_PREFIX": ("php2shell_path_prefix", str),
            "PHP2SHELL_STRENGTH": ("php2shell_strength", str),
            "PHP2SHELL_CANARY_TOKENS": ("php2shell_canary_tokens", "csv"),
            "PHP2SHELL_SCAN_BYTES": ("php2shell_max_scan_bytes", int),
            "PHP2SHELL_PRESSURE_BYTES": ("php2shell_pressure_bytes", int),
            "PHP2SHELL_SESSION_TTL": ("php2shell_session_ttl_seconds", int),
            "PHP2SHELL_RATE_LIMIT": ("php2shell_rate_limit_per_minute", int),
            "PHP2SHELL_MAX_PREVIEW_BYTES": ("php2shell_max_preview_bytes", int),
            "PHP2SHELL_WEBHOOK": ("php2shell_webhook", str),
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
