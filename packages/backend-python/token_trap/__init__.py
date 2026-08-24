"""TokenTrap - defensive LLM agent honeypot & token tarpit (Python backend)."""

from .config import TrapConfig, DEFAULT_PERSONA
from .detection import DEFAULT_INJECTION_KEYWORDS, detect_injection
from .traps import (
    AUDIT_POLICY_ID,
    AUDIT_POLICY_REV,
    STRENGTH_PRESETS,
    TrapEngine,
    compliance_ref,
    fnv1a32,
    plan_turn,
)
from .app import create_app

__version__ = "1.0.3"

__all__ = [
    "AUDIT_POLICY_ID",
    "AUDIT_POLICY_REV",
    "DEFAULT_INJECTION_KEYWORDS",
    "DEFAULT_PERSONA",
    "STRENGTH_PRESETS",
    "TrapConfig",
    "TrapEngine",
    "__version__",
    "compliance_ref",
    "create_app",
    "detect_injection",
    "fnv1a32",
    "plan_turn",
]
