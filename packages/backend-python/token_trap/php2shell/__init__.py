"""PHP2Shell decoy module."""

from .detector import detect_php2shell, scan_multipart
from .responses import BuiltResponse, build_response, plan_directive
from .router import create_php2shell_app, create_php2shell_router
from .state import InMemoryPhp2ShellStore, apply_detection, initial_state, session_key
from .types import (
    DEFAULT_MAX_PREVIEW_BYTES,
    DEFAULT_MAX_SCAN_BYTES,
    DEFAULT_PRESSURE_BYTES,
    DEFAULT_RATE_LIMIT_PER_MINUTE,
    DEFAULT_SESSION_TTL_SECONDS,
    DetectionResult,
    MultipartSummary,
    Php2ShellState,
    RequestInfo,
    Tarpit,
)

__all__ = [
    "DEFAULT_MAX_PREVIEW_BYTES",
    "DEFAULT_MAX_SCAN_BYTES",
    "DEFAULT_PRESSURE_BYTES",
    "DEFAULT_RATE_LIMIT_PER_MINUTE",
    "DEFAULT_SESSION_TTL_SECONDS",
    "BuiltResponse",
    "DetectionResult",
    "InMemoryPhp2ShellStore",
    "MultipartSummary",
    "Php2ShellState",
    "RequestInfo",
    "Tarpit",
    "apply_detection",
    "build_response",
    "create_php2shell_app",
    "create_php2shell_router",
    "detect_php2shell",
    "initial_state",
    "plan_directive",
    "scan_multipart",
    "session_key",
]
