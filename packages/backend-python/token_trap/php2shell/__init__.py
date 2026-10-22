"""PHP2Shell decoy module."""

from .detector import detect_php2shell, scan_multipart
from .responses import BuiltResponse, build_response, plan_directive
from .router import create_php2shell_app, create_php2shell_router
from .scanner import ScannerResult, build_scanner_response, parse_command, should_use_scanner
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
    ScannerState,
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
    "ScannerResult",
    "ScannerState",
    "Tarpit",
    "apply_detection",
    "build_response",
    "build_scanner_response",
    "create_php2shell_app",
    "create_php2shell_router",
    "detect_php2shell",
    "initial_state",
    "parse_command",
    "plan_directive",
    "scan_multipart",
    "session_key",
    "should_use_scanner",
]
