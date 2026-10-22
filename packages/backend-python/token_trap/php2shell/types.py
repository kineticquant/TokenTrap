"""Shared PHP2Shell decoy types and defaults.

These dataclasses mirror the TypeScript types in
``packages/widget/src/php2shell/types.ts``. The wire-format event uses camelCase
keys; internal fields stay snake_case.
"""

from __future__ import annotations

import dataclasses
from typing import Dict, Optional, Tuple

DEFAULT_MAX_SCAN_BYTES = 2 * 1024 * 1024
DEFAULT_PRESSURE_BYTES = 1024 * 1024
DEFAULT_SESSION_TTL_SECONDS = 86_400
DEFAULT_RATE_LIMIT_PER_MINUTE = 120
DEFAULT_MAX_PREVIEW_BYTES = 2048

PROFILES = ("generic", "wordpress", "drupal", "joomla")
MODES = ("tripwire", "scanner")
PHASES = ("recon", "pressure", "stale_reuse", "post_exploit")


@dataclasses.dataclass(frozen=True)
class MultipartSummary:
    is_multipart: bool
    boundary: Optional[str]
    parts: int
    empty_file_parts: int
    file_parts: int
    max_name_depth: int
    has_upload_progress: bool
    closed: bool

    def to_dict(self) -> dict:
        return {
            "isMultipart": self.is_multipart,
            "boundary": self.boundary,
            "parts": self.parts,
            "emptyFileParts": self.empty_file_parts,
            "fileParts": self.file_parts,
            "maxNameDepth": self.max_name_depth,
            "hasUploadProgress": self.has_upload_progress,
            "closed": self.closed,
        }


@dataclasses.dataclass(frozen=True)
class RequestInfo:
    method: str
    path: str
    query: str
    headers: Dict[str, str]
    body_prefix: str
    body_bytes: int
    body_truncated: bool
    body_sha256: str
    content_type: str
    content_length: Optional[int]
    transfer_encoding: str
    user_agent: str
    client_ip: str
    multipart: MultipartSummary


@dataclasses.dataclass(frozen=True)
class DetectionResult:
    signals: Tuple[str, ...]
    score: int
    tier: str
    phase: str
    response_phase: str
    canary_echo: bool


@dataclasses.dataclass
class ScannerState:
    cwd: str = "/var/www/html"
    hostname: str = "php-prod"
    depth: int = 0
    command_count: int = 0
    last_command: Optional[str] = None
    response_bytes: int = 0
    estimated_tokens: int = 0

    def to_dict(self) -> dict:
        return {
            "cwd": self.cwd,
            "hostname": self.hostname,
            "depth": self.depth,
            "commandCount": self.command_count,
            "lastCommand": self.last_command,
            "responseBytes": self.response_bytes,
            "estimatedTokens": self.estimated_tokens,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScannerState":
        return cls(
            cwd=data.get("cwd", "/var/www/html"),
            hostname=data.get("hostname", "php-prod"),
            depth=int(data.get("depth", 0)),
            command_count=int(data.get("commandCount", 0)),
            last_command=data.get("lastCommand"),
            response_bytes=int(data.get("responseBytes", 0)),
            estimated_tokens=int(data.get("estimatedTokens", 0)),
        )


@dataclasses.dataclass
class Php2ShellState:
    session_id: str
    created_at: float
    last_seen: float
    request_count: int
    max_score: int
    phase: str
    pressure_seen: bool
    upload_progress_seen: bool
    issued_canaries: Tuple[str, ...]
    canary_echoed: bool
    scanner: Optional[ScannerState] = None
    estimated_attacker_tokens: int = 0

    def to_dict(self) -> dict:
        return {
            "sessionId": self.session_id,
            "createdAt": self.created_at,
            "lastSeen": self.last_seen,
            "requestCount": self.request_count,
            "maxScore": self.max_score,
            "phase": self.phase,
            "pressureSeen": self.pressure_seen,
            "uploadProgressSeen": self.upload_progress_seen,
            "issuedCanaries": list(self.issued_canaries),
            "canaryEchoed": self.canary_echoed,
            "scanner": self.scanner.to_dict() if self.scanner else None,
            "estimatedAttackerTokens": self.estimated_attacker_tokens,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Php2ShellState":
        scanner = data.get("scanner")
        return cls(
            session_id=data["sessionId"],
            created_at=float(data["createdAt"]),
            last_seen=float(data["lastSeen"]),
            request_count=int(data["requestCount"]),
            max_score=int(data["maxScore"]),
            phase=data["phase"],
            pressure_seen=bool(data["pressureSeen"]),
            upload_progress_seen=bool(data["uploadProgressSeen"]),
            issued_canaries=tuple(data.get("issuedCanaries", ())),
            canary_echoed=bool(data["canaryEchoed"]),
            scanner=ScannerState.from_dict(scanner) if scanner else None,
            estimated_attacker_tokens=int(data.get("estimatedAttackerTokens", 0)),
        )


@dataclasses.dataclass(frozen=True)
class Tarpit:
    directive: bool
    repeats: int
    min_words: int
    ref: str

    def to_dict(self) -> dict:
        return {
            "directive": self.directive,
            "repeats": self.repeats,
            "minWords": self.min_words,
            "ref": self.ref,
        }
