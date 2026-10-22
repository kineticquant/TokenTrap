"""Pure PHP2Shell request detection.

This mirrors ``packages/widget/src/php2shell/detector.ts``. The shared fixture
suite in ``tests/fixtures/php2shell/cases.json`` is the cross-language contract.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional, Sequence, Tuple

from .signals import (
    CVE_TOKENS,
    PHASE_PRIORITY,
    PRESSURE_SIGNALS,
    PROFILE_PATHS,
    SIGNAL_WEIGHTS,
)
from .types import DetectionResult, MultipartSummary, Php2ShellState, RequestInfo

_BOUNDARY_RE = re.compile(r'boundary=(?:"([^"]+)"|([^;]+))', re.IGNORECASE)
_DISPOSITION_RE = re.compile(r"content-disposition\s*:", re.IGNORECASE)
_EMPTY_FILE_RE = re.compile(r'content-disposition:[^\r\n]*filename=""', re.IGNORECASE)
_FILE_RE = re.compile(r'content-disposition:[^\r\n]*filename="([^"]+)"', re.IGNORECASE)
_NAME_RE = re.compile(r'name="([^"]*)"', re.IGNORECASE)
_CMD_QUERY_RE = re.compile(r"(^|[?&;])(?:cmd|command|exec|shell|run)=", re.IGNORECASE)
_ID_QUERY_RE = re.compile(r"(^|[?&;])id(?:=|&|$)", re.IGNORECASE)
_BODY_CMD_RE = re.compile(r"\b(?:whoami|uname\s+-a|cat\s+/etc/passwd)\b", re.IGNORECASE)


def scan_multipart(body: str, content_type: str) -> MultipartSummary:
    is_multipart = "multipart/form-data" in content_type.lower()
    match = _BOUNDARY_RE.search(content_type)
    boundary = (match.group(1) or match.group(2) or "").strip() if match else None
    if not is_multipart or not boundary:
        return MultipartSummary(
            is_multipart=is_multipart,
            boundary=boundary,
            parts=0,
            empty_file_parts=0,
            file_parts=0,
            max_name_depth=0,
            has_upload_progress=False,
            closed=False,
        )

    parts = len(_DISPOSITION_RE.findall(body))
    empty_file_parts = len(_EMPTY_FILE_RE.findall(body))
    file_parts = len(_FILE_RE.findall(body))
    max_name_depth = 0
    for name in _NAME_RE.findall(body):
        max_name_depth = max(max_name_depth, name.count("["))

    return MultipartSummary(
        is_multipart=is_multipart,
        boundary=boundary,
        parts=parts,
        empty_file_parts=empty_file_parts,
        file_parts=file_parts,
        max_name_depth=max_name_depth,
        has_upload_progress="php_session_upload_progress" in body.lower(),
        closed=f"--{boundary}--" in body,
    )


def _get(prior, key: str, default=None):
    if prior is None:
        return default
    if isinstance(prior, dict):
        return prior.get(key, default)
    return getattr(prior, key, default)


def _cookie_value(cookie_header: str, name: str) -> str:
    for part in cookie_header.split(";"):
        idx = part.find("=")
        if idx == -1:
            continue
        if part[:idx].strip() == name:
            return part[idx + 1 :].strip()
    return ""


def _has_command_probe(request: RequestInfo) -> bool:
    query = request.query.lower()
    body = request.body_prefix.lower()
    if _CMD_QUERY_RE.search(query):
        return True
    if _ID_QUERY_RE.search(query):
        return True
    if request.multipart.is_multipart:
        return False
    return bool(_BODY_CMD_RE.search(body))


def _tier_for(score: int) -> str:
    if score >= 85:
        return "active_chain"
    if score >= 60:
        return "likely"
    if score >= 30:
        return "suspicious"
    return "observe"


def _later_phase(current: str, candidate: str) -> str:
    return candidate if PHASE_PRIORITY[candidate] > PHASE_PRIORITY[current] else current


def detect_php2shell(
    request: RequestInfo,
    prior: Optional[Php2ShellState],
    profile: str,
    pressure_bytes: int,
    canaries: Sequence[str],
) -> DetectionResult:
    mp = request.multipart
    signals = []
    seen = set()

    def add(signal: str) -> None:
        if signal not in seen:
            seen.add(signal)
            signals.append(signal)

    if mp.is_multipart and mp.has_upload_progress:
        add("upload_progress_field")
    if mp.is_multipart and mp.empty_file_parts >= 4:
        add("many_empty_file_parts")
    if mp.is_multipart and mp.max_name_depth >= 3:
        add("nested_field_names")
    if mp.is_multipart and request.content_length is None:
        add("lengthless_multipart")
    if mp.is_multipart and (
        request.body_bytes >= pressure_bytes or (request.content_length or 0) >= pressure_bytes
    ):
        add("oversized_multipart")

    prior_pressure = bool(
        _get(prior, "pressureSeen", False)
        or _get(prior, "pressure_seen", False)
        or _get(prior, "phase") in {"pressure", "stale_reuse", "post_exploit"}
    )
    if prior_pressure and mp.is_multipart and mp.has_upload_progress and mp.file_parts == 0:
        add("fileless_after_pressure")

    php_sess = _cookie_value(request.headers.get("cookie", ""), "PHPSESSID")
    if len(php_sess) >= 200 or (len(php_sess) >= 100 and "%" in php_sess):
        add("session_cookie_anomaly")

    full_path = f"{request.path}?{request.query}" if request.query else request.path
    if any(full_path.startswith(p) or p in full_path for p in PROFILE_PATHS.get(profile, ())):
        add("cms_recon_path")

    haystack = " ".join([full_path, request.body_prefix, *request.headers.values()]).lower()
    if any(token in haystack for token in CVE_TOKENS):
        add("cve_reference")
    if _has_command_probe(request):
        add("command_probe")

    issued = tuple(_get(prior, "issuedCanaries", ()) or _get(prior, "issued_canaries", ()) or ())
    canary_pool = tuple(value for value in (*issued, *canaries) if value)
    canary_echo = any(canary.lower() in haystack for canary in canary_pool)
    if canary_echo:
        add("canary_echo")

    score = 0
    for signal in signals:
        weight = SIGNAL_WEIGHTS[signal]
        if signal == "many_empty_file_parts":
            weight = min(40, 20 + 5 * max(0, mp.empty_file_parts - 4))
        elif signal == "nested_field_names":
            weight = min(35, 20 + 5 * max(0, mp.max_name_depth - 3))
        score += weight
    score = min(100, score)

    phase = _get(prior, "phase", "recon") or "recon"
    if any(signal in PRESSURE_SIGNALS for signal in signals):
        phase = _later_phase(phase, "pressure")
    if "fileless_after_pressure" in seen:
        phase = _later_phase(phase, "stale_reuse")
    if "command_probe" in seen or "canary_echo" in seen:
        phase = "post_exploit"

    if "command_probe" in seen or "canary_echo" in seen:
        response_phase = "post_exploit"
    elif "fileless_after_pressure" in seen:
        response_phase = "stale_reuse"
    elif any(signal in PRESSURE_SIGNALS for signal in signals):
        response_phase = "pressure"
    else:
        response_phase = "recon"

    return DetectionResult(
        signals=tuple(signals),
        score=score,
        tier=_tier_for(score),
        phase=phase,
        response_phase=response_phase,
        canary_echo=canary_echo,
    )
