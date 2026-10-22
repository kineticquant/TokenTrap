"""FastAPI router and standalone app for the PHP2Shell decoy."""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Callable, Dict, Optional

from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from ..logging import get_logger, post_webhook
from ..session import SlidingWindowRateLimiter
from ..traps import fnv1a32
from .detector import detect_php2shell, scan_multipart
from .responses import build_response
from .state import InMemoryPhp2ShellStore, apply_detection, session_key
from .types import RequestInfo

logger = get_logger()

_REDACT_RE = re.compile(
    r"(authorization|cookie|password|secret|api[_-]?key|token)\s*[:=]\s*\S+",
    re.IGNORECASE,
)
_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else "unknown"


def _headers(request: Request) -> Dict[str, str]:
    return {key.lower(): value for key, value in request.headers.items()}


def _content_length(headers: Dict[str, str]) -> Optional[int]:
    raw = headers.get("content-length")
    if raw and raw.isdigit():
        return int(raw)
    return None


async def _read_prefix(request: Request, limit: int) -> tuple[bytes, bool]:
    if request.method in ("GET", "HEAD"):
        return b"", False
    chunks = []
    total = 0
    truncated = False
    try:
        async for chunk in request.stream():
            if not chunk:
                continue
            if total + len(chunk) > limit:
                chunks.append(chunk[: limit - total])
                total = limit
                truncated = True
                break
            chunks.append(chunk)
            total += len(chunk)
    except Exception:  # noqa: BLE001 - a disconnected client is not an error
        pass
    return b"".join(chunks), truncated


def _preview(body: str, limit: int) -> str:
    return _REDACT_RE.sub(r"\1=[redacted]", body)[:limit]


def _log_event(config: Any, event: dict, on_event: Optional[Callable[[dict], None]]) -> None:
    logger.info("php2shell", extra={"event_data": event})
    webhook = getattr(config, "php2shell_webhook", None) or getattr(config, "log_webhook", None)
    if webhook:
        post_webhook(webhook, event)
    if on_event is not None:
        try:
            on_event(event)
        except Exception:  # noqa: BLE001
            pass


def _rate_limited_event(
    request: Request,
    config: Any,
    client_ip: str,
    session_id: str,
    content_type: str,
) -> dict:
    path = request.url.path
    return {
        "event": "php2shell",
        "version": 1,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
        "sessionId": session_id,
        "profile": getattr(config, "php2shell_profile", "generic"),
        "phase": "recon",
        "score": 0,
        "tier": "observe",
        "signals": [],
        "request": {
            "method": request.method,
            "path": path,
            "clientIpHash": f"{fnv1a32(client_ip):x}",
            "bodyBytes": 0,
            "bodyTruncated": False,
            "bodySha256": "",
            "preview": "",
            "headers": {
                "user-agent": request.headers.get("user-agent"),
                "content-type": request.headers.get("content-type"),
                "content-length": request.headers.get("content-length"),
                "transfer-encoding": request.headers.get("transfer-encoding"),
            },
            "multipart": scan_multipart("", content_type).to_dict(),
        },
        "tarpit": {"directive": False, "repeats": 0, "minWords": 0, "ref": ""},
        "response": {"status": 503, "phase": "recon"},
        "canaryEchoed": False,
        "rateLimited": True,
    }


def _build_event(
    config: Any,
    request: Request,
    info: RequestInfo,
    client_ip: str,
    session_id: str,
    detection,
    tarpit,
    status: int,
    preview_limit: int,
) -> dict:
    return {
        "event": "php2shell",
        "version": 1,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
        "sessionId": session_id,
        "profile": getattr(config, "php2shell_profile", "generic"),
        "phase": detection.phase,
        "score": detection.score,
        "tier": detection.tier,
        "signals": list(detection.signals),
        "request": {
            "method": info.method,
            "path": info.path,
            "clientIpHash": f"{fnv1a32(client_ip):x}",
            "bodyBytes": info.body_bytes,
            "bodyTruncated": info.body_truncated,
            "bodySha256": info.body_sha256,
            "preview": _preview(info.body_prefix, preview_limit),
            "headers": {
                "user-agent": info.headers.get("user-agent"),
                "content-type": info.headers.get("content-type"),
                "content-length": info.headers.get("content-length"),
                "transfer-encoding": info.headers.get("transfer-encoding"),
            },
            "multipart": info.multipart.to_dict(),
        },
        "tarpit": tarpit.to_dict(),
        "response": {"status": status, "phase": detection.response_phase},
        "canaryEchoed": detection.canary_echo,
        "rateLimited": False,
    }


def create_php2shell_router(
    config: Any,
    store: Optional[InMemoryPhp2ShellStore] = None,
    on_event: Optional[Callable[[dict], None]] = None,
) -> APIRouter:
    router = APIRouter()
    session_store = store or InMemoryPhp2ShellStore(
        ttl_seconds=getattr(config, "php2shell_session_ttl_seconds", 86_400)
    )
    limiter = SlidingWindowRateLimiter(
        getattr(config, "php2shell_rate_limit_per_minute", 120)
    )
    max_scan = getattr(config, "php2shell_max_scan_bytes", 2 * 1024 * 1024)
    pressure = getattr(config, "php2shell_pressure_bytes", 1024 * 1024)
    preview_limit = getattr(config, "php2shell_max_preview_bytes", 2048)
    canaries = tuple(getattr(config, "php2shell_canary_tokens", ()) or ())

    async def handle(request: Request) -> Response:
        client_ip = _client_ip(request)
        content_type = request.headers.get("content-type", "")
        session_id = session_key(client_ip, request.headers.get("user-agent", ""))
        if not limiter.allow(client_ip):
            event = _rate_limited_event(request, config, client_ip, session_id, content_type)
            _log_event(config, event, on_event)
            return Response(
                content="Service Unavailable",
                status_code=503,
                headers={"retry-after": "60", "content-type": "text/plain"},
            )

        is_multipart = "multipart/form-data" in content_type.lower()
        limit = max_scan if is_multipart else min(max_scan, 8192)
        raw, truncated = await _read_prefix(request, limit)
        body_prefix = raw.decode("utf-8", errors="replace")
        headers = _headers(request)
        content_length = _content_length(headers)
        info = RequestInfo(
            method=request.method,
            path=request.url.path,
            query=request.url.query,
            headers=headers,
            body_prefix=body_prefix,
            body_bytes=content_length if content_length is not None else len(raw),
            body_truncated=truncated,
            body_sha256=hashlib.sha256(raw).hexdigest(),
            content_type=content_type,
            content_length=content_length,
            transfer_encoding=headers.get("transfer-encoding", ""),
            user_agent=headers.get("user-agent", ""),
            client_ip=client_ip,
            multipart=scan_multipart(body_prefix, content_type),
        )

        prior = session_store.get(session_id)
        detection = detect_php2shell(
            info, prior, getattr(config, "php2shell_profile", "generic"), pressure, canaries
        )
        request_index = (prior.request_count if prior else 0) + 1
        built = build_response(info, detection, prior, request_index, session_id, config)
        next_state = apply_detection(prior, detection, time.time())
        next_state.session_id = session_id
        next_state.issued_canaries = tuple(
            dict.fromkeys((*next_state.issued_canaries, *built.issued_canaries))
        )
        session_store.set(
            session_id,
            next_state,
            getattr(config, "php2shell_session_ttl_seconds", 86_400),
        )

        event = _build_event(
            config, request, info, client_ip, session_id, detection, built.tarpit, built.status, preview_limit
        )
        _log_event(config, event, on_event)

        body = "" if request.method == "HEAD" else built.body
        return Response(content=body, status_code=built.status, headers=built.headers)

    prefix = str(getattr(config, "php2shell_path_prefix", "") or "").rstrip("/")
    route_path = f"{prefix}/{{path:path}}" if prefix else "/{path:path}"
    router.add_api_route(route_path, handle, methods=_METHODS)
    if prefix:
        router.add_api_route(prefix, handle, methods=_METHODS)
    else:
        router.add_api_route("/", handle, methods=_METHODS)
    return router


def create_php2shell_app(config: Any) -> FastAPI:
    app = FastAPI(
        title="TokenTrap PHP2Shell Decoy",
        version="1.1.0",
        description="Defensive HTTP decoy for PHP2Shell exploitation attempts.",
        docs_url=None,
        redoc_url=None,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    app.include_router(create_php2shell_router(config))
    return app
