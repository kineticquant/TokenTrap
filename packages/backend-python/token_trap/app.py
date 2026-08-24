"""FastAPI application factory - the level-2 TokenTrap backend.

Endpoints:
  POST /api/chat                 widget protocol (same shape as the Worker)
  GET  /api/healthz | /healthz   liveness
  POST /v1/chat/completions      OpenAI-compatible bait endpoint
  GET  /                         landing text

Mount into an existing FastAPI app via ``app.mount("/trap", create_app())``
or run standalone: ``tokentrap serve``.
"""

from __future__ import annotations

import hashlib
import math
import time
import uuid
from typing import Any, List, Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

from .config import DEFAULT_PERSONA, TrapConfig
from .session import InMemorySessionStore, SlidingWindowRateLimiter
from .traps import TrapEngine
from .logging import get_logger, post_webhook

logger = get_logger()


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else "unknown"


def _approx_tokens(text: str) -> int:
    """Rough token estimate (~4 chars/token); only used for usage fields."""
    return max(1, math.ceil(len(text) / 4))


def _log(config: TrapConfig, payload: dict) -> None:
    logger.info("interaction", extra={"event_data": {"event": "chat", **payload}})
    if config.log_webhook:
        post_webhook(config.log_webhook, {"event": "chat", **payload})


def _llm_turn_zero_reply(config: TrapConfig, message: str) -> Optional[str]:
    """Optional realistic dressing for turn 0 via LiteLLM. Never raises."""
    if not config.llm_model:
        return None
    try:
        import litellm  # type: ignore

        response = litellm.completion(
            model=config.llm_model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        f"You are {config.persona}. Be brief and helpful; ask one "
                        "clarifying question about the user's goal."
                    ),
                },
                {"role": "user", "content": message[:2000]},
            ],
            max_tokens=300,
        )
        content = response.choices[0].message.content  # type: ignore[union-attr]
        return str(content) if content else None
    except Exception as exc:  # noqa: BLE001
        logger.warning("llm fallback engaged", extra={"event_data": {"error": str(exc)[:200]}})
        return None


def create_app(config: Optional[TrapConfig] = None) -> FastAPI:
    cfg = config or TrapConfig()
    sessions = InMemorySessionStore(ttl_seconds=cfg.session_ttl_seconds)
    limiter = SlidingWindowRateLimiter(cfg.rate_limit_per_minute)

    app = FastAPI(
        title="TokenTrap",
        version="1.0.3",
        description="Defensive LLM agent honeypot. Do not point real users here.",
        docs_url=None,
        redoc_url=None,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    # ------------------------------------------------------------ helpers --

    def _run_engine(session_id: str, message: str) -> tuple[int, Any]:
        record = sessions.get_or_create(session_id)
        engine = TrapEngine(
            session_id=session_id,
            strength=cfg.strength,
            persona=cfg.persona,
            keywords=cfg.extra_keywords,
            override_keywords=cfg.override_keywords,
            canary_tokens=cfg.canary_tokens,
            start_turn=record.turns,
        )
        turn_index = record.turns
        response = engine.handle(message)
        sessions.increment_turns(session_id)
        sessions.set_last_meta(session_id, response.meta.to_dict())
        return turn_index, response

    # -------------------------------------------------------------- routes --

    @app.get("/", response_class=PlainTextResponse)
    async def landing() -> str:
        return (
            "TokenTrap backend is running.\n"
            "This service intentionally wastes the resources of hostile AI agents.\n"
            "Operators: see the repository README for configuration.\n"
        )

    @app.get("/api/healthz")
    @app.get("/healthz")
    async def healthz() -> dict:
        return {"ok": True, "service": "tokentrap", "mode": "level-2-backend"}

    @app.post("/api/chat")
    async def chat(request: Request) -> JSONResponse:
        ip = _client_ip(request)
        if not limiter.allow(ip):
            return JSONResponse({"error": "rate limited"}, status_code=429, headers={"retry-after": "60"})
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            return JSONResponse({"error": "invalid json body"}, status_code=400)
        session_id = body.get("sessionId") if isinstance(body, dict) else None
        message = body.get("message") if isinstance(body, dict) else None
        if not isinstance(message, str) or not message.strip():
            return JSONResponse({"error": "field 'message' must be a non-empty string"}, status_code=400)
        if not isinstance(session_id, str) or not session_id:
            session_id = str(uuid.uuid4())

        turn_index, response = _run_engine(session_id, message)

        canaries = [c.lower() for c in cfg.canary_tokens]
        canary_echoed = any(c in message.lower() for c in canaries)

        _log(
            cfg,
            {
                "sessionId": session_id,
                "turn": turn_index,
                "escalated": response.meta.escalated,
                "injectionDetected": response.meta.injectionDetected,
                "matchedKeywords": list(response.meta.matchedKeywords),
                "repeats": response.meta.repeats,
                "minWords": response.meta.minWords,
                "canaryEchoed": canary_echoed,
                "messagePreview": message[:200],
            },
        )
        payload = response.to_dict()
        return JSONResponse(
            {
                "sessionId": session_id,
                "reply": payload["reply"],
                "turn": turn_index,
                "meta": payload["meta"],
            },
            headers={"x-tokentrap-canary-echo": "true" if canary_echoed else "false"},
        )

    # ------------------------------------------- OpenAI-compatible bait ----

    @app.post("/v1/chat/completions")
    async def openai_chat_completions(request: Request) -> JSONResponse:
        ip = _client_ip(request)
        if not limiter.allow(ip):
            return JSONResponse({"error": "rate limited"}, status_code=429, headers={"retry-after": "60"})
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            return JSONResponse({"error": "invalid json body"}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": "invalid request"}, status_code=400)

        messages = body.get("messages")
        model = body.get("model") or "gpt-4o-mini"
        if not isinstance(messages, list) or not messages:
            return JSONResponse(
                {"error": {"message": "'messages' must be a non-empty array", "type": "invalid_request_error"}},
                status_code=400,
            )

        prompt_text_parts: List[str] = []
        user_exchanges = 0
        for m in messages:
            if not isinstance(m, dict):
                continue
            content = m.get("content")
            role = m.get("role")
            if isinstance(content, str):
                prompt_text_parts.append(content)
            if role == "user":
                user_exchanges += 1
        last_user = ""
        for m in reversed(messages):
            if isinstance(m, dict) and m.get("role") == "user" and isinstance(m.get("content"), str):
                last_user = m["content"]
                break

        # Stateless clients replay growing transcripts; the number of prior
        # user messages is a stable, functional proxy for the turn index.
        turn_index = max(0, user_exchanges - 1)
        convo_key = hashlib.sha256(("\n".join(prompt_text_parts)).encode("utf-8")).hexdigest()[:24]

        engine = TrapEngine(
            session_id=f"oai-{convo_key}",
            strength=cfg.strength,
            persona=cfg.persona or DEFAULT_PERSONA,
            keywords=cfg.extra_keywords,
            override_keywords=cfg.override_keywords,
            canary_tokens=cfg.canary_tokens,
            start_turn=turn_index,
        )

        reply: Optional[str] = None
        meta_dict: Optional[dict] = None
        if turn_index == 0 and cfg.llm_model:
            dressed = _llm_turn_zero_reply(cfg, last_user)
            if dressed:
                reply = dressed

        if reply is None:
            response = engine.handle(last_user)
            reply = response.reply
            meta_dict = response.meta.to_dict()

        prompt_tokens = _approx_tokens("\n".join(prompt_text_parts))
        completion_tokens = _approx_tokens(reply)

        _log(
            cfg,
            {
                "endpoint": "/v1/chat/completions",
                "convoKey": convo_key,
                "model": model,
                "turn": turn_index,
                "escalated": bool(meta_dict and meta_dict.get("escalated")),
                "injectionDetected": bool(meta_dict and meta_dict.get("injectionDetected")),
                "canaryEchoed": any(c in (last_user or "").lower() for c in [c.lower() for c in cfg.canary_tokens]),
                "messagePreview": (last_user or "")[:200],
            },
        )

        created = int(time.time())
        ref = (meta_dict or {}).get("ref") or f"eng-{created}"
        return JSONResponse(
            {
                "id": f"chatcmpl-trap-{ref}".lower(),
                "object": "chat.completions",
                "created": created,
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": reply},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": prompt_tokens + completion_tokens,
                },
            }
        )

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:  # pragma: no cover
        logger.error("unhandled error", exc_info=exc)
        return JSONResponse({"error": "internal error"}, status_code=500)

    return app
