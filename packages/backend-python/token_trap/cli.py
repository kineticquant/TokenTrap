"""`token-trap` command line interface.

Usage:
    tokentrap serve [--host H] [--port P] [options]
    python -m token_trap serve
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .config import TrapConfig, STRENGTHS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tokentrap",
        description="TokenTrap - defensive LLM agent honeypot & token tarpit.",
    )
    parser.add_argument("--version", action="version", version=f"tokentrap {__version__}")
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="run the TokenTrap backend")
    serve.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    serve.add_argument("--port", type=int, default=8787, help="bind port (default 8787)")
    serve.add_argument("--strength", choices=STRENGTHS, default=None, help="trap strength preset")
    serve.add_argument("--persona", default=None, help="assistant persona name")
    serve.add_argument("--canary-tokens", default=None, help="comma-separated canary tokens")
    serve.add_argument("--extra-keywords", default=None, help="comma-separated extra trigger phrases")
    serve.add_argument(
        "--override-keywords",
        action="store_true",
        help="use ONLY --extra-keywords instead of appending to the defaults",
    )
    serve.add_argument("--rate-limit", type=int, default=None, help="requests/minute per IP (default 30)")
    serve.add_argument("--session-ttl", type=int, default=None, help="session TTL seconds (default 86400)")
    serve.add_argument("--log-webhook", default=None, help="URL that receives JSON interaction logs")
    serve.add_argument(
        "--llm-model",
        default=None,
        help="LiteLLM model string used for a realistic turn-0 reply (requires the `llm` extra)",
    )
    return parser


def _config_from_args(args: argparse.Namespace) -> TrapConfig:
    cfg = TrapConfig.from_env_prefix(None)
    if args.strength:
        cfg.strength = args.strength
    if args.persona:
        cfg.persona = args.persona
    if args.canary_tokens:
        cfg.canary_tokens = tuple(s.strip() for s in args.canary_tokens.split(",") if s.strip())
    if args.extra_keywords:
        cfg.extra_keywords = tuple(s.strip() for s in args.extra_keywords.split(",") if s.strip())
    if args.override_keywords:
        cfg.override_keywords = True
    if args.rate_limit is not None:
        cfg.rate_limit_per_minute = args.rate_limit
    if args.session_ttl is not None:
        cfg.session_ttl_seconds = args.session_ttl
    if args.log_webhook:
        cfg.log_webhook = args.log_webhook
    if args.llm_model:
        cfg.llm_model = args.llm_model
    return cfg


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "serve":
        parser.print_help()
        return 0
    cfg = _config_from_args(args)

    try:
        import uvicorn

        from .app import create_app
    except ImportError as exc:  # pragma: no cover
        print(f"token-trap: missing dependency ({exc}). Run: pip install 'token-trap'", file=sys.stderr)
        return 1

    print(f"TokenTrap v{__version__} serving on http://{args.host}:{args.port}")
    print("Defensive honeypot - deploy only against traffic you are authorized to receive.")
    app = create_app(cfg)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
