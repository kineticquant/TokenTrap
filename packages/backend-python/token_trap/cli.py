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
    _add_php2shell_args(serve, enable_flag=True)

    decoy = sub.add_parser("php2shell", help="run a dedicated PHP2Shell HTTP decoy")
    decoy.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    decoy.add_argument("--port", type=int, default=8080, help="bind port (default 8080)")
    decoy.add_argument("--log-webhook", default=None, help="URL that receives JSON decoy events")
    _add_php2shell_args(decoy, enable_flag=False)
    return parser


def _add_php2shell_args(parser: argparse.ArgumentParser, *, enable_flag: bool) -> None:
    if enable_flag:
        parser.add_argument(
            "--php2shell",
            action="store_true",
            help="enable the PHP2Shell HTTP decoy on non-chat routes",
        )
    parser.add_argument(
        "--php2shell-profile",
        choices=("generic", "wordpress", "drupal", "joomla"),
        default=None,
        help="decoy identity (default generic)",
    )
    parser.add_argument("--php2shell-path-prefix", default=None, help="decoy path prefix")
    parser.add_argument(
        "--php2shell-strength", choices=STRENGTHS, default=None, help="tarpit strength for the decoy"
    )
    parser.add_argument("--php2shell-canary-tokens", default=None, help="comma-separated decoy canaries")
    parser.add_argument("--php2shell-scan-bytes", type=int, default=None, help="body inspection cap")
    parser.add_argument("--php2shell-pressure-bytes", type=int, default=None, help="OOM pressure threshold")
    parser.add_argument(
        "--php2shell-rate-limit", type=int, default=None, help="decoy requests/minute per IP"
    )
    parser.add_argument("--php2shell-webhook", default=None, help="URL that receives decoy events")


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
    if getattr(args, "php2shell", False):
        cfg.php2shell_enabled = True
    if getattr(args, "php2shell_profile", None):
        cfg.php2shell_profile = args.php2shell_profile
    if getattr(args, "php2shell_path_prefix", None) is not None:
        cfg.php2shell_path_prefix = args.php2shell_path_prefix
    if getattr(args, "php2shell_strength", None):
        cfg.php2shell_strength = args.php2shell_strength
    if getattr(args, "php2shell_canary_tokens", None):
        cfg.php2shell_canary_tokens = tuple(
            s.strip() for s in args.php2shell_canary_tokens.split(",") if s.strip()
        )
    if getattr(args, "php2shell_scan_bytes", None) is not None:
        cfg.php2shell_max_scan_bytes = args.php2shell_scan_bytes
    if getattr(args, "php2shell_pressure_bytes", None) is not None:
        cfg.php2shell_pressure_bytes = args.php2shell_pressure_bytes
    if getattr(args, "php2shell_rate_limit", None) is not None:
        cfg.php2shell_rate_limit_per_minute = args.php2shell_rate_limit
    if getattr(args, "php2shell_webhook", None):
        cfg.php2shell_webhook = args.php2shell_webhook
    return cfg


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command not in ("serve", "php2shell"):
        parser.print_help()
        return 0
    cfg = _config_from_args(args)
    if args.command == "php2shell":
        cfg.php2shell_enabled = True

    try:
        import uvicorn

        if args.command == "php2shell":
            from .php2shell.router import create_php2shell_app

            app = create_php2shell_app(cfg)
        else:
            from .app import create_app

            app = create_app(cfg)
    except ImportError as exc:  # pragma: no cover
        print(f"token-trap: missing dependency ({exc}). Run: pip install 'token-trap'", file=sys.stderr)
        return 1

    print(f"TokenTrap v{__version__} serving on http://{args.host}:{args.port}")
    print("Defensive honeypot - deploy only against traffic you are authorized to receive.")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
