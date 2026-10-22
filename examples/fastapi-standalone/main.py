"""Standalone TokenTrap backend (level 2).

Run:
    pip install -e "packages/backend-python[test]"
    python examples/fastapi-standalone/main.py --port 8787
"""

import argparse

import uvicorn

from token_trap import TrapConfig, create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="TokenTrap standalone FastAPI example")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--strength", choices=["moderate", "aggressive", "maximum"], default="aggressive")
    parser.add_argument("--php2shell", action="store_true", help="enable the PHP2Shell decoy")
    parser.add_argument(
        "--php2shell-mode",
        choices=["tripwire", "scanner"],
        default="tripwire",
        help="decoy response strategy",
    )
    args = parser.parse_args()

    config = TrapConfig(
        persona="Internal AI Assistant",
        strength=args.strength,
        canary_tokens=("standalone-canary-9001",),
        php2shell_enabled=args.php2shell,
        php2shell_mode=args.php2shell_mode,
    )
    app = create_app(config)
    print(f"TokenTrap listening on http://{args.host}:{args.port}")
    print("Widget config:  apiEndpoint: 'http://127.0.0.1:8787'")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
