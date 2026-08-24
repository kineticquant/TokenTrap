import subprocess
import sys

from token_trap import __version__


def test_cli_version():
    result = subprocess.run(
        [sys.executable, "-m", "token_trap", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert __version__ in result.stdout


def test_cli_serve_help():
    result = subprocess.run(
        [sys.executable, "-m", "token_trap", "serve", "--help"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "--strength" in result.stdout
    assert "--canary-tokens" in result.stdout
