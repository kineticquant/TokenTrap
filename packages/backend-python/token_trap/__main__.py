"""Enable `python -m token_trap serve`."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
