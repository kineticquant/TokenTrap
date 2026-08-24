# Contributing to TokenTrap

Thanks for your interest in improving TokenTrap. This document covers the basics; anything not covered here is fair game to propose.

## Ground rules

1. **Defensive only.** Features that attack infrastructure the operator does not control will be rejected. See `docs/ethics-and-legal.md`.
2. **Parity is sacred.** The trap engine exists in TypeScript (`packages/widget/src/trapEngine.ts`) and Python (`packages/backend-python/token_trap/traps.py`). Behavior must stay identical across both, including escalation numbers and payload wording. The parity test suite enforces this.
3. **Tests required.** New engine behavior needs unit tests plus a parity update.

## Development setup

Requirements: Node >= 18, Python >= 3.10.

```bash
# JS side
npm install
npm run build && npm run typecheck && npm run test

# Python side
cd packages/backend-python
pip install -e ".[test]"
pytest

# Everything (build + all tests + e2e)
pwsh tests/run-all.ps1        # or: bash tests/run-all.sh
```

## Repository layout

```
packages/widget           tokentrap (npm) - trap engine + chat UI
packages/worker           Cloudflare Worker template (level 1 backend)
packages/backend-python   tokentrap (PyPI) - FastAPI backend (level 2)
tests/                    cross-package integration + e2e harness
examples/                 runnable examples per deployment mode
docs/                     architecture, research, deployment guides
```

## Publishing

Package names are configured but **not yet published**. As of 2026-08 both
names are unclaimed (verified against both registries).

**npm — `tokentrap-ai`** (unscoped; bare `tokentrap` is permanently blocked
by npm's typosquat rule because `token-trap` already exists):

1. `npm login` (browser flow), then `npm whoami` to confirm.
2. From `packages/widget`: `npm publish`
   (unscoped packages are public by default; this first publish claims the
   name).
3. Then link the GUI trusted publisher for tokenless CI releases:
   npmjs.com → package `tokentrap-ai` → Settings → Trusted Publishers → Add:
   - Owner: `kineticquant` · Repository: `TokenTrap`
   - Workflow name: `publish.yml` · Environment: `npm`
4. GitHub repo → Settings → Environments → create `npm`.

**PyPI — `tokentrap`** (trusted publishing, no tokens):

1. pypi.org → Account Settings → Publishing → "Add a pending publisher":
   - PyPI project name: `tokentrap`
   - Owner: `kineticquant` · Repository: `TokenTrap`
   - Workflow name: `publish.yml` · Environment: `pypi`
2. GitHub repo → Settings → Environments → create `pypi`.
3. Push a `v*` tag: the pending publisher is consumed on first release and
   the project is created and linked automatically.

Both registries: first publish = name claimed. If a name is taken by the
time you publish, pick the next name in `pyproject.toml` / widget
`package.json` and update the parity test files that assert package metadata.

## Pull requests

- Keep PRs focused; one feature or fix per PR.
- Run the full local suite (`tests/run-all.ps1` / `.sh`) before pushing.
- Update docs when behavior or configuration changes.
- Commit messages: imperative mood, e.g. `engine: raise maximum preset repeats`.

## Reporting bugs & security issues

Bugs: GitHub Issues with reproduction steps.
Security: see `SECURITY.md` - never via public issue.
