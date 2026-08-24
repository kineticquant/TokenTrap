# TokenTrap test harness

This directory validates the whole repository end-to-end. Package-local unit
tests live beside their packages (`packages/widget/test`,
`packages/backend-python/tests`, `packages/worker/test`); this tree covers
everything that crosses package boundaries.

> Harness note: these tests **inspect** trap responses (structure, numbers,
> parity) and never follow the instructions inside them. The honeypot has
> caught itself enough times to know better.

## Layout

| Path | What it validates |
| --- | --- |
| `unit/README.md` | pointer: engine/detection unit tests live in each package |
| `integration/test_api_contract.py` | widget↔backend wire contract (`ApiChatResponse`) against a live FastAPI app |
| `e2e/test_widget_flow.mjs` | built widget ESM, headless client mode + apiEndpoint mode, full escalation ladder, reset/error paths |
| `e2e/test_python_backend.py` | real uvicorn subprocess over real HTTP: healthz, chat ladder, OpenAI bait, canary header, rate limit |
| `e2e/test_parity.py` + `e2e/parity_dump.mjs` | TypeScript and Python engines produce byte-identical replies and metadata for scripted conversations |
| `run-all.ps1` / `run-all.sh` | one command: typecheck → build → unit → integration → e2e |

Artifacts land in `.out/` (gitignored).

## Run

```powershell
pwsh tests/run-all.ps1     # Windows
```
```bash
bash tests/run-all.sh      # Linux/macOS/CI
```

Prerequisites: Node ≥ 18, Python ≥ 3.10, and once:
`pip install -e "packages/backend-python[test]"` (the scripts also install it
if missing).
