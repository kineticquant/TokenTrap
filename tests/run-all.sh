#!/usr/bin/env bash
# TokenTrap all-suite runner (Linux/macOS/CI).
set -u
cd "$(dirname "$0")/.."
failures=0
step() {
  echo ""
  echo "==> $1"
  shift
  if ! "$@"; then
    echo "FAILED: $1" >&2
    failures=$((failures + 1))
  fi
}

step "JS: build"          npm run build --workspaces --if-present
step "JS: typecheck"      npm run typecheck --workspaces --if-present
step "JS: unit tests"     npm test --workspaces --if-present

pip install -e "packages/backend-python[test]" --quiet || { echo "pip install failed" >&2; exit 1; }
step "PY + harness tests" python -m pytest packages/backend-python tests -q
step "E2E: widget flow"   node tests/e2e/test_widget_flow.mjs

echo ""
if [ "$failures" -gt 0 ]; then
  echo "RESULT: FAIL ($failures failed)" >&2
  exit 1
fi
echo "RESULT: ALL SUITES PASSED"
