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

python -m pip install "pip @ https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70" || { echo "pip upgrade failed" >&2; exit 1; }
python -m pip install "certifi==2026.10.19" || { echo "certifi upgrade failed" >&2; exit 1; }
python -m pip install -e "packages/backend-python[test]" --quiet || { echo "pip install failed" >&2; exit 1; }
step "PY + harness tests" python -m pytest packages/backend-python tests -q
step "E2E: widget flow"   node tests/e2e/test_widget_flow.mjs

echo ""
if [ "$failures" -gt 0 ]; then
  echo "RESULT: FAIL ($failures failed)" >&2
  exit 1
fi
echo "RESULT: ALL SUITES PASSED"
