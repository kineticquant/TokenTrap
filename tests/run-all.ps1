# TokenTrap all-suite runner (Windows / PowerShell 5.1+).
# Usage: pwsh -NoProfile -ExecutionPolicy Bypass -File tests/run-all.ps1

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$failures = New-Object System.Collections.Generic.List[string]
$sw = [System.Diagnostics.Stopwatch]::StartNew()

function Step($name, $scriptblock) {
  Write-Host ""
  Write-Host ("==> " + $name) -ForegroundColor Cyan
  & $scriptblock
  if ($LASTEXITCODE -ne 0) {
    Write-Host ("FAILED: " + $name) -ForegroundColor Red
    $script:failures.Add($name)
  }
}

Step "JS: build"             { npm run build --workspaces --if-present }
Step "JS: typecheck"         { npm run typecheck --workspaces --if-present }
Step "JS: unit tests"        { npm test --workspaces --if-present }
Step "PY: install package" {
  pip install -e "packages/backend-python[test]" --quiet
  if ($LASTEXITCODE -ne 0) { exit 1 }
}
Step "PY + harness tests"   { python -m pytest packages/backend-python tests -q }
Step "E2E: widget flow"     { node tests/e2e/test_widget_flow.mjs }

Write-Host ""
$sw.Stop()
if ($failures.Count -gt 0) {
  Write-Host ("RESULT: FAIL (" + $failures.Count + " failed): " + ($failures -join "; ")) -ForegroundColor Red
  exit 1
}
Write-Host "RESULT: ALL SUITES PASSED in" ([math]::Round($sw.Elapsed.TotalSeconds, 1)) "s" -ForegroundColor Green
exit 0
