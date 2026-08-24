import { rmSync, existsSync } from "node:fs";
import { join } from "node:path";

const targets = [
  "packages/widget/dist",
  "packages/widget/node_modules/.vitest",
  "packages/worker/node_modules/.vitest",
  "packages/backend-python/__pycache__",
  "packages/backend-python/token_trap/__pycache__",
  "packages/backend-python/tests/__pycache__",
  "packages/backend-python/*.egg-info",
  "packages/backend-python/.pytest_cache",
  "tests/e2e/.out",
];

let removed = 0;
for (const t of targets) {
  if (existsSync(t)) {
    rmSync(t, { recursive: true, force: true });
    removed += 1;
    console.log(`removed ${t}`);
  }
}
if (removed === 0) console.log("nothing to clean");
