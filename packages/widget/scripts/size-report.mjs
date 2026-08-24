import { readdirSync, statSync, readFileSync } from "node:fs";
import { join } from "node:path";

const distDir = new URL("../dist/", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");

function walk(dir) {
  let out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out = out.concat(walk(p));
    else out.push(p);
  }
  return out;
}

let total = 0;
for (const file of walk(distDir)) {
  if (file.endsWith(".map")) continue;
  const bytes = statSync(file).size;
  const gz = (readFileSync(file).length / 4) | 0; // rough estimate only for .js text
  total += bytes;
  console.log(`${file.padEnd(50)} ${(bytes / 1024).toFixed(1)} KB`);
}
console.log("-".repeat(60));
console.log(`total (excl. sourcemaps): ${(total / 1024).toFixed(1)} KB`);
