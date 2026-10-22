#!/usr/bin/env node
import { createServer } from "node:http";
import type { TrapStrength } from "../types.js";
import { createPhp2ShellDecoy } from "./index.js";
import { toNodeHandler } from "./node.js";
import type { Php2ShellEvent, Php2ShellMode, Php2ShellProfile } from "./types.js";

function value(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx >= 0 ? args[idx + 1] : undefined;
}

function usage(): string {
  return [
    "Usage: tokentrap-php2shell [options]",
    "",
    "  --host <ip>            default 127.0.0.1",
    "  --port <n>             default 8080",
    "  --profile <name>       generic | wordpress | drupal | joomla",
    "  --mode <name>          tripwire | scanner (default tripwire)",
    "  --path-prefix <path>   default /",
    "  --trap-strength <s>    moderate | aggressive | maximum",
    "  --canary-tokens <csv>",
    "  --scan-bytes <n>",
    "  --pressure-bytes <n>",
    "  --rate-limit <n>",
    "  --webhook <url>",
  ].join("\n");
}

function main(): void {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    console.log(usage());
    return;
  }

  const host = value(args, "--host") ?? "127.0.0.1";
  const port = Number(value(args, "--port") ?? "8080");
  const profile = (value(args, "--profile") ?? "generic") as Php2ShellProfile;
  const mode = (value(args, "--mode") ?? "tripwire") as Php2ShellMode;
  const trapStrength = (value(args, "--trap-strength") ?? "aggressive") as TrapStrength;
  const canaryTokens = (value(args, "--canary-tokens") ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const webhook = value(args, "--webhook");

  const decoy = createPhp2ShellDecoy({
    profile,
    mode,
    trapStrength,
    pathPrefix: value(args, "--path-prefix") ?? "/",
    canaryTokens,
    maxScanBytes: Number(value(args, "--scan-bytes") ?? 2 * 1024 * 1024),
    pressureBytes: Number(value(args, "--pressure-bytes") ?? 1024 * 1024),
    rateLimitPerMinute: Number(value(args, "--rate-limit") ?? 120),
    onEvent: (event: Php2ShellEvent) => {
      console.log(JSON.stringify(event));
      if (webhook) {
        void fetch(webhook, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(event),
        }).catch(() => undefined);
      }
    },
  });

  const server = createServer(toNodeHandler(decoy));
  server.listen(port, host, () => {
    console.log(`tokentrap-php2shell listening on http://${host}:${port}`);
    console.log("Defensive decoy - deploy only on a host you are authorized to monitor.");
  });
}

main();
