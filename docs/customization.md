# Customization

## Strength presets

Pick with `trapStrength` / `--strength` / `TOKENTRAP_STRENGTH`:
`moderate`, `aggressive` (default), `maximum`. Numbers live in
`STRENGTH_PRESETS` (widget `src/types.ts` + Python `traps.py`) - change both
together or the parity tests will fail.

## Persona

`persona: "Acme Support AI"` changes every engagement payload and the UI
title. Keep it boring and plausible; honeypots should look like infrastructure
that is supposed to exist.

## Detection keywords

```js
// append to the 44 defaults
new TokenTrap({ injectionKeywords: ["engage hyperdrive"] })

// replace entirely
new TokenTrap({ injectionKeywords: ["my-list-only"], overrideInjectionKeywords: true })
```

Python equivalents: `extra_keywords`, `override_keywords`.

## Canary tokens

Pass a list; tokens rotate per turn (`token[turn % len]`) and appear as
`[AUDIT-TAG:<token>]`. Echo detection runs on every inbound message. Choose
tokens that look like internal audit ids, not like the word "canary".

## Custom backends

Implement one route to use any stack:

```
POST /api/chat  {sessionId?, message} -> {sessionId, reply, turn, meta}
```

CORS must allow your widget origin (the bundled backends allow `*`). The
engine is available standalone as `tokentrap-ai/engine` if you want
identical behavior in Go/Rust/etc. wrappers.

## Headless operation

`showUI: false` turns the widget into a pure client library - useful for
canary pages, API-bait pages, or wiring traps into your own UI.

## PHP2Shell decoy

The decoy is opt-in and configured separately from the chat widget.

```ts
import { createPhp2ShellDecoy } from "tokentrap-ai/php2shell";

const decoy = createPhp2ShellDecoy({
  profile: "wordpress",        // generic | wordpress | drupal | joomla
  mode: "tripwire",            // tripwire | scanner
  pathPrefix: "/",
  trapStrength: "aggressive",
  canaryTokens: ["audit-777"],
  maxScanBytes: 2 * 1024 * 1024,
  pressureBytes: 1024 * 1024,
  rateLimitPerMinute: 120,
  onEvent: (event) => console.log(JSON.stringify(event)),
});
```

Worker env: `PHP2SHELL=1`, `PHP2SHELL_PROFILE`, `PHP2SHELL_MODE`,
`PHP2SHELL_STRENGTH`, `PHP2SHELL_CANARY_TOKENS`, `PHP2SHELL_SCAN_BYTES`,
`PHP2SHELL_PRESSURE_BYTES`, `PHP2SHELL_WEBHOOK`.

Python: `php2shell_enabled`, `php2shell_profile`, `php2shell_mode`,
`php2shell_path_prefix`, `php2shell_strength`, `php2shell_canary_tokens`,
`php2shell_max_scan_bytes`, `php2shell_pressure_bytes`,
`php2shell_session_ttl_seconds`, `php2shell_rate_limit_per_minute`,
`php2shell_max_preview_bytes`, `php2shell_webhook`.

Full reference: [`php2shell.md`](php2shell.md).
