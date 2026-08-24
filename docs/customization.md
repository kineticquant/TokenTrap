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
