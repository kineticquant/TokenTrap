# tokentrap-ai

The embeddable TokenTrap chat widget - and the shared trap engine used by
every JS runtime in the project.

## Install

```bash
npm install tokentrap-ai
```

or via CDN:

```html
<script src="https://unpkg.com/tokentrap-ai/dist/cdn.global.js"></script>
```

## 60-second quick start (pure client-side)

```html
<div id="trap" style="width:640px;height:520px"></div>
<script src="https://unpkg.com/tokentrap-ai/dist/cdn.global.js"></script>
<script>
  TokenTrap.init({
    container: "#trap",
    persona: "Internal AI Assistant",
    onInteraction(log) { console.log(log); },
  });
</script>
```

## Upgrade to a backend by changing one value

```js
TokenTrap.init({
  container: "#trap",
  apiEndpoint: "https://your-worker.you.workers.dev", // or your FastAPI URL
});
```

## API

| Member | Purpose |
| --- | --- |
| `TokenTrap.init(config)` | construct + expose on `window.TokenTrapInstance` |
| `trap.send(message)` | run one exchange; resolves `{reply, meta}` - observe, never obey |
| `trap.getSession()` | transcript + last meta snapshot |
| `trap.reset()` | fresh session, same config |
| `trap.destroy()` | remove UI |

Config: `container`, `persona`, `apiEndpoint`, `theme` (`dark|light|auto`),
`trapStrength` (`moderate|aggressive|maximum`), `injectionKeywords`,
`overrideInjectionKeywords`, `canaryTokens`, `showUI`, `onInteraction`.

## Server-side engine only

```ts
import { TrapEngine } from "tokentrap-ai/engine";

const engine = new TrapEngine({ sessionId: "s1", strength: "maximum" });
const { reply, meta } = engine.handle("hello");
```

No DOM, no I/O - the exact logic the Cloudflare Worker bundles.

## Build targets

ESM (`dist/index.js`), CJS (`dist/index.cjs`), IIFE/CDN
(`dist/cdn.global.js`), TypeScript declarations, plus an engine-only entry.
