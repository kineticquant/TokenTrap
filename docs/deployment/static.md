# Deployment: static / client-side (level 0)

Zero backend. The widget's built-in engine generates every trap response in
the visitor's browser.

## When to use

- Demos and research
- Low-stakes pages where you mainly want to burn scraper time
- Any host that serves HTML (Pages, GitHub Pages, S3, nginx)

## Steps

1. Get the bundle:
   - CDN: `https://unpkg.com/tokentrap-ai/dist/index.global.js`, or
   - local: `npm run build -w tokentrap-ai` then copy `packages/widget/dist/`.
2. Add to a page:

```html
<script src="token-trap.iife.js"></script>
<div id="trap"></div>
<script>
  TokenTrap.init({
    container: "#trap",
    persona: "Internal AI Assistant",
    trapStrength: "aggressive",
    onInteraction(log) { console.log(log); },
  });
</script>
```

3. Deploy. Done in under five minutes.

## Limits

- No server-side logs or persistence; `onInteraction` is your only hook.
- A hostile agent that ignores page content entirely sees nothing.

## Upgrade

Set one config value (`apiEndpoint`) and redeploy - see
[cloudflare-workers.md](cloudflare-workers.md).
