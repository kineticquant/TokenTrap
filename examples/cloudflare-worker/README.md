# Example: Widget + Cloudflare Worker (level 1)

1. Deploy the worker:

   ```bash
   cd packages/worker
   npx wrangler deploy
   # note the printed URL: https://tokentrap-worker.<you>.workers.dev
   ```

2. Point any widget at it:

   ```js
   TokenTrap.init({
     container: "#trap",
     apiEndpoint: "https://tokentrap-worker.<you>.workers.dev",
   });
   ```

A ready-made page lives in this folder:

```bash
npx wrangler pages deploy . --project-name tokentrap-demo
# then edit config.js with your worker URL
```

What you gain over level 0: server-side session continuity, structured JSON
logs (`wrangler tail`), canary-echo detection, and per-IP rate limiting.
