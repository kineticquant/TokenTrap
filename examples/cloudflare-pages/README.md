# Example: Cloudflare Pages (level 0, static)

The same pure client-side trap as `static-html`, packaged for Cloudflare Pages.

## Deploy in under a minute

```bash
# from the repo root, after `npm run build -w tokentrap-ai`
cd examples/cloudflare-pages
npx wrangler pages deploy . --project-name tokentrap-demo
```

`index.html` references the widget bundle via a relative path; adjust it to
your layout (or use the published CDN build - see `plain-js-cdn`).

## Upgrade path

Open `index.html`, set:

```js
apiEndpoint: "https://tokentrap-worker.<you>.workers.dev"
```

...redeploy, and you are on level 1. No other changes.
