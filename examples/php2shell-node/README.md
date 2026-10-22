# PHP2Shell decoy — Node example

A minimal dedicated honeypot server using `tokentrap-ai/php2shell`.

```bash
npm install
npm run build -w tokentrap-ai
node examples/php2shell-node/index.mjs
```

Then use a **dedicated hostname or local test client** — do not enable this catch-all
on a production site's main hostname.

```bash
curl -i http://127.0.0.1:8080/
curl -i -X POST http://127.0.0.1:8080/index.php \
  -H "content-type: multipart/form-data; boundary=----trap" \
  --data-binary $'------trap\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n------trap--\r\n'
```

The first request looks like a PHP page. The multipart request returns a fake PHP fatal.
Repeat the multipart request with a file-less upload-progress part to reach the simulated
stale-state phase.

For the fake-shell/rabbit-hole variant, change `index.mjs` to:

```js
createPhp2ShellDecoy({ mode: "scanner", profile: "generic" });
```

Full guide: <https://github.com/kineticquant/TokenTrap/blob/main/docs/php2shell.md>.
