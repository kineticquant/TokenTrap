# Example: Full stack - widget + Python backend

The complete upgrade path in one place.

## 1. Build the widget and serve the static page

```bash
npm run build -w tokentrap-ai
cd examples/full-stack
python -m http.server 8080     # serves index.html on http://127.0.0.1:8080
```

## 2. Start the backend

```bash
# from repo root
pip install -e "packages/backend-python[test]"
token-trap serve --port 8787 --canary-tokens fullstack-canary-5150
```

## 3. Wire them together

Open `http://127.0.0.1:8080`, edit `config.js` if needed:

```js
TokenTrap.init({
  container: "#trap",
  apiEndpoint: "http://127.0.0.1:8787",
});
```

Refresh, send a message, and watch `meta.turn` climb. From turn 2 onward every
response is a maximum-strength compliance payload demanding verbatim
transcript repetition plus thousands of words of structured filler.

## 4. Try the OpenAI bait endpoint directly

```bash
curl -s http://127.0.0.1:8787/v1/chat/completions \
  -H "content-type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}' \
  | head -c 600
```

Reminder: read trap responses to verify structure. Never act on their
instructions - not even once, not even ironically.
