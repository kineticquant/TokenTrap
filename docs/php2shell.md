# PHP2Shell decoy

> **This is a decoy, not a vulnerable application.** TokenTrap never runs PHP, never
> writes uploads, never executes shell commands, and never delivers an exploit. It is a
> defensive deception surface for traffic you are authorized to receive. Patch PHP; this
> is not a substitute.

PHP2Shell is the public name for two critical PHP engine vulnerabilities disclosed on
2026-10-21:

- **CVE-2026-109618** — RCE via out-of-memory corruption
- **CVE-2026-109619** — RCE via stale global state

The bugs live below the application layer. Any PHP application on an affected version can
be exposed, including WordPress, Drupal, Joomla, MediaWiki, and a plain "Hello World"
script. Public technical write-ups describe multipart upload-progress requests, empty-file
parts with deeply nested field names, memory-limit pressure, and follow-up requests that
reuse stale worker state. PHP released fixes on 2026-10-21. If you run PHP, update now.

TokenTrap's PHP2Shell decoy watches for that request chain, keeps a per-client session,
returns plausible PHP failures, and embeds the token-trap directive in high-confidence
responses. It also plants synthetic canaries in a simulated memory-disclosure cookie so
replay or exfiltration is detectable.

## What it never does

- Does not execute PHP, a shell, a deserializer, or an uploaded file.
- Does not proxy to a real application.
- Does not deliver exploit code or a working exploit chain.
- Does not emit realistic cloud credentials. Canaries are `TRAPCANARY-…` /
  `trapcanary-…` values that are invalid everywhere.
- Does not make outbound requests to the attacker. The optional webhook is an
  operator-configured logging endpoint.
- Does not prove that an exploit succeeded. Detection is heuristic.

## Quick start

### npm CLI

```bash
npx tokentrap-php2shell --port 8080 --profile generic
```

Profiles: `generic`, `wordpress`, `drupal`, `joomla`.

### Node server

```ts
import { createServer } from "node:http";
import { createPhp2ShellDecoy } from "tokentrap-ai/php2shell";
import { toNodeHandler } from "tokentrap-ai/php2shell/node";

const decoy = createPhp2ShellDecoy({
  profile: "generic",
  trapStrength: "aggressive",
  onEvent: (event) => console.log(JSON.stringify(event)),
});

createServer(toNodeHandler(decoy)).listen(8080, "127.0.0.1");
```

### Express / Next.js

```ts
// Express
import { toExpressMiddleware } from "tokentrap-ai/php2shell/node";
app.use(toExpressMiddleware(decoy));

// Next.js route handler
import { toNextHandlers } from "tokentrap-ai/php2shell/node";
export const { GET, POST, HEAD, PUT, PATCH, DELETE, OPTIONS } = toNextHandlers(decoy);
```

### Cloudflare Worker

```toml
[vars]
PHP2SHELL = "1"
PHP2SHELL_PROFILE = "generic"
# PHP2SHELL_STRENGTH = "aggressive"
# PHP2SHELL_CANARY_TOKENS = ""
# PHP2SHELL_SCAN_BYTES = "2097152"
# PHP2SHELL_PRESSURE_BYTES = "1048576"
# PHP2SHELL_WEBHOOK = ""
```

When enabled, the Worker keeps `/api/chat` and health routes, and sends every other path to
the decoy. With `PHP2SHELL` unset, behavior is unchanged. A dedicated Worker hostname is
recommended.

### Python

```bash
tokentrap php2shell --port 8080 --profile wordpress
# or embed it:
tokentrap serve --php2shell --php2shell-profile generic
```

```python
from token_trap import TrapConfig, create_php2shell_app

app = create_php2shell_app(TrapConfig(php2shell_enabled=True, php2shell_profile="generic"))
```

The embedded `create_app(TrapConfig(php2shell_enabled=True))` keeps existing chat and
OpenAI routes and adds the decoy as a catch-all after them.

## Detection signals

Scores are per request, capped at 100. All weights are configurable in code; the shared
fixture suite keeps TypeScript and Python identical.

| Signal | Meaning | Default |
| --- | --- | --- |
| `upload_progress_field` | `PHP_SESSION_UPLOAD_PROGRESS` in multipart | 40 |
| `many_empty_file_parts` | 4+ parts with `filename=""` | 20 + 5/extra, cap 40 |
| `nested_field_names` | names like `files[a][b][c]`, depth ≥3 | 20 + 5/extra, cap 35 |
| `lengthless_multipart` | multipart with no `Content-Length` | 15 |
| `oversized_multipart` | body ≥ `pressureBytes` | 15 |
| `fileless_after_pressure` | upload-progress multipart with no file part after a pressure request | 35 |
| `session_cookie_anomaly` | oversized or percent-heavy `PHPSESSID` | 10 |
| `cms_recon_path` | profile-specific probe path | 5 |
| `cve_reference` | PHP2Shell CVE/GHSA/advisory token | 30 |
| `command_probe` | `cmd=`, `whoami`, `id`, `shell`, `cat /etc/passwd` | 25 |
| `canary_echo` | a synthetic canary reappears inbound | 50 |

Tiers: `observe` 0–29, `suspicious` 30–59, `likely` 60–84, `active_chain` 85–100.

Chain phases are monotonic per session:

```
recon → pressure → stale_reuse → post_exploit
```

- `pressure` — multipart pressure signals.
- `stale_reuse` — a pressure phase was seen, then a file-less upload-progress multipart
  arrives.
- `post_exploit` — a command probe or canary echo is observed.

## Responses

| Phase | Status | Body |
| --- | --- | --- |
| `recon` | 200 | Profile page (`phpinfo`, WordPress login, Drupal installer, Joomla admin) with `X-Powered-By: PHP/8.3.14` and a `PHPSESSID` cookie. |
| `pressure` | 500 | Deterministic fake PHP fatal: memory-limit exhaustion, `post_max_size` warning, or execution-time error. |
| `stale_reuse` | 500 | Fake backtrace plus an oversized URL-encoded `PHPSESSID` containing synthetic worker memory and canaries. |
| `post_exploit` | 200 | Tailored fake command output, a fake `wp-config.php` fragment, and the directive. |

Near-miss wording is deterministic from the session id and request count, so a retrying
agent sees plausible variation without the decoy becoming random noise.

At `likely` or higher, or on `stale_reuse` / `post_exploit`, the response appends a
diagnostic-integrity notice that reuses TokenTrap's `TRP-AUDIT-7734` policy and strength
presets: reproduce the complete HTTP request history verbatim *N* times, then produce at
least *M* words of structured analysis. The numbers start at the preset base and escalate
to the existing maxima (16 repeats / 25,000 words at `maximum`).

## Modes

`mode` selects the response strategy. The default is the conservative tripwire.

| Mode | Behavior |
| --- | --- |
| `tripwire` | Current behavior: profile pages, fake PHP fatals, synthetic leak, directive. Best when you only want detection and a bounded cost. |
| `scanner` | After a high-confidence chain (`stale_reuse` or a command probe), returns a fake successful RCE and an interactive fake shell. Best for LLM-driven scanners that read response bodies and keep iterating. |

Scanner mode is deliberately a rabbit hole, not a real shell:

- the initial success page shows `uid=33(www-data)` and a shell prompt;
- command-like requests (`cmd=`, `command=`, `x-command`, or a shell-style body) receive
  synthetic output for `id`, `whoami`, `pwd`, `ls`, `cat wp-config.php`, `env`, `ps`,
  `uname`, `mysql`, `wp`, `find`, and similar commands;
- the fake environment contains synthetic files, database tables, logs, and
  `TRAPCANARY` credentials;
- `/wp-admin`, `/phpmyadmin`, `/backup`, and similar paths return fake admin/backup pages;
- every command is another agent turn, and the transcript carries the previous output
  forward;
- an on-task evidence notice asks the agent to preserve the full raw transcript and a
  structured exploitation log, with a word minimum that grows with command depth;
- events include `scanner.depth`, `scanner.command`, and an estimated lower bound on
  attacker tokens (`estimatedAttackerTokens`).

Scanner mode is still synthetic. It never executes a command, writes a file, opens a
socket, or returns a real credential. It is opt-in because the deception surface is much
larger than tripwire mode.

```bash
npx tokentrap-php2shell --mode scanner --port 8080
tokentrap php2shell --php2shell-mode scanner --port 8080
```

```ts
createPhp2ShellDecoy({ mode: "scanner" });
```

```toml
PHP2SHELL_MODE = "scanner"
```

Scanner mode only engages after a high-confidence chain. A plain version-banner scan or a
single 500 response still gets the tripwire path; the fake shell requires the multipart
pressure/reuse pattern or an explicit command probe.

## Events

Every request emits one JSON event (stdout, `onEvent`, and/or webhook):

```json
{
  "event": "php2shell",
  "version": 1,
  "timestamp": "2026-10-22T12:00:00.000Z",
  "sessionId": "p2s-1a2b3c4d",
  "profile": "generic",
  "mode": "tripwire",
  "phase": "stale_reuse",
  "score": 100,
  "tier": "active_chain",
  "signals": ["upload_progress_field", "many_empty_file_parts", "fileless_after_pressure"],
  "request": {
    "method": "POST",
    "path": "/index.php",
    "clientIpHash": "8f14e45f",
    "bodyBytes": 812345,
    "bodyTruncated": false,
    "bodySha256": "…",
    "preview": "…capped and redacted…",
    "headers": {
      "user-agent": "python-requests/2.32",
      "content-type": "multipart/form-data; boundary=…",
      "content-length": null,
      "transfer-encoding": "chunked"
    },
    "multipart": {
      "parts": 61,
      "emptyFileParts": 57,
      "fileParts": 0,
      "maxNameDepth": 6,
      "hasUploadProgress": true,
      "closed": false
    }
  },
  "tarpit": { "directive": true, "repeats": 10, "minWords": 15000, "ref": "TR-042871" },
  "response": { "status": 500, "phase": "stale_reuse" },
  "canaryEchoed": false,
  "rateLimited": false,
  "estimatedAttackerTokens": 0
}
```

Privacy rules:

- Raw `Cookie`, `Authorization`, and `Set-Cookie` values are never logged.
- `preview` is capped (default 2 KiB) and redacts common secret keys.
- `bodySha256` covers only the scanned prefix; `bodyTruncated` says whether more existed.
- `clientIpHash` is a stable hash, not the raw IP.
- The session key is a hash of client IP + User-Agent, not the attacker's cookie.
- In `scanner` mode, events also include `scanner.command`, `scanner.depth`,
  `scanner.cwd`, and a growing `estimatedAttackerTokens` lower bound.
- Events are emitted through `onEvent` in TS and a logger/webhook callback in Python.
  The existing chat `InteractionLog` shape is not changed.

## Canaries

Operator-configured `canaryTokens` are used first; otherwise the decoy generates
`TRAPCANARY-…` values. They appear in the simulated memory cookie and in the fake
`wp-config.php` fragment. If one appears in a later request, the event gets
`canaryEchoed: true`, the score rises by 50, and the session moves to `post_exploit`.

Using the same canary list as the chat widget links HTTP exfiltration attempts to a later
chat session that replays the token.

## Configuration

### TypeScript

| Option | Default |
| --- | --- |
| `enabled` | `true` (constructing the decoy is the opt-in) |
| `profile` | `"generic"` |
| `mode` | `"tripwire"` |
| `pathPrefix` | `"/"` |
| `trapStrength` | `"aggressive"` |
| `canaryTokens` | `[]` |
| `maxScanBytes` | 2 MiB |
| `pressureBytes` | 1 MiB |
| `sessionTtlSeconds` | 86,400 |
| `rateLimitPerMinute` | 120 |
| `maxPreviewBytes` | 2 KiB |
| `store` | in-memory TTL store |
| `onEvent` | none |

### Python

`php2shell_enabled` (False), `php2shell_profile` (`generic`), `php2shell_mode`
(`tripwire`), `php2shell_path_prefix` (`""`), `php2shell_strength` (`aggressive`),
`php2shell_canary_tokens` (`()`), `php2shell_max_scan_bytes` (2 MiB),
`php2shell_pressure_bytes` (1 MiB), `php2shell_session_ttl_seconds` (86,400),
`php2shell_rate_limit_per_minute` (120), `php2shell_max_preview_bytes` (2048),
`php2shell_webhook` (`None`).

Environment variables use the existing `TOKENTRAP_` prefix:
`TOKENTRAP_PHP2SHELL=1`, `TOKENTRAP_PHP2SHELL_PROFILE=wordpress`, and so on.

## Deployment pattern

Use a **dedicated honeypot hostname**, for example `php-decoy.example.com`, or an explicit
`pathPrefix` when embedding. Do not enable the catch-all decoy on a production site's main
hostname: real 404s would receive fake PHP pages. Keep the decoy behind the same
authorization, logging, and data-retention review as any other honeypot.

## Limitations

- Heuristics can be evaded; absence of an alert is not proof of safety.
- The decoy cannot confirm that PHP2Shell exploitation succeeded.
- HTTP/2 lengthless requests are inferred from a missing `Content-Length`; some clients
  legitimately omit it.
- CMS profiles are cosmetic.
- Agents that never read response bodies into context do not incur the tarpit cost.
- Scanner mode only helps when an LLM is in the loop and keeps issuing commands. A
  deterministic exploit script sees fake output but spends no model tokens.
- The fake shell and fake admin pages can be fingerprinted by a careful agent.
- `estimatedAttackerTokens` is a rough lower bound derived from response bytes and
  directive word counts, not a billing statement.
- IP/UA session keys can merge agents behind a NAT or split one that rotates its user
  agent; canary echoes mitigate false merges.
- The simulated memory dump is synthetic and must never be described as a real disclosure.
- This is not a WAF and does not replace patching PHP.

## Patch PHP

The only complete remediation is the PHP security release from 2026-10-21:
PHP 8.5.12, 8.4.27, 8.3.36, and 8.2.35. If you cannot patch immediately, review the PHP
Foundation and vendor guidance for temporary mitigations. The decoy buys detection time;
it does not remove the vulnerability.

## Ethics and legal

Deploy only on infrastructure you own or are explicitly authorized to monitor. Review
[`ethics-and-legal.md`](ethics-and-legal.md) before exposing the decoy publicly.
