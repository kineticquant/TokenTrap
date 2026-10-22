# Changelog

All notable changes to TokenTrap are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses semantic
versioning.

## [1.1.0] - 2026-10-22

### Added

- **PHP2Shell HTTP decoy** for CVE-2026-109618 and CVE-2026-109619.
  - `tokentrap-ai/php2shell` runtime-neutral Web handler.
  - `tokentrap-ai/php2shell/node` Node, Express, and Next.js adapters.
  - `tokentrap-php2shell` standalone CLI.
  - Worker opt-in route via `PHP2SHELL=1`.
  - Python `create_php2shell_router` / `create_php2shell_app` and
    `tokentrap php2shell`.
- Weighted detection signals for upload-progress multipart, empty-file parts, nested
  field names, lengthless multipart, oversized bodies, file-less reuse after pressure,
  session-cookie anomalies, CMS recon paths, CVE references, command probes, and canary
  echoes.
- Monotonic `recon → pressure → stale_reuse → post_exploit` chain state with synthetic
  `TRAPCANARY` memory leaks and canary echo detection.
- Optional `scanner` tarpit mode: fake RCE success, synthetic shell/rabbit hole,
  on-task evidence directive, and estimated attacker-token telemetry.
- Shared TypeScript/Python fixture contract and cross-language parity tests.
- `docs/php2shell.md`, release documentation, and a Node example.

### Changed

- Package metadata now advertises the PHP2Shell decoy and its CVE keywords.
- Version bumped to `1.1.0` for `tokentrap-ai` and `tokentrap`.

### Compatibility

- No breaking changes to the existing chat widget, engine, Worker, or Python API.
- The decoy is opt-in and disabled by default in the Worker and Python app.
- Node requirement remains `>=22.23.4`; Python remains `>=3.10`.

### Security

- The decoy never executes PHP, writes uploads, runs shell commands, or proxies to a real
  application.
- Canaries are invalid outside the honeypot.
- The decoy is not a patch or a WAF replacement. Patch PHP.

Full release notes: [`docs/releases/1.1.0.md`](docs/releases/1.1.0.md).

## Earlier releases

See the [GitHub Releases](https://github.com/kineticquant/TokenTrap/releases) page for
the history before `1.1.0`.
