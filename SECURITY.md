# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.x     | yes       |

## Reporting a vulnerability

**Do not open a public issue for security reports.**

Email the maintainers via the address listed on the repository's `Settings -> Security` contact, or open a [private vulnerability report](../../security/advisories/new). Include:

- Affected package(s) (tokentrap-ai, `tokentrap` PyPI, worker template)
- Steps to reproduce / proof of concept
- Impact assessment

You will receive an acknowledgment within 72 hours. We aim to release fixes within 14 days for high-severity issues.

## Scope notes

TokenTrap is a **defensive honeypot**. Reports about "the traps are too aggressive" or "an attacker LLM wasted its own tokens" are, by design, not vulnerabilities.

If you discover that TokenTrap can be trivially repurposed as an *offensive* tool (e.g. attacking infrastructure the operator does not control), please report it — hardening against misuse is explicitly in scope.
