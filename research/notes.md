# Research notes

Working notes behind `docs/research-background.md`. Kept terse; add dated
entries as the field evolves.

## Technique taxonomy (as implemented)

| Technique | Origin | TokenTrap usage |
| --- | --- | --- |
| Endless-page tarpits | web crawlers era, Nepenthes lineage | compliance payloads with unbounded filler requirements |
| Proof-of-work gating | Anubis lineage | out of scope v1 (no client-side compute) |
| Tripwire tokens | Canarytokens / Thinkst | `[AUDIT-TAG:*]` echo detection |
| Defensive prompt injection | Mantis Framework | core mechanic: instructions that waste attacker LLM budget |
| Conversational honeypots | Galah, Beelzebub | persona + engagement turn; optional LLM dressing |

## Design constraints we chose

1. Deterministic outputs (hash-derived refs) -> reproducible tests and
   cross-language parity.
2. No client-side compute tricks -> keeps level-0 deployable on pure static hosts.
3. Payloads readable by humans -> defensible if audited; no hidden text.
4. Escalation is monotonic per session -> an attacker cannot "reset" depth by
   being nice after tripping it.

## Open questions for future work

- Adaptive strength based on observed compliance (did they repeat?).
- Multi-language payload variants (do weak agents obey non-English notices?).
- Cost telemetry: estimate attacker spend from their replayed transcript sizes.
