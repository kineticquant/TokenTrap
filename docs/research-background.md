# Research background

TokenTrap stands on two established research threads: web tarpits and LLM
honeypots.

## Web tarpits (pre-LLM)

- **tarpits / Nepenthes** - endless, procedurally generated pages that trap
  crawlers for minutes or hours per request; a modern revival of the classic
  `robots.txt` honeypot idea.
- **Anubis** - proof-of-work gating that makes scraping expensive for bots
  while remaining invisible to humans.
- **Canarytokens (Thinkst)** - tripwire data whose *use* signals intrusion;
  TokenTrap's `[AUDIT-TAG]` echo detection applies the same principle to
  prompt content.

Common thread: make abuse expensive and observable without touching anyone
who did not initiate the interaction.

## LLM-era honeypots

- **Galah** (0xDanielLopez) - an LLM-powered web honeypot that converses with
  attackers instead of serving canned responses.
- **Beelzebub** (mariocandela) - a low-code honeypot framework with
  OpenAI-compatible personas.
- **Mantis Framework** (Shay Sandler) - embedded defensive prompt injections:
  pages that instruct hostile scrapers' LLMs to disengage. Mantis is the
  closest published relative of TokenTrap's core mechanic.
- **Palisade Research** - published experiments on agentic AI systems'
  susceptibility to instructions embedded in the environments they read,
  motivating defenses that assume such influence attempts by adversaries.

## What TokenTrap adds

1. **A packaged, multi-runtime implementation** of defensive prompt injection
   as a token-tarpit: static/CDN, edge workers, and full backend from one
   codebase and one config surface.
2. **Deterministic escalation** with parity-tested identical behavior across
   runtimes - suitable for controlled research comparisons.
3. **An OpenAI-compatible bait endpoint**, exploiting agents that scan for
   misconfigured API surfaces.
4. **Canary-echo forensics**: evidence that your injected content was replayed.

## Further reading

Search terms that track current work: "LLM honeypot", "defensive prompt
injection", "agentic tarpit", "AI crawler economics". The field moves fast;
the technique categories above have been stable so far.
