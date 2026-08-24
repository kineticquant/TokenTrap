# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Static HTML/CSS, single self-contained file (`OVERVIEW.html`) at repo root - the
user's explicit request ("generate a static html in project root"). No build
step, no framework.

## Users

Primary: software architects and developers evaluating or onboarding into the
TokenTrap repository (the user's explicit correction: "this is NOT a landing
page - it's a static repo page for architects and developers"). They arrive
from GitHub, want a fast, precise rundown of what the utility does, why it
exists, how it behaves, and how to deploy it. Secondary: security researchers
scanning for mechanism details and test/parity guarantees.

## Product Purpose

TokenTrap is a defensive honeypot & token tarpit for hostile LLM agents: it
serves plausible assistant surfaces whose responses embed escalating
compliance obligations (verbatim transcript repetition x2-x16, structured
filler up to ~25k words), wasting the attacker agent's token budget while
generating reconnaissance logs. Success means an evaluator understands the
mechanism, trust level, and deployment path within minutes.

## Positioning

Deterrence through cost rather than censorship: the same engine runs
client-side, on Cloudflare Workers, or as a FastAPI backend, selected by one
config value, with byte-identical escalation behavior enforced by TS<->PY
parity tests. Neighboring honeypots cannot truthfully claim that parity
guarantee.

## Operating Context

Read as a repo-root artifact on GitHub or any static host; often alongside an
IDE (dark ambient light). Relative links into `docs/`, `examples/`,
`packages/` must keep working when served from the repository root.

## Capabilities and Constraints

- Three deployment levels (static / edge worker / Python backend), one
  `apiEndpoint` value apart.
- Escalation presets: moderate/aggressive/maximum; injection keywords (44
  defaults); deterministic TR-###### references; canary tokens with echo
  detection.
- Constraint: single HTML file, inline CSS/JS, no framework, offline-friendly
  (system fallback fonts acceptable beyond two sourced families).

## Brand Commitments

Visual direction pinned by the user: **terminal dark**, consistent with the
shipped widget UI (#0b0f14 ground, #11161d panels, #4ade80/#22d3ee accents,
system-sans base). Explicitly NOT a marketing landing page: information
density and precision over persuasion.

## Evidence on Hand

README.md (motivation, quick starts, packages table); docs/how-the-trap-works.md
(escalation ladder, preset tables); docs/architecture.md (levels, wire
contract); docs/ethics-and-legal.md (scope, no-liability text);
packages/widget/src/ui.ts (incumbent palette). All page copy derives from
these; no testimonials, metrics, or customer claims may be invented.

## Product Principles

1. Mechanism first: show the trap working, never describe it vaguely.
2. Numbers are the argument: preset tables, parity counts, bundle size.
3. Honest scope: defensive-only framing and the no-liability disclaimer are
   part of the interface, not footnotes.

## Accessibility & Inclusion

Body contrast >= 4.5:1 on dark ground; secondary text tinted from palette hues,
never pure gray. Full keyboard focus visibility; `prefers-reduced-motion`
honored for the hero reveal. Semantic landmarks and heading order.
