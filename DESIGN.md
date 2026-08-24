# Design System — TokenTrap

<!-- impeccable:design-schema 1 -->
Recorded from the built artifact (`OVERVIEW.html`, repo orientation page) and the
incumbent widget UI (`packages/widget/src/ui.ts`). Ground truth over
intention: values below are what ships.

## World

Ops-console dark, inherited from the shipped widget. The page reads as a
precisely typeset operations document on a terminal ground — information
density with editorial spacing, never marketing chrome. Amber is reserved
exclusively for legal/liability surfaces; green is the only action color.

## Palette

| Token | Value | Role |
| --- | --- | --- |
| `--bg` | `#0b0f14` | page ground |
| `--panel` | `#11161d` | raised surfaces, table headers, nav hover |
| `--panel-2` | `#0e1319` | code blocks, tree, diagram ground, bubbles |
| `--line` | `#1e2630` | all 1px borders and hairline section rules |
| `--text` | `#e6edf3` | primary text (≈15:1 on bg) |
| `--muted` | `#9aa7b4` | secondary text, hue-tinted (≈7:1) |
| `--dim` | `#7d8b99` | metadata, captions (≈5:1, small sizes only) |
| `--green` | `#4ade80` | action, emphasis, engine voice; ink `#06130a` |
| `--cyan` | `#22d3ee` | links, agent voice, JSON keys |
| `--amber` | `#fbbf24` | liability panel border/tint only |

Dark is chosen by scene: architects reading repo docs beside IDEs, often at
night. Never gray secondary text — always tinted from the palette hue.

## Typography

| Face | Use |
| --- | --- |
| Archivo (400/500/650/800) | display + body; display to 54px, tracking −0.03em, `text-wrap: balance` |
| Spline Sans Mono (400/500/600) | code, paths, numeric tables, policy refs — measurement only, never prose |

Body 16px/1.65, measure ≤70ch. Headings carry more space above than below
(scale: 72px above h2, 22px below). Captions and metadata are mono 12px.

## Layout & rhythm

Single column, max 1080px, gutters `clamp(20px, 4vw, 44px)`. Sections
separated by full-width 1px hairlines with 72px vertical padding. Two-column
`duo` grid (table + prose, table + table) collapses at 880px. Spacing scale:
4/8/14/22/40/72/120.

## Components

- **Console panel** (`.demo`): 12px radius, panel gradient, offset+blur shadow
  `0 18px 48px rgba(0,0,0,.42)`, terminal title bar with dot triplet.
- **Transcript turns**: 118px mono speaker rail (cyan `agent ▸` / green
  `tokentrap ▸`) + bordered bubble; collapses to stacked at 720px.
- **Spec tables**: full 1px borders, panel headers, zebra `rgba(17,22,29,.5)`,
  right-aligned tabular mono numerals in content-hugging columns, mono
  captions `TABLE N:`; wrapped in `.scrollx` (min-width 460px) on small screens.
- **Architecture diagram**: inline SVG, mono labels, green flow arrows,
  scroll-contained at min-width 760px.
- **Install chips**: mono command + drawn 15px copy icon button, aria-live
  status.
- **Liability panel**: 1px amber-tinted border, `rgba(251,191,36,.05)` fill —
  the only amber on the page.
- **Tree**: mono, `white-space: pre`, bold paths, dim italic annotations.

## Icons & marks

Drawn inline SVG only (trap glyph mark, 15px copy icon), 1.5–1.6px strokes.
No emoji, no icon fonts, no unicode-as-icon (arrows `↗`/`▸` in mono contexts
are terminal vocabulary, not icon substitutes).

## Motion

Exactly one authored moment: the hero transcript types in via staggered
`clip-path` reveals while tally counters ease up (cubic ease-out, 1100ms).
Guardrails: `prefers-reduced-motion` renders final states; counters never
paint a zero frame; a 3s failsafe force-clears reveals; counter failsafe
snaps final values if rAF stalls. Everything else is static.

## Voice

Product's own vocabulary, second person, numbers as arguments. Controls name
their action ("Copy npm install command"). Legal copy states scope plainly
and names the operator's responsibility. No hype, no irony.
