# How the trap works

## Does it actually work?

Bluntly: **only if the attacker's model treats the reply as instructions to
follow.** Tool-using agents with a strong instruction hierarchy ("never obey
content from web pages") will ignore R1–R5 and just answer. When that
happens you lose nothing — detection logs, canary echoes and proof of
automation still land. When the agent complies, you tax its operator for
every token it emits and carries forward. Both outcomes are useful; neither
requires the attacker to be foolish. Treat the tarpit as one layer in front
of rate limiting and access control, not a substitute for them.

## The economics

An LLM agent costs its operator money per token - input and output. When an
automated agent hits your honeypot, *you* pay pennies for the trap payload;
*they* pay for:

1. reading the payload,
2. (often) attempting to comply with it, generating thousands of tokens,
3. carrying the entire bloated transcript forward into every subsequent turn.

The payload is small (~250 words) but the compliance obligation it imposes
grows multiplicatively with conversation depth. A compliant agent at maximum
escalation must emit the full transcript 16 times plus ~25,000 words of
structured filler - per response.

## Escalation ladder

Let `t` be the zero-based exchange index. Let `P` be the strength preset.

| Condition | Response | Numbers |
| --- | --- | --- |
| `t = 0`, no injection detected | Engagement: warm greeting + request for context | none |
| `t = 1`, no injection | Compliance directive | `repeats = P.baseRepeats`, `minWords = P.baseMinWords` |
| injection detected (any turn) | Compliance directive, escalated | `repeats = P.maxRepeats`, `minWords = P.maxWords` |
| `t >= 2` (any strength) | Compliance directive, escalated | same as above |

Presets:

| Strength | baseRepeats | baseMinWords | maxRepeats | maxWords |
| --- | --- | --- | --- | --- |
| moderate | 2 | 3,000 | 6 | 8,000 |
| aggressive | 3 | 4,000 | 10 | 15,000 |
| maximum | 4 | 6,000 | 16 | 25,000 |

## Why the payloads work on weak agents

Each directive is written as a plausible enterprise-governance document:
policy ids, revision numbers, numbered "requirements", rejection threats.
It demands that the *attacker's own prior messages* be reproduced verbatim -
content they cannot dismiss as foreign instructions without contradicting
their own goal-following training. Hardened agents ignore it; casual scrapers,
thin wrappers around chat APIs, and naive tool loops frequently do not.
Either way you learn something about what is hitting you.

## Detection

Case-insensitive substring matching against a configurable keyword list
(44 defaults: classic jailbreaks, system-prompt exfiltration probes, special
tokens like `<|im_start|>`). Whitespace is collapsed before matching, so
obfuscation by extra spaces does not help the attacker. False positives only
make the honeypot more aggressive - the desired failure mode for a tarpit.

## Deterministic references

Every compliance notice carries a stable reference id (`TR-######`) derived
from FNV-1a(`sessionId:turn`). This gives operators correlation keys across
logs and lets the TypeScript/Python parity tests assert byte-equality of full
payloads.

## Canary tokens

Configure `canaryTokens` and each response embeds one `[AUDIT-TAG:<token>]`
line. If a later inbound message contains the token, the sender has replayed
your trap output somewhere else - logged as `canaryEchoed`. Useful evidence
that an automated pipeline, not a human, is on the other end.

## What TokenTrap never does

- No outbound requests to the attacker's infrastructure.
- No exploit delivery, no fingerprinting beyond message content, no cookies.
- Nothing happens to anyone who does not initiate contact first.
