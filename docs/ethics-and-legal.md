# Ethics & legal notes

## Purpose

TokenTrap is a **defensive** tool. It protects resources you operate - your
sites, your APIs, your content - from automated abuse by making that abuse
expensive for the abuser. It is published to help defenders, researchers, and
the broader discussion about agentic crawling economics.

## What it does

- Serves plausible-but-wasteful responses to automated agents that request
  them.
- Instructs those agents, via defensive prompt injection, to spend their own
  tokens reproducing transcripts and generating filler.
- Logs interactions and detects replayed canary tokens.

## What it never does

- No outbound connections to the visitor/attacker.
- No malware, exploits, or fingerprinting beyond message text.
- No deception of humans; a human reading the output sees an obviously
  bureaucratic compliance notice.
- Nothing happens without the remote side initiating contact first.

## Intended use

- On infrastructure you own or are explicitly authorized to defend.
- With honest disclosure where third parties host content on your behalf
  (check your CDN/host's ToS; some platforms restrict honeypot content).
- As part of defense-in-depth (rate limiting, auth, robots policy), not as a
  substitute.

## Unintended use

Do not point TokenTrap at systems you do not control. Do not modify it to
deliver harmful instructions, exfiltrate data, or target specific people.
Those uses are outside the project's license grant in spirit; please report
such forks/misuses via SECURITY.md.

## Legal landscape (not legal advice)

Resource-wasting honeypots operate in roughly the same territory as
long-standing web tarpits: you are serving content to clients who requested
it. Considerations vary by jurisdiction - defamation-free content, no
entrapment-style luring of identifiable individuals, data-protection rules
for anything you log. If in doubt, get counsel before deploying publicly at
scale.

## No responsibility / no liability

TokenTrap is provided "as is", without warranty of any kind (see `LICENSE`).
To the maximum extent permitted by applicable law, the maintainers and
contributors accept **no responsibility and no liability** for:

- **Misuse** of the software, including any use outside the defensive scope
  described in this document;
- **Deployment decisions**, including where, how, and against whom the
  software is operated;
- **Legal compliance in any jurisdiction.** Laws on honeypots, deception,
  data logging, computer misuse, and automated traffic differ between - and
  within - countries, and change over time. The maintainers make no claim
  that TokenTrap is lawful or compliant in your jurisdiction; verifying that
  is entirely the operator's responsibility.

By deploying TokenTrap you accept these terms in full.
