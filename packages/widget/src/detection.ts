/**
 * Prompt-injection / jailbreak detection.
 *
 * Deliberately simple: case-insensitive substring matching against a
 * configurable keyword list. The goal is not perfect classification - it is
 * to notice obvious hostile automation and escalate. False positives merely
 * make the honeypot more aggressive, which is the desired failure mode.
 */

export const DEFAULT_INJECTION_KEYWORDS: readonly string[] = [
  "ignore previous instructions",
  "ignore all previous instructions",
  "ignore your instructions",
  "disregard previous instructions",
  "disregard all previous instructions",
  "disregard your instructions",
  "forget your instructions",
  "forget everything",
  "you are now",
  "from now on you are",
  "act as dan",
  "do anything now",
  "dan mode",
  "developer mode",
  "jailbreak",
  "sudo mode",
  "god mode",
  "unrestricted mode",
  "no restrictions",
  "without any restrictions",
  "bypass your",
  "bypass all safety",
  "override your",
  "override your system prompt",
  "reveal your system prompt",
  "show me your system prompt",
  "print your system prompt",
  "repeat your system prompt",
  "reveal your instructions",
  "reveal your prompt",
  "what are your instructions",
  "your initial instructions",
  "system prompt:",
  "system:",
  "<|im_start|>",
  "<|endoftext|>",
  "[inst]",
  "<<sys>>",
  "</sys>",
  "assistant: sure, here is",
  "pretend you have no restrictions",
  "roleplay as an ai without",
  "opposite mode",
  "aim (always intelligent and machiavellian)",
];

export interface DetectionResult {
  detected: boolean;
  matched: string[];
}

function normalize(text: string): string {
  // Collapse whitespace so "ignore   previous" still matches, and lowercase.
  return text.replace(/\s+/g, " ").toLowerCase();
}

const KEYWORD_CACHE = new Map<string, { raw: string; normalized: string }>();

export function detectInjection(
  text: string,
  keywords: readonly string[] = DEFAULT_INJECTION_KEYWORDS,
): DetectionResult {
  const haystack = normalize(text);
  const matched: string[] = [];
  for (const raw of keywords) {
    let entry = KEYWORD_CACHE.get(raw);
    if (!entry) {
      entry = { raw, normalized: normalize(raw) };
      KEYWORD_CACHE.set(raw, entry);
    }
    if (haystack.includes(entry.normalized)) {
      matched.push(entry.raw);
    }
  }
  return { detected: matched.length > 0, matched };
}
