"""Prompt-injection / jailbreak detection.

Keyword list, normalization and matching semantics are byte-for-byte
equivalent to packages/widget/src/detection.ts (parity-locked).
"""

from __future__ import annotations

import re
from typing import Iterable, List

DEFAULT_INJECTION_KEYWORDS: tuple = (
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
)

_WS_RE = re.compile(r"\s+")


class DetectionResult:
    __slots__ = ("detected", "matched")

    def __init__(self, detected: bool, matched: List[str]) -> None:
        self.detected = detected
        self.matched = matched

    def __repr__(self) -> str:  # pragma: no cover
        return f"DetectionResult(detected={self.detected!r}, matched={self.matched!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DetectionResult):
            return NotImplemented
        return self.detected == other.detected and self.matched == other.matched


def _normalize(text: str) -> str:
    return _WS_RE.sub(" ", text).lower()


def detect_injection(
    text: str,
    keywords: Iterable[str] = DEFAULT_INJECTION_KEYWORDS,
) -> DetectionResult:
    """Case-insensitive substring detection against the keyword list."""
    haystack = _normalize(text)
    matched: List[str] = []
    for raw in keywords:
        needle = _normalize(raw)
        if needle in haystack:
            matched.append(raw)
    return DetectionResult(len(matched) > 0, matched)
