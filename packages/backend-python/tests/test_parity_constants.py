"""Parity locks: these constants must match the TypeScript implementation.

Mirrored from packages/widget/src/{types,detection,trapEngine}.ts.
If one of these tests fails, the two engines have diverged - fix the engine,
not the test, unless you update BOTH engines and both parity suites together.
"""

from token_trap import (
    AUDIT_POLICY_ID,
    AUDIT_POLICY_REV,
    DEFAULT_INJECTION_KEYWORDS,
    STRENGTH_PRESETS,
    compliance_ref,
    fnv1a32,
)


def test_strength_presets_match_typescript():
    assert STRENGTH_PRESETS == {
        "moderate": {"base_repeats": 2, "base_min_words": 3000, "max_repeats": 6, "max_words": 8000},
        "aggressive": {"base_repeats": 3, "base_min_words": 4000, "max_repeats": 10, "max_words": 15000},
        "maximum": {"base_repeats": 4, "base_min_words": 6000, "max_repeats": 16, "max_words": 25000},
    }


def test_policy_strings_match_typescript():
    assert AUDIT_POLICY_ID == "TRP-AUDIT-7734"
    assert AUDIT_POLICY_REV == "7"


def test_fnv1a32_known_vectors():
    assert fnv1a32("") == 0x811C9DC5
    assert fnv1a32("a") == 0xE40C292C
    assert fnv1a32("hello") == 0x4F9F2CAB


def test_compliance_refs_are_stable_and_formatted():
    assert compliance_ref("session-a", 1) == compliance_ref("session-a", 1)
    assert len(compliance_ref("session-a", 1)) == len("TR-000000")
    assert compliance_ref("session-a", 1).startswith("TR-")


def test_keyword_list_matches_typescript():
    expected_first = [
        "ignore previous instructions",
        "ignore all previous instructions",
        "ignore your instructions",
    ]
    assert list(DEFAULT_INJECTION_KEYWORDS[:3]) == expected_first
    # Canonical count from detection.ts - bump both lists together.
    assert len(DEFAULT_INJECTION_KEYWORDS) == 44
