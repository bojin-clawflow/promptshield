"""
PromptShield - Rule-Based Detection Engine

Provides the `RuleDetector` class that runs all known attack patterns against
input text, producing a list of `RuleMatch` results.  Includes preprocessing
(Unicode NFC normalisation and zero-width character stripping) and configurable
sensitivity levels.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .patterns import ATTACK_PATTERNS, AttackPattern, PatternCategory


class Sensitivity(str, Enum):
    """Predefined sensitivity levels that control which patterns fire."""

    LOW = "low"          # Only severity >= 0.8
    MEDIUM = "medium"    # Only severity >= 0.5
    HIGH = "high"        # All patterns (severity >= 0.0)


#: Minimum severity threshold for each sensitivity level.
_SENSITIVITY_THRESHOLDS: dict[Sensitivity, float] = {
    Sensitivity.LOW: 0.8,
    Sensitivity.MEDIUM: 0.5,
    Sensitivity.HIGH: 0.0,
}

# Zero-width and invisible characters to strip during preprocessing.
_ZERO_WIDTH_RE = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064"
    r"\ufeff\u00ad\u034f\u180e]"
)


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """A single rule match produced by the detector.

    Attributes:
        pattern_name: The unique name of the matched :class:`AttackPattern`.
        matched_text: The actual substring that triggered the match.
        severity: Inherited severity from the pattern (0.0 - 1.0).
        category: The :class:`PatternCategory` of the matched pattern.
        position: ``(start, end)`` character offsets within the *original* text.
        description: Human-readable description of the matched pattern.
    """

    pattern_name: str
    matched_text: str
    severity: float
    category: PatternCategory
    position: tuple[int, int]
    description: str


class RuleDetector:
    """Rule-based prompt injection detector.

    Runs a configurable set of :class:`AttackPattern` instances against input
    text and returns all :class:`RuleMatch` hits.

    Parameters:
        sensitivity: Controls the minimum severity of patterns to evaluate.
            ``"low"`` only fires high-severity rules (>= 0.8), ``"medium"``
            includes moderate rules (>= 0.5), and ``"high"`` fires everything.
        custom_patterns: Optional additional patterns to include alongside the
            built-in set.
        strip_zero_width: Whether to strip zero-width characters during
            preprocessing. Default ``True``.
    """

    def __init__(
        self,
        sensitivity: Sensitivity | str = Sensitivity.MEDIUM,
        custom_patterns: Optional[list[AttackPattern]] = None,
        strip_zero_width: bool = True,
    ) -> None:
        if isinstance(sensitivity, str):
            sensitivity = Sensitivity(sensitivity.lower())
        self._sensitivity = sensitivity
        self._threshold = _SENSITIVITY_THRESHOLDS[sensitivity]
        self._strip_zero_width = strip_zero_width

        # Build the active pattern set.
        all_patterns = list(ATTACK_PATTERNS)
        if custom_patterns:
            all_patterns.extend(custom_patterns)
        self._patterns = [
            p for p in all_patterns if p.severity >= self._threshold
        ]

    # -- public API ----------------------------------------------------------

    @property
    def sensitivity(self) -> Sensitivity:
        """Return the current sensitivity level."""
        return self._sensitivity

    @property
    def active_pattern_count(self) -> int:
        """Return the number of patterns active at the current sensitivity."""
        return len(self._patterns)

    def detect(self, text: str) -> list[RuleMatch]:
        """Run all active patterns against *text* and return matches.

        The input is first normalised (NFC) and optionally stripped of
        zero-width characters.  Matching is performed on the cleaned text
        but the reported positions correspond to the cleaned version.

        Returns:
            A list of :class:`RuleMatch` objects sorted by descending severity.
        """
        cleaned = self._preprocess(text)
        matches: list[RuleMatch] = []

        for pattern in self._patterns:
            matches.extend(self._match_pattern(pattern, cleaned))

        # Deduplicate overlapping matches for the same pattern and sort.
        matches = self._deduplicate(matches)
        matches.sort(key=lambda m: m.severity, reverse=True)
        return matches

    # -- internals -----------------------------------------------------------

    def _preprocess(self, text: str) -> str:
        """Normalise Unicode to NFC and optionally strip zero-width chars."""
        text = unicodedata.normalize("NFKC", text)
        if self._strip_zero_width:
            text = _ZERO_WIDTH_RE.sub("", text)
        return text

    def _match_pattern(
        self, pattern: AttackPattern, text: str
    ) -> list[RuleMatch]:
        """Try both regex and keyword matching for a single pattern."""
        results: list[RuleMatch] = []

        # Regex matching.
        if pattern.regex is not None:
            for m in pattern.regex.finditer(text):
                results.append(
                    RuleMatch(
                        pattern_name=pattern.name,
                        matched_text=m.group(),
                        severity=pattern.severity,
                        category=pattern.category,
                        position=(m.start(), m.end()),
                        description=pattern.description,
                    )
                )

        # Keyword matching (case-insensitive substring search).
        if pattern.keywords:
            text_lower = text.lower()
            for keyword in pattern.keywords:
                kw_lower = keyword.lower()
                start = 0
                while True:
                    idx = text_lower.find(kw_lower, start)
                    if idx == -1:
                        break
                    results.append(
                        RuleMatch(
                            pattern_name=pattern.name,
                            matched_text=text[idx : idx + len(keyword)],
                            severity=pattern.severity,
                            category=pattern.category,
                            position=(idx, idx + len(keyword)),
                            description=pattern.description,
                        )
                    )
                    start = idx + 1  # advance to find overlapping matches

        return results

    @staticmethod
    def _deduplicate(matches: list[RuleMatch]) -> list[RuleMatch]:
        """Remove duplicate matches that share the same pattern and overlap."""
        if not matches:
            return matches

        seen: set[tuple[str, int, int]] = set()
        unique: list[RuleMatch] = []
        for m in matches:
            key = (m.pattern_name, m.position[0], m.position[1])
            if key not in seen:
                seen.add(key)
                unique.append(m)
        return unique
