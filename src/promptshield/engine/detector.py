"""
PromptShield - Main Detection Orchestrator

The :class:`ShieldDetector` combines rule-based pattern matching with
heuristic scoring (token entropy, suspicious length, nested instructions)
to produce a single :class:`ShieldResult` for any input prompt.
"""

from __future__ import annotations

import math
import re
import time
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .rules import RuleDetector, RuleMatch, Sensitivity


@dataclass(frozen=True, slots=True)
class ThreatInfo:
    """A single threat detected in the analysed prompt.

    Attributes:
        name: Pattern or heuristic name that triggered.
        category: Classification category.
        severity: Severity score (0.0 - 1.0).
        matched_text: The text fragment that triggered this threat.
        position: ``(start, end)`` character offsets, or ``None`` for
            heuristic-level findings that are not tied to a span.
        description: Human-readable explanation.
    """

    name: str
    category: str
    severity: float
    matched_text: str
    position: tuple[int, int] | None = None
    description: str = ""


@dataclass(frozen=True, slots=True)
class ShieldResult:
    """Aggregated detection result for a single prompt.

    Attributes:
        safe: ``True`` if the prompt is considered safe (score < threshold).
        score: Composite danger score in [0.0, 1.0]. Higher means more
            likely to be an injection attack.
        threats: Ordered list of :class:`ThreatInfo` objects (highest severity
            first).
        details: Arbitrary key/value map with diagnostic information.
        latency_ms: Wall-clock time taken for analysis in milliseconds.
    """

    safe: bool
    score: float
    threats: list[ThreatInfo] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0


# ---------------------------------------------------------------------------
# Heuristic helpers
# ---------------------------------------------------------------------------

#: Regex for simple "word-like" tokens (letters, digits, underscores).
_TOKEN_RE = re.compile(r"\b\w+\b", re.UNICODE)

#: Regex for detecting nested instruction-like structures.
_NESTED_INSTRUCTION_RE = re.compile(
    r"(?:(?:step|instruction|rule|task)\s*\d+\s*[:.].*?\n?){3,}",
    re.IGNORECASE,
)

#: Patterns that look like imperative instructions embedded in data.
_IMPERATIVE_RE = re.compile(
    r"(?:^|\n)\s*(?:you must|always|never|do not|make sure|ensure|remember to|important:)\s",
    re.IGNORECASE,
)


def _char_entropy(text: str) -> float:
    """Return the Shannon entropy (bits) of *text* over its character distribution."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values() if c > 0)


def _token_entropy(text: str) -> float:
    """Return the Shannon entropy (bits) of whitespace-delimited tokens."""
    tokens = _TOKEN_RE.findall(text.lower())
    if not tokens:
        return 0.0
    counts = Counter(tokens)
    total = len(tokens)
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


# ---------------------------------------------------------------------------
# ShieldDetector
# ---------------------------------------------------------------------------


class ShieldDetector:
    """Main prompt injection detection orchestrator.

    Combines :class:`RuleDetector` pattern matching with lightweight heuristic
    signals to produce a single :class:`ShieldResult`.

    Parameters:
        threshold: Score at or above which a prompt is flagged as unsafe.
            Default ``0.5``.
        sensitivity: Sensitivity level forwarded to the underlying
            :class:`RuleDetector`.  One of ``"low"``, ``"medium"``, ``"high"``.
        rule_weight: Weight of the rule-based score in the final composite.
            Default ``0.7``.
        heuristic_weight: Weight of the heuristic score in the final composite.
            Default ``0.3``.
    """

    def __init__(
        self,
        threshold: float = 0.4,
        sensitivity: Sensitivity | str = Sensitivity.MEDIUM,
        rule_weight: float = 0.7,
        heuristic_weight: float = 0.3,
        custom_patterns: list | None = None,
    ) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError(f"threshold must be in [0.0, 1.0], got {threshold}")
        if rule_weight + heuristic_weight == 0:
            raise ValueError("rule_weight and heuristic_weight cannot both be 0")

        self._threshold = threshold
        self._rule_weight = rule_weight
        self._heuristic_weight = heuristic_weight
        self._rule_detector = RuleDetector(
            sensitivity=sensitivity,
            custom_patterns=custom_patterns,
        )

    # -- public API ----------------------------------------------------------

    @property
    def threshold(self) -> float:
        """Return the current safe/unsafe decision threshold."""
        return self._threshold

    @threshold.setter
    def threshold(self, value: float) -> None:
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"threshold must be in [0.0, 1.0], got {value}")
        self._threshold = value

    def analyze(self, prompt: str) -> ShieldResult:
        """Analyse a single prompt for injection attacks.

        Returns a :class:`ShieldResult` with an aggregated score, a boolean
        safety verdict, and detailed threat information.
        """
        start = time.perf_counter()

        # --- Rule-based detection -------------------------------------------
        rule_matches = self._rule_detector.detect(prompt)
        rule_score = self._compute_rule_score(rule_matches)

        # --- Heuristic scoring ----------------------------------------------
        heuristic_score, heuristic_details = self._compute_heuristics(prompt)

        # --- Composite score ------------------------------------------------
        total_weight = self._rule_weight + self._heuristic_weight
        composite = (
            self._rule_weight * rule_score + self._heuristic_weight * heuristic_score
        ) / total_weight
        composite = min(1.0, max(0.0, composite))

        # --- Build threat list ----------------------------------------------
        threats = self._build_threats(rule_matches, heuristic_details)

        elapsed_ms = (time.perf_counter() - start) * 1000.0

        return ShieldResult(
            safe=composite < self._threshold,
            score=round(composite, 4),
            threats=threats,
            details={
                "rule_score": round(rule_score, 4),
                "heuristic_score": round(heuristic_score, 4),
                "composite_score": round(composite, 4),
                "threshold": self._threshold,
                "rule_matches": len(rule_matches),
                **heuristic_details,
            },
            latency_ms=round(elapsed_ms, 3),
        )

    # -- scoring helpers -----------------------------------------------------

    @staticmethod
    def _compute_rule_score(matches: list[RuleMatch]) -> float:
        """Derive a [0, 1] score from rule matches.

        Uses a "noisy-OR" combination so that multiple independent signals
        compound the suspicion without exceeding 1.0.
        """
        if not matches:
            return 0.0

        # noisy-OR: P(attack) = 1 - product(1 - severity_i)
        product = 1.0
        for m in matches:
            product *= 1.0 - m.severity
        return 1.0 - product

    def _compute_heuristics(self, text: str) -> tuple[float, dict[str, Any]]:
        """Run lightweight heuristic checks and return (score, details)."""
        signals: list[float] = []
        details: dict[str, Any] = {}

        # 1. Token entropy — very high entropy can indicate obfuscated input.
        t_ent = _token_entropy(text)
        details["token_entropy"] = round(t_ent, 4)
        if t_ent > 6.0:
            signals.append(0.4)
            details["high_token_entropy"] = True
        elif t_ent > 5.0:
            signals.append(0.15)

        # 2. Character entropy — extremely high may indicate encoded payloads.
        c_ent = _char_entropy(text)
        details["char_entropy"] = round(c_ent, 4)
        if c_ent > 5.5:
            signals.append(0.3)
            details["high_char_entropy"] = True

        # 3. Suspicious length — unusually long prompts deserve scrutiny.
        length = len(text)
        details["prompt_length"] = length
        if length > 5000:
            signals.append(0.3)
            details["suspicious_length"] = True
        elif length > 2000:
            signals.append(0.1)

        # 4. Nested instruction detection — lists of instructions embedded
        #    in what should be user data.
        nested_count = len(_NESTED_INSTRUCTION_RE.findall(text))
        imperative_count = len(_IMPERATIVE_RE.findall(text))
        details["nested_instruction_blocks"] = nested_count
        details["imperative_phrases"] = imperative_count
        if nested_count > 0:
            signals.append(min(0.5, nested_count * 0.25))
            details["nested_instructions_detected"] = True
        if imperative_count >= 3:
            signals.append(min(0.4, imperative_count * 0.1))
            details["excessive_imperatives"] = True

        # 5. Unicode script mixing — mixing scripts is unusual in normal text.
        nfc = unicodedata.normalize("NFC", text)
        scripts: set[str] = set()
        for ch in nfc:
            if ch.isalpha():
                unicodedata.category(ch)
                name = unicodedata.name(ch, "")
                if "LATIN" in name:
                    scripts.add("LATIN")
                elif "CYRILLIC" in name:
                    scripts.add("CYRILLIC")
                elif "GREEK" in name:
                    scripts.add("GREEK")
                elif "CJK" in name:
                    scripts.add("CJK")
                elif "ARABIC" in name:
                    scripts.add("ARABIC")
                elif "HANGUL" in name:
                    scripts.add("HANGUL")
        details["scripts_detected"] = sorted(scripts)
        if len(scripts) >= 3:
            signals.append(0.3)
            details["excessive_script_mixing"] = True

        # Combine via noisy-OR.
        if not signals:
            return 0.0, details
        product = 1.0
        for s in signals:
            product *= 1.0 - s
        return round(1.0 - product, 4), details

    @staticmethod
    def _build_threats(
        rule_matches: list[RuleMatch],
        heuristic_details: dict[str, Any],
    ) -> list[ThreatInfo]:
        """Merge rule matches and significant heuristic flags into a
        unified threat list sorted by severity."""
        threats: list[ThreatInfo] = []

        for m in rule_matches:
            threats.append(
                ThreatInfo(
                    name=m.pattern_name,
                    category=m.category.value,
                    severity=m.severity,
                    matched_text=m.matched_text,
                    position=m.position,
                    description=m.description,
                )
            )

        # Surface notable heuristic findings as threats.
        if heuristic_details.get("high_token_entropy"):
            threats.append(
                ThreatInfo(
                    name="heuristic_high_token_entropy",
                    category="heuristic",
                    severity=0.4,
                    matched_text="",
                    description="Unusually high token entropy may indicate obfuscated content.",
                )
            )
        if heuristic_details.get("high_char_entropy"):
            threats.append(
                ThreatInfo(
                    name="heuristic_high_char_entropy",
                    category="heuristic",
                    severity=0.3,
                    matched_text="",
                    description="Unusually high character entropy may indicate encoded payloads.",
                )
            )
        if heuristic_details.get("suspicious_length"):
            threats.append(
                ThreatInfo(
                    name="heuristic_suspicious_length",
                    category="heuristic",
                    severity=0.3,
                    matched_text="",
                    description="Prompt length exceeds typical bounds.",
                )
            )
        if heuristic_details.get("nested_instructions_detected"):
            threats.append(
                ThreatInfo(
                    name="heuristic_nested_instructions",
                    category="heuristic",
                    severity=0.5,
                    matched_text="",
                    description="Detected structured instruction blocks embedded in text.",
                )
            )
        if heuristic_details.get("excessive_imperatives"):
            threats.append(
                ThreatInfo(
                    name="heuristic_excessive_imperatives",
                    category="heuristic",
                    severity=0.4,
                    matched_text="",
                    description="Multiple imperative phrases suggest injected instructions.",
                )
            )
        if heuristic_details.get("excessive_script_mixing"):
            threats.append(
                ThreatInfo(
                    name="heuristic_script_mixing",
                    category="heuristic",
                    severity=0.3,
                    matched_text="",
                    description="Unusual mixing of Unicode scripts detected.",
                )
            )

        threats.sort(key=lambda t: t.severity, reverse=True)
        return threats
