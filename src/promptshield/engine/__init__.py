"""
PromptShield Detection Engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Core detection engine for identifying prompt injection attacks.

Public API::

    from promptshield.engine import ShieldDetector, ShieldResult

    detector = ShieldDetector(threshold=0.5, sensitivity="medium")
    result: ShieldResult = detector.analyze("some user input")
    print(result.safe, result.score, result.threats)

Classes exported:
    - :class:`ShieldDetector` -- main orchestrator
    - :class:`ShieldResult` -- analysis result
    - :class:`ThreatInfo` -- individual threat detail
    - :class:`RuleDetector` -- rule-based sub-detector
    - :class:`RuleMatch` -- single rule match
    - :class:`Sensitivity` -- sensitivity level enum
    - :class:`AttackPattern` -- pattern definition
    - :class:`PatternCategory` -- pattern category enum
"""

from .detector import ShieldDetector, ShieldResult, ThreatInfo
from .patterns import ATTACK_PATTERNS, AttackPattern, PatternCategory
from .rules import RuleDetector, RuleMatch, Sensitivity

__all__ = [
    "ShieldDetector",
    "ShieldResult",
    "ThreatInfo",
    "RuleDetector",
    "RuleMatch",
    "Sensitivity",
    "AttackPattern",
    "PatternCategory",
    "ATTACK_PATTERNS",
]
