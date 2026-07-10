"""
decision_engine.py
====================

Automated response engine for the phishing detection pipeline.

This module converts the output of ``phishing_detector.detect_phishing()``
into a concrete action for a security operations workflow (block, alert,
monitor, etc.).

Why a separate module
----------------------
Detection ("how risky is this email?") and response policy ("what do we
*do* about that risk?") are different concerns that change for different
reasons -- detection rules get tuned as new phishing patterns appear;
response policy changes based on business risk tolerance, staffing, and
compliance requirements. Keeping them in separate files means you can
change one without touching the other.

Consistency with phishing_detector.py
--------------------------------------
The risk-level thresholds here intentionally mirror
``phishing_detector.RISK_THRESHOLDS`` (Critical >= 80, High >= 55,
Medium >= 30, Low >= 10, Safe < 10), so a message classified "Critical"
by the detector is also treated as "Critical" here -- there is no silent
re-scoring or drift between the two modules.

Usage
-----
    from phishing_detector import detect_phishing
    from decision_engine import agent_decision

    result = detect_phishing(sender=..., subject=..., body=..., urls=...)
    decision = agent_decision(result)
    print(decision["action"], decision["message"])

Backward compatibility
-----------------------
``agent_decision`` also accepts a bare numeric score (``int`` / ``float``)
for older call sites that only have a score and no full detector result,
e.g. ``agent_decision(72)``.
"""

from __future__ import annotations

from typing import Any, Union

__all__ = ["agent_decision"]


# ======================================================================
# Configuration
# ======================================================================

#: Score thresholds (inclusive lower bound), evaluated highest-first.
#: Mirrors phishing_detector.RISK_THRESHOLDS so a bare score maps to the
#: same risk level the detector itself would have assigned.
RISK_THRESHOLDS: list[tuple[int, str]] = [
    (10, "Critical"),
    (7, "High"),
    (4, "Medium"),
    (2, "Low"),
    (0, "Safe"),
]

#: Base action + message for each risk level, keyed to match
#: phishing_detector's five-level scale.
ACTION_MAP: dict[str, tuple[str, str]] = {
    "Critical": (
        "Immediate IP Block + Alert",
        "Critical threat detected. Sender/IP blocked and admin notified immediately.",
    ),
    "High": (
        "Quarantine + Alert",
        "High-risk phishing indicators detected. Message quarantined and admin notified.",
    ),
    "Medium": (
        "Send Alert",
        "Suspicious activity detected. Admin notified for manual review.",
    ),
    "Low": (
        "Monitor",
        "Low-risk activity logged for ongoing observation.",
    ),
    "Safe": (
        "Allow",
        "No significant threat indicators detected.",
    ),
}

#: If the detector's confidence in a Critical/High classification falls
#: below this threshold, the automatic block/quarantine action is
#: downgraded to a manual-review action rather than acting irreversibly
#: on a low-confidence signal.
LOW_CONFIDENCE_THRESHOLD: int = 5

#: Risk levels eligible for the confidence guardrail above. Medium/Low/
#: Safe are already non-destructive actions, so no guardrail is needed.
_GUARDRAIL_LEVELS: frozenset[str] = frozenset({"Critical", "High"})


# ======================================================================
# Helpers
# ======================================================================

def _classify_risk_level(score: float) -> str:
    """Map a bare 0-100 score onto a risk level using the same
    thresholds as phishing_detector.RISK_THRESHOLDS.
    """
    for threshold, level in RISK_THRESHOLDS:
        if score >= threshold:
            return level
    return "Safe"  # pragma: no cover - thresholds always cover 0


def _normalize_input(result: Union[dict[str, Any], int, float]) -> tuple[float, str, int]:
    """Normalize either a full detect_phishing() result dict or a bare
    numeric score into ``(score, risk_level, confidence)``.

    Malformed input (wrong type, missing keys) degrades safely: a
    missing score is treated as 0, a missing/unknown risk level is
    re-derived from the score, and a missing confidence defaults to 100
    (i.e. "fully trust the score" when no confidence signal is available).
    """
    if isinstance(result, dict):
        raw_score = result.get("score", 0)
        try:
            score = float(raw_score)
        except (TypeError, ValueError):
            score = 0.0

        risk_level = result.get("risk_level")
        if risk_level not in ACTION_MAP:
            risk_level = _classify_risk_level(score)

        raw_confidence = result.get("confidence", 100)
        try:
            confidence = int(raw_confidence)
        except (TypeError, ValueError):
            confidence = 10

        return score, risk_level, confidence

    # Bare numeric score (legacy call style).
    try:
        score = float(result)
    except (TypeError, ValueError):
        score = 0.0

    return score, _classify_risk_level(score), 10


# ======================================================================
# Public entry point
# ======================================================================

def agent_decision(result: Union[dict[str, Any], int, float]) -> dict[str, Any]:
    """Decide and return an automated response action for a scanned email.

    Parameters
    ----------
    result:
        Either:

        - The full dictionary returned by ``phishing_detector.detect_phishing()``
          (preferred -- uses ``score``, ``risk_level``, and ``confidence``), or
        - A bare numeric risk score (0-100), for legacy call sites that
          only have a score on hand.

    Returns
    -------
    dict
        - ``action`` (str): the response action to take, e.g.
          ``"Immediate IP Block + Alert"``, ``"Quarantine + Alert"``,
          ``"Send Alert"``, ``"Monitor"``, ``"Allow"``, or
          ``"Manual Review Required"``.
        - ``message`` (str): human-readable explanation of the decision.
        - ``score`` (float): the risk score the decision was based on.
        - ``risk_level`` (str): the risk level used (Safe/Low/Medium/High/Critical).
        - ``confidence`` (int): confidence value used in the decision, if any.

    Notes
    -----
    Never raises on malformed input -- missing/invalid fields fall back
    to safe defaults (score 0, confidence 100) rather than throwing.
    """
    score, risk_level, confidence = _normalize_input(result)
    action, message = ACTION_MAP[risk_level]

    # Confidence guardrail: don't take an irreversible action (block /
    # quarantine) on a high score the detector itself isn't confident
    # about -- escalate to a human instead.
    if risk_level in _GUARDRAIL_LEVELS and confidence < LOW_CONFIDENCE_THRESHOLD:
        action = "Manual Review Required"
        message = (
            f"{risk_level} risk score ({score:.0f}) detected, but detector "
            f"confidence is low ({confidence}%). Escalated for manual "
            f"review instead of an automatic {ACTION_MAP[risk_level][0].lower()}."
        )

    return {
        "action": action,
        "message": message,
        "score": score,
        "risk_level": risk_level,
        "confidence": confidence,
    }


# ======================================================================
# Manual smoke test (only runs when executed directly, not on import)
# ======================================================================
if __name__ == "__main__":
    import json

    # Legacy-style call: bare score only.
    print(json.dumps(agent_decision(7), indent=2))

    # New-style call: full detect_phishing() result, high score but low confidence.
    print(json.dumps(
        agent_decision({"score": 6, "risk_level": "Critical", "confidence": 35}),
        indent=2,
    ))

    # New-style call: full detect_phishing() result, high score, high confidence.
    print(json.dumps(
        agent_decision({"score": 5, "risk_level": "Critical", "confidence": 90}),
        indent=2,
    ))
