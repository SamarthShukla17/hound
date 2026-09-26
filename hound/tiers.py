"""Profit-versus-disruption tiers: the deterministic half.

The model states `value_flow` and `attacker_gain` (kb/FINDING_TIERS.md). This module supplies what
needs no model: normalising the tier, deciding whether a stated gain is a real statement, and the
severity check that flags a high/critical claim resting on disruption alone.
"""

import re

TIERS = ("profit", "disruption", "unclear")
_NO_GAIN = {"", "none", "n/a", "na", "-", "nil", "no", "null", "zero", "0"}
# Words that justify high/critical for a finding where the attacker does not profit: a permanent
# loss of user funds, or a protocol that cannot honour what it owes.
_SEVERE_RE = re.compile(
    r"permanent|irrecoverab|unrecoverab|forever|insolven|unbacked|undercollateral|bad debt|drain|theft|stolen|steal|"
    r"loss of (?:user )?funds|funds? (?:are|is) (?:lost|locked|frozen)|can(?:not|'t) (?:withdraw|redeem)",
    re.IGNORECASE,
)
_QUANTIFIED_RE = re.compile(r"\d")


def normalise(value) -> str:
    v = str(value or "").strip().lower()
    return v if v in TIERS else "unclear"


def stated_gain(text) -> bool:
    """A real statement of attacker gain: non-empty, not a 'none' variant."""
    return str(text or "").strip().lower() not in _NO_GAIN


def tier_of(finding: dict, verdict=None) -> str:
    """The tier to report: the judge's recomputed one when it gave one, else the hunter's."""
    judged = getattr(verdict, "value_flow", None)
    return normalise(judged) if judged else normalise(finding.get("value_flow"))


def tier_warning(finding: dict, severity: str, tier: str) -> str:
    """A note (not a kill) when the tier does not support the severity claimed."""
    if severity not in ("high", "critical"):
        return ""
    if tier == "unclear":
        return "severity high/critical but the attacker gain was never accounted (value_flow unclear)"
    if tier == "profit":
        if not (stated_gain(finding.get("attacker_gain")) and _QUANTIFIED_RE.search(str(finding.get("attacker_gain")))):
            return "classified profit but attacker_gain is not quantified"
        return ""
    text = f"{finding.get('impact', '')} {finding.get('attacker_gain', '')}"
    if not _SEVERE_RE.search(text):
        return "severity high/critical on a disruption-tier finding with no permanent-freeze, theft or insolvency claim: justify or lower"
    return ""
