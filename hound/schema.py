"""Pydantic schemas: Finding, Verdict, severity ranking."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from .tiers import normalise as _norm_tier, stated_gain

Severity = Literal["critical", "high", "medium", "low"]

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Kills issued by the deterministic gates rather than by a model. These are self-justifying —
# the disproof IS that the citation does not resolve — so they are exempt from having to cite
# a disproof location. Every other kill is a model deleting evidence and must cite.
CITATION_GATE = "citation gate"
STALE_CITATION = "stale citation (file changed since hunt)"
GATE_KILLS = (CITATION_GATE, STALE_CITATION)


class Finding(BaseModel):
    """Mechanism before impact, in this order, on purpose.

    The dominant hunter failure is naming the right lines and inventing the wrong defect:
    the model reaches real code, then narrates a consequence (theft, minting, draining) it
    never traced. observation/invariant/violation are required so the impact has to be
    derived from something stated first, rather than asserted.
    """

    title: str
    severity: Severity
    bug_class: str = ""
    location: str
    observation: str  # what the cited lines literally do — no consequence
    invariant: str  # the property those lines are supposed to maintain
    violation: str  # the input/sequence that breaks it, cited
    root_cause: str  # summary of observation + invariant + violation
    impact: str  # must follow FROM the three above
    exploit_steps: list[str]
    falsification: str = ""
    confidence: float = Field(0.5, ge=0, le=1)
    # profit | disruption | unclear: does the attacker END UP WITH MORE value than they started with
    # (kb/FINDING_TIERS.md). attacker_gain is the equity accounting in one line, or "none".
    value_flow: str = "unclear"
    attacker_gain: str = ""

    @field_validator("value_flow", mode="before")
    @classmethod
    def _tier_is_normalised(cls, v):
        return _norm_tier(v)

    @model_validator(mode="after")
    def _profit_must_state_its_gain(self):
        # A profit claim with no stated gain is an unfinished accounting, not a profit: downgrade it
        # rather than drop the finding (a dropped finding is lost recall).
        if self.value_flow == "profit" and not stated_gain(self.attacker_gain):
            self.value_flow = "unclear"
        return self

    @field_validator("observation", "invariant", "violation", mode="before")
    @classmethod
    def _mechanism_must_be_stated(cls, v, info):
        if not (isinstance(v, str) and v.strip()):
            raise ValueError(
                f"{info.field_name} is required: state what the cited lines do, the property they "
                f"must maintain, and what breaks it, before asserting any impact"
            )
        return v


class Verdict(BaseModel):
    verdict: Literal["keep", "kill", "needs_poc"]
    reason: str
    severity: Severity | None = None
    killed_by: str = ""
    # Where the disproof lives, as path:line or path:start-end. killed_by is prose; this is a
    # citation, so a kill can be checked by the same citation gate the findings go through.
    # A kill must cite the guard that kills it.
    disproof_location: str = ""
    # The judge's own recomputation of the equity test; None = the judge did not say.
    value_flow: str | None = None

    @field_validator("value_flow", mode="before")
    @classmethod
    def _blank_tier_is_none(cls, v):
        if v is None or (isinstance(v, str) and v.strip().lower() in ("", "null", "none")):
            return None
        return _norm_tier(v)

    @model_validator(mode="after")
    def _kill_must_cite_its_disproof(self):
        if self.killed_by in GATE_KILLS:
            return self
        if self.verdict == "kill" and not self.disproof_location.strip():
            raise ValueError("verdict 'kill' requires disproof_location (path:line of the guard that disproves it)")
        return self

    # Models routinely emit the *string* "null" (or "") for "no severity", and null for an
    # empty killed_by. Those mean "absent", not "invalid" — coerce them instead of failing.
    @field_validator("severity", mode="before")
    @classmethod
    def _blank_severity_is_none(cls, v):
        if isinstance(v, str) and v.strip().lower() in ("", "null", "none"):
            return None
        return v

    @field_validator("killed_by", mode="before")
    @classmethod
    def _null_killed_by_is_empty(cls, v):
        return "" if v is None else v
