"""Pydantic schemas: Finding, Verdict, severity ranking."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

Severity = Literal["critical", "high", "medium", "low"]

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Kills issued by the deterministic gates rather than by a model. These are self-justifying —
# the disproof IS that the citation does not resolve — so they are exempt from having to cite
# a disproof location. Every other kill is a model deleting evidence and must cite.
CITATION_GATE = "citation gate"
STALE_CITATION = "stale citation (file changed since hunt)"
GATE_KILLS = (CITATION_GATE, STALE_CITATION)


class Finding(BaseModel):
    title: str
    severity: Severity
    bug_class: str = ""
    location: str
    root_cause: str
    impact: str
    exploit_steps: list[str]
    falsification: str = ""
    confidence: float = Field(0.5, ge=0, le=1)


class Verdict(BaseModel):
    verdict: Literal["keep", "kill", "needs_poc"]
    reason: str
    severity: Severity | None = None
    killed_by: str = ""
    # Where the disproof lives, as path:line or path:start-end. killed_by is prose; this is a
    # citation, so a kill can be checked by the same citation gate the findings go through.
    # A kill must cite the guard that kills it.
    disproof_location: str = ""

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
