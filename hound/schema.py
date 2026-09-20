"""Pydantic schemas: Finding, Verdict, severity ranking."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator

Severity = Literal["critical", "high", "medium", "low"]

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


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
