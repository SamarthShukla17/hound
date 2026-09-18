"""Pydantic schemas: Finding, Verdict, severity ranking."""

from typing import Literal

from pydantic import BaseModel, Field

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
