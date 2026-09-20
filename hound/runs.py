"""findings.json I/O.

The current format is an object: {"judge_mode", "provenance", "findings": [...]}.
Runs written before provenance existed are a bare list; they are read as
judge_mode="gate" (the only behaviour that existed then) with no provenance.
"""

import json
from pathlib import Path

from .schema import CITATION_GATE, STALE_CITATION  # noqa: F401  (re-exported for callers)


def read_findings(run_dir):
    """(meta, findings) for a run directory, tolerating the legacy list format."""
    data = json.loads((Path(run_dir) / "findings.json").read_text())
    if isinstance(data, list):
        return {"judge_mode": "gate", "provenance": None, "legacy": True}, data
    meta = {k: v for k, v in data.items() if k != "findings"}
    meta.setdefault("judge_mode", "gate")
    return meta, data.get("findings", [])


def is_hard_kill(finding: dict) -> bool:
    """Killed by a deterministic gate (citation / stale), as opposed to a judge opinion."""
    if "hard_kill" in finding:
        return bool(finding["hard_kill"])
    return (finding.get("verdict") or {}).get("killed_by") in (CITATION_GATE, STALE_CITATION)


def write_findings(run_dir, judge_mode: str, provenance: dict, findings: list, **meta) -> None:
    """`meta` (scope profile, seed, lenses, passes, ...) is stored beside the findings so a
    run's numbers stay interpretable later."""
    doc = {**meta, "judge_mode": judge_mode, "provenance": provenance, "findings": findings}
    (Path(run_dir) / "findings.json").write_text(json.dumps(doc, indent=2, sort_keys=True))
