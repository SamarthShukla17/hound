"""Load third-party audit findings into hound's Finding shape so they can be scored on the
same scorer as our own runs.

These findings did NOT come from a hound scan. There is no hunt, no map, no provenance, and
nothing has passed the citation gate. That matters for how the result should be read: our own
runs discard a finding whose citation does not resolve to real code, so a like-for-like
comparison has to at least MEASURE that for the imported set rather than quietly grading
findings whose line numbers point nowhere. Hence resolve_citations() and the external/unverified
marking carried on every record and in the run meta.
"""

import json
from pathlib import Path

from .verify import spans

EXTERNAL_MARK = "EXTERNAL — third-party findings, no hound provenance, citation gate NOT applied"
SEVERITY_BUCKETS = {"high": ("critical", "high", "medium"), "low": ("low",)}


def load_entries(path) -> list:
    """The raw third-party records, in file order."""
    data = json.loads(Path(path).read_text())
    return data if isinstance(data, list) else data.get("findings", [])


def resolve_citations(entries: list, files: list) -> tuple:
    """(resolved, unresolved) using the SAME resolver the citation gate uses.

    A third-party finding is not exempt from citing real code; it just never had anything
    check. Returns the entries paired with their resolved spans so callers can report how
    many would have been killed by our own gate.
    """
    resolved, unresolved = [], []
    for e in entries:
        loc = e.get("location", "") or ""
        found = spans(loc, files)
        (resolved if found else unresolved).append((e, found))
    return resolved, unresolved


def to_findings(entries: list, files: list, source: str) -> list:
    """Finding-shaped dicts, ids assigned in input order (F001...).

    Fields hound would normally derive from a hunt (observation/invariant/violation) stay
    empty rather than being invented: the scorer reads root_cause and title, and fabricating
    the mechanism fields would put words in the third party's mouth.
    """
    out = []
    for n, e in enumerate(entries, 1):
        cited = sorted({src.sha256 for src, _, _ in spans(e.get("location", "") or "", files)})
        out.append({
            "id": f"F{n:03d}",
            "title": e.get("title", ""),
            "severity": e.get("severity", ""),
            "location": e.get("location", ""),
            "root_cause": e.get("root_cause", ""),
            "impact": e.get("impact", ""),
            "observation": "", "invariant": "", "violation": "",
            "exploit_steps": [], "falsification": "",
            "lenses": [], "votes": 1, "confidence": None,
            "cited": cited,
            "citation_resolves": bool(cited),
            "external": True,
            "source": source,
            "provenance_verified": False,
            "hard_kill": False,
            "verdict": {"verdict": "keep", "reason": EXTERNAL_MARK, "killed_by": ""},
        })
    return out


def write_run_dir(out_dir, findings: list, source: str, bucket: str = "") -> Path:
    """A minimal run dir `hound score` can read. provenance is None ON PURPOSE -- score's
    provenance check then warns, which is the correct signal for an unverified import."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps({
        "judge_mode": "advisory",
        "provenance": None,
        "external": True,
        "source": source,
        "bucket": bucket,
        "note": EXTERNAL_MARK,
        "findings": findings,
    }, indent=2, sort_keys=True))
    (out / "map.json").write_text(json.dumps({"map": {}, "provenance": None}, indent=2))
    return out
