"""~/.hound/killed.jsonl: human-confirmed false-positive corpus.

ONLY the `hound kill` command writes here. A judge's own kills stay in the
run directory and never reach the corpus — a model's wrong kill must not
become a permanent filter that hides the same real bug from every future
scan. This file is the compounding memory RESOURCES §5 describes: every
candidate killed by hand makes future runs cheaper.

The path is fixed under the user's home directory (override with
HOUND_CORPUS) rather than relative to the invocation directory, so it stays
one file that follows you across targets instead of silently splitting
depending on which folder `hound` was run from.
"""

import json
import os
from pathlib import Path


def default_path() -> Path:
    override = os.environ.get("HOUND_CORPUS")
    if override:
        return Path(override)
    return Path.home() / ".hound" / "killed.jsonl"


def append(entry: dict, path=None) -> None:
    path = Path(path) if path is not None else default_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")


def recent(n: int = 40, path=None) -> str:
    """The tail of the corpus, formatted for injection into hunter/judge
    prompts. An empty or missing corpus renders "" — it must never break a
    prompt that includes it."""
    path = Path(path) if path is not None else default_path()
    if not path.exists():
        return ""

    entries = []
    for line in path.read_text().splitlines()[-n:]:
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return "\n".join(
        f"- {e.get('title', '')} @ {e.get('location', '')} :: killed by {e.get('reason', '')}"
        for e in entries
    )


def kill_finding(run_dir, finding_id: str, reason: str, path=None) -> dict:
    """Read `finding_id` out of run_dir/findings.json and append it to the
    corpus with a human-supplied reason."""
    findings_path = Path(run_dir) / "findings.json"
    findings = json.loads(findings_path.read_text())
    match = next((f for f in findings if f.get("id") == finding_id), None)
    if match is None:
        raise ValueError(f"finding {finding_id!r} not found in {findings_path}")

    entry = {
        "title": match.get("title", ""),
        "location": match.get("location", ""),
        "root_cause": match.get("root_cause", ""),
        "reason": reason,
    }
    append(entry, path=path)
    return entry
