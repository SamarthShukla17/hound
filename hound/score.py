"""score command: LLM-graded comparison of a run's findings against ground truth."""

import json
from pathlib import Path

from .llm import Router

SYSTEM_PROMPT = """You are grading a smart-contract audit tool against a ground-truth answer key.

For EACH ground-truth bug, decide whether ANY of the candidate findings names the same
root-cause defect — the same specific thing wrong in the code, not merely the same file or
function — and whether that finding's fix would actually eliminate the bug.

EXACT   = same root cause AND the fix eliminates it.
PARTIAL = same root cause but a narrower, different, or missing fix, or severity off by two or
          more levels (critical/high/medium/low).
MISS    = a different root cause, even if it's one function away from the real bug.

This is the bar real audit tooling gets graded on. Do not soften it, and do not let a
near-miss inflate the score — a MISS that reads as "close" is still a bug that would not have
been submitted.

Also list, in off_catalog, any candidate finding that matches NO ground-truth bug. Some of
these are noise, but some may be real bugs outside the answer key — surface them rather than
silently counting them as false positives.

Output ONLY this JSON shape:
{"scores": [{"gt_id": "...", "verdict": "EXACT|PARTIAL|MISS", "finding_id": "F001 or null", "why": "..."}],
 "off_catalog": [{"finding_id": "...", "note": "..."}]}"""


def _candidate_summary(finding: dict) -> dict:
    return {
        "id": finding.get("id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "location": finding.get("location"),
        "root_cause": finding.get("root_cause"),
        "impact": finding.get("impact"),
    }


async def score(args) -> int:
    run_dir = Path(args.run_dir)
    findings = json.loads((run_dir / "findings.json").read_text())
    truth_text = Path(args.truth).read_text()

    include_killed = getattr(args, "include_killed", False)
    scored_findings = [
        f for f in findings if include_killed or f.get("verdict", {}).get("verdict") != "kill"
    ]
    candidates = [_candidate_summary(f) for f in scored_findings]

    user_prompt = (
        "TASK: SCORE\n\n"
        f"GROUND TRUTH:\n{truth_text}\n\n"
        f"CANDIDATE FINDINGS:\n{json.dumps(candidates, indent=2, sort_keys=True)}"
    )

    router = Router(models_path=args.models, local_only=args.local_only)
    data = await router.chat_json("scorer", SYSTEM_PROMPT, user_prompt, temperature=0.0, max_tokens=4000)

    scores = data.get("scores", []) if isinstance(data, dict) else []
    off_catalog = data.get("off_catalog", []) if isinstance(data, dict) else []

    exact = sum(1 for s in scores if s.get("verdict") == "EXACT")
    partial = sum(1 for s in scores if s.get("verdict") == "PARTIAL")
    miss = sum(1 for s in scores if s.get("verdict") == "MISS")
    n = len(scores)
    weighted_recall = (exact + 0.5 * partial) / n * 100 if n else 0.0

    known_ids = {f.get("id") for f in scored_findings}
    matched_ids = {s["finding_id"] for s in scores if s.get("finding_id") in known_ids}
    precision = (len(matched_ids) / len(scored_findings) * 100) if scored_findings else 0.0

    print(f"{'gt_id':10} {'verdict':8} {'finding':8} why")
    for s in scores:
        finding_col = str(s.get("finding_id") or "-")
        print(f"{s.get('gt_id', ''):10} {s.get('verdict', ''):8} {finding_col:8} {s.get('why', '')}")
    print()
    print(f"EXACT: {exact}  PARTIAL: {partial}  MISS: {miss}")
    print(f"weighted recall: {weighted_recall:.1f}%")
    print(f"precision proxy: {precision:.1f}%")

    if off_catalog:
        print()
        print("off-catalog (unmatched findings — may be real bugs outside the answer key):")
        for entry in off_catalog:
            print(f"  {entry.get('finding_id', '')}: {entry.get('note', '')}")

    result = {
        "scores": scores,
        "off_catalog": off_catalog,
        "counts": {"EXACT": exact, "PARTIAL": partial, "MISS": miss},
        "weighted_recall_pct": weighted_recall,
        "precision_proxy_pct": precision,
        "include_killed": include_killed,
    }
    (run_dir / "score.json").write_text(json.dumps(result, indent=2, sort_keys=True))
    return 0
