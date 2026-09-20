"""score command: LLM-graded comparison of a run's findings against ground truth."""

import asyncio
import json
import re
from collections import Counter
from pathlib import Path

from .llm import Router

RETRY_DELAY_SECONDS = 30
DEGENERATE_SHARE = 0.8
DEGENERATE_MIN_SCORES = 3

SYSTEM_PROMPT = """You are grading a smart-contract audit tool against a ground-truth answer key.

For EACH ground-truth bug, decide whether ANY of the candidate findings names the same
root-cause defect — the same specific thing wrong in the code, not merely the same file or
function — and whether that finding's fix would actually eliminate the bug.

COVERAGE: you must consider EVERY candidate finding for EVERY ground-truth bug. Do not compare a
bug against only the first finding or the most prominent one. In each "why", name the finding you
matched, or for a MISS name the closest finding you checked and say how it differs. finding_id must
be exactly one of the ids in the CANDIDATE FINDINGS list, or null. Never invent an id.

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
{"scores": [{"gt_id": "...", "verdict": "EXACT|PARTIAL|MISS", "finding_id": "<an id from CANDIDATE FINDINGS, or null>", "why": "..."}],
 "off_catalog": [{"finding_id": "...", "note": "..."}]}"""

_ID_RE = re.compile(r"\bF\d{3}\b")
# "F001-F024" names a whole range, not one finding; don't let it read as a mention of F001.
_ID_RANGE_RE = re.compile(r"\bF\d{3}\s*(?:-|–|to|through)\s*F\d{3}\b")
_VERDICTS = ("EXACT", "PARTIAL", "MISS")


def _candidate_summary(finding: dict) -> dict:
    return {
        "id": finding.get("id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "location": finding.get("location"),
        "root_cause": finding.get("root_cause"),
        "impact": finding.get("impact"),
    }


def degenerate_share(scores: list) -> tuple:
    """(finding_id, share) for the finding id mentioned by the largest share of
    the "why" strings, or (None, 0.0). Id ranges like "F001-F024" don't count."""
    if not scores:
        return None, 0.0
    mentions = Counter()
    for s in scores:
        why = _ID_RANGE_RE.sub("", str(s.get("why", "")))
        for fid in set(_ID_RE.findall(why)):
            mentions[fid] += 1
    if not mentions:
        return None, 0.0
    fid, count = mentions.most_common(1)[0]
    return fid, count / len(scores)


def _sanitize(scores: list, known_ids: set) -> list:
    """Enforce that every match points at a supplied finding. A match claiming a
    finding that doesn't exist (or none at all) can't be credited: downgrade to MISS."""
    warnings = []
    for s in scores:
        verdict = str(s.get("verdict", "")).strip().upper()
        fid = s.get("finding_id")
        if isinstance(fid, str) and fid.strip().lower() in ("", "null", "none"):
            fid = None

        problem = None
        if verdict not in _VERDICTS:
            problem = f"unrecognized verdict {s.get('verdict')!r}"
            verdict = "MISS"
        elif fid is not None and fid not in known_ids:
            problem = f"finding_id {fid!r} is not one of the supplied findings"
            fid = None
            if verdict != "MISS":
                verdict = "MISS"
        elif verdict != "MISS" and fid is None:
            problem = f"{verdict} without a finding_id"
            verdict = "MISS"

        s["verdict"], s["finding_id"] = verdict, fid
        if problem:
            s["why"] = f"{s.get('why', '')} [downgraded to MISS: {problem}]".strip()
            warnings.append(f"{s.get('gt_id', '?')}: {problem}")
    return warnings


async def _call_scorer(router, user_prompt: str):
    """One scorer call, retried ONCE after a pause if it fails on a 429."""
    for attempt in (1, 2):
        try:
            return await router.chat_json("scorer", SYSTEM_PROMPT, user_prompt, temperature=0.0)
        except Exception as exc:  # noqa: BLE001
            if attempt == 1 and "429" in str(exc):
                print(f"scorer rate-limited (429); retrying once in {RETRY_DELAY_SECONDS}s")
                await asyncio.sleep(RETRY_DELAY_SECONDS)
                continue
            raise


async def score(args) -> int:
    run_dir = Path(args.run_dir)
    try:
        findings = json.loads((run_dir / "findings.json").read_text())
        truth_text = Path(args.truth).read_text()
    except (OSError, json.JSONDecodeError) as exc:
        print(f"score: cannot read inputs: {exc}")
        return 1

    include_killed = getattr(args, "include_killed", False)
    scored_findings = [
        f for f in findings if include_killed or f.get("verdict", {}).get("verdict") != "kill"
    ]
    candidates = [_candidate_summary(f) for f in scored_findings]
    known_ids = {f.get("id") for f in scored_findings}

    user_prompt = (
        "TASK: SCORE\n\n"
        f"GROUND TRUTH:\n{truth_text}\n\n"
        f"CANDIDATE FINDINGS:\n{json.dumps(candidates, indent=2, sort_keys=True)}"
    )

    try:
        router = Router(models_path=args.models, local_only=args.local_only)
        data = await _call_scorer(router, user_prompt)
    except Exception as exc:  # noqa: BLE001 - a scorer failure is a clean exit, not a traceback
        print(f"score failed: {str(exc)[:300]}")
        return 1

    scores = data.get("scores", []) if isinstance(data, dict) else []
    off_catalog = data.get("off_catalog", []) if isinstance(data, dict) else []

    sanitize_warnings = _sanitize(scores, known_ids)
    for w in sanitize_warnings:
        print(f"WARNING: {w}")

    top_id, share = degenerate_share(scores)
    degenerate = len(scores) >= DEGENERATE_MIN_SCORES and share > DEGENERATE_SHARE
    if degenerate:
        print(
            f"WARNING: {share:.0%} of the reasons mention {top_id} — the scorer likely degenerated "
            f"(comparing every bug against one finding). Do not trust this score."
        )

    exact = sum(1 for s in scores if s["verdict"] == "EXACT")
    partial = sum(1 for s in scores if s["verdict"] == "PARTIAL")
    miss = sum(1 for s in scores if s["verdict"] == "MISS")
    n = len(scores)
    weighted_recall = (exact + 0.5 * partial) / n * 100 if n else 0.0

    matched_ids = {s["finding_id"] for s in scores if s["finding_id"] in known_ids}
    precision = (len(matched_ids) / len(scored_findings) * 100) if scored_findings else 0.0

    print(f"{'gt_id':10} {'verdict':8} {'finding':8} why")
    for s in scores:
        finding_col = str(s.get("finding_id") or "-")
        print(f"{s.get('gt_id', ''):10} {s['verdict']:8} {finding_col:8} {s.get('why', '')}")
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
        "degenerate_warning": degenerate,
        "downgraded": sanitize_warnings,
    }
    (run_dir / "score.json").write_text(json.dumps(result, indent=2, sort_keys=True))
    return 0
