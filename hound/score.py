"""score command: LLM-graded comparison of a run's findings against ground truth."""

import asyncio
import json
import re
from collections import Counter
from pathlib import Path

from .codebase import check_provenance
from .llm import Router
from .runs import is_hard_kill, read_findings

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


def select_scored(findings: list, mode: str, include_killed: bool = False, as_gate: bool = False) -> list:
    """Which findings a score covers.

    advisory run: everything except deterministic-gate kills (the judge only annotated).
    gate run (and legacy runs): everything the judge did not kill.
    --as-gate: what a judge gate WOULD have kept, on any run (drops every judge kill).
    --include-killed: everything, including deterministic-gate kills.
    """
    def judge_killed(f):
        return (f.get("verdict") or {}).get("verdict") == "kill"

    if include_killed:
        return list(findings)
    if as_gate or mode != "advisory":
        return [f for f in findings if not judge_killed(f)]
    return [f for f in findings if not is_hard_kill(f)]


def _provenance_warnings(meta: dict) -> list:
    provenance = meta.get("provenance")
    if not provenance:
        print("note: this run has no provenance (written before provenance existed); "
              "cannot check the working tree against what was read")
        return []
    problems = check_provenance(provenance)
    for p in problems:
        print(f"WARNING: run provenance does not match the working tree — {p}")
    if problems:
        print("WARNING: the code changed since this run read it; finding locations may no longer "
              "point at the code that was cited.")
    return problems


async def score(args) -> int:
    run_dir = Path(args.run_dir)
    try:
        meta, findings = read_findings(run_dir)
        truth_text = Path(args.truth).read_text()
    except (OSError, json.JSONDecodeError) as exc:
        print(f"score: cannot read inputs: {exc}")
        return 1

    include_killed = getattr(args, "include_killed", False)
    as_gate = getattr(args, "as_gate", False)
    judge_mode = meta.get("judge_mode", "gate")
    provenance_problems = _provenance_warnings(meta)
    scored_findings = select_scored(findings, judge_mode, include_killed, as_gate)
    print(f"scoring {len(scored_findings)} of {len(findings)} findings "
          f"(run judge_mode={judge_mode}{', as-gate' if as_gate else ''}{', include-killed' if include_killed else ''})")
    candidates = [_candidate_summary(f) for f in scored_findings]
    known_ids = {f.get("id") for f in scored_findings}

    user_prompt = (
        "TASK: SCORE\n\n"
        f"GROUND TRUTH:\n{truth_text}\n\n"
        f"CANDIDATE FINDINGS:\n{json.dumps(candidates, indent=2, sort_keys=True)}"
    )

    router = None
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
        "as_gate": as_gate,
        "judge_mode": judge_mode,
        "scored_finding_ids": sorted(known_ids),
        "degenerate_warning": degenerate,
        "downgraded": sanitize_warnings,
        "provenance_mismatches": provenance_problems,
        "cost": router.report(),
    }
    (run_dir / "score.json").write_text(json.dumps(result, indent=2, sort_keys=True))
    print(json.dumps(router.report(), indent=2))
    return 0


_RANK = {"MISS": 0, "PARTIAL": 1, "EXACT": 2}


def union_scores(run_dirs) -> dict:
    """Combine several scored runs (e.g. seeds). A ground-truth bug counts as found if ANY run
    found it, at the best verdict any run gave it. This is how the single-agent baseline's
    ~22% was produced, so it is the fair comparison for a fan-out run's recall."""
    runs = []
    for d in run_dirs:
        data = json.loads((Path(d) / "score.json").read_text())
        meta, _ = read_findings(d)
        runs.append({
            "label": f"{Path(d).name} (seed {meta.get('seed', '?')})",
            "recall": data["weighted_recall_pct"],
            "verdicts": {s["gt_id"]: s["verdict"] for s in data["scores"]},
        })

    gt_ids = list(dict.fromkeys(g for r in runs for g in r["verdicts"]))
    best, found_by = {}, {}
    for g in gt_ids:
        verdicts = {r["label"]: r["verdicts"].get(g, "MISS") for r in runs}
        best[g] = max(verdicts.values(), key=_RANK.get)
        found_by[g] = [label for label, v in verdicts.items() if v != "MISS"]

    exact = sum(v == "EXACT" for v in best.values())
    partial = sum(v == "PARTIAL" for v in best.values())
    n = len(gt_ids)
    return {
        "per_run": [{"label": r["label"], "weighted_recall_pct": r["recall"]} for r in runs],
        "union": {
            "EXACT": exact, "PARTIAL": partial, "MISS": n - exact - partial,
            "weighted_recall_pct": (exact + 0.5 * partial) / n * 100 if n else 0.0,
        },
        "best": best,
        "found_by": found_by,
        "only_one_run": {g: labels[0] for g, labels in found_by.items() if len(labels) == 1},
    }


def print_union(result: dict) -> None:
    for r in result["per_run"]:
        print(f"{r['label']:38} weighted recall {r['weighted_recall_pct']:5.1f}%")
    u = result["union"]
    print(f"{'UNION (found by ANY run)':38} weighted recall {u['weighted_recall_pct']:5.1f}%  "
          f"(EXACT {u['EXACT']}, PARTIAL {u['PARTIAL']}, MISS {u['MISS']})")
    print("\nfound at all:")
    for g, labels in result["found_by"].items():
        if labels:
            print(f"  {g:6} {result['best'][g]:8} by {len(labels)}/{len(result['per_run'])} runs")
    print("\ncaught by exactly ONE run (run-to-run variance):")
    for g, label in result["only_one_run"].items():
        print(f"  {g:6} {result['best'][g]:8} only {label}")
    if not result["only_one_run"]:
        print("  (none)")
