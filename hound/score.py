"""score command: LLM-graded comparison of a run's findings against ground truth."""

import asyncio
import json
import re
from collections import Counter
from pathlib import Path

import os

from .codebase import check_provenance
from .llm import OutOfCredits, Router
from .runs import is_hard_kill, read_findings
from .verify import parse_locations

RETRY_DELAY_SECONDS = 30
# Per-bug calls are small, but reasoning still runs long; generous since the run is finished.
SCORER_CALL_CEILING = 900
DEGENERATE_SHARE = 0.8
DEGENERATE_MIN_SCORES = 3
# One call per ground-truth bug, repeated, majority wins. Grading all 23 bugs in a single call
# was not reproducible: the same three artifacts scored twice swung 8.7 -> 4.3 and 8.7 -> 13.0,
# a +/-4.4 point swing, larger than most effects being measured. A per-bug call has a far
# smaller reasoning surface, and repeating it turns residual nondeterminism into a measurable
# agreement number instead of silent noise.
SCORE_REPEATS = 2          # a 3rd call only breaks a tie
MAX_REPEATS = 3
CANDIDATE_PAD = 60         # lines either side of a bug's own location

SYSTEM_PROMPT = """You are grading a smart-contract audit tool against ONE bug from a ground-truth
answer key.

You are given exactly one ground-truth bug and every candidate finding the tool produced. Decide
whether ANY candidate names the same root-cause defect — the same specific thing wrong in the
code, not merely the same file or function — and whether that finding's fix would actually
eliminate the bug.

Consider EVERY candidate. Do not stop at the first plausible one.

ALTERNATE CLAIMS: a candidate may carry alternate_claims — other readings of the SAME lines (an
earlier pass's explanation that a later one replaced, or merged duplicates). Consider the primary
reading AND every alternate. If ANY of them names the ground-truth defect, that is a match:
credit the candidate by its id and say in "why" which reading matched.

EXACT   = same root cause AND the fix eliminates it.
PARTIAL = same root cause but a narrower, different, or missing fix, or severity off by two or
          more levels (critical/high/medium/low).
MISS    = a different root cause, even if it's one function away from the real bug.

This is the bar real audit tooling gets graded on. Do not soften it, and do not let a near-miss
inflate the score — a MISS that reads as "close" is still a bug that would not have been
submitted. finding_id must be exactly one of the ids in CANDIDATE FINDINGS, or null for a MISS.
Never invent an id.

Output ONLY this JSON shape:
{"verdict": "EXACT|PARTIAL|MISS", "finding_id": "<an id from CANDIDATE FINDINGS, or null>", "why": "..."}"""


_GT_LOC_RE = re.compile(r"(\w+\.(?:sol|rs|vy|move|cairo|go))#L(\d+)(?:-#?L?(\d+))?")


def bug_locations(gt_text: str) -> list:
    """(file, start, end) for every source link in a ground-truth entry."""
    out = []
    for m in _GT_LOC_RE.finditer(gt_text):
        a = int(m.group(2))
        out.append((m.group(1), a, int(m.group(3) or a)))
    return out


def candidates_for_bug(gt_text: str, candidates: list, pad: int = CANDIDATE_PAD) -> tuple:
    """The candidates worth grading against ONE bug, and why that many.

    Sending all candidates for every bug is what pushed a per-bug call back over the token
    cap. A candidate citing a different file cannot be the same defect, so narrow to the
    bug's own FILE -- but never tighter than that.

    An earlier version returned only the candidates within +/-pad of the ground truth's own
    citation and discarded the rest of the file whenever that set was non-empty. That silently
    threw away correct findings, because a ground-truth citation often does NOT contain the
    line that has to change. Measured on this bench: of 11 located-but-misread bugs, 9 name a
    fix outside their own cited range. M-02 cites Marketplace.sol 413-422 and 459-471 while
    its fix belongs at line 288 in listVesting(); every run produced a candidate citing
    276-288, and all of them were dropped from M-02's grading because other candidates
    happened to sit nearer the citation.

    So: grade against near AND same-file candidates, near first, de-duplicated by id. The
    +/-pad distinction is kept only to order and explain the set, never to delete from it.
    """
    locs = bug_locations(gt_text)
    if not locs:
        return candidates, "all (no parseable bug location)"

    near, same_file = [], []
    for c in candidates:
        cited = parse_locations(c.get("location", "") or "")
        matched_file = matched_near = False
        for path, x, y in cited:
            fname = os.path.basename(path)
            for gfile, ga, gb in locs:
                if fname != gfile:
                    continue
                matched_file = True
                if not (y + pad < ga or gb + pad < x):
                    matched_near = True
        if matched_near:
            near.append(c)
        elif matched_file:
            same_file.append(c)

    if near or same_file:
        seen, merged = set(), []
        for c in [*near, *same_file]:  # near first: most likely match leads the list
            cid = c.get("id") or id(c)
            if cid not in seen:
                seen.add(cid)
                merged.append(c)
        return merged, (f"{len(merged)} in {os.path.basename(locs[0][0])} "
                        f"({len(near)} near +/-{pad}, {len(same_file)} elsewhere in the file)")
    return candidates, f"all {len(candidates)} (none cite this file)"


_GT_ENTRY_RE = re.compile(r"^### ([HM]-\d+)\s*[-—]\s*(.+)$", re.M)


def split_ground_truth(text: str) -> dict:
    """{gt_id: full section text}. An id appearing twice (summary list, then full description)
    keeps the LAST, longest occurrence, which is the description."""
    entries = {}
    matches = list(_GT_ENTRY_RE.finditer(text))
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[m.start():end].strip()
        gid = m.group(1)
        if gid not in entries or len(body) > len(entries[gid]):
            entries[gid] = body
    return entries


_ID_RE = re.compile(r"\bF\d{3}\b")
# "F001-F024" names a whole range, not one finding; don't let it read as a mention of F001.
_ID_RANGE_RE = re.compile(r"\bF\d{3}\s*(?:-|–|to|through)\s*F\d{3}\b")
_VERDICTS = ("EXACT", "PARTIAL", "MISS")


def _candidate_summary(finding: dict) -> dict:
    """One candidate for the scorer, carrying every claim made about those lines.

    A candidate can hold more than one reading of the same code: the diagnose stage replaces
    the locating pass's explanation but keeps it as hunter_claim, and dedup keeps merged
    paraphrases as alternates. Scoring only the primary loses a bug whose CORRECT reading was
    the one replaced (M-10 was matched before diagnosis and lost after). Any claim matching
    counts, so the candidate is credited if any reading of it was right.
    """
    summary = {
        "id": finding.get("id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "location": finding.get("location"),
        "root_cause": finding.get("root_cause"),
        "impact": finding.get("impact"),
    }

    claims = []
    hunter = finding.get("hunter_claim")
    if isinstance(hunter, dict) and (hunter.get("root_cause") or hunter.get("impact")):
        claims.append({"source": "located (pre-diagnosis)", "title": hunter.get("title", ""),
                       "root_cause": hunter.get("root_cause", ""), "impact": hunter.get("impact", "")})
    for alt in finding.get("alternates") or []:
        claims.append({"source": "merged duplicate", "title": alt.get("title", ""),
                       "root_cause": alt.get("root_cause", ""), "impact": alt.get("impact", "")})
    if claims:
        summary["alternate_claims"] = claims
    return summary


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


def intended_scorer_model(router) -> str:
    targets = router.roles.get("scorer") or []
    return targets[0]["model"] if targets else ""


def scorer_fallback_error(router) -> str:
    """"" if the scorer ran on its configured primary model, else why to abort.

    A score graded by a fallback model is not a result: the free fallback has already been
    observed degenerating (comparing all 23 bugs against one finding). Better no number than
    a number from a different grader than the one named.
    """
    intended = intended_scorer_model(router)
    used = {c["model"] for c in router.call_log if c["role"] == "scorer"}
    strayed = used - {intended}
    if strayed:
        return f"scored by {', '.join(sorted(strayed))}, not the configured {intended!r}"
    return ""


async def _score_one_call(router, gt_id: str, gt_text: str, candidates_json: str, attempt: int,
                          pass_id: str = "") -> dict:
    """One grading call for ONE bug. Retried once on a 429; 402 aborts the whole run."""
    user = (
        "TASK: SCORE\n\n"
        f"GROUND-TRUTH BUG {gt_id}:\n{gt_text}\n\n"
        f"CANDIDATE FINDINGS:\n{candidates_json}"
    )
    for tries in (1, 2):
        try:
            return await router.chat_json(
                "scorer", SYSTEM_PROMPT, user, temperature=0.0,
                ceiling=SCORER_CALL_CEILING,
                # Repeats must actually re-sample: without a distinct salt every repeat is one
                # cache hit and the "majority" is one opinion counted three times.
                cache_salt=f"{pass_id}:{gt_id}#{attempt}" if pass_id else f"{gt_id}#{attempt}",
            )
        except OutOfCredits:
            raise
        except Exception as exc:  # noqa: BLE001
            if tries == 1 and "429" in str(exc):
                await asyncio.sleep(RETRY_DELAY_SECONDS)
                continue
            # NOT silently a MISS: an ungraded bug that counts as MISS understates recall and
            # looks identical to a real miss. Marked failed and reconciled by the caller.
            print(f"  {gt_id}: grading call failed ({str(exc)[:80]})")
            return {"verdict": None, "failed": True, "why": f"grading call failed: {exc}"}


def majority(votes: list) -> tuple:
    """(verdict, agreement, finding_id). With no majority, take the most conservative verdict
    seen: an unreproducible match is not a match."""
    verdicts = [v.get("verdict") for v in votes]
    counts = Counter(verdicts)
    top, n = counts.most_common(1)[0]
    if n == 1:  # all three disagreed
        top = min(verdicts, key=lambda x: _VERDICTS.index(x) if x in _VERDICTS else -1, default="MISS")
        top = "MISS" if "MISS" in verdicts else top
        n = counts[top]
    ids = [v.get("finding_id") for v in votes if v.get("verdict") == top and v.get("finding_id")]
    return top, f"{n}/{len(votes)}", (Counter(ids).most_common(1)[0][0] if ids else None)


async def score_all_bugs(router, gt_entries: dict, candidates: list, repeats: int = SCORE_REPEATS,
                         pass_id: str = ""):
    """One call per ground-truth bug, repeated, majority wins.

    Runs `repeats` calls per bug and only pays for a third when those disagree, so a bug the
    grader is confident about costs two calls and a contested one costs three.
    """
    payloads, why = {}, {}
    for gid, text in gt_entries.items():
        subset, reason = candidates_for_bug(text, candidates)
        payloads[gid] = json.dumps(subset, indent=2, sort_keys=True)
        why[gid] = reason
    for gid in sorted(gt_entries):
        print(f"  {gid}: grading against {why[gid]}")

    async def run(gid, attempt):
        return await _score_one_call(router, gid, gt_entries[gid], payloads[gid], attempt, pass_id)

    jobs = [(gid, a) for gid in sorted(gt_entries) for a in range(repeats)]
    print(f"scoring {len(gt_entries)} bugs x {repeats} repeats = {len(jobs)} calls (3rd only on a tie)")
    results = await asyncio.gather(*(run(gid, a) for gid, a in jobs))

    by_bug = {}
    for (gid, _), res in zip(jobs, results):
        by_bug.setdefault(gid, []).append(res if isinstance(res, dict) else {"verdict": None, "failed": True})

    # tie-break only where the first calls disagree
    contested = [gid for gid, votes in by_bug.items()
                 if len({v.get("verdict") for v in votes if not v.get("failed")}) > 1]
    if contested:
        print(f"tie-breaking {len(contested)} contested bug(s): {', '.join(sorted(contested))}")
        extra = await asyncio.gather(*(run(gid, repeats) for gid in contested))
        for gid, res in zip(contested, extra):
            by_bug[gid].append(res if isinstance(res, dict) else {"verdict": None, "failed": True})

    ungradeable = [gid for gid, votes in by_bug.items() if all(v.get("failed") for v in votes)]
    if ungradeable:
        raise RuntimeError(
            f"{len(ungradeable)} ground-truth bug(s) could not be graded at all "
            f"({', '.join(sorted(ungradeable)[:5])}): scoring them as MISS would understate recall"
        )

    scores, agreements = [], {}
    for gid in sorted(gt_entries):
        votes = [v for v in by_bug[gid] if not v.get("failed")]
        verdict, agreement, fid = majority(votes)
        agreements[gid] = agreement
        why_text = next((v.get("why", "") for v in votes if v.get("verdict") == verdict), "")
        scores.append({"gt_id": gid, "verdict": verdict, "finding_id": fid,
                       "why": why_text, "agreement": agreement,
                       "candidates_considered": why[gid],
                       "votes": [v.get("verdict") for v in votes]})
    return scores, agreements


def derive_off_catalog(scores: list, candidates: list) -> list:
    """Candidates no bug matched. Derived, not asked for: it needs no judgement, and a model
    asked to list them alongside grading was the source of the old boilerplate."""
    matched = {s["finding_id"] for s in scores if s.get("finding_id")}
    return [{"finding_id": c["id"], "note": "matched no ground-truth bug"}
            for c in candidates if c.get("id") not in matched]


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

    gt_entries = split_ground_truth(truth_text)
    if not gt_entries:
        print(f"score: no '### <id> - <title>' ground-truth entries found in {args.truth}")
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
    repeats = int(getattr(args, "repeats", None) or SCORE_REPEATS)

    router = None
    try:
        router = Router(models_path=args.models, local_only=args.local_only)
        scores, agreements = await score_all_bugs(
            router, gt_entries, candidates, repeats, pass_id=getattr(args, "pass_id", "") or ""
        )
    except OutOfCredits as exc:
        print(f"OUT OF CREDITS — run aborted: {exc}")
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"score failed: {str(exc)[:300]}")
        return 1

    strayed = scorer_fallback_error(router)
    if strayed:
        print(f"SCORE ABORTED: {strayed}. A run graded by a fallback scorer is not a result; "
              f"no score.json written.")
        return 2

    sanitize_warnings = _sanitize(scores, known_ids)
    for w in sanitize_warnings:
        print(f"WARNING: {w}")
    off_catalog = derive_off_catalog(scores, candidates)

    exact = sum(1 for s in scores if s["verdict"] == "EXACT")
    partial = sum(1 for s in scores if s["verdict"] == "PARTIAL")
    miss = sum(1 for s in scores if s["verdict"] == "MISS")
    n = len(scores)
    weighted_recall = (exact + 0.5 * partial) / n * 100 if n else 0.0

    matched_ids = {s["finding_id"] for s in scores if s["finding_id"] in known_ids}
    precision = (len(matched_ids) / len(scored_findings) * 100) if scored_findings else 0.0

    unanimous = sum(1 for a in agreements.values() if a.startswith(str(repeats)))
    print(f"{'gt_id':7} {'verdict':8} {'agree':6} {'finding':8} why")
    for s in scores:
        print(f"{s['gt_id']:7} {s['verdict']:8} {s.get('agreement',''):6} "
              f"{str(s.get('finding_id') or '-'):8} {s.get('why','')[:90]}")
    print()
    print(f"EXACT: {exact}  PARTIAL: {partial}  MISS: {miss}")
    print(f"weighted recall: {weighted_recall:.1f}%")
    print(f"precision proxy: {precision:.1f}%")
    print(f"scorer agreement: {unanimous}/{n} bugs unanimous across {repeats} repeats")

    if off_catalog:
        print()
        print(f"off-catalog: {len(off_catalog)} candidate(s) matched no ground-truth bug")

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
        "repeats": repeats,
        "agreement": agreements,
        "unanimous_bugs": unanimous,
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
