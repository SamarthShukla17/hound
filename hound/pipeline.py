"""scan orchestration: map -> hunt -> dedup -> citation gate -> judge -> judge2 -> poc -> report.

This is the only module that spends money: everything it calls (agents.py)
degrades gracefully on its own, so the job here is sequencing, honest
accounting of what was and wasn't checked, and never spending past a plan
the operator already saw.
"""

import asyncio
import hashlib
import json
from datetime import datetime
from pathlib import Path

from .agents import hunter, judge, mapper, poc
from .codebase import build_provenance, check_provenance, chunk, load, rel_path
from .knowledge import load_kb, poc_refs, select
from .llm import OutOfCredits, Router, parse_cache_any_model
from .runs import CITATION_GATE, STALE_CITATION, is_hard_kill, read_findings, write_findings
from .scope import DEFAULT_PROFILE, resolve_scope
from .schema import SEV_RANK, Verdict
from .verify import dedup, judge_context, snippets, spans

JUDGE_MODES = ("advisory", "gate")

_VERDICT_ORDER = {"keep": 0, "needs_poc": 1, "kill": 2}
_MAP_LIST_FIELDS = ("actors", "entry_points", "state_machine", "subsystems", "trust_edges", "invariants")


def _read_text_or_empty(path) -> str:
    return Path(path).read_text() if path else ""


def _read_scope_globs(path):
    if not path:
        return None
    globs = []
    for line in Path(path).read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            globs.append(line)
    return globs or None


def _merge_maps(maps: list) -> dict:
    merged = {field: [] for field in _MAP_LIST_FIELDS}
    summaries = []
    for m in maps:
        if not isinstance(m, dict):
            continue
        for field in _MAP_LIST_FIELDS:
            value = m.get(field)
            if isinstance(value, list):
                merged[field].extend(value)
        summary = m.get("summary")
        if isinstance(summary, str) and summary.strip():
            summaries.append(summary.strip())
    merged["summary"] = "\n".join(summaries)
    return merged


def _map_text(merged: dict, map_cap: int) -> str:
    is_empty = not merged["summary"] and not any(merged[f] for f in _MAP_LIST_FIELDS)
    if is_empty:
        return ""
    return json.dumps(merged, sort_keys=True, indent=2)[:map_cap]


def _severity_for_report(cand: dict, verdict: Verdict) -> str:
    return verdict.severity or cand["severity"]


def _cited_salt(cand: dict) -> str:
    """Hash of the exact files this candidate cites, folded into judge cache keys. The
    judge's prompt may be only a window of the file, so an edit elsewhere in the file
    would otherwise still hit a cached verdict about the old contents."""
    cited = cand.get("cited") or {}
    joined = "\n".join(f"{path}:{sha}" for path, sha in sorted(cited.items()))
    return hashlib.sha256(joined.encode()).hexdigest() if joined else ""


def citation_gate(cands: list, current_files: list):
    """The deterministic hard gate. `current_files` is a FRESH load of the target.

    A candidate dies if its citation no longer resolves to a real in-range line
    (CITATION_GATE) or resolves but the file's content differs from what the hunter
    read (STALE_CITATION). Returns (queue, hard) where hard maps id -> kill Verdict.
    """
    queue, hard = [], {}
    for c in cands:
        expected = set((c.get("cited") or {}).values())
        if not spans(c["location"], current_files):
            hard[c["id"]] = Verdict(
                verdict="kill",
                reason="location does not resolve to a real, in-range line",
                killed_by=CITATION_GATE,
            )
        elif expected and not spans(c["location"], current_files, expected_hash=expected):
            hard[c["id"]] = Verdict(
                verdict="kill",
                reason="the cited file's content differs from what the hunter read",
                killed_by=STALE_CITATION,
            )
        else:
            queue.append(c)
    return queue, hard


def verify_disproofs(verdicts: dict, files: list) -> int:
    """Put every judge kill's disproof citation through the same gate the findings face.

    A kill deletes evidence, so it must point at real code. If the cited guard does not
    resolve to an in-range line, the kill is downgraded to needs_poc — the candidate goes to
    the human instead of being removed on an unverifiable claim. Deterministic gate kills are
    exempt: their disproof IS that the citation does not resolve. Returns how many were
    downgraded.
    """
    downgraded = 0
    for fid, v in list(verdicts.items()):
        if v.verdict != "kill" or v.killed_by in (CITATION_GATE, STALE_CITATION):
            continue
        if spans(v.disproof_location, files):
            continue
        verdicts[fid] = Verdict(
            verdict="needs_poc",
            reason=f"{v.reason} || KILL NOT ACCEPTED: disproof citation "
                   f"{v.disproof_location!r} does not resolve to a real in-range line",
            severity=v.severity,
        )
        downgraded += 1
    return downgraded


def _cited_provenance(full: dict, deduped: list) -> dict:
    cited = {rel for c in deduped for rel in (c.get("cited") or {})}
    return {**full, "files": {rel: meta for rel, meta in full["files"].items() if rel in cited}}


async def run_judges(router, kb, queue, contexts, *, map_text, known, killed, notes, scope, no_judge2, files=()) -> dict:
    """The judge stage: judge every queued candidate, then judge2 (if configured) on the keeps.

    Shared by scan and rejudge so a re-judge is exactly the judge stage of a scan, nothing
    else. A judge2 kill downgrades a keep to needs_poc with the dissent appended: a
    disagreement between two model families is information for the human, not a tiebreak.
    """
    def call(role, c):
        return judge(
            router, kb, role, c, contexts[c["id"]], pmap=map_text, known=known, killed=killed,
            cache_salt=_cited_salt(c), scope=scope, notes=notes,
        )

    results = await asyncio.gather(*(call("judge", c) for c in queue))
    verdicts = {c["id"]: v for c, v in zip(queue, results)}

    unciteable = verify_disproofs(verdicts, files)
    if unciteable:
        print(f"{unciteable} judge kill(s) downgraded to needs_poc: disproof citation did not resolve")

    keeps = [c for c in queue if verdicts[c["id"]].verdict == "keep"]
    if not no_judge2 and not router.has("judge2") and keeps:
        print(f"judge2: no target configured — {len(keeps)} keeps are single-judge, no dissent signal")
    if not no_judge2 and router.has("judge2") and keeps:
        for c, v2 in zip(keeps, await asyncio.gather(*(call("judge2", c) for c in keeps))):
            if v2.verdict == "kill":
                v1 = verdicts[c["id"]]
                verdicts[c["id"]] = Verdict(
                    verdict="needs_poc",
                    reason=f"{v1.reason} || JUDGE2 DISSENT: {v2.reason}",
                    severity=v1.severity,
                    killed_by=v1.killed_by,
                )
    return verdicts


def judge_queue(queue: list, max_judge: int):
    """Order candidates by (votes, severity, confidence); anything past max_judge becomes an
    explicit needs_poc "not judged", never silently dropped. Returns (queue, overflow_verdicts)."""
    queue = sorted(queue, key=lambda c: (-c.get("votes", 1), SEV_RANK[c["severity"]], -c.get("confidence", 0.5)))
    overflow, queue = queue[max_judge:], queue[:max_judge]
    return queue, {c["id"]: Verdict(verdict="needs_poc", reason="not judged (over --max-judge)") for c in overflow}


ABORT_MESSAGE = "OUT OF CREDITS — run aborted"
MAP_FAILED_EXIT = 3


async def scan(args) -> int:
    try:
        return await _scan(args)
    except OutOfCredits as exc:
        print(f"{ABORT_MESSAGE}: {exc}")
        return 2


async def rejudge(args) -> int:
    try:
        return await _rejudge(args)
    except OutOfCredits as exc:
        print(f"{ABORT_MESSAGE}: {exc}")
        return 2


async def _scan(args) -> int:
    kb = load_kb(args.kb)
    scope_globs = _read_scope_globs(args.scope)
    known_text = _read_text_or_empty(args.known)
    notes_text = _read_text_or_empty(args.notes)

    judge_mode = getattr(args, "judge_mode", "advisory")
    if judge_mode not in JUDGE_MODES:
        print(f"unknown --judge-mode {judge_mode!r} (expected one of {', '.join(JUDGE_MODES)})")
        return 1

    try:
        scope = resolve_scope(getattr(args, "scope_profile", DEFAULT_PROFILE), getattr(args, "scope_rules", None))
    except (OSError, ValueError) as exc:
        print(f"scope rules: {exc}")
        return 1

    files, refused = load(args.target, scope_globs)
    print(f"{len(files)} files in scope, {len(refused)} refused")
    if refused:
        for path in refused[:5]:
            print(f"  refused: {path}")
        if len(refused) > 5:
            print(f"  ... and {len(refused) - 5} more")
    if not files:
        print("no files in scope — check --scope globs against the target's actual paths")
        return 1

    total_lines = sum(len(f.lines) for f in files)
    chunks = chunk(files, args.budget)
    lenses = select(kb.lenses, args.lenses)
    hunter_calls = len(chunks) * len(lenses) * args.passes

    print(f"files: {len(files)}  lines: {total_lines}  chunks: {len(chunks)}  lenses: {len(lenses)}  passes: {args.passes}")
    print(f"planned: {len(chunks)} map calls + {hunter_calls} hunter calls + up to {args.max_judge} judge calls")
    print(f"scope profile: {scope.name} ({scope.source})")
    print(f"judge mode: {judge_mode}" + (" (judge annotates; nothing it says removes a candidate)" if judge_mode == "advisory" else " (judge kills are removed from the default scored set)"))

    if args.dry_run:
        for lens in lenses:
            print(f"  {lens.id:4} {lens.kind:8} {lens.title}")
        return 0

    router = Router(
        models_path=args.models, local_only=args.local_only, seed=args.seed, fresh=args.fresh,
        cache_any_model=parse_cache_any_model(getattr(args, "cache_any_model", None)),
    )

    # --- MAP ---
    # Hunting with an empty map is not a degraded run, it is a different experiment: every
    # hunter prompt loses its MAP block. Retry once, then abort rather than produce a seed
    # that cannot be compared with the ones beside it.
    raw_maps = await asyncio.gather(*(mapper(router, kb, c, notes_text, scope=scope) for c in chunks))
    failed = [i for i, m in enumerate(raw_maps) if not m]
    if failed:
        print(f"mapper returned nothing for {len(failed)}/{len(chunks)} chunk(s); retrying once")
        router.fresh = True  # never re-serve the failed reply from cache
        retried = await asyncio.gather(
            *(mapper(router, kb, chunks[i], notes_text, scope=scope) for i in failed)
        )
        router.fresh = args.fresh
        for i, m in zip(failed, retried):
            raw_maps[i] = m
        still_failed = [i for i, m in enumerate(raw_maps) if not m]
        if still_failed:
            print(
                f"SEED ABORTED: mapper failed for {len(still_failed)}/{len(chunks)} chunk(s) after a retry. "
                f"Hunting with an empty map would make this run non-comparable; no run written."
            )
            return MAP_FAILED_EXIT

    merged_map = _merge_maps(raw_maps)
    map_text = _map_text(merged_map, args.map_cap)
    map_ok = bool(map_text)

    run_dir = Path(args.out) / datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=True)
    provenance_all = build_provenance(args.target, files)
    (run_dir / "map.json").write_text(
        json.dumps({"provenance": provenance_all, "map": merged_map}, indent=2, sort_keys=True)
    )

    # --- HUNT ---
    # TODO(step 8): thread hound.corpus.recent() through as `killed` once it exists.
    killed_text = ""
    found = []
    # Which lenses actually produced candidates, and which produced nothing *because they
    # failed* — a zero is only a clean negative if status is ok.
    lens_stats = {lens.id: {"raw": 0, "status": "not reached"} for lens in lenses}
    for p in range(args.passes):
        already = [f"{c['title']} ({c['location']})" for c in found]
        temp = args.temp + 0.15 * p
        lens_order = [lens for _ in chunks for lens in lenses]
        tasks = [
            hunter(
                router, kb, lens, c, pmap=map_text, known=known_text, killed=killed_text, already=already,
                temp=temp, scope=scope, notes=notes_text,
            )
            for c in chunks
            for lens in lenses
        ]
        for (lens, result) in zip(lens_order, await asyncio.gather(*tasks)):
            stat = lens_stats[lens.id]
            if not result.ok:
                stat["status"] = f"failed: {result.error}"  # sticky: a failure in any pass counts
            elif stat["status"] == "not reached":
                stat["status"] = "ok"
            for finding in result.findings:
                stat["raw"] += 1
                finding["pass"] = p
                # sha256 of each file this finding cites, as the hunter read it.
                finding["cited"] = {
                    rel_path(args.target, src.path): src.sha256 for src, _, _ in spans(finding["location"], files)
                }
                found.append(finding)

    # --- DEDUP ---
    deduped = dedup(found, files)
    print(f"{len(found)} raw -> {len(deduped)} unique")

    # --- CITATION GATE (deterministic; a hard gate in both judge modes) ---
    # Reload from disk: a file edited since the hunter read it must not be judged as if
    # it still said what was cited.
    current_files, _ = load(args.target, scope_globs)
    queue, verdicts = citation_gate(deduped, current_files)
    hard_ids = set(verdicts)

    # --- JUDGE QUEUE ---
    queue, overflow_verdicts = judge_queue(queue, args.max_judge)
    verdicts.update(overflow_verdicts)

    contexts = {c["id"]: judge_context(c["location"], files, args.judge_budget) for c in queue}

    # --- JUDGE ---
    verdicts.update(
        await run_judges(
            router, kb, queue, contexts, map_text=map_text, known=known_text, killed=killed_text,
            notes=notes_text, scope=scope, no_judge2=args.no_judge2, files=files,
        )
    )

    # --- POC ---
    refs_text = poc_refs(kb.lenses)
    pocs_dir = run_dir / "pocs"
    pocs_dir.mkdir(parents=True, exist_ok=True)

    # PoC spend goes only to candidates the judge did not kill, in both modes: generating a
    # PoC is a cost decision, not the removal of evidence.
    poc_targets = [c for c in deduped if verdicts[c["id"]].verdict != "kill" and c["id"] not in hard_ids]
    poc_frameworks = ["Foundry (Solidity)" if ".sol" in c["location"] else "LiteSVM (Rust)" for c in poc_targets]
    poc_code_ctx = [
        contexts.get(c["id"]) or judge_context(c["location"], files, args.judge_budget) for c in poc_targets
    ]
    poc_results = await asyncio.gather(
        *(
            poc(router, kb, c, ctx, framework=fw, refs=refs_text, scope=scope)
            for c, ctx, fw in zip(poc_targets, poc_code_ctx, poc_frameworks)
        )
    )

    poc_paths = {}
    for c, framework, poc_code in zip(poc_targets, poc_frameworks, poc_results):
        ext = "t.sol" if "Solidity" in framework else "rs"
        poc_path = pocs_dir / f"{c['id']}.{ext}"
        poc_path.write_text(poc_code)
        poc_paths[c["id"]] = poc_path

    # --- WRITE ---
    findings_out = []
    for c in deduped:
        entry = dict(c)
        entry["verdict"] = verdicts[c["id"]].model_dump()
        entry["hard_kill"] = c["id"] in hard_ids
        if c["id"] in poc_paths:
            entry["poc_path"] = str(poc_paths[c["id"]])
        findings_out.append(entry)
    write_findings(
        run_dir, judge_mode, _cited_provenance(provenance_all, deduped), findings_out,
        scope=scope.as_dict(), seed=args.seed, lenses=args.lenses, passes=args.passes, scope_globs=scope_globs,
        map_ok=map_ok, lens_stats=lens_stats,
    )

    (run_dir / "report.md").write_text(_render_report(args.target, deduped, verdicts, files, judge_mode, hard_ids))

    counts = {v: sum(1 for c in deduped if c["id"] not in hard_ids and verdicts[c["id"]].verdict == v)
              for v in ("keep", "kill", "needs_poc")}
    print(
        f"judge verdicts ({judge_mode}): keep={counts['keep']} kill={counts['kill']} "
        f"needs_poc={counts['needs_poc']} | removed by deterministic gates: {len(hard_ids)}"
    )
    productive = {lid: st["raw"] for lid, st in lens_stats.items() if st["raw"]}
    broken = {lid: st["status"] for lid, st in lens_stats.items() if st["status"] not in ("ok", "not reached")}
    print(f"lenses producing candidates: {productive or 'NONE'} ({len(productive)}/{len(lens_stats)})")
    if broken:
        print(f"LENSES THAT FAILED (recall holes, not clean negatives): {broken}")
    print(f"wrote {run_dir}")
    print(json.dumps(router.report(), indent=2))
    return 0


def _detail_section(c: dict, v: Verdict, files, judge_label: str) -> list:
    lines = [
        f"## {c['id']} — {c['title']}",
        "",
        f"- {judge_label}: {v.verdict}",
        f"- Severity: {_severity_for_report(c, v)} (hunter said {c['severity']})",
        f"- Bug class: {c.get('bug_class', '')}",
        f"- Location: {c['location']}",
        f"- Votes: {c.get('votes', 1)} (lenses: {', '.join(c.get('lenses', []))})",
        "",
        f"Root cause: {c['root_cause']}",
        "",
        f"Impact: {c['impact']}",
        "",
        "Exploit steps:",
    ]
    for i, step in enumerate(c.get("exploit_steps", []), start=1):
        lines.append(f"{i}. {step}")
    lines += ["", f"Falsify by: {c.get('falsification', '')}", "", f"Judge: {v.verdict} — {v.reason}", ""]
    snippet = snippets(c["location"], files, pad=3)
    if snippet:
        lines += ["```", snippet, "```"]
    lines.append("")
    return lines


def _render_report(target, deduped, verdicts, files, judge_mode="advisory", hard_ids=frozenset()) -> str:
    advisory = judge_mode == "advisory"
    lines = [
        f"# hound scan report: {target}",
        "",
        "> Machine output. UNVERIFIED until I read the cited lines and run the PoC.",
        "",
    ]
    if advisory:
        lines += [
            "> Judge mode: **advisory**. The judge annotates every candidate; nothing it says removes "
            "one. Only the deterministic gates (citation, stale-citation) remove candidates.",
            "",
        ]
    else:
        lines += ["> Judge mode: **gate**. Candidates the judge killed are listed at the bottom.", ""]

    live = [c for c in deduped if c["id"] not in hard_ids]
    gated = [c for c in deduped if c["id"] in hard_ids]

    if advisory:
        # I triage: most independently-corroborated first, then by severity.
        ordered = sorted(live, key=lambda c: (-c.get("votes", 1), SEV_RANK[_severity_for_report(c, verdicts[c["id"]])], c["id"]))
        head, judge_label = "judge", "Judge opinion"
    else:
        ordered = sorted(
            live,
            key=lambda c: (
                _VERDICT_ORDER[verdicts[c["id"]].verdict],
                SEV_RANK[_severity_for_report(c, verdicts[c["id"]])],
                -c.get("votes", 1),
            ),
        )
        head, judge_label = "verdict", "Verdict"

    lines += [
        f"| id | {head} | severity | votes | lenses | title | location |",
        "|---|---|---|---|---|---|---|",
    ]
    for c in ordered:
        v = verdicts[c["id"]]
        lines.append(
            f"| {c['id']} | {v.verdict} | {_severity_for_report(c, v)} | {c.get('votes', 1)} | "
            f"{', '.join(c.get('lenses', []))} | {c['title']} | {c['location']} |"
        )
    lines.append("")

    for c in ordered:
        v = verdicts[c["id"]]
        if not advisory and v.verdict == "kill":
            continue
        lines += _detail_section(c, v, files, judge_label)

    if not advisory:
        judge_killed = [c for c in ordered if verdicts[c["id"]].verdict == "kill"]
        if judge_killed:
            lines += ["## Killed by the judge", ""]
            for c in judge_killed:
                v = verdicts[c["id"]]
                lines.append(f"- {c['id']}: killed_by={v.killed_by or 'unspecified'} — {v.reason}")
            lines.append("")

    if gated:
        lines += ["## Removed by deterministic gates", ""]
        for c in gated:
            v = verdicts[c["id"]]
            lines.append(f"- {c['id']} ({c['title']}): killed_by={v.killed_by} — {v.reason}")

    return "\n".join(lines)


def _verdict_counts(candidates: list, verdicts: dict, hard_ids) -> dict:
    return {
        v: sum(1 for c in candidates if c["id"] not in hard_ids and verdicts[c["id"]].verdict == v)
        for v in ("keep", "kill", "needs_poc")
    }


async def _rejudge(args) -> int:
    """Re-run ONLY the judge stage on a finished run and write a new run dir.

    Hunting is the expensive, free-tier-rate-limited half; judge prompts and scope rules are
    what you iterate on. This reads findings.json, refuses if the code on disk no longer
    matches the provenance recorded when the hunter read it (a judge must not read different
    code than was cited), and re-judges the same candidates under the given scope rules.
    """
    src_dir = Path(args.run_dir)
    try:
        meta, findings = read_findings(src_dir)
        map_doc = json.loads((src_dir / "map.json").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"rejudge: cannot read the run: {exc}")
        return 1

    provenance = meta.get("provenance")
    if not provenance:
        print("rejudge: this run predates provenance, so the code it read can't be verified; re-scan instead")
        return 1
    problems = check_provenance(provenance)
    if problems:
        print("rejudge REFUSED: the working tree no longer matches what the hunter read:")
        for p in problems:
            print(f"  - {p}")
        return 1

    judge_mode = getattr(args, "judge_mode", "advisory")
    if judge_mode not in JUDGE_MODES:
        print(f"unknown --judge-mode {judge_mode!r} (expected one of {', '.join(JUDGE_MODES)})")
        return 1
    try:
        scope = resolve_scope(getattr(args, "scope_profile", DEFAULT_PROFILE), getattr(args, "scope_rules", None))
    except (OSError, ValueError) as exc:
        print(f"scope rules: {exc}")
        return 1

    kb = load_kb(args.kb)
    known_text = _read_text_or_empty(args.known)
    notes_text = _read_text_or_empty(args.notes)
    scope_globs = meta.get("scope_globs")
    files, _ = load(provenance["target"], scope_globs)
    merged_map = map_doc.get("map") if isinstance(map_doc, dict) else None
    map_text = _map_text(merged_map, args.map_cap) if isinstance(merged_map, dict) and "summary" in merged_map else ""

    carried_hard = {f["id"] for f in findings if is_hard_kill(f)}
    verdicts = {f["id"]: Verdict(**f["verdict"]) for f in findings if f["id"] in carried_hard}
    live = [f for f in findings if f["id"] not in carried_hard]
    queue, new_hard = citation_gate(live, files)
    verdicts.update(new_hard)
    hard_ids = carried_hard | set(new_hard)
    queue, overflow_verdicts = judge_queue(queue, args.max_judge)
    verdicts.update(overflow_verdicts)

    print(f"rejudging {len(queue)} of {len(findings)} candidates from {src_dir} "
          f"(carried over {len(carried_hard)} gate kills) under scope profile: {scope.name} ({scope.source})")
    router = Router(
        models_path=args.models, local_only=args.local_only, seed=meta.get("seed", 0), fresh=args.fresh,
        cache_any_model=parse_cache_any_model(getattr(args, "cache_any_model", None)),
    )
    contexts = {c["id"]: judge_context(c["location"], files, args.judge_budget) for c in queue}
    verdicts.update(
        await run_judges(
            router, kb, queue, contexts, map_text=map_text, known=known_text, killed="",
            notes=notes_text, scope=scope, no_judge2=args.no_judge2, files=files,
        )
    )

    run_dir = Path(args.out) / (datetime.now().strftime("%Y%m%d-%H%M%S") + "-rejudge")
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "map.json").write_text(json.dumps(map_doc, indent=2, sort_keys=True))

    out = []
    for f in findings:
        entry = {k: v for k, v in f.items() if k not in ("verdict", "poc_path", "hard_kill")}
        entry["verdict"] = verdicts[f["id"]].model_dump()
        entry["hard_kill"] = f["id"] in hard_ids
        out.append(entry)
    write_findings(
        run_dir, judge_mode, provenance, out, scope=scope.as_dict(), seed=meta.get("seed", 0),
        lenses=meta.get("lenses"), passes=meta.get("passes"), scope_globs=scope_globs,
        rejudged_from=str(src_dir),
    )
    (run_dir / "report.md").write_text(
        _render_report(provenance["target"], out, verdicts, files, judge_mode, hard_ids)
    )

    counts = _verdict_counts(out, verdicts, hard_ids)
    print(f"judge verdicts ({judge_mode}): keep={counts['keep']} kill={counts['kill']} needs_poc={counts['needs_poc']}")
    print(f"wrote {run_dir}")
    print(json.dumps(router.report(), indent=2))
    return 0
