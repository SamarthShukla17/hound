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
from .codebase import build_provenance, chunk, load, rel_path
from .knowledge import load_kb, poc_refs, select
from .llm import Router
from .runs import CITATION_GATE, STALE_CITATION, is_hard_kill, write_findings
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


def _cited_provenance(full: dict, deduped: list) -> dict:
    cited = {rel for c in deduped for rel in (c.get("cited") or {})}
    return {**full, "files": {rel: meta for rel, meta in full["files"].items() if rel in cited}}


async def scan(args) -> int:
    kb = load_kb(args.kb)
    scope_globs = _read_scope_globs(args.scope)
    known_text = _read_text_or_empty(args.known)
    notes_text = _read_text_or_empty(args.notes)

    judge_mode = getattr(args, "judge_mode", "advisory")
    if judge_mode not in JUDGE_MODES:
        print(f"unknown --judge-mode {judge_mode!r} (expected one of {', '.join(JUDGE_MODES)})")
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
    print(f"judge mode: {judge_mode}" + (" (judge annotates; nothing it says removes a candidate)" if judge_mode == "advisory" else " (judge kills are removed from the default scored set)"))

    if args.dry_run:
        for lens in lenses:
            print(f"  {lens.id:4} {lens.kind:8} {lens.title}")
        return 0

    router = Router(models_path=args.models, local_only=args.local_only, seed=args.seed, fresh=args.fresh)

    # --- MAP ---
    raw_maps = await asyncio.gather(*(mapper(router, kb, c, notes_text) for c in chunks))
    merged_map = _merge_maps(raw_maps)
    map_text = _map_text(merged_map, args.map_cap)

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
    for p in range(args.passes):
        already = [f"{c['title']} ({c['location']})" for c in found]
        temp = args.temp + 0.15 * p
        tasks = [
            hunter(router, kb, lens, c, pmap=map_text, known=known_text, killed=killed_text, already=already, temp=temp)
            for c in chunks
            for lens in lenses
        ]
        for findings in await asyncio.gather(*tasks):
            for finding in findings:
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
    queue.sort(key=lambda c: (-c.get("votes", 1), SEV_RANK[c["severity"]], -c.get("confidence", 0.5)))
    overflow, queue = queue[args.max_judge:], queue[: args.max_judge]
    for c in overflow:
        verdicts[c["id"]] = Verdict(verdict="needs_poc", reason="not judged (over --max-judge)")

    contexts = {c["id"]: judge_context(c["location"], files, args.judge_budget) for c in queue}

    # --- JUDGE ---
    judge1 = await asyncio.gather(
        *(
            judge(
                router, kb, "judge", c, contexts[c["id"]], pmap=map_text, known=known_text,
                killed=killed_text, cache_salt=_cited_salt(c),
            )
            for c in queue
        )
    )
    for c, verdict in zip(queue, judge1):
        verdicts[c["id"]] = verdict

    keeps = [c for c in queue if verdicts[c["id"]].verdict == "keep"]
    if not args.no_judge2 and not router.has("judge2") and keeps:
        print(f"judge2: no target configured — {len(keeps)} keeps are single-judge, no dissent signal")
    if not args.no_judge2 and router.has("judge2") and keeps:
        judge2 = await asyncio.gather(
            *(
                judge(
                    router, kb, "judge2", c, contexts[c["id"]], pmap=map_text, known=known_text,
                    killed=killed_text, cache_salt=_cited_salt(c),
                )
                for c in keeps
            )
        )
        for c, v2 in zip(keeps, judge2):
            if v2.verdict == "kill":
                v1 = verdicts[c["id"]]
                verdicts[c["id"]] = Verdict(
                    verdict="needs_poc",
                    reason=f"{v1.reason} || JUDGE2 DISSENT: {v2.reason}",
                    severity=v1.severity,
                    killed_by=v1.killed_by,
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
            poc(router, kb, c, ctx, framework=fw, refs=refs_text)
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
    write_findings(run_dir, judge_mode, _cited_provenance(provenance_all, deduped), findings_out)

    (run_dir / "report.md").write_text(_render_report(args.target, deduped, verdicts, files, judge_mode, hard_ids))

    counts = {v: sum(1 for c in deduped if c["id"] not in hard_ids and verdicts[c["id"]].verdict == v)
              for v in ("keep", "kill", "needs_poc")}
    print(
        f"judge verdicts ({judge_mode}): keep={counts['keep']} kill={counts['kill']} "
        f"needs_poc={counts['needs_poc']} | removed by deterministic gates: {len(hard_ids)}"
    )
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
