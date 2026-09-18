"""scan orchestration: map -> hunt -> dedup -> citation gate -> judge -> judge2 -> poc -> report.

This is the only module that spends money: everything it calls (agents.py)
degrades gracefully on its own, so the job here is sequencing, honest
accounting of what was and wasn't checked, and never spending past a plan
the operator already saw.
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path

from .agents import hunter, judge, mapper, poc
from .codebase import chunk, load
from .knowledge import load_kb, poc_refs, select
from .llm import Router
from .schema import SEV_RANK, Verdict
from .verify import dedup, judge_context, snippets, spans

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


async def scan(args) -> int:
    kb = load_kb(args.kb)
    scope_globs = _read_scope_globs(args.scope)
    known_text = _read_text_or_empty(args.known)
    notes_text = _read_text_or_empty(args.notes)

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
    (run_dir / "map.json").write_text(map_text or "{}")

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
                found.append(finding)

    # --- DEDUP ---
    deduped = dedup(found, files)
    print(f"{len(found)} raw -> {len(deduped)} unique")

    # --- CITATION GATE ---
    verdicts = {}
    queue = []
    for c in deduped:
        if spans(c["location"], files):
            queue.append(c)
        else:
            verdicts[c["id"]] = Verdict(
                verdict="kill",
                reason="location does not resolve to a real, in-range line",
                killed_by="citation gate",
            )

    # --- JUDGE QUEUE ---
    queue.sort(key=lambda c: (-c.get("votes", 1), SEV_RANK[c["severity"]], -c.get("confidence", 0.5)))
    overflow, queue = queue[args.max_judge:], queue[: args.max_judge]
    for c in overflow:
        verdicts[c["id"]] = Verdict(verdict="needs_poc", reason="not judged (over --max-judge)")

    contexts = {c["id"]: judge_context(c["location"], files, args.judge_budget) for c in queue}

    # --- JUDGE ---
    judge1 = await asyncio.gather(
        *(
            judge(router, kb, "judge", c, contexts[c["id"]], pmap=map_text, known=known_text, killed=killed_text)
            for c in queue
        )
    )
    for c, verdict in zip(queue, judge1):
        verdicts[c["id"]] = verdict

    keeps = [c for c in queue if verdicts[c["id"]].verdict == "keep"]
    if not args.no_judge2 and router.has("judge2") and keeps:
        judge2 = await asyncio.gather(
            *(
                judge(router, kb, "judge2", c, contexts[c["id"]], pmap=map_text, known=known_text, killed=killed_text)
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

    poc_targets = [c for c in deduped if verdicts[c["id"]].verdict != "kill"]
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
        if c["id"] in poc_paths:
            entry["poc_path"] = str(poc_paths[c["id"]])
        findings_out.append(entry)
    (run_dir / "findings.json").write_text(json.dumps(findings_out, indent=2, sort_keys=True))

    (run_dir / "report.md").write_text(_render_report(args.target, deduped, verdicts, files))

    print(f"wrote {run_dir}")
    print(json.dumps(router.report(), indent=2))
    return 0


def _render_report(target, deduped, verdicts, files) -> str:
    lines = [
        f"# hound scan report: {target}",
        "",
        "> Machine output. UNVERIFIED until I read the cited lines and run the PoC.",
        "",
        "| id | verdict | severity | votes | lenses | title | location |",
        "|---|---|---|---|---|---|---|",
    ]

    def sort_key(c):
        v = verdicts[c["id"]]
        return (_VERDICT_ORDER[v.verdict], SEV_RANK[_severity_for_report(c, v)], -c.get("votes", 1))

    ordered = sorted(deduped, key=sort_key)

    for c in ordered:
        v = verdicts[c["id"]]
        lines.append(
            f"| {c['id']} | {v.verdict} | {_severity_for_report(c, v)} | {c.get('votes', 1)} | "
            f"{', '.join(c.get('lenses', []))} | {c['title']} | {c['location']} |"
        )

    lines.append("")
    for c in ordered:
        v = verdicts[c["id"]]
        if v.verdict == "kill":
            continue
        lines.append(f"## {c['id']} — {c['title']}")
        lines.append("")
        lines.append(f"- Verdict: {v.verdict}")
        lines.append(f"- Severity: {_severity_for_report(c, v)} (hunter said {c['severity']})")
        lines.append(f"- Bug class: {c.get('bug_class', '')}")
        lines.append(f"- Location: {c['location']}")
        lines.append(f"- Votes: {c.get('votes', 1)} (lenses: {', '.join(c.get('lenses', []))})")
        lines.append("")
        lines.append(f"Root cause: {c['root_cause']}")
        lines.append("")
        lines.append(f"Impact: {c['impact']}")
        lines.append("")
        lines.append("Exploit steps:")
        for i, step in enumerate(c.get("exploit_steps", []), start=1):
            lines.append(f"{i}. {step}")
        lines.append("")
        lines.append(f"Falsify by: {c.get('falsification', '')}")
        lines.append("")
        lines.append(f"Judge: {v.verdict} — {v.reason}")
        lines.append("")

        snippet = snippets(c["location"], files, pad=3)
        if snippet:
            lines.append("```")
            lines.append(snippet)
            lines.append("```")
        lines.append("")

    killed = [c for c in ordered if verdicts[c["id"]].verdict == "kill"]
    if killed:
        lines.append("## Killed")
        lines.append("")
        for c in killed:
            v = verdicts[c["id"]]
            lines.append(f"- {c['id']}: killed_by={v.killed_by or 'unspecified'} — {v.reason}")

    return "\n".join(lines)
