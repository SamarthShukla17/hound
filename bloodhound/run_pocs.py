"""run-pocs: feed each live candidate's PoC scaffold through the Forger and record the verdict.

Mirrors hound.chain's command shape (read findings.json, resolve the target, run, write back)
but never re-decides severity or kills a finding — it only attaches `entry["forge"]`, the
execution-gated verdict, for a human (or `hound score`) to read alongside the judge's own verdict.
Only Foundry (Solidity) PoCs are forged; a LiteSVM (Rust) poc_path is left untouched — the
differential gate as written compiles/runs against `forge`, not `cargo`.
"""

from pathlib import Path

from hound.runs import is_hard_kill, read_findings, write_findings

from .forger import forge_candidate

FORGE_SUBDIR = "test/.bloodhound"


def forgeable(meta, findings) -> list:
    """Live candidates (not killed by judge or gate) with a Foundry PoC scaffold on disk."""
    hard_ids = {f["id"] for f in findings if is_hard_kill(f)}
    out = []
    for f in findings:
        if f["id"] in hard_ids:
            continue
        if (f.get("verdict") or {}).get("verdict") == "kill":
            continue
        poc_path = f.get("poc_path")
        if not poc_path or not str(poc_path).endswith(".t.sol"):
            continue
        out.append(f)
    return out


async def run_pocs_command(args) -> int:
    """`hound run-pocs RUN_DIR`: forge every live candidate's PoC scaffold against the real target."""
    from hound.knowledge import load_kb

    meta, findings = read_findings(args.run_dir)
    target = args.target or (meta.get("provenance") or {}).get("target")
    if not target:
        print("cannot find the target: pass --target PATH")
        return 1

    router = None
    if not args.no_llm:
        from hound.llm import Router

        router = Router(models_path=args.models, local_only=args.local_only, seed=0, fresh=False)

    kb = load_kb(args.kb)
    candidates = forgeable(meta, findings)
    forge_dir = Path(target) / FORGE_SUBDIR

    results = {}
    for c in candidates:
        if router is None:
            print(f"{c['id']}: skipped (--no-llm; the compile/repair loop needs a router)")
            continue
        result = await forge_candidate(
            router, kb, c, Path(c["poc_path"]).read_text(), target, forge_dir,
            max_repairs=args.max_repairs,
        )
        results[c["id"]] = result
        print(f"{c['id']}: {result.status}" + (f" ({result.notes})" if result.notes else ""))

    findings_out = []
    for f in findings:
        entry = dict(f)
        if f["id"] in results:
            r = results[f["id"]]
            entry["forge"] = {
                "status": r.status,
                "iterations": r.iterations,
                "notes": r.notes,
            }
        findings_out.append(entry)

    extra_meta = {k: v for k, v in meta.items() if k not in ("judge_mode", "provenance")}
    write_findings(args.run_dir, meta.get("judge_mode", "gate"), meta.get("provenance"), findings_out, **extra_meta)

    forged = sum(1 for r in results.values() if r.status == "forged")
    print(f"{len(candidates)} candidate(s) with a Foundry PoC, {len(results)} forged-attempted, {forged} confirmed forged")
    return 0
