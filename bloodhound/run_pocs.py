"""run-pocs: feed each live candidate's PoC scaffold through the Forger, the Refutation Panel,
the Novelty classifier (when the panel doesn't kill it), and the Dossier renderer.

Mirrors hound.chain's command shape (read findings.json, resolve the target, run, write back)
but never re-decides severity or kills a finding — it only attaches `entry["forge"]`,
`entry["refute"]`, `entry["novelty"]`, and `entry["dossier_path"]` for a human (or `hound score`)
to read alongside the judge's own verdict. Only Foundry (Solidity) PoCs are forged; a LiteSVM
(Rust) poc_path is left untouched — the differential gate as written compiles/runs against
`forge`, not `cargo`.
"""

from pathlib import Path

from hound.runs import is_hard_kill, read_findings, write_findings

from .dossier import render as render_dossier
from .forger import forge_candidate
from .novelty import classify, load_records
from .refute import run_panel

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
    corpus = load_records(args.corpus) if args.corpus else []

    forge_results = {}
    panel_results = {}
    novelty_results = {}
    for c in candidates:
        if router is None:
            print(f"{c['id']}: skipped (--no-llm; the compile/repair loop needs a router)")
            continue
        result = await forge_candidate(
            router, kb, c, Path(c["poc_path"]).read_text(), target, forge_dir,
            max_repairs=args.max_repairs,
        )
        forge_results[c["id"]] = result
        print(f"{c['id']}: {result.status}" + (f" ({result.notes})" if result.notes else ""))

        if result.status != "forged" or args.no_panel:
            continue
        panel = await run_panel(router, kb, c, result, target, forge_dir)
        panel_results[c["id"]] = panel
        verb = "KILLED by refutation" if panel.killed else "survived the panel"
        print(f"{c['id']}: {verb}" + (f" — {panel.surviving_refutation}" if panel.surviving_refutation else ""))

        if panel.killed or not corpus:
            continue
        novelty = await classify(router, args.embed_role, c, corpus)
        novelty_results[c["id"]] = novelty
        print(f"{c['id']}: novelty={novelty.verdict}" + (f" ({novelty.notes})" if novelty.notes else ""))

    commit = (meta.get("provenance") or {}).get("commit") or ""
    dossier_dir = Path(args.run_dir) / "dossiers"
    by_id = {f["id"]: f for f in findings}
    dossier_paths = {}
    for fid, r in forge_results.items():
        if r.status != "forged":
            continue
        panel = panel_results.get(fid)
        if panel is not None and panel.killed:
            continue
        dossier_dir.mkdir(parents=True, exist_ok=True)
        text = render_dossier(by_id[fid], r, panel, novelty_results.get(fid), commit=commit)
        path = dossier_dir / f"{fid}.md"
        path.write_text(text)
        dossier_paths[fid] = path
        print(f"{fid}: dossier -> {path}")

    findings_out = []
    for f in findings:
        entry = dict(f)
        if f["id"] in forge_results:
            r = forge_results[f["id"]]
            entry["forge"] = {"status": r.status, "iterations": r.iterations, "notes": r.notes}
        if f["id"] in panel_results:
            p = panel_results[f["id"]]
            entry["refute"] = {
                "killed": p.killed,
                "surviving_refutation": p.surviving_refutation,
                "role_verdicts": p.role_verdicts,
                "notes": p.notes,
            }
        if f["id"] in novelty_results:
            n = novelty_results[f["id"]]
            entry["novelty"] = {"verdict": n.verdict, "nearest": n.nearest, "notes": n.notes}
        if f["id"] in dossier_paths:
            entry["dossier_path"] = str(dossier_paths[f["id"]])
        findings_out.append(entry)

    extra_meta = {k: v for k, v in meta.items() if k not in ("judge_mode", "provenance")}
    write_findings(args.run_dir, meta.get("judge_mode", "gate"), meta.get("provenance"), findings_out, **extra_meta)

    forged = sum(1 for r in forge_results.values() if r.status == "forged")
    killed_by_panel = sum(1 for p in panel_results.values() if p.killed)
    print(
        f"{len(candidates)} candidate(s) with a Foundry PoC, {len(forge_results)} forged-attempted, "
        f"{forged} confirmed forged, {killed_by_panel} killed by the refutation panel"
    )
    return 0
