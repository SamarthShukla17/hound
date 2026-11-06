"""invariants command: load human-curated claims, forge a handler per claim, run the fast gate.

Mirrors hound.config_check's target-based command shape (load the codebase, run, write
timestamped artifacts under --out) rather than hound.chain/run-pocs's run-dir shape, since an
invariant campaign starts from a claims file and a target, not from a finished scan.
"""

import json
from datetime import datetime
from pathlib import Path

from . import deepfuzz, manifest
from .costgov import BUDGET_EXCEEDED_EXIT_CODE, CostGovernor
from .invariants import forge_invariant, load_claims

HANDLER_SUBDIR = "test/.bloodhound/invariants"
DEEPFUZZ_SUBDIR = "test/.bloodhound/deepfuzz"
CONTEXT_BUDGET_CHARS = 60_000


def code_context(target_root, files, budget: int = CONTEXT_BUDGET_CHARS) -> str:
    """Concatenate in-scope source (hound.codebase.load's Src list) into one prompt block, each
    file headed by its path, cut off once `budget` is reached rather than truncating a file
    mid-body."""
    target_root = Path(target_root)
    parts, total = [], 0
    for src in files:
        rel = src.path.relative_to(target_root) if src.path.is_absolute() else src.path
        chunk = f"// ===== FILE: {rel} =====\n" + "\n".join(src.lines) + "\n"
        if total + len(chunk) > budget:
            break
        parts.append(chunk)
        total += len(chunk)
    return "\n".join(parts)


def to_dict(results: dict, deep_results: dict | None = None) -> dict:
    deep_results = deep_results or {}
    out = {
        cid: {"status": r.status, "iterations": r.iterations, "notes": r.notes, "trace": r.trace[:4000]}
        for cid, r in results.items()
    }
    for cid, tools in deep_results.items():
        out[cid]["deep_fuzz"] = {
            tool: {"status": dr.status, "notes": dr.notes, "raw_output": dr.raw_output[:4000]}
            for tool, dr in tools.items()
        }
    return out


def render(results: dict, deep_results: dict | None = None) -> str:
    deep_results = deep_results or {}
    lines = ["# Invariant Engine run", ""]
    for cid, r in results.items():
        lines.append(f"## {cid}: {r.status}")
        if r.notes:
            lines.append(f"- {r.notes}")
        if r.trace:
            lines += ["```", r.trace[:2000], "```"]
        for tool, dr in deep_results.get(cid, {}).items():
            lines.append(f"- deep-fuzz ({tool}): {dr.status}" + (f" — {dr.notes}" if dr.notes else ""))
        lines.append("")
    return "\n".join(lines) + "\n"


def write_artifacts(out_dir, results: dict, deep_results: dict | None = None) -> None:
    out_dir = Path(out_dir)
    (out_dir / "invariants.json").write_text(json.dumps(to_dict(results, deep_results), indent=2, sort_keys=True))
    (out_dir / "invariants.md").write_text(render(results, deep_results))


async def invariants_command(args) -> int:
    """`hound invariants TARGET --invariants PATH`."""
    from hound.codebase import load
    from hound.knowledge import load_kb
    from hound.llm import Router

    claims = load_claims(args.invariants)
    if args.claim:
        claims = [c for c in claims if c.id == args.claim]
    if not claims:
        print("no claims to run (check --invariants / --claim)")
        return 1

    files, _ = load(args.target, None)
    ctx = code_context(args.target, files)
    kb = load_kb(args.kb)
    router = Router(models_path=args.models, local_only=args.local_only, seed=0, fresh=False)
    handler_dir = Path(args.target) / HANDLER_SUBDIR
    deepfuzz_dir = Path(args.target) / DEEPFUZZ_SUBDIR
    governor = CostGovernor(router, args.max_cost)
    deep_fuzz_mode = getattr(args, "deep_fuzz", "off")

    results = {}
    deep_results = {}
    for claim in claims:
        if not governor.check():
            print(f"cost ceiling ${args.max_cost:.2f} reached (spent ${governor.spent():.2f}) — stopping, "
                  f"{len(claims) - len(results)} claim(s) not attempted")
            break
        result = await forge_invariant(router, kb, claim, ctx, args.target, handler_dir, max_repairs=args.max_repairs)
        results[claim.id] = result
        print(f"{claim.id}: {result.status}" + (f" ({result.notes})" if result.notes else ""))

        # Only escalate a "held" result: a counterexample already falsified the claim (a deeper
        # campaign confirms nothing new), and compile_failed left nothing to fuzz. Off by default
        # - a real campaign runs minutes per tool, not the seconds the fast gate takes.
        if deep_fuzz_mode != "off" and result.status == "held" and governor.check():
            deep_results[claim.id] = await deepfuzz.escalate(
                router, kb, claim, ctx, args.target, deepfuzz_dir, tool=deep_fuzz_mode,
                max_repairs=args.max_repairs, timeout=args.deep_fuzz_timeout,
            )
            for tool, dr in deep_results[claim.id].items():
                print(f"  deep-fuzz ({tool}): {dr.status}" + (f" — {dr.notes}" if dr.notes else ""))

    out = Path(args.out) / datetime.now().strftime("invariants-%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    write_artifacts(out, results, deep_results)
    manifest.write(
        out / "manifest.json", "invariants",
        {"target": args.target, "invariants": args.invariants, "claim": args.claim,
         "max_repairs": args.max_repairs, "max_cost_usd": args.max_cost, "deep_fuzz": deep_fuzz_mode},
        router, governor,
    )

    counterexamples = sum(1 for r in results.values() if r.status == "counterexample")
    print(f"{len(results)} claim(s) run, {counterexamples} counterexample(s), wrote {out}")
    return BUDGET_EXCEEDED_EXIT_CODE if governor.breached else 0
