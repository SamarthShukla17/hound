"""Deploy/config parameter cross-check: join, flag, review, report.

config_extract.py produces the raw facts; this module joins them into one table, adds the flags
that need no model (never set, verify-vs-deploy mismatch, gap against an upstream reference), and
hands the table to a reviewer with kb/CONFIG_CHECKS.md. The reviewer's job is the part machines
miss: magnitude/reachability of each threshold against the rest of the configuration, and
parameter pairs and triples that are only dangerous together.
"""

import asyncio
import json
import math
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ValidationError

from .config_extract import (
    ParamSpec, Setting, extract_settings, extract_specs, find_config_files, scale_label,
)
from .knowledge import load_doc
from .llm import OutOfCredits
from .solfuncs import find_functions

REVIEW_ROLES = ("config", "judge")
MAX_ROWS_IN_PROMPT = 160

SYSTEM = (
    "You are a senior smart-contract auditor cross-checking a protocol's deployed configuration against "
    "what its contracts assume. You compute; you never guess a value that is not in the table."
)


class RowVerdict(BaseModel):
    contract: str = ""
    param: str
    verdict: Literal["safe", "flag", "unverified"]
    reason: str = ""


class Combination(BaseModel):
    params: list[str]
    concern: str
    numbers: str = ""
    verify: str = ""


class Magnitude(BaseModel):
    param: str
    threshold: str = ""
    max_reachable: str = ""
    reachable: bool
    reason: str = ""


class ConfigReview(BaseModel):
    rows: list[RowVerdict] = []
    combinations: list[Combination] = []
    magnitude_checks: list[Magnitude] = []


@dataclass
class Row:
    contract: str
    param: str
    scope: str
    deployed_expr: str
    deployed_value: int | None
    human: str
    source: str
    checks: list = field(default_factory=list)
    readers: list = field(default_factory=list)
    asserted: list = field(default_factory=list)
    flags: list = field(default_factory=list)


@dataclass
class ConfigCheck:
    files: list
    rows: list = field(default_factory=list)
    unset: list = field(default_factory=list)  # setter branches the deploy never calls
    constants: list = field(default_factory=list)  # hard-coded parameters
    wiring: list = field(default_factory=list)  # address arguments (module wiring), not tunable values
    unmatched: list = field(default_factory=list)  # deploy settings with no matching setter
    review: dict = field(default_factory=dict)


def _norm(s: str) -> str:
    return s.lower().replace("_", "").strip()


def _reference_gap(row: Row, refs: list, hints: dict) -> str:
    """Flag a deployed value that differs materially from an upstream reference of the same name."""
    if not row.deployed_value:
        return ""
    for ref in refs:
        if _norm(ref["param"]) != _norm(row.param):
            continue
        ref_contract = ref.get("contract", "")
        if hints and row.contract in hints and ref_contract not in hints[row.contract]:
            continue
        try:
            rv = float(ref["value"])
        except (TypeError, ValueError):
            continue
        if rv <= 0:
            continue
        candidates = [row.deployed_value / s for s in (1, 10 ** 18, 10 ** 27, 10 ** 45)]
        best = min(candidates, key=lambda c: abs(math.log(c / rv)) if c > 0 else 1e9)
        if best <= 0:
            continue
        ratio = best / rv
        if abs(ratio - 1) > 0.15:  # a premium/discount parameter moves value by its own percentage
            return (f"differs from upstream reference {ref['value']} ({ref.get('context', '')}): "
                    f"deployed ~{best:g} is {ratio:.3g}x")
    return ""


def build(target_root, sources: dict, refs: list = None, hints: dict = None, scripts=None) -> ConfigCheck:
    """`sources` = {path: Solidity text}; `scripts` = explicit config files (default: discovered)."""
    root = Path(target_root)
    scripts = scripts if scripts is not None else find_config_files(root)
    contract_names = {f.contract for text in sources.values() for f in find_functions(text)}
    settings = []
    for p in scripts:
        settings += extract_settings(Path(p).read_text(encoding="utf-8", errors="replace"), str(Path(p).relative_to(root)), contract_names)
    specs = extract_specs(sources)
    check = ConfigCheck(files=[str(Path(p).relative_to(root)) for p in scripts])
    setters = {(s.contract, _norm(s.name)): s for s in specs if s.kind == "setter"}
    by_name = {}
    for s in specs:
        if s.kind == "setter":
            by_name.setdefault(_norm(s.name), []).append(s)
    defaults = {(s.contract, s.variable): s for s in specs if s.kind == "default"}
    check.constants = [s for s in specs if s.kind == "constant"]

    asserts = [s for s in settings if s.kind == "assert"]
    set_keys = set()
    for st in (s for s in settings if s.kind == "param"):
        spec = setters.get((st.contract, _norm(st.name))) or (by_name.get(_norm(st.name)) or [None])[0]
        if spec is None:
            check.unmatched.append(f"{st.contract}.{st.name} = {st.expr} ({st.path}:{st.line})")
            continue
        set_keys.add((spec.contract, _norm(spec.name)))
        if st.value is None and re.fullmatch(r"\w*(Address|address|Addr)\w*|\w+\.address", st.expr.strip()):
            check.wiring.append(f"{spec.contract}.{spec.name} = {st.expr.strip()} ({st.path}:{st.line})")
            continue
        row = Row(spec.contract, spec.name, st.scope, " ".join(st.expr.split()), st.value, scale_label(st.value),
                  f"{st.path}:{st.line}", spec.checks, spec.readers)
        for a in asserts:
            if _norm(a.name) == _norm(spec.name) and _norm(a.contract) in (_norm(spec.contract), ""):
                row.asserted.append(f"{a.path}:{a.line} expects {' '.join(a.expr.split())}")
                if a.value is not None and st.value is not None and a.value != st.value and not st.scope:
                    row.flags.append(f"verify script expects {a.value} but deploy sets {st.value}")
        gap = _reference_gap(row, refs or [], hints or {})
        if gap:
            row.flags.append(gap)
        check.rows.append(row)

    for s in specs:
        if s.kind == "setter" and (s.contract, _norm(s.name)) not in set_keys:
            d = defaults.get((s.contract, s.variable))
            check.unset.append({
                "contract": s.contract, "param": s.name, "setter_checks": s.checks, "readers": s.readers,
                "default": (f"constructor sets {d.default_expr}" + (f" = {d.default_value}" if d.default_value is not None else ""))
                if d else "no constructor assignment (zero/false/none)",
                "loc": f"{s.path}:{s.line}",
            })
    return check


# ------------------------------------------------------------------ review + report


def _prompt(check: ConfigCheck) -> str:
    def row(r):
        return {"contract": r.contract, "param": r.param, "scope": r.scope, "deployed": r.deployed_expr,
                "value": r.deployed_value, "human": r.human, "source": r.source, "setter_checks": r.checks,
                "read_by": r.readers[:8], "verify_asserts": r.asserted, "flags": r.flags}

    payload = {
        "deployed_parameters": [row(r) for r in check.rows[:MAX_ROWS_IN_PROMPT]],
        "never_set_by_deploy": check.unset[:80],
        "hard_coded_constants": [{"contract": c.contract, "name": c.name, "expr": c.default_expr, "value": c.default_value,
                                  "loc": f"{c.path}:{c.line}"} for c in check.constants[:80]],
        "deploy_settings_with_no_matching_setter": check.unmatched[:40],
    }
    return "CONFIGURATION TABLE:\n" + json.dumps(payload, indent=1, default=str) + \
        "\n\nTASK: CONFIG CROSS-CHECK\nWork through every section of the checklist. Return ONLY the JSON object described in the output contract."


async def review(router, kb_doc: str, check: ConfigCheck) -> dict:
    role = next((r for r in REVIEW_ROLES if router.has(r)), None)
    if role is None:
        return {}
    try:
        data = await router.chat_json(role, "\n\n".join([SYSTEM, kb_doc]), _prompt(check), temperature=0.0)
        return ConfigReview(**data).model_dump()
    except OutOfCredits:
        raise
    except (ValidationError, TypeError, ValueError, RuntimeError) as exc:
        return {"error": str(exc)[:200]}


def render(check: ConfigCheck) -> str:
    lines = ["# Deploy / config cross-check", "", f"Scripts read: {', '.join(check.files) or '_none found_'}", ""]
    lines += ["## Deployed parameters", "", "| Contract | Param | Scope | Deployed | Value | Source | Flags |", "|---|---|---|---|---|---|---|"]
    for r in check.rows:
        lines.append(f"| {r.contract} | {r.param} | {r.scope} | `{r.deployed_expr}` | {r.human or (r.deployed_value if r.deployed_value is not None else '')} | {r.source} | {'; '.join(r.flags)} |")
    lines += ["", "## Never set by the deploy scripts (run on constructor defaults)", ""]
    lines += [f"- **{u['contract']}.{u['param']}** - {u['default']} ({u['loc']})" for u in check.unset] or ["_none_"]
    lines += ["", "## Hard-coded constants", ""]
    lines += [f"- {c.contract}.{c.name} = `{c.default_expr}`" + (f" ({c.default_value})" if c.default_value is not None else "") + f" ({c.path}:{c.line})" for c in check.constants] or ["_none_"]
    if check.unmatched:
        lines += ["", "## Deploy settings with no matching setter (typo or stale?)", ""] + [f"- {u}" for u in check.unmatched]
    rv = check.review
    if rv and "error" not in rv:
        flagged = [r for r in rv["rows"] if r["verdict"] == "flag"]
        lines += ["", "## Reviewer: flagged parameters", ""]
        lines += [f"- **{r['contract']}.{r['param']}**: {r['reason']}" for r in flagged] or ["_none_"]
        lines += ["", "## Reviewer: parameter combinations", ""]
        lines += [f"- {', '.join(c['params'])}: {c['concern']}" + (f" _({c['numbers']})_" if c["numbers"] else "") for c in rv["combinations"]] or ["_none_"]
        lines += ["", "## Reviewer: magnitude / reachability", ""]
        lines += [f"- **{m['param']}** threshold {m['threshold']} vs max reachable {m['max_reachable']}: "
                  f"{'reachable' if m['reachable'] else 'NOT REACHABLE'} - {m['reason']}" for m in rv["magnitude_checks"]] or ["_none_"]
    elif rv:
        lines += ["", f"_Reviewer failed: {rv['error']}_"]
    return "\n".join(lines) + "\n"


def notes_for_hunters(check: ConfigCheck, cap: int = 3000) -> str:
    rv = check.review
    rows = [f"- {r.contract}.{r.param} = {r.human or r.deployed_expr}: {'; '.join(r.flags)}" for r in check.rows if r.flags]
    if rv and "error" not in rv:
        rows += [f"- {r['contract']}.{r['param']}: {r['reason']}" for r in rv["rows"] if r["verdict"] == "flag"]
        rows += [f"- combination {', '.join(c['params'])}: {c['concern']}" for c in rv["combinations"]]
        rows += [f"- {m['param']} threshold {m['threshold']} is NOT reachable (max {m['max_reachable']}): {m['reason']}"
                 for m in rv["magnitude_checks"] if not m["reachable"]]
    if not rows:
        return ""
    return ("DEPLOYED CONFIGURATION CONCERNS (from the deploy/verify scripts, not test defaults; a finding that depends "
            "on these values must state them):\n" + "\n".join(rows))[:cap]


def to_dict(check: ConfigCheck) -> dict:
    return {"wiring": check.wiring, "files": check.files, "rows": [asdict(r) for r in check.rows], "unset": check.unset,
            "constants": [asdict(c) for c in check.constants], "unmatched": check.unmatched, "review": check.review}


def write_artifacts(run_dir, check: ConfigCheck) -> None:
    run_dir = Path(run_dir)
    (run_dir / "config_check.json").write_text(json.dumps(to_dict(check), indent=2, sort_keys=True, default=str))
    (run_dir / "config_check.md").write_text(render(check))


async def run(target_root, files, *, router=None, kb_dir="kb", refs=None, hints=None) -> ConfigCheck | None:
    """Build the table from the in-scope Solidity plus every deploy/verify script under the target;
    None when no scripts exist (nothing to cross-check)."""
    from .codebase import rel_path

    sources = {rel_path(target_root, f.path): "\n".join(f.lines) for f in files}
    check = build(target_root, sources, refs=refs, hints=hints)
    if not check.files:
        return None
    if router is not None:
        check.review = await review(router, load_doc(kb_dir, "CONFIG_CHECKS.md"), check)
    return check


async def config_command(args) -> int:
    """`hound config-check TARGET`."""
    from datetime import datetime

    from .codebase import load
    from .llm import Router
    from .pipeline import _read_scope_globs
    from .upstream import detect, gather_target_text, load_registry

    files, _ = load(args.target, _read_scope_globs(args.scope))
    registry = load_registry()
    found = detect(gather_target_text(args.target, files), registry)
    refs, hints = ([], {}) if not found else (found[0][0].reference_params, found[0][0].contract_hints)
    router = None if args.no_llm else Router(models_path=args.models, local_only=args.local_only, seed=0, fresh=False)
    check = await run(args.target, files, router=router, kb_dir=args.kb, refs=refs, hints=hints)
    if check is None:
        print("no deploy/verify scripts found under the target (looked in scripts/, script/, deploy/ and *deploy*/*verify*/*config* files)")
        return 1
    out = Path(args.out) / datetime.now().strftime("config-%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    write_artifacts(out, check)
    print(f"{len(check.rows)} deployed parameters, {sum(1 for r in check.rows if r.flags)} flagged, "
          f"{len(check.unset)} never set, {len(check.constants)} hard-coded constants; reviewer: "
          f"{'ran' if check.review and 'error' not in check.review else ('failed' if check.review else 'skipped')}")
    print(f"wrote {out}")
    return 0
