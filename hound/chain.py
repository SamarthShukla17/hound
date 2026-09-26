"""Chained-finding check: do two findings on the same mechanism combine into something neither is?

The mechanical half finds candidates cheaply: each finding's cited lines are mapped to their
enclosing functions and to the storage variables those functions touch (solfuncs), and pairs that
share RARE state are ranked. Disruption-tier findings are prioritised, since that is where a chain
can turn a nuisance into an extraction. The model half (kb/CHAINING.md) does the expensive part:
write the combined sequence, do the equity accounting, try to kill it.

Nothing here decides that a chain works. A pair only becomes a result if the accounting is positive.
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from itertools import combinations
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ValidationError

from .codebase import rel_path
from .knowledge import load_doc
from .llm import OutOfCredits
from .runs import is_hard_kill, read_findings
from .solfuncs import find_functions, function_at, mask, state_variables, touched_state, written_state
from .tiers import tier_of
from .verify import spans

CHAIN_ROLES = ("chain", "judge")
SYSTEM = (
    "You are a senior smart-contract auditor testing whether two confirmed findings combine into a larger "
    "one. You do equity accounting and you try to kill the chain before you claim it."
)
_HIT = {"chain_profit", "chain_stronger"}


class ChainVerdict(BaseModel):
    verdict: Literal["chain_profit", "chain_stronger", "chain_no_gain", "infeasible"]
    shared_mechanism: str = ""
    sequence: list[str] = []
    attacker_gain: str = ""
    reason: str = ""
    falsification: str = ""


@dataclass
class Footprint:
    finding_id: str
    functions: set = field(default_factory=set)  # "Contract.name"
    state: set = field(default_factory=set)  # "Contract.var" touched (read or written)
    writes: set = field(default_factory=set)  # the subset the function or its callees WRITE
    snippets: dict = field(default_factory=dict)  # function key -> body text


@dataclass
class Candidate:
    a: str
    b: str
    shared_state: list
    shared_functions: list
    score: float
    shared_writes: list = field(default_factory=list)  # shared state that at least one side WRITES


# Pause/lock/liveness flags are read by nearly every guarded function, so two findings sharing one are
# rarely related. `breached`-style solvency state is deliberately NOT here: that is where real chains meet.
_GUARD_FLAG_RE = re.compile(r"paus|^live$|stopped|initiali[sz]ed|reentran|^_?status$|^_?locked$|^_?entered$", re.IGNORECASE)
_CALL_RE = re.compile(r"(?:\b\w+\s*\.\s*)?\b([A-Za-z_]\w*)\s*\(")
_MAX_CALLEES_PER_NAME = 3


def _callee_state(body: str, funcs_by_name: dict, state_owner: dict) -> tuple:
    """Storage touched by what the body CALLS, one level deep, resolved by name across the in-scope
    contracts: an external call like `RESERVE_ACCOUNTING.freeSlack()` reaches `ReserveAccounting`'s
    storage, and a public-variable getter like `.totalReserve()` reaches that variable itself.
    Without this, two findings that meet only through another contract never look related."""
    reached, wrote = set(), set()
    for name in set(_CALL_RE.findall(mask(body))):
        for cont, var in state_owner.get(name, ()):  # a public state-variable getter (a read)
            reached.add(f"{cont}.{var}")
        for callee, svars in funcs_by_name.get(name, [])[:_MAX_CALLEES_PER_NAME]:
            reached |= {f"{callee.contract}.{v}" for v in touched_state(callee, svars)}
            wrote |= {f"{callee.contract}.{v}" for v in written_state(callee, svars)}
    return reached, wrote


def footprints(findings: list, files, root) -> dict:
    """{finding id: Footprint} from each finding's cited lines: the functions they sit in, the storage
    those functions touch, and the storage reached through the calls they make."""
    per_file, funcs_by_name, state_owner = {}, {}, {}
    for src in files:
        text = "\n".join(src.lines)
        funcs, svars = find_functions(text), state_variables(text)
        per_file[src.path] = (funcs, svars)
        for fn in funcs:
            if fn.has_body and fn.name and fn.kind == "function":
                funcs_by_name.setdefault(fn.name, []).append((fn, svars))
        for cont in {fn.contract for fn in funcs}:
            for v in svars:
                state_owner.setdefault(v, set()).add((cont, v))
    out = {}
    for f in findings:
        fp = Footprint(f["id"])
        for src, a, b in spans(f["location"], files):
            funcs, svars = per_file.get(src.path, ([], set()))
            for line in range(a, b + 1):
                fn = function_at(funcs, line)
                if fn is None or fn.key in fp.functions:
                    continue
                fp.functions.add(fn.key)
                fp.snippets[fn.key] = f"{rel_path(root, src.path)}:{fn.start_line}-{fn.end_line}\nfunction {fn.header}\n{fn.body}"
                fp.state |= {f"{fn.contract}.{v}" for v in touched_state(fn, svars)}
                fp.writes |= {f"{fn.contract}.{v}" for v in written_state(fn, svars)}
                reached, wrote = _callee_state(fn.body, funcs_by_name, state_owner)
                fp.state |= reached
                fp.writes |= wrote
        out[f["id"]] = fp
    return out


def rank_pairs(findings: list, prints: dict, verdicts_tier: dict, max_pairs: int = 12) -> list:
    """Candidate pairs sharing state, best first. Rare shared state scores higher than state that
    half the findings touch; a pair containing a disruption-tier finding gets a bonus."""
    n = len(findings)
    freq = {}
    for fp in prints.values():
        for v in fp.state:
            freq[v] = freq.get(v, 0) + 1
    cands = []
    for a, b in combinations([f["id"] for f in findings], 2):
        pa, pb = prints[a], prints[b]
        shared_state = sorted(pa.state & pb.state)
        shared_fn = sorted(pa.functions & pb.functions)
        # A chain needs state one finding changes and the other depends on. State both only READ
        # (a pause flag, an immutable) is not a lead, however many such variables are shared.
        shared_writes = [v for v in shared_state if v in pa.writes or v in pb.writes]
        if not shared_writes and not shared_fn:
            continue
        common = max(2, n // 2)
        score = 3.0 * len(shared_fn)
        for v in shared_state:
            weight = 1.0 if freq[v] <= common else 0.2
            if _GUARD_FLAG_RE.search(v.split(".")[-1]):
                weight *= 0.15
            score += weight * (2.0 if v in shared_writes else 0.25)
        if "disruption" in (verdicts_tier[a], verdicts_tier[b]):
            score *= 1.5
        if verdicts_tier[a] == verdicts_tier[b] == "profit":
            score *= 0.5  # two profits do not need chaining to matter
        cands.append(Candidate(a, b, shared_state, shared_fn, round(score, 2), shared_writes))
    return sorted(cands, key=lambda c: -c.score)[:max_pairs]


def _finding_block(f: dict, tier: str) -> str:
    keep = {k: f.get(k) for k in ("id", "title", "severity", "location", "observation", "invariant", "violation",
                                  "impact", "exploit_steps", "attacker_gain")}
    return json.dumps({**keep, "tier": tier}, indent=1, default=str)


def _prompt(fa: dict, fb: dict, ta: str, tb: str, cand: Candidate, prints: dict) -> str:
    code = {}
    for fid in (cand.a, cand.b):
        code.update(prints[fid].snippets)
    parts = [
        f"FINDING A:\n{_finding_block(fa, ta)}", f"FINDING B:\n{_finding_block(fb, tb)}",
        "SHARED STATE (written by at least one side): " + (", ".join(cand.shared_writes) or "(none: they share a function)")
        + ("\nSHARED STATE (both only read): " + ", ".join(sorted(set(cand.shared_state) - set(cand.shared_writes)))[:400]
           if set(cand.shared_state) - set(cand.shared_writes) else "")
        + ("\nSHARED FUNCTIONS: " + ", ".join(cand.shared_functions) if cand.shared_functions else ""),
        "CODE OF THE CITED FUNCTIONS:\n" + "\n\n".join(code.values()),
        "TASK: CHAIN CHECK\nFollow the protocol. Return ONLY the JSON object described in the output contract.",
    ]
    return "\n\n".join(parts)


async def check_pair(router, doc: str, role: str, fa, fb, ta, tb, cand, prints) -> dict:
    try:
        data = await router.chat_json(role, "\n\n".join([SYSTEM, doc]), _prompt(fa, fb, ta, tb, cand, prints), temperature=0.0)
        return ChainVerdict(**data).model_dump()
    except OutOfCredits:
        raise
    except (ValidationError, TypeError, ValueError, RuntimeError) as exc:
        return {"error": str(exc)[:200]}


@dataclass
class ChainResult:
    candidates: list = field(default_factory=list)
    results: dict = field(default_factory=dict)  # "A+B" -> verdict dict | {"error": ...}
    considered: int = 0


def live_findings(run_dir) -> list:
    """Findings still standing: not removed by a deterministic gate, not killed by the judge."""
    _meta, findings = read_findings(run_dir)
    return [f for f in findings if not is_hard_kill(f) and (f.get("verdict") or {}).get("verdict") != "kill"]


async def run(findings: list, files, root, *, router=None, kb_dir="kb", max_pairs: int = 12) -> ChainResult:
    res = ChainResult(considered=len(findings))
    if len(findings) < 2:
        return res
    from .schema import Verdict

    prints = footprints(findings, files, root)
    tiers = {}
    for f in findings:
        v = f.get("verdict")
        tiers[f["id"]] = tier_of(f, Verdict(**v) if isinstance(v, dict) and "verdict" in v else None)
    res.candidates = rank_pairs(findings, prints, tiers, max_pairs)
    role = next((r for r in CHAIN_ROLES if router is not None and router.has(r)), None)
    if role and res.candidates:
        by_id = {f["id"]: f for f in findings}
        doc = load_doc(kb_dir, "CHAINING.md")
        verdicts = await asyncio.gather(*(
            check_pair(router, doc, role, by_id[c.a], by_id[c.b], tiers[c.a], tiers[c.b], c, prints)
            for c in res.candidates
        ))
        res.results = {f"{c.a}+{c.b}": v for c, v in zip(res.candidates, verdicts)}
    return res


def render(res: ChainResult, findings: list) -> str:
    title = {f["id"]: f["title"] for f in findings}
    lines = ["# Chained-finding check", "",
             f"{res.considered} live findings; {len(res.candidates)} pairs share state and were considered "
             f"({len(res.results)} reviewed by a model).", ""]
    hits = [(k, v) for k, v in res.results.items() if v.get("verdict") in _HIT]
    lines += ["## Chains that combine into something larger"]
    if not hits:
        lines.append("_none_")
    for k, v in hits:
        a, b = k.split("+")
        lines += ["", f"### {k}: {v['verdict']}  ({title.get(a, a)} + {title.get(b, b)})",
                  f"- shared mechanism: {v['shared_mechanism']}", f"- attacker gain: {v['attacker_gain'] or 'none'}",
                  f"- {v['reason']}"] + [f"  {i}. {s}" for i, s in enumerate(v["sequence"], 1)] + \
                 [f"- falsify by: {v['falsification']}"]
    lines += ["", "## Every pair considered (shared state, then verdict)"]
    for c in res.candidates:
        v = res.results.get(f"{c.a}+{c.b}")
        verdict = "not reviewed" if v is None else (f"error: {v['error']}" if "error" in v else v["verdict"])
        lines.append(f"- {c.a} + {c.b} (score {c.score}): {', '.join(c.shared_state + c.shared_functions) or '-'} -> {verdict}")
    return "\n".join(lines) + "\n"


def write_artifacts(run_dir, res: ChainResult, findings: list) -> None:
    run_dir = Path(run_dir)
    (run_dir / "chains.json").write_text(json.dumps({
        "considered": res.considered,
        "candidates": [c.__dict__ for c in res.candidates], "results": res.results}, indent=2, sort_keys=True))
    (run_dir / "chains.md").write_text(render(res, findings))


def hits(res: ChainResult) -> list:
    return [k for k, v in res.results.items() if v.get("verdict") in _HIT]


async def chain_command(args) -> int:
    """`hound chain RUN_DIR`: chain-check a finished run; needs the target to map citations to code."""
    from .codebase import load
    from .llm import Router

    meta, _ = read_findings(args.run_dir)
    target = args.target or (meta.get("provenance") or {}).get("target")
    if not target:
        print("cannot find the target: pass --target PATH")
        return 1
    files, _ = load(target, meta.get("scope_globs") or None)
    findings = live_findings(args.run_dir)
    router = None if args.no_llm else Router(models_path=args.models, local_only=args.local_only, seed=0, fresh=False)
    res = await run(findings, files, target, router=router, kb_dir=args.kb, max_pairs=args.max_pairs)
    write_artifacts(args.run_dir, res, findings)
    print(f"{res.considered} live findings, {len(res.candidates)} pairs share state, {len(res.results)} reviewed, "
          f"{len(hits(res))} chain(s) found")
    print(f"wrote {Path(args.run_dir) / 'chains.md'}")
    return 0
