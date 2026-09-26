"""Upstream-diff orchestration: detect the upstream, fetch it, compare literally, then have a model
decide what each deterministic difference actually does.

The comparison (stmtdiff.py) never issues a verdict; this module asks the reviewer for one per
function pair, with both real bodies in the prompt and the checklist from kb/DEVIATION_REVIEW.md.
Output is two artifacts, upstream_diff.json and upstream_diff.md, plus a compact block of notes
that is handed to the hunters so they start from the deviations instead of rediscovering them.
"""

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ValidationError

from .agents import _user_prompt
from .codebase import rel_path
from .knowledge import load_doc
from .llm import OutOfCredits
from .stmtdiff import compare
from .upstream import detect, fetch, gather_target_text, load_registry

Classification = Literal["cosmetic", "intentional-extension", "semantic-safe", "semantic-risky", "regression"]
Risk = Literal["none", "low", "medium", "high"]
_RISK_RANK = {"high": 0, "medium": 1, "low": 2, "none": 3, "unreviewed": 4}
REVIEW_ROLES = ("diff", "judge")  # a dedicated `diff` role if configured, else the judge's models

REVIEW_SYSTEM = (
    "You are a senior smart-contract auditor comparing a fork against the real upstream it was "
    "derived from. You decide, difference by difference, whether the fork changed behaviour. "
    "You never assume equivalence and you never invent a difference."
)


class Deviation(BaseModel):
    upstream: str = ""
    target: str = ""
    what: str
    why_it_matters: str = ""
    invariant_at_risk: str = ""


class DeviationReview(BaseModel):
    classification: Classification
    risk: Risk
    summary: str
    deviations: list[Deviation] = []
    worth_hunting: bool = False
    hunt_hint: str = ""


@dataclass
class UpstreamDiff:
    upstream_key: str
    upstream_name: str
    fetch_failures: list = field(default_factory=list)
    result: dict = field(default_factory=dict)
    reviews: dict = field(default_factory=dict)  # pair index -> DeviationReview dict | {"error": ...}
    skipped: list = field(default_factory=list)  # pair labels beyond the review cap


def _label(pair) -> str:
    return f"{pair.target.contract}.{pair.target.name or pair.target.kind}"


def _span(path: str, start: int, end: int) -> str:
    return f"{path}:{start}-{end}"


def _pair_prompt(pair, upstream_name: str) -> str:
    diffs = "\n".join(
        f"- [{', '.join(d.kinds)}] upstream L{d.upstream_line or '-'}: {d.upstream or '(absent)'}  |  "
        f"target L{d.target_line or '-'}: {d.target or '(absent)'}"
        for d in pair.diffs[:30]
    )
    up_src = f"function {pair.upstream.header}\n{pair.upstream.body}"
    tg_src = f"function {pair.target.header}\n{pair.target.body}"
    return _user_prompt(
        f"UPSTREAM ({upstream_name}) {_span(pair.upstream_file, pair.upstream.start_line, pair.upstream.end_line)}:\n{up_src}",
        f"TARGET {_span(pair.target_file, pair.target.start_line, pair.target.end_line)}:\n{tg_src}",
        f"DETERMINISTIC STATEMENT DIFFERENCES (skeleton-normalised; renames/require-vs-if already folded):\n{diffs}",
        "TASK: DEVIATION REVIEW\nDecide what each difference does. Return ONLY the JSON object described in the "
        "output contract.",
    )


async def review_pair(router, review_doc: str, pair, upstream_name: str, role: str) -> dict:
    system = "\n\n".join([REVIEW_SYSTEM, review_doc])
    try:
        data = await router.chat_json(role, system, _pair_prompt(pair, upstream_name), temperature=0.0)
        return DeviationReview(**data).model_dump()
    except OutOfCredits:
        raise
    except (ValidationError, TypeError, ValueError, RuntimeError) as exc:
        return {"error": str(exc)[:200]}


def _pick_role(router) -> str | None:
    for role in REVIEW_ROLES:
        if router.has(role):
            return role
    return None


def _vendored_filter(target_sources: dict, upstream_sources: dict) -> dict:
    """OpenZeppelin-style upstreams: only diff files the target ships itself (same basename),
    never anything under node_modules/lib."""
    wanted = {Path(p).name for p in upstream_sources}
    return {
        p: t for p, t in target_sources.items()
        if Path(p).name in wanted and not any(part in ("node_modules", "lib") for part in Path(p).parts)
    }


def _target_sources(root, files) -> dict:
    """{repo-relative path: source text} for the in-scope files (citations stay portable)."""
    return {rel_path(root, f.path): "\n".join(f.lines) for f in files}


def gather_text_for_detection(target_root, files) -> str:
    """README/docs plus source comments for `detect` (a thin alias so callers need one import)."""
    return gather_target_text(target_root, files)


def resolve_upstream(choice: str, text: str, registry: dict):
    """Which upstream to diff against: 'off' -> None, a registry key -> that one, 'auto' -> the
    strongest detection (or None)."""
    if choice == "off":
        return None
    if choice == "auto":
        found = detect(text, registry)
        return found[0][0] if found else None
    if choice not in registry:
        raise ValueError(f"unknown upstream {choice!r} (known: {', '.join(registry)})")
    return registry[choice]


async def upstream_diff(
    target_root, files, *, choice: str = "auto", router=None, kb_dir: str = "kb", cache_dir=".hound_cache",
    max_pairs: int = 40, registry_path=None, fetcher=None,
) -> UpstreamDiff | None:
    registry = load_registry(registry_path)
    text = gather_target_text(target_root, files)
    up = resolve_upstream(choice, text, registry)
    if up is None:
        return None

    sources, failures = fetch(up, cache_dir, fetcher)
    out = UpstreamDiff(up.key, up.name, fetch_failures=failures)
    if not sources:
        return out  # nothing to compare against; the failures say why

    target = _target_sources(target_root, files)
    if up.vendored_only:
        target = _vendored_filter(target, sources)
    out.result = compare(target, sources, hints=up.contract_hints, aliases=up.function_aliases)

    role = _pick_role(router) if router is not None else None
    review_doc = load_doc(kb_dir, "DEVIATION_REVIEW.md")
    candidates = [(i, p) for i, p in enumerate(out.result["pairs"]) if p.diffs]
    chosen, rest = candidates[:max_pairs], candidates[max_pairs:]
    out.skipped = [_label(p) for _, p in rest]
    if role and chosen:
        reviewed = await asyncio.gather(*(review_pair(router, review_doc, p, up.name, role) for _, p in chosen))
        out.reviews = {i: r for (i, _), r in zip(chosen, reviewed)}
    return out


# ------------------------------------------------------------------ output


def _pair_dict(pair, review) -> dict:
    return {
        "target": f"{pair.target.contract}.{pair.target.name or pair.target.kind}",
        "target_loc": _span(pair.target_file, pair.target.start_line, pair.target.end_line),
        "upstream": f"{pair.upstream.contract}.{pair.upstream.name or pair.upstream.kind}",
        "upstream_loc": _span(pair.upstream_file, pair.upstream.start_line, pair.upstream.end_line),
        "similarity": round(pair.similarity, 3),
        "priority": pair.priority,
        "diffs": [
            {"kinds": d.kinds, "upstream": d.upstream, "target": d.target,
             "upstream_line": d.upstream_line, "target_line": d.target_line}
            for d in pair.diffs
        ],
        "review": review,
    }


def to_dict(diff: UpstreamDiff) -> dict:
    pairs = diff.result.get("pairs", [])
    return {
        "upstream": diff.upstream_key, "name": diff.upstream_name, "fetch_failures": diff.fetch_failures,
        "contract_pairs": diff.result.get("contract_pairs", {}),
        "removed_upstream": diff.result.get("removed_upstream", []),
        "added_target": diff.result.get("added_target", []),
        "unreviewed_beyond_cap": diff.skipped,
        "pairs": [_pair_dict(p, diff.reviews.get(i)) for i, p in enumerate(pairs)],
    }


def _rank(entry: dict) -> tuple:
    r = entry["review"]
    risk = r.get("risk", "unreviewed") if r and "error" not in r else "unreviewed"
    return (_RISK_RANK.get(risk, 4), -entry["priority"])


def render_report(diff: UpstreamDiff) -> str:
    d = to_dict(diff)
    lines = [f"# Upstream diff vs {d['name']}", ""]
    if d["fetch_failures"]:
        lines += ["## Fetch failures (no comparison was possible for these files)"] + [f"- {f}" for f in d["fetch_failures"]] + [""]
    pairs = d["pairs"]
    deviating = [p for p in pairs if p["diffs"]]
    lines += [
        f"{len(pairs)} functions paired, {len(deviating)} with deterministic differences, "
        f"{len(pairs) - len(deviating)} identical after normalisation.", "",
    ]
    reviewed = [p for p in deviating if p["review"] and "error" not in p["review"]]
    flagged = sorted((p for p in reviewed if p["review"]["risk"] in ("high", "medium")), key=_rank)
    lines.append("## Deviations that need a human (risk high/medium)")
    if not flagged:
        lines.append("_none flagged by the reviewer_")
    for p in flagged:
        r = p["review"]
        lines += ["", f"### {p['target']}  <-  {p['upstream']}  [{r['classification']}, risk {r['risk']}]",
                  f"- target {p['target_loc']} | upstream {p['upstream_loc']}", f"- {r['summary']}"]
        for dev in r["deviations"]:
            lines.append(f"  - **{dev['what']}** (upstream {dev['upstream'] or '-'} / target {dev['target'] or '-'}): "
                         f"{dev['why_it_matters']}" + (f" _Invariant: {dev['invariant_at_risk']}_" if dev["invariant_at_risk"] else ""))
        if r["hunt_hint"]:
            lines.append(f"  - hunt: {r['hunt_hint']}")
    lines += ["", "## Removed vs upstream (functions the fork does not have)"]
    lines += [f"- {x}" for x in d["removed_upstream"]] or ["_none_"]
    lines += ["", "## Added vs upstream (functions with no upstream counterpart)"]
    lines += [f"- {x}" for x in d["added_target"]] or ["_none_"]
    unreviewed = [p for p in deviating if not p["review"] or "error" in (p["review"] or {})]
    if unreviewed or d["unreviewed_beyond_cap"]:
        lines += ["", "## Not reviewed by a model (raw deterministic differences only)"]
        lines += [f"- {p['target']} <- {p['upstream']} ({len(p['diffs'])} differences)" for p in unreviewed]
        lines += [f"- {x} (beyond the review cap)" for x in d["unreviewed_beyond_cap"]]
    cos = [p for p in reviewed if p["review"]["risk"] in ("low", "none")]
    lines += ["", f"## Reviewed and judged low/no risk: {len(cos)}"]
    lines += [f"- {p['target']}: {p['review']['classification']} — {p['review']['summary']}" for p in cos]
    return "\n".join(lines) + "\n"


def write_artifacts(run_dir, diff: UpstreamDiff) -> None:
    run_dir = Path(run_dir)
    (run_dir / "upstream_diff.json").write_text(json.dumps(to_dict(diff), indent=2, sort_keys=True))
    (run_dir / "upstream_diff.md").write_text(render_report(diff))


def hunter_notes(diff: UpstreamDiff, cap: int = 3500) -> str:
    """A compact block for the hunters' SCOPE NOTES: the reviewed high/medium deviations and the
    removed upstream functions, so hunting starts from them."""
    d = to_dict(diff)
    rows = []
    for p in sorted((p for p in d["pairs"] if p["review"] and "error" not in p["review"]), key=_rank):
        r = p["review"]
        if r["risk"] in ("high", "medium") or r["worth_hunting"]:
            rows.append(f"- {p['target']} ({p['target_loc']}) vs {p['upstream']}: [{r['classification']}/{r['risk']}] "
                        f"{r['summary']}" + (f" Hunt: {r['hunt_hint']}" if r["hunt_hint"] else ""))
    if d["removed_upstream"]:
        rows.append("- Functions upstream has that this fork removed: " + ", ".join(d["removed_upstream"][:20]))
    if not rows:
        return ""
    text = f"UPSTREAM DEVIATIONS (literal diff vs {d['name']}; start from these, do not assume 'same as upstream'):\n" + "\n".join(rows)
    return text[:cap]


async def diff_command(args) -> int:
    """`hound diff TARGET`: the upstream diff on its own, writing upstream_diff.{json,md}."""
    from datetime import datetime

    from .codebase import load
    from .llm import Router
    from .pipeline import _read_scope_globs

    files, _ = load(args.target, _read_scope_globs(args.scope))
    if not files:
        print("no files in scope")
        return 1
    router = None if args.no_llm else Router(models_path=args.models, local_only=args.local_only, seed=0, fresh=False)
    try:
        diff = await upstream_diff(
            args.target, files, choice=args.upstream, router=router, kb_dir=args.kb, max_pairs=args.max_pairs,
        )
    except (ValueError, OSError) as exc:
        print(f"diff: {exc}")
        return 1
    if diff is None:
        print("no known upstream detected (name one with --upstream NAME; see upstreams.yaml)")
        return 1
    out = Path(args.out) / datetime.now().strftime("diff-%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    write_artifacts(out, diff)
    pairs = diff.result.get("pairs", [])
    print(f"{diff.upstream_name}: {len(pairs)} pairs, {sum(1 for p in pairs if p.diffs)} with differences, "
          f"{len(diff.reviews)} reviewed, {len(diff.result.get('removed_upstream', []))} removed upstream functions")
    if diff.fetch_failures:
        print("fetch failures: " + "; ".join(diff.fetch_failures))
    print(f"wrote {out}")
    return 0
