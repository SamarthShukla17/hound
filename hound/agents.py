"""Agent prompts: mapper, hunter, judge, poc.

No orchestration here (that's pipeline.py, step 7): each function takes a
Router, builds a prompt, calls one role, validates the result, and returns.
Every function degrades gracefully — a model failure or malformed JSON
returns an empty/neutral result with a printed warning, never an exception
that would kill a 40-call scan partway through.
"""

import json

from pydantic import ValidationError

from .schema import Finding, Verdict

IMPACT_LADDER = """IMPACT LADDER
- critical: direct theft, unbacked mint, or permanent freeze reachable by an unprivileged actor.
- high: fund loss or permanent lock under a reachable condition; a broken core invariant; privilege escalation.
- medium: bounded value leakage, mis-accounting, or griefing/DoS of a core function.
Explicitly ignore: style, gas, events, naming, centralization/admin-trust, admin misconfiguration."""

EVIDENCE_RULES = """EVIDENCE RULES
- Cite only real numbered lines, as path:line or path:start-end. No citation means no finding.
- Name the root-cause defect (the exact missing or wrong check), not a symptom.
- State the cheapest test that would prove the finding wrong.
- Privileged-only paths, known/acknowledged issues, and listed killed false positives are not findings.
- Reason privately, step by step. Output ONLY the requested JSON — no prose, no code fences."""

ROLE_PROMPT = (
    "You are a senior smart-contract security auditor working inside an automated audit "
    "harness. You find exploitable, in-scope bugs — you never invent them."
)


def system(kb) -> str:
    """Shared system prompt: role, impact ladder, kb.principles verbatim, evidence rules."""
    return "\n\n".join([ROLE_PROMPT, IMPACT_LADDER, kb.principles, EVIDENCE_RULES])


def _user_prompt(*sections: str) -> str:
    """Join non-empty sections, stable content first, variable content last.

    Callers pass sections already in that order: code, then map, then
    known/killed/already context, then the task. The 20 lenses run over the
    same chunk with an identical prefix so providers (and Ollama's KV cache)
    can reuse it — never reorder this for readability.
    """
    return "\n\n".join(s for s in sections if s)


async def mapper(r, kb, code: str, notes: str = "") -> dict:
    sys_prompt = system(kb)
    notes_block = f"SCOPE NOTES:\n{notes}" if notes else ""
    task = (
        "TASK: MAP\n"
        "Build a structural map of the code above. Return ONLY this JSON shape:\n"
        '{"summary": "...", "actors": ["..."], '
        '"entry_points": [{"loc": "path:line", "who": "anyone|role:<x>", "moves_value": true}], '
        '"state_machine": ["..."], "subsystems": ["..."], "trust_edges": ["..."], '
        '"invariants": [{"id": "I1", "statement": "...", "threatened_by": ["..."]}]}\n\n'
        "Invariants must be falsifiable sentences (something a concrete test could disprove), "
        "and must always include: value conservation, no unbacked mint, authority integrity, "
        "and no unprivileged permanent lock — plus anything else specific to this code."
    )
    user = _user_prompt(code, notes_block, task)

    try:
        data = await r.chat_json("mapper", sys_prompt, user, temperature=0.1, max_tokens=3000)
    except Exception as exc:  # noqa: BLE001 - a scan continues without a map, just less well
        print(f"[agents] mapper failed: {exc}")
        return {}
    if not isinstance(data, dict):
        print("[agents] mapper returned a non-object JSON value")
        return {}
    return data


async def hunter(r, kb, lens, code: str, pmap=None, known: str = "", killed: str = "", already=None, temp: float = 0.3):
    sys_prompt = system(kb)

    map_block = f"MAP:\n{json.dumps(pmap, sort_keys=True)}" if pmap else ""
    known_block = f"KNOWN/ACKNOWLEDGED ISSUES:\n{known}" if known else ""
    killed_block = f"KILLED FALSE POSITIVES:\n{killed}" if killed else ""
    already_block = (
        "ALREADY FOUND (an earlier pass over this same code — do not repeat these):\n"
        + "\n".join(f"- {title}" for title in already)
        if already
        else ""
    )
    lens_block = f"LENS {lens.id} — {lens.title}\n{lens.body}"
    task = (
        "TASK: HUNT\n"
        f"Stand ONLY in lens {lens.id} above. Every other lens runs as its own separate call "
        "over this same code — do not drift into them. A blurry read that mixes vantage points "
        "defeats the entire point of fanning out across lenses.\n"
        "Report at most 4 findings. If nothing survives its own falsification check from this "
        'lens, {"findings": []} is a correct and good answer — never force a finding to avoid '
        "an empty result.\n\n"
        'Return ONLY this JSON shape: {"findings": [{"title": "...", '
        '"severity": "critical|high|medium|low", "bug_class": "...", '
        '"location": "path:line-or-range", "root_cause": "...", "impact": "...", '
        '"exploit_steps": ["..."], "falsification": "...", "confidence": 0.5}]}'
    )
    user = _user_prompt(code, map_block, known_block, killed_block, already_block, lens_block, task)

    try:
        data = await r.chat_json("hunter", sys_prompt, user, temperature=temp, max_tokens=2000)
    except Exception as exc:  # noqa: BLE001
        print(f"[agents] hunter ({lens.id}) failed: {exc}")
        return []

    raw_findings = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(raw_findings, list):
        print(f"[agents] hunter ({lens.id}) returned no findings list")
        return []

    survivors = []
    for entry in raw_findings:
        if not isinstance(entry, dict):
            continue
        try:
            finding = Finding(**entry)
        except ValidationError:
            continue
        if finding.severity == "low":
            continue
        record = finding.model_dump()
        record["lenses"] = [lens.id]
        record["votes"] = 1
        survivors.append(record)
    return survivors


async def judge(r, kb, role: str, cand: dict, code: str, pmap=None, known: str = "", killed: str = "") -> Verdict:
    sys_prompt = system(kb)

    map_block = f"MAP:\n{json.dumps(pmap, sort_keys=True)}" if pmap else ""
    known_block = f"KNOWN/ACKNOWLEDGED ISSUES:\n{known}" if known else ""
    killed_block = f"KILLED FALSE POSITIVES:\n{killed}" if killed else ""
    cand_block = (
        "CANDIDATE FINDING (its own wording may misdescribe the code — verify against the "
        "source above, don't trust the narration):\n" + json.dumps(cand, sort_keys=True)
    )
    task = (
        "TASK: FALSIFY\n"
        "Follow these steps, in order:\n"
        "1. Verify every cited line actually says what the candidate claims.\n"
        "2. Hunt for the cheapest disproof: an existing guard, modifier, constraint, caller "
        "restriction, a rounding direction that already protects the protocol, an unreachable "
        "state, privileged-only access, a known/acknowledged issue, or a match against a listed "
        "killed false positive.\n"
        "3. Only if no disproof survives, the reasoning is coherent end to end, and the attacker "
        "is unprivileged: verdict = keep.\n\n"
        "If the logic holds but hinges on a runtime value you cannot see here (deploy config, "
        "actual token behavior, on-chain parameters): verdict = needs_poc. That is a real third "
        "answer, not a hedge — it routes the candidate to a human instead of silently killing it.\n\n"
        'Return ONLY this JSON shape: {"verdict": "keep|kill|needs_poc", "reason": "...", '
        '"severity": "critical|high|medium|low or null", "killed_by": "..."}'
    )
    user = _user_prompt(code, map_block, known_block, killed_block, cand_block, task)

    try:
        data = await r.chat_json(role, sys_prompt, user, temperature=0.0, max_tokens=1000)
        return Verdict(**data)
    except Exception as exc:  # noqa: BLE001 - never kill a candidate because the judge call failed
        print(f"[agents] judge ({role}) failed: {exc}")
        return Verdict(verdict="needs_poc", reason=str(exc))


async def poc(r, kb, cand: dict, code: str, framework: str = "foundry", refs: str = "") -> str:
    sys_prompt = system(kb)

    refs_block = f"POC SKELETONS FOR REFERENCE:\n{refs[:6000]}" if refs else ""
    cand_block = "FINDING TO REPRODUCE:\n" + json.dumps(cand, sort_keys=True)
    task = (
        "TASK: POC\n"
        f"Write a minimal {framework} test. A green run means the bug is real; a red run "
        "(reverts, or an assertion fails) is a clean kill — either outcome is useful evidence.\n"
        "Assert the exploit's actual effect on balances or state, never just that a call "
        "succeeded without reverting.\n"
        "Mark every assumption you have to make (deploy config, roles, token behavior, etc.) "
        "with a `// ASSUME:` comment on its own line.\n"
        "Output ONLY code — no prose, no explanation, no code fences."
    )
    user = _user_prompt(code, refs_block, cand_block, task)

    try:
        return await r.chat("poc", sys_prompt, user, temperature=0.2, max_tokens=2000)
    except Exception as exc:  # noqa: BLE001
        print(f"[agents] poc failed: {exc}")
        return f"// PoC generation failed: {exc}\n// This is a stub, not a test.\n"
