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
from .scope import as_scope

EVIDENCE_RULES = """EVIDENCE RULES
- Cite only real numbered lines, as path:line or path:start-end. No citation means no finding.
- Name the root-cause defect (the exact missing or wrong check), not a symptom.
- State the cheapest test that would prove the finding wrong.
- Known/acknowledged issues and listed killed false positives are not findings.
- Reason privately, step by step. Output ONLY the requested JSON — no prose, no code fences."""

ROLE_PROMPT = (
    "You are a senior smart-contract security auditor working inside an automated audit "
    "harness. You find exploitable, in-scope bugs — you never invent them."
)


def system(kb, scope=None) -> str:
    """Shared system prompt: role, the run's impact ladder, kb.principles verbatim, the run's
    SCOPE RULES, evidence rules. `scope` is a Scope (or rules text); default is contest."""
    sc = as_scope(scope)
    return "\n\n".join([ROLE_PROMPT, sc.ladder, kb.principles, sc.text, EVIDENCE_RULES])


def _map_block(pmap) -> str:
    """pmap may be a dict (serialized here) or an already-formatted string
    (e.g. pipeline.py's merged-and-truncated map text) — never double-encode."""
    if not pmap:
        return ""
    text = pmap if isinstance(pmap, str) else json.dumps(pmap, sort_keys=True)
    return f"MAP:\n{text}"


def _salt(cache_salt: str) -> dict:
    """Forward cache_salt only when set, so routers that don't take it still work."""
    return {"cache_salt": cache_salt} if cache_salt else {}


def _user_prompt(*sections: str) -> str:
    """Join non-empty sections, stable content first, variable content last.

    Callers pass sections already in that order: code, then map, then
    known/killed/already context, then the task. The 20 lenses run over the
    same chunk with an identical prefix so providers (and Ollama's KV cache)
    can reuse it — never reorder this for readability.
    """
    return "\n\n".join(s for s in sections if s)


async def mapper(r, kb, code: str, notes: str = "", scope=None) -> dict:
    sys_prompt = system(kb, scope)
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
        f"and {as_scope(scope).lock_invariant} — plus anything else specific to this code."
    )
    user = _user_prompt(code, notes_block, task)

    try:
        data = await r.chat_json("mapper", sys_prompt, user, temperature=0.1)
    except Exception as exc:  # noqa: BLE001 - a scan continues without a map, just less well
        print(f"[agents] mapper failed: {exc}")
        return {}
    if not isinstance(data, dict):
        print("[agents] mapper returned a non-object JSON value")
        return {}
    return data


async def hunter(
    r, kb, lens, code: str, pmap=None, known: str = "", killed: str = "", already=None, temp: float = 0.3,
    cache_salt: str = "", scope=None, notes: str = "",
):
    sys_prompt = system(kb, scope)

    map_block = _map_block(pmap)
    notes_block = f"SCOPE NOTES (trusted roles, exclusions):\n{notes}" if notes else ""
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
    user = _user_prompt(code, map_block, notes_block, known_block, killed_block, already_block, lens_block, task)

    try:
        data = await r.chat_json("hunter", sys_prompt, user, temperature=temp, **_salt(cache_salt))
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


async def judge(
    r, kb, role: str, cand: dict, code: str, pmap=None, known: str = "", killed: str = "", cache_salt: str = "",
    scope=None, notes: str = "",
) -> Verdict:
    sys_prompt = system(kb, scope)

    map_block = _map_block(pmap)
    notes_block = f"SCOPE NOTES (trusted roles, exclusions):\n{notes}" if notes else ""
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
        "state, a known/acknowledged issue, an exclusion the SCOPE RULES above actually make, or a match against a listed "
        "killed false positive.\n"
        "3. Only if no disproof survives, the reasoning is coherent end to end, and the finding is "
        "in scope under the SCOPE RULES above: verdict = keep. Apply those rules exactly as written; "
        "do not add exclusions of your own.\n\n"
        "If the logic holds but hinges on a runtime value you cannot see here (deploy config, "
        "actual token behavior, on-chain parameters): verdict = needs_poc. That is a real third "
        "answer, not a hedge — it routes the candidate to a human instead of silently killing it.\n\n"
        'Return ONLY this JSON shape: {"verdict": "keep|kill|needs_poc", "reason": "...", '
        '"severity": "critical|high|medium|low or null", "killed_by": "..."}'
    )
    user = _user_prompt(code, map_block, notes_block, known_block, killed_block, cand_block, task)

    try:
        data = await r.chat_json(role, sys_prompt, user, temperature=0.0, **_salt(cache_salt))
    except Exception as exc:  # noqa: BLE001 - never kill a candidate because the judge call failed
        print(f"[agents] judge ({role}) failed: {exc}")
        return Verdict(verdict="needs_poc", reason=str(exc))

    try:
        return Verdict(**data)
    except (ValidationError, TypeError) as first_error:
        # The model answered, just not in the verdict shape (missing "verdict", wrong types).
        # Ask ONCE for a well-formed verdict rather than silently defaulting to needs_poc.
        print(f"[agents] judge ({role}) verdict failed validation, repairing once: {str(first_error)[:120]}")

    repair_user = _user_prompt(
        user,
        "REPAIR: your previous reply was not a valid verdict:\n"
        + json.dumps(data, sort_keys=True, default=str)[:2000]
        + '\nReply again with ONLY {"verdict": "keep|kill|needs_poc", "reason": "...", '
        '"severity": "critical|high|medium|low or null", "killed_by": "..."}. '
        '"verdict" and "reason" are required.',
    )
    try:
        repaired = await r.chat_json(role, sys_prompt, repair_user, temperature=0.0, **_salt(cache_salt))
        return Verdict(**repaired)
    except Exception as exc:  # noqa: BLE001
        print(f"[agents] judge ({role}) repair failed: {exc}")
        return Verdict(verdict="needs_poc", reason=f"judge reply unusable after one repair: {exc}")


async def poc(r, kb, cand: dict, code: str, framework: str = "foundry", refs: str = "", scope=None) -> str:
    sys_prompt = system(kb, scope)

    refs_block = f"POC SKELETONS FOR REFERENCE:\n{refs[:6000]}" if refs else ""
    cand_block = "FINDING TO REPRODUCE:\n" + json.dumps(cand, sort_keys=True)
    task = (
        "TASK: POC\n"
        f"Write a minimal {framework} test. A green run means the bug is real; a red run "
        "(reverts, or an assertion fails) is a clean kill — either outcome is useful evidence.\n"
        "Assert the exploit's actual effect on balances or state, never just that a call "
        "succeeded without reverting.\n"
        "The file must be self-contained and compilable against the target: import the target "
        "contract from the code shown above, and reference NO contract, interface, helper or "
        "mock that is not either imported from that code or defined in full in this same file. "
        "If the exploit needs an attacker contract, define it in full in this file, including "
        "any fallback/receive function that re-enters the target. Nothing that does not "
        "compile is a PoC.\n"
        "Mark every assumption you have to make (deploy config, roles, token behavior, etc.) "
        "with a `// ASSUME:` comment on its own line.\n"
        "Output ONLY code — no prose, no explanation, no code fences."
    )
    user = _user_prompt(code, refs_block, cand_block, task)

    try:
        return await r.chat("poc", sys_prompt, user, temperature=0.2)
    except Exception as exc:  # noqa: BLE001
        print(f"[agents] poc failed: {exc}")
        return f"// PoC generation failed: {exc}\n// This is a stub, not a test.\n"
