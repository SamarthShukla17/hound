"""Agent prompts: mapper, hunter, judge, poc.

No orchestration here (that's pipeline.py, step 7): each function takes a
Router, builds a prompt, calls one role, validates the result, and returns.
Every function degrades gracefully — a model failure or malformed JSON
returns an empty/neutral result with a printed warning, never an exception
that would kill a 40-call scan partway through.
"""

import asyncio
import json
from dataclasses import dataclass, field

from pydantic import ValidationError

from .llm import OutOfCredits
from .schema import Finding, Verdict
from .scope import as_scope

EVIDENCE_RULES = """EVIDENCE RULES
- Cite only real numbered lines, as path:line or path:start-end. No citation means no finding.
- Name the root-cause defect (the exact missing or wrong check), not a symptom.
- State the cheapest test that would prove the finding wrong.
- Known/acknowledged issues and listed killed false positives are not findings.
- Reason privately, step by step. Output ONLY the requested JSON — no prose, no code fences."""

# A lens that fails and a lens that legitimately finds nothing both used to return [], so a
# recall hole looked identical to a clean negative. HuntResult keeps them distinct.


@dataclass
class HuntResult:
    findings: list = field(default_factory=list)
    ok: bool = True
    error: str = ""

    def __len__(self):
        return len(self.findings)

    def __iter__(self):
        return iter(self.findings)


ROLE_PROMPT = (
    "You are a senior smart-contract security auditor working inside an automated audit "
    "harness. You find exploitable, in-scope bugs — you never invent them."
)


def system(kb, scope=None) -> str:
    """Shared system prompt: role, the run's impact ladder, kb.principles verbatim, the run's
    SCOPE RULES, evidence rules. `scope` is a Scope (or rules text); default is contest."""
    sc = as_scope(scope)
    parts = [ROLE_PROMPT, sc.ladder, kb.principles, sc.text, EVIDENCE_RULES]
    tiers = getattr(kb, "tiers", "")
    if tiers:
        parts.insert(2, tiers)
    return "\n\n".join(parts)


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
    except OutOfCredits:
        raise  # never degrade gracefully past an unpayable call
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
) -> HuntResult:
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
        "Fill these four fields IN THIS ORDER, and do not write a later one before an earlier one:\n"
        "  1. observation — what the cited lines literally do: the state they read or write, the "
        "arithmetic they perform, the control flow they take. NO consequence.\n"
        "  2. invariant — the protocol property those lines are supposed to maintain.\n"
        "  3. violation — the specific input or call sequence that breaks that property, cited.\n"
        "  4. impact — what follows FROM the violation. It must be derivable from 1-3 alone.\n"
        "  5. value_flow + attacker_gain — run the equity test from the FINDING TIERS section: what does the "
        "attacker hold before and after, net of everything they pay? value_flow is profit ONLY if they end with "
        "strictly more (name whose loss it is, with numbers in attacker_gain); disruption if the protocol or others "
        "are harmed but the attacker does not come out ahead (attacker_gain: none); unclear if you could not "
        "finish the accounting.\n\n"
        "If you cannot derive the impact from your own observation and invariant, lower the "
        "severity or return nothing. Do not assert theft, minting, draining or locking unless you "
        "traced the value movement in the cited code. The most common failure is naming the right "
        "lines and inventing the wrong defect.\n\n"
        'Return ONLY this JSON shape: {"findings": [{"title": "...", '
        '"severity": "critical|high|medium|low", "bug_class": "...", '
        '"location": "path:line-or-range", "observation": "...", "invariant": "...", '
        '"violation": "...", "root_cause": "summary of observation + invariant + violation", '
        '"impact": "...", "exploit_steps": ["..."], "falsification": "...", "confidence": 0.5, '
        '"value_flow": "profit|disruption|unclear", "attacker_gain": "one line with numbers, or none"}]}'
    )
    user = _user_prompt(code, map_block, notes_block, known_block, killed_block, already_block, lens_block, task)

    try:
        # No wall-clock wrapper here: the budget belongs in the router, where it can start at
        # slot acquisition. Wrapping the whole coroutine charged a lens for queue time and
        # killed 13 of 14 lenses on a concurrency:1 provider for waiting their turn.
        data = await r.chat_json("hunter", sys_prompt, user, temperature=temp, **_salt(cache_salt))
    except OutOfCredits:
        raise  # never degrade gracefully past an unpayable call
    except Exception as exc:  # noqa: BLE001
        print(f"[agents] hunter ({lens.id}) failed: {exc}")
        return HuntResult(ok=False, error=str(exc)[:200])

    raw_findings = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(raw_findings, list):
        print(f"[agents] hunter ({lens.id}) returned no findings list")
        return HuntResult(ok=False, error="no findings list in reply")

    survivors = []
    dropped = []
    for entry in raw_findings:
        if not isinstance(entry, dict):
            dropped.append("not an object")
            continue
        try:
            finding = Finding(**entry)
        except ValidationError as exc:
            # Visible, so a drop in candidate count is attributable to format rather than
            # mistaken for the lens finding nothing.
            dropped.append(",".join(str(e["loc"][0]) for e in exc.errors()))
            continue
        if finding.severity == "low":
            continue
        record = finding.model_dump()
        record["lenses"] = [lens.id]
        record["votes"] = 1
        survivors.append(record)
    if dropped:
        print(f"[agents] hunter ({lens.id}) dropped {len(dropped)} malformed finding(s): {dropped}")
    return HuntResult(findings=survivors)


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
        "If you kill it, you MUST cite where the disproof lives in disproof_location, as "
        "path:line or path:start-end (the modifier, require, or guard that defeats the exploit). "
        "A kill you cannot cite is not a kill — use needs_poc instead.\n"
        "3. Recompute the equity test from the FINDING TIERS section yourself and report the tier in value_flow: "
        "does the attacker end with strictly more value than they started with (profit), or is the protocol or "
        "someone else harmed with no attacker gain (disruption)? Do not just repeat the candidate's claim. A "
        "high/critical severity resting on disruption alone needs a permanent freeze or insolvency; otherwise lower it.\n"
        "4. Only if no disproof survives, the reasoning is coherent end to end, and the finding is "
        "in scope under the SCOPE RULES above: verdict = keep. Apply those rules exactly as written; "
        "do not add exclusions of your own.\n\n"
        "If the logic holds but hinges on a runtime value you cannot see here (deploy config, "
        "actual token behavior, on-chain parameters): verdict = needs_poc. That is a real third "
        "answer, not a hedge — it routes the candidate to a human instead of silently killing it.\n\n"
        'Return ONLY this JSON shape: {"verdict": "keep|kill|needs_poc", "reason": "...", '
        '"severity": "critical|high|medium|low or null", "killed_by": "...", '
        '"disproof_location": "path:line (REQUIRED when verdict is kill, else empty)", '
        '"value_flow": "profit|disruption|unclear"}'
    )
    user = _user_prompt(code, map_block, notes_block, known_block, killed_block, cand_block, task)

    try:
        data = await r.chat_json(role, sys_prompt, user, temperature=0.0, **_salt(cache_salt))
    except OutOfCredits:
        raise  # never degrade gracefully past an unpayable call
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
        '"severity": "critical|high|medium|low or null", "killed_by": "...", '
        '"disproof_location": "path:line"}. "verdict" and "reason" are required, and a "kill" '
        'also requires "disproof_location" citing the guard that disproves the finding.',
    )
    try:
        repaired = await r.chat_json(role, sys_prompt, repair_user, temperature=0.0, **_salt(cache_salt))
        return Verdict(**repaired)
    except OutOfCredits:
        raise  # never degrade gracefully past an unpayable call
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
    except OutOfCredits:
        raise  # never degrade gracefully past an unpayable call
    except Exception as exc:  # noqa: BLE001
        print(f"[agents] poc failed: {exc}")
        return f"// PoC generation failed: {exc}\n// This is a stub, not a test.\n"


def _invariant_checklist(pmap) -> str:
    """Render the mapper's invariants as a numbered checklist for the diagnoser to CHECK.

    MEASURED WORSE -- kept behind mode="invariant", NOT the default. Do not promote it without
    new measurements. Tested 2026-09-23 on the two regions it was designed for:

      M-10  open framing found the real defect (releaseRate recomputed ignoring amountClaimed);
            invariant framing marked all 6 invariants satisfied and returned defect_found=False.
            Correct -> wrong.
      M-02  both framings wrong; invariant framing returned defect_found=False.

      Escape hatches fired 0 times in 12 invariant checks: mis_stated never true,
      uncovered_property never set.

    The root cause is structural, not a prompt-wording problem. The mapper derives invariants
    FROM the code, so a broken check gets written up as the specification: the real I4 read
    "a user cannot transfer more vested tokens than they currently hold (total - claimed)",
    which restates M-10's buggy condition verbatim. Checking the code against it certifies the
    bug. A checklist of six mostly-irrelevant properties also invites six cheap dismissals
    ("this does not affect...") instead of re-reading what the lines do.

    The hypothesis was that turning generation into discrimination would curb fabrication. It
    would need invariants from a source independent of the code under test to be worth retrying.

    Returns "" when the map carries no invariants, so callers can fall back to open-ended.
    """
    if not pmap:
        return ""
    data = pmap
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except (json.JSONDecodeError, ValueError):
            return ""  # pipeline may pass pre-formatted map TEXT; nothing to extract
    if not isinstance(data, dict):
        return ""
    data = data.get("map", data)  # runs/*/map.json nests the map under "map"
    invariants = data.get("invariants") or []
    lines = [
        f"  {inv.get('id', f'I{n}')}: {inv.get('statement', '')}"
        for n, inv in enumerate(invariants, 1)
        if isinstance(inv, dict) and inv.get("statement")
    ]
    return "INVARIANTS TO CHECK (from the map):\n" + "\n".join(lines) if lines else ""


DIAGNOSE_INVARIANT_TASK = (
    "TASK: DIAGNOSE\n"
    "A prior pass located these lines. Its explanation is withheld on purpose so it cannot "
    "anchor you on the wrong story.\n\n"
    "Do NOT invent a property to test. Go through the listed invariants ONE AT A TIME and, for "
    "each, answer whether THESE lines violate it. Cite the specific line for every answer.\n\n"
    "CRITICAL — the listed invariants were inferred from this same code, so an invariant may "
    "have been copied from the very check that is broken. If a stated invariant is satisfied "
    "only because it restates the buggy condition, say so: set mis_stated to true for that id, "
    "give the property the protocol ACTUALLY needs, and judge the lines against that instead. "
    "Likewise, if the real defect here is not covered by any listed invariant, set "
    "uncovered_property and judge against it. A correct answer can be that every listed "
    "invariant holds and nothing is wrong.\n\n"
    "Then, only if something is genuinely violated, fill these IN THIS ORDER:\n"
    "  1. observation — what the cited lines literally do. NO consequence.\n"
    "  2. invariant — the property actually broken (the corrected one, if you corrected it).\n"
    "  3. violation — the specific input or call sequence that breaks it, cited.\n"
    "  4. impact — what follows FROM the violation, derivable from 1-3 alone.\n\n"
    "Do not assert theft, minting, draining or locking unless you traced the value movement.\n\n"
    'Return ONLY this JSON shape: {"checks": [{"invariant_id": "I1", "violated": false, '
    '"mis_stated": false, "why": "...", "cited_line": "File.sol:123"}], '
    '"uncovered_property": "", "defect_found": true, "title": "...", '
    '"severity": "critical|high|medium|low", "bug_class": "...", "observation": "...", '
    '"invariant": "...", "violation": "...", "impact": "...", '
    '"exploit_steps": ["..."], "falsification": "...", "confidence": 0.5}'
)


DIAGNOSE_TASK = (
    "TASK: DIAGNOSE\n"
    "Something at the cited lines may be wrong. You have NOT been told what anyone thinks the "
    "problem is, on purpose: a prior pass located these lines but its explanation is withheld so "
    "it cannot anchor you on the wrong story.\n\n"
    "Read the code and state what, if anything, ACTUALLY violates an invariant here. It may be a "
    "different defect from the one you would expect at such lines, and it may be nothing at all — "
    "\"nothing is wrong here\" is a correct and valuable answer.\n\n"
    "Fill these IN THIS ORDER, and do not write a later one before an earlier one:\n"
    "  1. observation — what the cited lines literally do: state read or written, arithmetic "
    "performed, control flow taken. NO consequence.\n"
    "  2. invariant — the protocol property those lines are supposed to maintain.\n"
    "  3. violation — the specific input or call sequence that breaks that property, cited.\n"
    "  4. impact — what follows FROM the violation, derivable from 1-3 alone.\n\n"
    "Do not assert theft, minting, draining or locking unless you traced the value movement in "
    "the code above. If nothing here breaks an invariant, set defect_found to false and say why "
    "in observation.\n\n"
    'Return ONLY this JSON shape: {"defect_found": true, "title": "...", '
    '"severity": "critical|high|medium|low", "bug_class": "...", "observation": "...", '
    '"invariant": "...", "violation": "...", "impact": "...", '
    '"exploit_steps": ["..."], "falsification": "...", "confidence": 0.5}'
)


async def diagnose(r, kb, code: str, location: str, pmap=None, scope=None, notes: str = "",
                   cache_salt: str = "", mode: str = "open"):
    """Read the cited region cold and say what is actually wrong there, if anything.

    Deliberately receives the location and the code but NOT the locating pass's root_cause or
    impact. The measured failure mode is that a hunter reaches the right lines and then invents
    the defect; handing its story to the diagnoser would just launder that story. Returns a dict
    with defect_found plus the mechanism fields, or {} if the call fails.

    mode="open"      the original open-ended framing: "state what violates an invariant here".
                     THE DEFAULT, and measured better -- see _invariant_checklist.
    mode="invariant" check the map's invariants one at a time. MEASURED WORSE (it flipped M-10
                     from correct to "no defect found"); kept only for a future retry with
                     invariants sourced independently of the code under test.
                     Falls back to "open" when the map carries no invariants, because an empty
                     checklist would otherwise ask the model to check nothing.
    """
    sys_prompt = system(kb, scope)
    map_block = _map_block(pmap)
    notes_block = f"SCOPE NOTES (trusted roles, exclusions):\n{notes}" if notes else ""
    loc_block = f"LINES TO EXAMINE: {location}"

    checklist = _invariant_checklist(pmap) if mode == "invariant" else ""
    task = DIAGNOSE_INVARIANT_TASK if checklist else DIAGNOSE_TASK
    user = _user_prompt(code, map_block, notes_block, checklist, loc_block, task)

    try:
        data = await r.chat_json("diagnose", sys_prompt, user, temperature=0.0, **_salt(cache_salt))
    except OutOfCredits:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f"[agents] diagnose ({location}) failed: {exc}")
        return {}
    if not isinstance(data, dict):
        print(f"[agents] diagnose ({location}) returned a non-object")
        return {}
    return data
