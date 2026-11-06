"""Refutation Panel: adversarial binary-checklist review of a forged PoC, verified by injection.

judge2 (hound/pipeline.py) is a single second-model holistic opinion that runs BEFORE a PoC
exists, and it only ever downgrades keep -> needs_poc. This module runs AFTER forge_candidate
has already produced a forged PoC (status == "forged") and treats every refuter's claim as
unproven until it is injected into the real test and re-run: "unreachable because X" only counts
if adding X to the test (as an assumption) makes the attack stop passing. A model can be argued
into or out of a refutation; forge build/test re-running it cannot.

Position-bias control: each role is asked twice, with the claim and the PoC code in swapped
order. A role whose two answers disagree is discarded as unreliable rather than averaged -
averaging a contradiction would manufacture a confidence neither answer earned.
"""

import asyncio
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ValidationError, model_validator

from hound.agents import system
from hound.llm import OutOfCredits

from .forger import compile, first_test_name, run_test

# Configure these in models.yaml, same as judge2; a role left unconfigured is simply skipped
# (router.has(role) is False) and the panel runs on however many of the three are available.
REFUTER_ROLES = ("refute1", "refute2", "refute3")

_INJECT_TEMPLATE = r"function\s+{name}\s*\([^)]*\)[^{{]*\{{"


class RefuterVerdict(BaseModel):
    verdict: Literal["could-not-refute", "refuted"]
    reason: str
    checklist: dict = {}
    # A one-line Solidity require()/vm.assume() statement capturing the blocking condition this
    # refuter claims exists. Required for "refuted" so the claim can actually be tested, not just
    # asserted - the same discipline schema.Verdict applies to disproof_location on a kill.
    injectable_assumption: str = ""

    @model_validator(mode="after")
    def _refuted_must_be_injectable(self):
        if self.verdict == "refuted" and not self.injectable_assumption.strip():
            raise ValueError(
                "verdict 'refuted' requires injectable_assumption: a concrete require()/vm.assume() "
                "statement capturing the blocking condition, so the claim can be re-run, not just asserted"
            )
        return self


@dataclass
class PanelResult:
    """killed=True means one refutation survived injection and the finding should be downgraded
    (same spirit as judge2's dissent downgrade in pipeline.py). role_verdicts is evidence for the
    dossier/human, not a vote count - this module kills on the first SURVIVING refutation, not
    on a majority."""

    killed: bool
    surviving_refutation: str = ""
    role_verdicts: dict = field(default_factory=dict)
    notes: str = ""


def _checklist_task() -> str:
    return (
        "TASK: REFUTE\n"
        "Try to kill this PoC. Answer each check honestly, then give a verdict.\n"
        "CHECKS (answer true/false in \"checklist\"):\n"
        "- reachable: is the attacked path reachable by the attacker identity the finding claims?\n"
        "- unguarded: is there NO guard, modifier, or require upstream that already blocks the precondition?\n"
        "- sequenceable: can the claimed actor actually sequence these calls (permissions, block/ordering constraints)?\n"
        "- real_invariant: is the failing assertion actually the claimed invariant, not a harness artifact "
        "(mock misconfiguration, missing init)?\n"
        "- economically_real: is the impact a real loss/gain, not just a state-accounting inconsistency with no victim?\n"
        'verdict = "refuted" only if at least one check is false AND you can state a concrete blocking condition. '
        "If refuted, injectable_assumption MUST be one line of valid Solidity (a require(...) or vm.assume(...) "
        "statement) that, if true, is exactly the condition that blocks the attack - it will be inserted into the "
        "test and re-run, so it must compile and must actually capture your claim, not merely assert the outcome.\n"
        'Return ONLY: {"verdict": "could-not-refute|refuted", "reason": "...", '
        '"checklist": {"reachable": true|false, "unguarded": true|false, "sequenceable": true|false, '
        '"real_invariant": true|false, "economically_real": true|false}, "injectable_assumption": "..."}'
    )


def _refuter_user(finding: dict, attack_code: str, attack_trace: str, order: str) -> str:
    claim_block = "CLAIMED BUG:\n" + json.dumps(finding, sort_keys=True)[:3000]
    code_block = f"FORGED POC (already compiled and passing):\n{attack_code}\n\nEXECUTION TRACE:\n{attack_trace[:3000]}"
    sections = [claim_block, code_block] if order == "claim_first" else [code_block, claim_block]
    return "\n\n".join(sections + [_checklist_task()])


async def _one_refuter_call(router, sys_prompt, role, finding, attack_code, attack_trace, order) -> RefuterVerdict | None:
    user = _refuter_user(finding, attack_code, attack_trace, order)
    try:
        data = await router.chat_json(role, sys_prompt, user, temperature=0.0, cache_salt=f"refute-{order}")
    except OutOfCredits:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f"[refute] {role} ({order}) failed: {exc}")
        return None

    try:
        return RefuterVerdict(**data)
    except (ValidationError, TypeError) as exc:
        print(f"[refute] {role} ({order}) verdict failed validation, repairing once: {str(exc)[:120]}")

    repair_user = user + "\n\nREPAIR: your previous reply was not valid: " + json.dumps(data, default=str)[:1500]
    try:
        repaired = await router.chat_json(role, sys_prompt, repair_user, temperature=0.0, cache_salt=f"refute-{order}-repair")
        return RefuterVerdict(**repaired)
    except OutOfCredits:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f"[refute] {role} ({order}) repair failed: {exc}")
        return None


async def _ask_refuter(router, kb, role, finding, attack_code, attack_trace, scope=None) -> RefuterVerdict | None:
    """Swap-and-discard: ask the same role twice with sections reordered. Disagreement between
    the two answers means the role's verdict depends on position, not substance - discard it
    rather than pick one arbitrarily or average toward false confidence."""
    sys_prompt = system(kb, scope)
    a, b = await asyncio.gather(
        _one_refuter_call(router, sys_prompt, role, finding, attack_code, attack_trace, "claim_first"),
        _one_refuter_call(router, sys_prompt, role, finding, attack_code, attack_trace, "code_first"),
    )
    if a is None or b is None:
        return None
    if a.verdict != b.verdict:
        return None
    return a


def inject_assumption(code: str, test_name: str, assumption: str) -> str | None:
    """Insert `assumption` as the first statement inside test_name's body. None if the function
    signature can't be located in `code` - the caller must treat that refutation as unverified,
    never as surviving by default."""
    pattern = re.compile(_INJECT_TEMPLATE.format(name=re.escape(test_name)))
    m = pattern.search(code)
    if not m:
        return None
    stmt = assumption.strip()
    if not stmt.endswith(";"):
        stmt += ";"
    return code[: m.end()] + f"\n        {stmt}\n" + code[m.end() :]


async def run_panel(
    router,
    kb,
    finding: dict,
    forge_result,
    target_root,
    forge_dir,
    *,
    scope=None,
    roles=REFUTER_ROLES,
    runner=subprocess.run,
) -> PanelResult:
    """Only meaningful on a ForgeResult with status == "forged". Asks every configured refuter
    role; any "refuted" verdict is re-verified by injecting its assumption into the attack test
    and re-running it. A refutation only survives (and kills the finding) if the attack no
    longer passes with the assumption in place - an assertion a refuter can't back with a
    passing injected test never counts against the finding.
    """
    configured = [r for r in roles if router.has(r)]
    if not configured:
        return PanelResult(killed=False, notes="no refuter role configured - panel skipped")

    test_name = first_test_name(forge_result.poc_code)
    if not test_name:
        return PanelResult(killed=False, notes="no test_* function in the forged PoC - panel skipped")

    answers = await asyncio.gather(
        *(
            _ask_refuter(router, kb, role, finding, forge_result.poc_code, forge_result.attack_output, scope)
            for role in configured
        )
    )

    forge_dir = Path(forge_dir)
    forge_dir.mkdir(parents=True, exist_ok=True)
    fid = re.sub(r"[^\w.-]", "_", str(finding.get("id") or finding.get("title") or "candidate"))
    role_verdicts = {}

    for role, verdict in zip(configured, answers):
        if verdict is None:
            role_verdicts[role] = {"verdict": "unreliable", "reason": "no usable answer (error, or claim-first/code-first disagreed)"}
            continue

        entry = {"verdict": verdict.verdict, "reason": verdict.reason, "checklist": verdict.checklist}
        role_verdicts[role] = entry
        if verdict.verdict != "refuted":
            continue

        injected = inject_assumption(forge_result.poc_code, test_name, verdict.injectable_assumption)
        if injected is None:
            entry["injection"] = "could not locate the test body to inject into - unverified, does not count"
            continue

        inj_path = forge_dir / f"{fid}_refute_{role}.t.sol"
        inj_path.write_text(injected)
        ok, err = compile(inj_path, target_root, runner)
        if not ok:
            entry["injection"] = f"injected assumption did not compile - unverified: {err[:200]}"
            continue

        passed, _trace = run_test(inj_path, target_root, test_name, runner)
        if passed:
            entry["injection"] = "attack still passed with the assumption in place - refutation INVALID"
            continue

        entry["injection"] = "attack no longer passed with the assumption in place - refutation SURVIVES"
        return PanelResult(killed=True, surviving_refutation=f"{role}: {verdict.reason}", role_verdicts=role_verdicts)

    return PanelResult(killed=False, role_verdicts=role_verdicts)
