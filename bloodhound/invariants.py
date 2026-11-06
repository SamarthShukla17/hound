"""Invariant Engine: human-curated claims -> generated Foundry invariant-test handler -> fast
fuzz gate. Deep Echidna/Medusa campaigns and Medusa's profit-optimization mode are deliberately
NOT in this module - cut per the masterplan's own cut-list, which keeps the fast Foundry gate
and human curation as the two things that never get cut.

Why claims are human-curated and never mapper-derived: hound/agents.py's _invariant_checklist
docstring already measured what happens otherwise - checking code against invariants the mapper
inferred FROM that same code let an LLM certify the bug instead of catching it (escape hatches
fired 0 times across 12 invariant checks on a known defect). A claim here must come from a
source independent of the code under test (the protocol's own docs), which is exactly what
invariants.yaml holds and why nothing in this module ever writes to it - only a human does.
"""

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from hound.agents import system
from hound.llm import OutOfCredits

from .forger import DEFAULT_MAX_REPAIRS, compile_with_repairs, run_test

_INVARIANT_FN_RE = re.compile(r"function\s+(invariant_\w+)\s*\(")


class InvariantClaim(BaseModel):
    """One human-curated, falsifiable property from invariants.yaml.

    `property` is the formal statement a handler must encode; `claim`/`source` exist for the
    dossier and for the human who wrote this - they are never fed back into generating the
    claim itself, only into prompting the handler that tests it.
    """

    id: str
    claim: str
    property: str
    source: str = ""
    ghosts: list[str] = Field(default_factory=list)
    handler_targets: list[str] = Field(default_factory=list)
    attacker_roles: list[str] = Field(default_factory=list)


def load_claims(path) -> list[InvariantClaim]:
    """invariants.yaml -> claims, in file order. Raises on a malformed entry rather than
    silently dropping it - a claim that didn't parse is not one the campaign actually ran."""
    data = yaml.safe_load(Path(path).read_text()) or []
    return [InvariantClaim(**c) for c in data]


@dataclass
class InvariantResult:
    """status:
    - "held": the fast gate ran and found no counterexample within its run/depth budget. This
      is NOT proof - it is a clean negative, same epistemic weight as any other fuzz non-finding.
    - "counterexample": forge found a call sequence that breaks the claimed property. This is a
      lead, not a confirmed finding - it still needs the same Forger/Panel scrutiny as any other
      candidate before anyone trusts it.
    - "compile_failed": the handler never became a compiling invariant test within the repair
      budget, so no verdict was reached either way.
    """

    status: str
    handler_code: str = ""
    trace: str = ""
    iterations: int = 0
    notes: str = ""


def _handler_prompt(claim: InvariantClaim, code_context: str) -> str:
    ghosts = ", ".join(claim.ghosts) or "(none stated - add whatever cumulative accounting state you need)"
    targets = ", ".join(claim.handler_targets) or "(infer from the claim and the code below)"
    roles = ", ".join(claim.attacker_roles) or "(any)"
    return (
        "TASK: INVARIANT HANDLER\n"
        "Write a Foundry invariant-test handler for this HUMAN-CURATED claim. Encode it faithfully - "
        "do not weaken, narrow, or reinterpret it to make it easier to satisfy.\n"
        f"CLAIM: {claim.claim}\n"
        f"FORMAL PROPERTY: {claim.property}\n"
        f"SUGGESTED GHOST VARIABLES (cumulative accounting state to track; extend if the property needs more): {ghosts}\n"
        f"TARGET FUNCTIONS TO WRAP: {targets}\n"
        f"ATTACKER ROLES TO SIMULATE: {roles}\n\n"
        "Write ONE self-contained Foundry test file that:\n"
        "1. Defines a Handler contract wrapping the target functions above with bounded inputs "
        "(Foundry's targetContract/StdInvariant pattern), updating the ghost variables on every call.\n"
        "2. Defines a test contract (extends the repo's Test/StdInvariant base as applicable) that "
        f"deploys the target, calls targetContract(address(handler)), and has exactly one function "
        f"named invariant_{claim.id} asserting the FORMAL PROPERTY above over the ghost variables "
        "and/or the real contract state.\n"
        "3. Imports the target contract(s) from the code shown below; defines any attacker contract "
        "needed in full in this same file - nothing that is not imported or defined here.\n"
        "Mark every assumption (deploy config, roles, the bounds you chose) with a `// ASSUME:` comment "
        "on its own line.\n"
        "Output ONLY code - no prose, no explanation, no code fences.\n\n"
        f"CODE:\n{code_context}"
    )


async def forge_invariant(
    router,
    kb,
    claim: InvariantClaim,
    code_context: str,
    target_root,
    handler_dir,
    *,
    scope=None,
    max_repairs: int = DEFAULT_MAX_REPAIRS,
    runner=subprocess.run,
) -> InvariantResult:
    """Generate, compile/repair, and fast-gate one claim's handler.

    This runs `forge test` only - Foundry's own fast, in-process fuzzer. It does not launch an
    overnight Echidna/Medusa campaign; a "held" result here is what would earn that larger,
    separately-budgeted campaign, not a substitute for one.
    """
    handler_dir = Path(handler_dir)
    handler_dir.mkdir(parents=True, exist_ok=True)
    handler_path = handler_dir / f"{claim.id}_handler.t.sol"

    try:
        seed = await router.chat(
            "poc", system(kb, scope), _handler_prompt(claim, code_context), temperature=0.2,
            cache_salt=f"invariant-{claim.id}",
        )
    except OutOfCredits:
        raise
    except Exception as exc:  # noqa: BLE001
        return InvariantResult(status="compile_failed", notes=f"handler generation failed: {exc}")

    code, compiled, err, iters = await compile_with_repairs(
        router, kb, seed, target_root, handler_path, scope=scope, max_repairs=max_repairs, runner=runner
    )
    if not compiled:
        return InvariantResult(status="compile_failed", handler_code=code, iterations=iters, notes=f"handler never compiled: {err}")

    m = _INVARIANT_FN_RE.search(code)
    if not m:
        return InvariantResult(
            status="compile_failed", handler_code=code, iterations=iters,
            notes="no invariant_* function found in the generated handler",
        )
    test_name = m.group(1)

    held, trace = run_test(handler_path, target_root, test_name, runner)
    if held:
        return InvariantResult(status="held", handler_code=code, trace=trace, iterations=iters)
    return InvariantResult(
        status="counterexample", handler_code=code, trace=trace, iterations=iters,
        notes="forge found a call sequence that breaks the claimed property - read the trace; "
        "this is a lead, not a confirmed finding, until it goes through the Forger/Panel like any other candidate",
    )
