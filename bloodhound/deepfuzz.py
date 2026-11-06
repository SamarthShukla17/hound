"""Deep fuzz escalation: Echidna/Medusa campaigns on a claim Foundry's own fast gate could not
already falsify. Deliberately separate from invariants.py's forge_invariant(), which is the fast
Foundry gate the masterplan's own cut-list keeps as the thing that never gets cut — this module
is the "larger, separately-budgeted campaign" its docstring says a "held" result would earn, not
a replacement for it.

Only escalate a claim whose InvariantResult.status == "held": a "counterexample" is already
falsified (a deeper campaign confirms nothing a human needs), and "compile_failed" has no handler
to fuzz. Callers (run_invariants.py) enforce that gate and the opt-in flag; this module itself
places no such restriction, since it has no notion of the fast gate's outcome.

Why this generates a SEPARATE self-contained contract rather than reusing forge_invariant's
Foundry StdInvariant handler: Echidna/Medusa deploy ONE named contract via its own constructor
and fuzz its public functions directly - they don't run through Foundry's targetContract/
invariant_* test-runner machinery. So the generated contract here self-deploys everything in its
own constructor (no external setUp()) and exposes the property as one `echidna_<id>()` function
returning bool - Echidna's own naming convention, reused for Medusa too (see
write_medusa_config's propertyTesting.testPrefixes) so one generated file serves both tools.

Output parsing is grounded in real local runs of Echidna 2.3.3 and Medusa 1.5.1 (not guessed):
Echidna exits 0 on a held property, nonzero with "<name>: failed!" in stdout on a counterexample.
Medusa's exit code is NOT reliable for this - it returned 0 even with a failing assertion-mode
test in one run - so this module always parses "Test summary: N test(s) passed, M test(s) failed"
from its stdout; nonzero exit without a parseable summary is treated as "error", not "held".
Medusa's coverageEnabled: false crashed with a nil-pointer panic on this machine's build (1.5.1),
so write_medusa_config always sets it true regardless of what the caller asks for.
"""

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from hound.agents import system
from hound.llm import OutOfCredits

from .forger import DEFAULT_MAX_REPAIRS, compile_with_repairs

DEFAULT_TEST_LIMIT = 50_000
DEFAULT_SEQ_LEN = 100
DEFAULT_TIMEOUT_SECONDS = 300
PROPERTY_PREFIX = "echidna_"

_SANITIZE_RE = re.compile(r"[^A-Za-z0-9_]")
_MEDUSA_SUMMARY_RE = re.compile(r"Test summary:\s*(\d+)\s*test\(s\) passed,\s*(\d+)\s*test\(s\) failed")


def property_name(claim_id: str) -> str:
    """A claim id may contain characters invalid in a Solidity identifier (e.g. `R-01`);
    sanitize once so the generated contract, the config's test-prefix match, and the output
    parser all agree on the same name."""
    return PROPERTY_PREFIX + _SANITIZE_RE.sub("_", claim_id)


def echidna_available(runner=subprocess.run) -> bool:
    return runner is not subprocess.run or shutil.which("echidna") is not None


def medusa_available(runner=subprocess.run) -> bool:
    return runner is not subprocess.run or shutil.which("medusa") is not None


@dataclass
class DeepFuzzResult:
    """status:
    - "held": the campaign ran its full budget and found no counterexample. Same epistemic
      weight as the fast gate's "held" - a clean negative, not a proof - just over a much larger
      run/depth budget than Foundry's own fuzzer spends.
    - "counterexample": the tool found a call sequence that breaks the property. A lead, not a
      confirmed finding - same Forger/Panel scrutiny as any other candidate.
    - "compile_failed": the generated contract never compiled within the repair budget.
    - "unavailable": the binary isn't installed. Never conflate with "held" - an unrun campaign
      proves nothing.
    - "error": the tool ran but its output didn't parse into a clear pass/fail (e.g. it crashed).
    """

    status: str
    tool: str
    raw_output: str = ""
    notes: str = ""
    contract_code: str = ""


def _target_prompt(claim, code_context: str, prop_name: str) -> str:
    targets = ", ".join(claim.handler_targets) or "(infer from the claim and the code below)"
    roles = ", ".join(claim.attacker_roles) or "(any)"
    return (
        "TASK: DEEP-FUZZ TARGET CONTRACT\n"
        "Write a Foundry-compiling, SELF-DEPLOYING Solidity contract for Echidna/Medusa to fuzz "
        "directly (not a Foundry test file) for this HUMAN-CURATED claim. Encode it faithfully - "
        "do not weaken, narrow, or reinterpret it to make it easier to satisfy.\n"
        f"CLAIM: {claim.claim}\n"
        f"FORMAL PROPERTY: {claim.property}\n"
        f"TARGET FUNCTIONS TO WRAP: {targets}\n"
        f"ATTACKER ROLES TO SIMULATE: {roles}\n\n"
        "Write ONE self-contained Solidity file (no forge-std import, no vm cheatcodes - Echidna/"
        "Medusa deploy and call it directly, not through Foundry's test runner) that:\n"
        "1. Deploys every contract it depends on INSIDE ITS OWN CONSTRUCTOR - no external setUp(), "
        "no test framework base contract. This is the one contract Echidna/Medusa will deploy.\n"
        "2. Defines public/external functions wrapping the target functions above with bounded "
        "inputs, updating any cumulative accounting state (ghosts) the property needs on every call.\n"
        f"3. Defines EXACTLY ONE function named `{prop_name}` with signature "
        f"`function {prop_name}() public view returns (bool)` that returns true iff the FORMAL "
        "PROPERTY above currently holds over the ghost state and/or the real contract state. "
        "Define no other function with this prefix.\n"
        "4. Imports the target contract(s) from the code shown below; defines any attacker "
        "contract needed in full in this same file - nothing that is not imported or defined here.\n"
        "Mark every assumption (deploy config, roles, the bounds you chose) with a `// ASSUME:` "
        "comment on its own line.\n"
        "Output ONLY code - no prose, no explanation, no code fences.\n\n"
        f"CODE:\n{code_context}"
    )


async def generate_target(
    router, kb, claim, code_context: str, target_root, write_path, *, scope=None,
    max_repairs: int = DEFAULT_MAX_REPAIRS, runner=subprocess.run,
) -> tuple[str, bool, str, int]:
    """Generate + compile/repair the self-deploying fuzz target. Returns (code, compiled, err,
    iterations) - same shape as forger.compile_with_repairs, which this delegates the compile/
    repair loop to rather than re-implementing it."""
    prop_name = property_name(claim.id)
    try:
        seed = await router.chat(
            "poc", system(kb, scope), _target_prompt(claim, code_context, prop_name), temperature=0.2,
            cache_salt=f"deepfuzz-{claim.id}",
        )
    except OutOfCredits:
        raise
    except Exception as exc:  # noqa: BLE001
        return "", False, f"target generation failed: {exc}", 0
    return await compile_with_repairs(
        router, kb, seed, target_root, write_path, scope=scope, max_repairs=max_repairs, runner=runner
    )


def write_echidna_config(path, *, test_limit: int = DEFAULT_TEST_LIMIT, seq_len: int = DEFAULT_SEQ_LEN) -> None:
    Path(path).write_text(
        "testMode: property\n"
        f"testLimit: {test_limit}\n"
        f"seqLen: {seq_len}\n"
    )


def write_medusa_config(path, contract_name: str, prop_name: str, *, timeout: int = DEFAULT_TIMEOUT_SECONDS,
                         call_sequence_length: int = DEFAULT_SEQ_LEN, corpus_dir="medusa_corpus") -> None:
    """coverageEnabled is always True: False crashed Medusa 1.5.1 with a nil-pointer panic in a
    real local run, not a guess. propertyTesting's prefix is set to echidna_'s own convention so
    the one generated contract's single property function serves both tools."""
    import json

    config = {
        "fuzzing": {
            "workers": 2,
            "timeout": timeout,
            "testLimit": 0,
            "callSequenceLength": call_sequence_length,
            "corpusDirectory": corpus_dir,
            "coverageEnabled": True,
            "targetContracts": [contract_name],
            "deploymentOrder": [contract_name],
            "testing": {
                "stopOnFailedTest": True,
                "propertyTesting": {"enabled": True, "testPrefixes": [PROPERTY_PREFIX]},
                "assertionTesting": {"enabled": False},
                "testViewMethods": False,
            },
        },
        "compilation": {
            "platform": "crytic-compile",
            "platformConfig": {"target": ".", "solcVersion": "", "exportDirectory": "", "args": []},
        },
    }
    Path(path).write_text(json.dumps(config, indent=2))


def run_echidna(contract_path, contract_name: str, config_path, prop_name: str, target_root,
                 *, runner=subprocess.run, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> DeepFuzzResult:
    if not echidna_available(runner):
        return DeepFuzzResult(status="unavailable", tool="echidna", notes="echidna is not installed")
    cmd = ["echidna", str(contract_path), "--contract", contract_name, "--config", str(config_path)]
    try:
        proc = runner(cmd, cwd=str(target_root), capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return DeepFuzzResult(status="error", tool="echidna", notes=f"echidna did not complete: {exc}")
    out = (proc.stdout or "") + (proc.stderr or "")
    if f"{prop_name}: failed" in out:
        return DeepFuzzResult(status="counterexample", tool="echidna", raw_output=out,
                               notes="echidna found a call sequence that breaks the claimed property")
    if f"{prop_name}: passing" in out and proc.returncode == 0:
        return DeepFuzzResult(status="held", tool="echidna", raw_output=out)
    if proc.returncode == 0:
        return DeepFuzzResult(status="held", tool="echidna", raw_output=out)
    return DeepFuzzResult(status="error", tool="echidna", raw_output=out,
                           notes=f"echidna exited {proc.returncode} without a parseable pass/fail line")


def run_medusa(config_path, prop_name: str, target_root,
                *, runner=subprocess.run, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> DeepFuzzResult:
    if not medusa_available(runner):
        return DeepFuzzResult(status="unavailable", tool="medusa", notes="medusa is not installed")
    cmd = ["medusa", "fuzz", "--config", str(config_path)]
    try:
        proc = runner(cmd, cwd=str(target_root), capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return DeepFuzzResult(status="error", tool="medusa", notes=f"medusa did not complete: {exc}")
    out = (proc.stdout or "") + (proc.stderr or "")
    m = _MEDUSA_SUMMARY_RE.search(out)
    if not m:
        return DeepFuzzResult(status="error", tool="medusa", raw_output=out,
                               notes="medusa exited without a parseable 'Test summary' line")
    failed = int(m.group(2))
    if failed > 0:
        return DeepFuzzResult(status="counterexample", tool="medusa", raw_output=out,
                               notes=f"medusa found {failed} failing property test(s)")
    return DeepFuzzResult(status="held", tool="medusa", raw_output=out)


async def escalate(
    router, kb, claim, code_context: str, target_root, out_dir, *, tool: str = "echidna", scope=None,
    max_repairs: int = DEFAULT_MAX_REPAIRS, test_limit: int = DEFAULT_TEST_LIMIT,
    timeout: int = DEFAULT_TIMEOUT_SECONDS, runner=subprocess.run,
) -> dict:
    """Generate+compile the one shared target contract, then run the requested tool(s) against
    it. `tool` is "echidna", "medusa", or "both". Returns {tool_name: DeepFuzzResult}.

    Callers decide WHEN to call this (only on a "held" fast-gate result, only when the user
    opted in) - this function always runs what it's asked, it does not re-check that gate.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    contract_name = f"DeepFuzz_{_SANITIZE_RE.sub('_', claim.id)}"
    prop_name = property_name(claim.id)
    contract_path = out_dir / f"{contract_name}.sol"

    code, compiled, err, iters = await generate_target(
        router, kb, claim, code_context, target_root, contract_path, scope=scope,
        max_repairs=max_repairs, runner=runner,
    )
    if not compiled:
        failure = DeepFuzzResult(
            status="compile_failed", tool=tool, contract_code=code,
            notes=f"deep-fuzz target never compiled after {iters} repair round(s): {err}",
        )
        tools = ("echidna", "medusa") if tool == "both" else (tool,)
        return {t: failure for t in tools}

    results = {}
    if tool in ("echidna", "both"):
        echidna_config = out_dir / f"{contract_name}_echidna.yaml"
        write_echidna_config(echidna_config, test_limit=test_limit)
        results["echidna"] = run_echidna(contract_path, contract_name, echidna_config, prop_name,
                                          target_root, runner=runner, timeout=timeout)
        results["echidna"].contract_code = code
    if tool in ("medusa", "both"):
        medusa_config = out_dir / f"{contract_name}_medusa.json"
        write_medusa_config(medusa_config, contract_name, prop_name, timeout=timeout)
        results["medusa"] = run_medusa(medusa_config, prop_name, target_root, runner=runner, timeout=timeout)
        results["medusa"].contract_code = code
    return results
