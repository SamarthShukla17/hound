"""PoC Forger: deterministic repair, compile/repair loop, and the differential acceptance gate.

Mirrors the ReX shape (generate -> compile -> LLM-repair -> re-compile -> run) with one addition
that kills the dominant LLM-PoC failure mode (a tautological assertion that would pass with or
without the attack): a finding is "forged" only if an attack run DEMONSTRATES the bug AND a
control run — the same test, with the exploit step(s) removed by a second LLM call — does NOT.
Compile/test execution is real (forge build / forge test); only the repair and control-variant
steps touch an LLM, and both are re-verified by the same compile/test gate as the original.

Consumes hound's existing PoC scaffold (hound.agents.poc()) and hound's existing Router/KB —
this module adds the execution loop around them, it does not re-implement generation.
"""

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from hound.agents import system
from hound.llm import OutOfCredits

COMPILE_TIMEOUT_SECONDS = 120
TEST_TIMEOUT_SECONDS = 180
DEFAULT_MAX_REPAIRS = 4

_FENCE_RE = re.compile(r"^```[a-zA-Z]*\n|\n```\s*$", re.MULTILINE)
_PRAGMA_RE = re.compile(r"pragma solidity\s+[^;]+;")
_TEST_FN_RE = re.compile(r"function\s+(test_\w+)\s*\(")


@dataclass
class ForgeResult:
    """Outcome of one candidate's run through the Forger.

    `status` is the only field a caller needs to branch on:
    - "forged": attack run demonstrated the bug, control run did not — differential gate passed.
    - "unforged": either the attack never demonstrated the bug, or the control also passed
      (the gate rejected it as tautological), or the control couldn't be verified at all.
    - "compile_failed": the attack PoC itself never became a compiling test within the repair
      budget, so no verdict could be reached.
    Everything else is evidence to attach to the finding record, not a decision input.
    """

    status: str
    poc_code: str = ""
    control_code: str = ""
    attack_output: str = ""
    control_output: str = ""
    iterations: int = 0
    notes: str = ""


def strip_fences(code: str) -> str:
    """Drop a leading/trailing markdown fence some models add despite being told not to."""
    return _FENCE_RE.sub("", code).strip() + "\n"


def normalise_pragma(code: str, target_root) -> str:
    """Rewrite `pragma solidity ...;` to the target's own foundry.toml solc pin, when there is
    one. A guessed pragma is the single most common reason an otherwise-correct PoC fails to
    compile against a real repo."""
    toml_path = Path(target_root) / "foundry.toml"
    if not toml_path.is_file():
        return code
    m = re.search(r'solc\s*=\s*["\']([\d.]+)["\']', toml_path.read_text())
    if not m or not _PRAGMA_RE.search(code):
        return code
    return _PRAGMA_RE.sub(f"pragma solidity ^{m.group(1)};", code, count=1)


def deterministic_repair(code: str, target_root) -> str:
    """Fixes that need no model. Runs before every compile attempt, including the first, so the
    LLM repair loop never spends a turn on something free."""
    return normalise_pragma(strip_fences(code), target_root)


def first_test_name(code: str) -> str | None:
    m = _TEST_FN_RE.search(code)
    return m.group(1) if m else None


def compile(poc_path, target_root, runner=subprocess.run) -> tuple[bool, str]:
    """(ok, stderr-or-empty). Never raises: a target this can't reach just fails the gate."""
    if runner is subprocess.run and shutil.which("forge") is None:
        return False, "forge is not installed"
    cmd = ["forge", "build", "--match-path", str(poc_path)]
    try:
        proc = runner(cmd, cwd=str(target_root), capture_output=True, text=True, timeout=COMPILE_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"forge build did not complete: {exc}"
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout or "").strip()
    return True, ""


def run_test(poc_path, target_root, test_name: str, runner=subprocess.run) -> tuple[bool, str]:
    """(passed, trace). `passed` is forge's own pass/fail; the caller decides what pass/fail
    means for the attack run versus the control run."""
    if runner is subprocess.run and shutil.which("forge") is None:
        return False, "forge is not installed"
    cmd = ["forge", "test", "--match-path", str(poc_path), "--match-test", test_name, "-vvvv"]
    try:
        proc = runner(cmd, cwd=str(target_root), capture_output=True, text=True, timeout=TEST_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"forge test did not complete: {exc}"
    return proc.returncode == 0, (proc.stdout or "") + (proc.stderr or "")


def _repair_prompt(code: str, compiler_error: str) -> str:
    return (
        "TASK: REPAIR\n"
        "The Foundry test below failed to compile against the real target repo. Fix ONLY what "
        "the compiler error names (imports, types, signatures) — do not rewrite the exploit "
        "logic and do not weaken or remove any assertion.\n\n"
        f"COMPILER ERROR:\n{compiler_error[:4000]}\n\n"
        f"TEST FILE:\n{code}\n\n"
        "Output ONLY the corrected file — no prose, no explanation, no code fences."
    )


def _control_prompt(code: str, finding: dict) -> str:
    return (
        "TASK: CONTROL VARIANT\n"
        "Below is a PoC test that claims to demonstrate a bug. Produce a CONTROL variant: the "
        "same file, the same test function name, the same final assertion, but with the "
        "attacker's exploit step(s) removed or replaced by normal/benign behavior, so the test "
        "exercises the non-attack path only. Keep setup/deploy code identical — change only the "
        "attack step(s). This exists to prove the assertion is not tautological: if this variant "
        "still passes without the attack, the original PoC never actually tested the claimed bug.\n\n"
        f"CLAIMED BUG:\n{json.dumps(finding, sort_keys=True)[:3000]}\n\n"
        f"ATTACK TEST FILE:\n{code}\n\n"
        "Output ONLY the corrected file — no prose, no explanation, no code fences."
    )


async def _compile_with_repairs(
    router, kb, code: str, target_root, write_path, *, scope=None, max_repairs=DEFAULT_MAX_REPAIRS, runner=subprocess.run
):
    """Deterministic repair, then up to `max_repairs` LLM-repair/recompile rounds.

    Returns (final_code, compiled, last_error, iterations_used).
    """
    code = deterministic_repair(code, target_root)
    write_path.write_text(code)
    ok, err = compile(write_path, target_root, runner)
    iterations = 0
    while not ok and iterations < max_repairs:
        iterations += 1
        try:
            code = await router.chat(
                "poc", system(kb, scope), _repair_prompt(code, err), temperature=0.1, cache_salt=f"forge-repair{iterations}"
            )
        except OutOfCredits:
            raise
        except Exception as exc:  # noqa: BLE001
            return code, False, f"repair call failed: {exc}", iterations
        code = deterministic_repair(code, target_root)
        write_path.write_text(code)
        ok, err = compile(write_path, target_root, runner)
    return code, ok, err, iterations


async def forge_candidate(
    router,
    kb,
    finding: dict,
    poc_code: str,
    target_root,
    forge_dir,
    *,
    scope=None,
    max_repairs: int = DEFAULT_MAX_REPAIRS,
    runner=subprocess.run,
) -> ForgeResult:
    """Run one candidate's PoC scaffold through compile/repair and the differential gate.

    `forge_dir` must be a directory forge can see from `target_root` (e.g. a `test/` subfolder)
    — the attack and control files are written there, named after the finding's id, and left on
    disk as evidence.
    """
    forge_dir = Path(forge_dir)
    forge_dir.mkdir(parents=True, exist_ok=True)
    fid = re.sub(r"[^\w.-]", "_", str(finding.get("id") or finding.get("title") or "candidate"))

    attack_path = forge_dir / f"{fid}_attack.t.sol"
    code, compiled, err, iters = await _compile_with_repairs(
        router, kb, poc_code, target_root, attack_path, scope=scope, max_repairs=max_repairs, runner=runner
    )
    if not compiled:
        return ForgeResult(status="compile_failed", poc_code=code, iterations=iters, notes=f"attack PoC never compiled: {err}")

    test_name = first_test_name(code)
    if not test_name:
        return ForgeResult(status="compile_failed", poc_code=code, iterations=iters, notes="no test_* function found in generated PoC")

    attack_passed, attack_trace = run_test(attack_path, target_root, test_name, runner)
    if not attack_passed:
        return ForgeResult(
            status="unforged", poc_code=code, attack_output=attack_trace, iterations=iters,
            notes="attack run did not pass: bug not demonstrated",
        )

    try:
        control_seed = await router.chat(
            "poc", system(kb, scope), _control_prompt(code, finding), temperature=0.1, cache_salt="forge-control0"
        )
    except OutOfCredits:
        raise
    except Exception as exc:  # noqa: BLE001
        return ForgeResult(
            status="unforged", poc_code=code, attack_output=attack_trace, iterations=iters,
            notes=f"control variant generation failed, gate inconclusive: {exc}",
        )

    control_path = forge_dir / f"{fid}_control.t.sol"
    control_code, control_compiled, control_err, control_iters = await _compile_with_repairs(
        router, kb, control_seed, target_root, control_path, scope=scope, max_repairs=max_repairs, runner=runner
    )
    total_iters = iters + control_iters
    if not control_compiled:
        return ForgeResult(
            status="unforged", poc_code=code, control_code=control_code, attack_output=attack_trace,
            iterations=total_iters, notes=f"control variant never compiled, gate inconclusive: {control_err}",
        )

    control_passed, control_trace = run_test(control_path, target_root, test_name, runner)
    if control_passed:
        return ForgeResult(
            status="unforged", poc_code=code, control_code=control_code, attack_output=attack_trace,
            control_output=control_trace, iterations=total_iters,
            notes="rejected by differential gate: control (attack removed) also passed",
        )

    return ForgeResult(
        status="forged", poc_code=code, control_code=control_code, attack_output=attack_trace,
        control_output=control_trace, iterations=total_iters, notes="",
    )
