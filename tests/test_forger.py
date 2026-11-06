"""Step J: PoC Forger — deterministic repair, compile/repair loop, differential gate. No real forge."""

import asyncio
from types import SimpleNamespace

import pytest

from bloodhound.forger import (
    ForgeResult,
    compile,
    deterministic_repair,
    first_test_name,
    forge_candidate,
    normalise_pragma,
    run_test,
    strip_fences,
)
from hound.knowledge import KB


@pytest.fixture
def kb():
    return KB(principles="1. FALSIFICATION-FIRST-MARKER: find the cheapest disproof.", lenses=[])


@pytest.fixture
def finding():
    return {"id": "HB-001", "title": "rounding splits a payout", "severity": "high"}


class FakeRouter:
    """chat() returns successive items from `replies` on each call; records every call."""

    def __init__(self, replies=None, error=None):
        self.replies = list(replies) if replies is not None else []
        self.error = error
        self.calls = []

    async def chat(self, role, system, user, *, temperature=0.3, max_tokens=2048, cache_salt=""):
        self.calls.append({"role": role, "system": system, "user": user, "cache_salt": cache_salt})
        if self.error is not None:
            raise self.error
        return self.replies.pop(0) if self.replies else "// empty repair\nfunction test_x() public {}\n"


# --- deterministic repair -------------------------------------------------


def test_strip_fences():
    assert strip_fences("```solidity\ncontract X {}\n```") == "contract X {}\n"
    assert strip_fences("contract X {}") == "contract X {}\n"


def test_normalise_pragma(tmp_path):
    (tmp_path / "foundry.toml").write_text('[profile.default]\nsolc = "0.8.19"\n')
    code = 'pragma solidity ^0.8.0;\ncontract X {}\n'
    assert "pragma solidity ^0.8.19;" in normalise_pragma(code, tmp_path)


def test_normalise_pragma_no_foundry_toml_is_noop(tmp_path):
    code = "pragma solidity ^0.8.0;\n"
    assert normalise_pragma(code, tmp_path) == code


def test_deterministic_repair_combines_both(tmp_path):
    (tmp_path / "foundry.toml").write_text('solc = "0.8.21"\n')
    code = "```solidity\npragma solidity ^0.8.0;\ncontract X {}\n```"
    out = deterministic_repair(code, tmp_path)
    assert "```" not in out
    assert "0.8.21" in out


def test_first_test_name():
    assert first_test_name("function test_payoutSplit() public {}") == "test_payoutSplit"
    assert first_test_name("contract X {}") is None


# --- compile / run_test (fake subprocess runner) --------------------------


def test_compile_ok(tmp_path):
    fake = lambda cmd, **kw: SimpleNamespace(returncode=0, stdout="", stderr="")  # noqa: E731
    ok, err = compile(tmp_path / "A.t.sol", tmp_path, runner=fake)
    assert ok and err == ""


def test_compile_failure_returns_stderr(tmp_path):
    fake = lambda cmd, **kw: SimpleNamespace(returncode=1, stdout="", stderr="identifier not found")  # noqa: E731
    ok, err = compile(tmp_path / "A.t.sol", tmp_path, runner=fake)
    assert not ok
    assert "identifier not found" in err


def test_run_test_pass_and_fail(tmp_path):
    passing = lambda cmd, **kw: SimpleNamespace(returncode=0, stdout="ok", stderr="")  # noqa: E731
    failing = lambda cmd, **kw: SimpleNamespace(returncode=1, stdout="revert", stderr="")  # noqa: E731
    ok, _ = run_test(tmp_path / "A.t.sol", tmp_path, "test_x", runner=passing)
    assert ok
    ok, trace = run_test(tmp_path / "A.t.sol", tmp_path, "test_x", runner=failing)
    assert not ok and "revert" in trace


# --- forge_candidate: the differential gate --------------------------------


def _scripted_runner(results):
    """results: list of SimpleNamespace, consumed in call order (build, test, build, test, ...)."""
    calls = {"i": 0}

    def runner(cmd, **kw):
        r = results[calls["i"]]
        calls["i"] += 1
        return r

    return runner


OK = SimpleNamespace(returncode=0, stdout="PASS", stderr="")
FAIL = SimpleNamespace(returncode=1, stdout="FAIL", stderr="assertion failed")


def test_forge_candidate_forged_when_attack_passes_and_control_fails(kb, finding, tmp_path):
    attack_code = "function test_poc_HB001() public { assertEq(1, 2); }"
    control_code = "function test_poc_HB001() public { assertEq(1, 1); }"
    router = FakeRouter(replies=[control_code])
    # build(attack)=OK, test(attack)=OK(pass), build(control)=OK, test(control)=FAIL
    runner = _scripted_runner([OK, OK, OK, FAIL])

    result = asyncio.run(
        forge_candidate(router, kb, finding, attack_code, tmp_path, tmp_path / "test" / "bh", runner=runner)
    )

    assert result.status == "forged"
    assert result.iterations == 0
    assert result.control_code.strip() == control_code.strip()


def test_forge_candidate_unforged_when_attack_does_not_pass(kb, finding, tmp_path):
    attack_code = "function test_poc_HB001() public { assertEq(1, 2); }"
    router = FakeRouter()
    # build(attack)=OK, test(attack)=FAIL -> stop, never generate a control
    runner = _scripted_runner([OK, FAIL])

    result = asyncio.run(
        forge_candidate(router, kb, finding, attack_code, tmp_path, tmp_path / "test" / "bh", runner=runner)
    )

    assert result.status == "unforged"
    assert "bug not demonstrated" in result.notes
    assert router.calls == []  # no LLM call needed: killed before the control step


def test_forge_candidate_unforged_when_control_also_passes_tautological_gate(kb, finding, tmp_path):
    attack_code = "function test_poc_HB001() public { assertEq(1, 2); }"
    control_code = "function test_poc_HB001() public { assertEq(1, 2); }"  # still passes w/o attack
    router = FakeRouter(replies=[control_code])
    runner = _scripted_runner([OK, OK, OK, OK])  # control run also passes

    result = asyncio.run(
        forge_candidate(router, kb, finding, attack_code, tmp_path, tmp_path / "test" / "bh", runner=runner)
    )

    assert result.status == "unforged"
    assert "differential gate" in result.notes


def test_forge_candidate_compile_failed_after_exhausting_repairs(kb, finding, tmp_path):
    attack_code = "function test_poc_HB001() public { broken }"
    router = FakeRouter(replies=["still broken 1", "still broken 2", "still broken 3", "still broken 4"])
    # every build attempt fails: 1 initial + 4 repairs = 5 build calls, no test calls ever reached
    runner = _scripted_runner([FAIL] * 5)

    result = asyncio.run(
        forge_candidate(
            router, kb, finding, attack_code, tmp_path, tmp_path / "test" / "bh", runner=runner, max_repairs=4
        )
    )

    assert result.status == "compile_failed"
    assert result.iterations == 4
    assert len(router.calls) == 4


def test_forge_candidate_repairs_then_succeeds(kb, finding, tmp_path):
    attack_code = "function test_poc_HB001() public { broken }"
    fixed_code = "function test_poc_HB001() public { assertEq(1, 2); }"
    control_code = "function test_poc_HB001() public { assertEq(1, 1); }"
    router = FakeRouter(replies=[fixed_code, control_code])
    # build(attack)=FAIL, [repair], build(attack)=OK, test(attack)=OK, build(control)=OK, test(control)=FAIL
    runner = _scripted_runner([FAIL, OK, OK, OK, FAIL])

    result = asyncio.run(
        forge_candidate(router, kb, finding, attack_code, tmp_path, tmp_path / "test" / "bh", runner=runner)
    )

    assert result.status == "forged"
    assert result.iterations == 1
    assert fixed_code in result.poc_code  # repaired code (not the originally-broken one) was used


def test_forge_candidate_no_test_function_is_compile_failed(kb, finding, tmp_path):
    code_without_test_fn = "contract NotATest {}"
    router = FakeRouter()
    runner = _scripted_runner([OK])  # compiles fine, but has no test_* function

    result = asyncio.run(
        forge_candidate(router, kb, finding, code_without_test_fn, tmp_path, tmp_path / "test" / "bh", runner=runner)
    )

    assert result.status == "compile_failed"
    assert "no test_" in result.notes
