"""Step K: Refutation Panel — binary checklist, swap-and-discard, injection re-verify. No real forge."""

import asyncio
from types import SimpleNamespace

import pytest

from bloodhound.forger import ForgeResult
from bloodhound.refute import inject_assumption, run_panel
from hound.knowledge import KB


@pytest.fixture
def kb():
    return KB(principles="1. FALSIFICATION-FIRST-MARKER: find the cheapest disproof.", lenses=[])


@pytest.fixture
def finding():
    return {"id": "HB-001", "title": "rounding splits a payout", "severity": "high"}


@pytest.fixture
def forged():
    return ForgeResult(
        status="forged",
        poc_code="function test_poc_HB001() public { assertEq(1, 2); }",
        attack_output="trace: assertion failed",
    )


COULD_NOT = {"verdict": "could-not-refute", "reason": "no disproof found", "checklist": {"reachable": True}}


def refuted(assumption="require(msg.sender == keeper);"):
    return {"verdict": "refuted", "reason": "keeper-only path", "checklist": {"reachable": False}, "injectable_assumption": assumption}


class FakeRouter:
    """Scripted per-role chat_json queue, consumed in call order (claim_first then code_first)."""

    def __init__(self, scripts: dict):
        self.scripts = {r: list(v) for r, v in scripts.items()}
        self.calls = []

    def has(self, role):
        return role in self.scripts

    async def chat_json(self, role, system, user, *, temperature=0.0, max_tokens=2048, cache_salt=""):
        self.calls.append({"role": role, "cache_salt": cache_salt})
        queue = self.scripts.get(role)
        if not queue:
            raise RuntimeError(f"no script for role {role}")
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


OK = SimpleNamespace(returncode=0, stdout="PASS", stderr="")
FAIL = SimpleNamespace(returncode=1, stdout="FAIL", stderr="assertion failed")


def _scripted_runner(results):
    calls = {"i": 0}

    def runner(cmd, **kw):
        r = results[calls["i"]]
        calls["i"] += 1
        return r

    return runner


# --- inject_assumption -----------------------------------------------------


def test_inject_assumption_inserts_after_opening_brace():
    code = "function test_x() public {\n    assertEq(1, 2);\n}"
    out = inject_assumption(code, "test_x", "require(true)")
    assert "require(true);" in out
    assert out.index("require(true);") < out.index("assertEq(1, 2);")


def test_inject_assumption_returns_none_if_test_not_found():
    assert inject_assumption("contract X {}", "test_missing", "require(true)") is None


# --- run_panel ---------------------------------------------------------


def test_run_panel_no_roles_configured_is_a_noop(kb, finding, forged, tmp_path):
    router = FakeRouter({})
    result = asyncio.run(run_panel(router, kb, finding, forged, tmp_path, tmp_path / "test" / "bh"))
    assert result.killed is False
    assert "no refuter role configured" in result.notes


def test_run_panel_all_could_not_refute_does_not_kill(kb, finding, forged, tmp_path):
    router = FakeRouter({"refute1": [COULD_NOT, COULD_NOT]})
    result = asyncio.run(run_panel(router, kb, finding, forged, tmp_path, tmp_path / "test" / "bh"))
    assert result.killed is False
    assert result.role_verdicts["refute1"]["verdict"] == "could-not-refute"


def test_run_panel_swap_disagreement_is_discarded_as_unreliable(kb, finding, forged, tmp_path):
    router = FakeRouter({"refute1": [refuted(), COULD_NOT]})  # claim_first says refuted, code_first disagrees
    result = asyncio.run(run_panel(router, kb, finding, forged, tmp_path, tmp_path / "test" / "bh"))
    assert result.killed is False
    assert result.role_verdicts["refute1"]["verdict"] == "unreliable"


def test_run_panel_refutation_invalid_when_injection_still_passes(kb, finding, forged, tmp_path):
    router = FakeRouter({"refute1": [refuted(), refuted()]})  # both swaps agree: refuted
    runner = _scripted_runner([OK, OK])  # injected build=OK, injected test=OK (attack still passes)
    result = asyncio.run(run_panel(router, kb, finding, forged, tmp_path, tmp_path / "test" / "bh", runner=runner))
    assert result.killed is False
    assert "INVALID" in result.role_verdicts["refute1"]["injection"]


def test_run_panel_refutation_survives_and_kills_the_finding(kb, finding, forged, tmp_path):
    router = FakeRouter({"refute1": [refuted(), refuted()]})
    runner = _scripted_runner([OK, FAIL])  # injected build=OK, injected test=FAIL (attack no longer passes)
    result = asyncio.run(run_panel(router, kb, finding, forged, tmp_path, tmp_path / "test" / "bh", runner=runner))
    assert result.killed is True
    assert result.surviving_refutation.startswith("refute1:")
    assert "SURVIVES" in result.role_verdicts["refute1"]["injection"]


def test_run_panel_injection_that_fails_to_compile_is_unverified_not_surviving(kb, finding, forged, tmp_path):
    router = FakeRouter({"refute1": [refuted(), refuted()]})
    runner = _scripted_runner([FAIL])  # injected build fails outright
    result = asyncio.run(run_panel(router, kb, finding, forged, tmp_path, tmp_path / "test" / "bh", runner=runner))
    assert result.killed is False
    assert "unverified" in result.role_verdicts["refute1"]["injection"]


def test_run_panel_malformed_answer_is_repaired_once(kb, finding, forged, tmp_path):
    bad = {"verdict": "maybe"}  # invalid literal -> ValidationError -> one repair attempt
    router = FakeRouter({"refute1": [bad, COULD_NOT, COULD_NOT]})
    result = asyncio.run(run_panel(router, kb, finding, forged, tmp_path, tmp_path / "test" / "bh"))
    # claim_first required a repair call (consumes the 2nd script item), code_first used the 3rd
    assert result.role_verdicts["refute1"]["verdict"] == "could-not-refute"


def test_run_panel_no_test_function_in_poc_is_a_noop(kb, finding, tmp_path):
    router = FakeRouter({"refute1": [COULD_NOT, COULD_NOT]})
    forged_no_test = ForgeResult(status="forged", poc_code="contract NotATest {}", attack_output="")
    result = asyncio.run(run_panel(router, kb, finding, forged_no_test, tmp_path, tmp_path / "test" / "bh"))
    assert result.killed is False
    assert "no test_" in result.notes
