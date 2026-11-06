"""Step L: Invariant Engine — claim loading, handler generation, compile/repair, fast gate. No real forge."""

import asyncio
from types import SimpleNamespace

import pytest
import yaml
from pydantic import ValidationError

from bloodhound.invariants import InvariantClaim, forge_invariant, load_claims
from hound.knowledge import KB


@pytest.fixture
def kb():
    return KB(principles="1. FALSIFICATION-FIRST-MARKER: find the cheapest disproof.", lenses=[])


def _claim(**overrides):
    base = dict(
        id="PLE-003",
        claim="Plether never splits one fresh payout between an immediate credit and a new claim",
        property="payout == credited_now OR payout == claim_recorded, never a mix",
        source="docs.plether.com",
        ghosts=["total_credits_issued"],
        handler_targets=["closePosition"],
        attacker_roles=["trader"],
    )
    base.update(overrides)
    return InvariantClaim(**base)


class FakeRouter:
    def __init__(self, chat_replies=None, chat_error=None):
        self.chat_replies = list(chat_replies) if chat_replies is not None else []
        self.chat_error = chat_error
        self.calls = []

    async def chat(self, role, system, user, *, temperature=0.3, max_tokens=2048, cache_salt=""):
        self.calls.append({"role": role, "cache_salt": cache_salt})
        if self.chat_error is not None:
            raise self.chat_error
        return self.chat_replies.pop(0) if self.chat_replies else "function invariant_x() public {}\n"


OK = SimpleNamespace(returncode=0, stdout="PASS", stderr="")
FAIL = SimpleNamespace(returncode=1, stdout="FAIL", stderr="counterexample found")


def _scripted_runner(results):
    calls = {"i": 0}

    def runner(cmd, **kw):
        r = results[calls["i"]]
        calls["i"] += 1
        return r

    return runner


# --- load_claims -----------------------------------------------------------


def test_load_claims_parses_yaml_list(tmp_path):
    path = tmp_path / "invariants.yaml"
    path.write_text(
        yaml.dump([
            {"id": "A1", "claim": "never splits", "property": "p == c xor p == q", "ghosts": ["x"]},
        ])
    )
    claims = load_claims(path)
    assert len(claims) == 1
    assert claims[0].id == "A1"
    assert claims[0].ghosts == ["x"]
    assert claims[0].source == ""  # optional field defaults


def test_load_claims_empty_file_is_empty_list(tmp_path):
    path = tmp_path / "invariants.yaml"
    path.write_text("")
    assert load_claims(path) == []


def test_invariant_claim_requires_claim_and_property():
    with pytest.raises(ValidationError):
        InvariantClaim(id="A1")


# --- forge_invariant: the fast gate -----------------------------------------


def test_forge_invariant_held_when_no_counterexample(kb, tmp_path):
    handler = "function invariant_PLE003() public { assertTrue(true); }"
    router = FakeRouter(chat_replies=[handler])
    runner = _scripted_runner([OK, OK])  # build=OK, test(invariant)=OK (held)

    result = asyncio.run(
        forge_invariant(router, kb, _claim(), "// code", tmp_path, tmp_path / "test" / "bh", runner=runner)
    )

    assert result.status == "held"
    assert result.iterations == 0


def test_forge_invariant_counterexample_when_gate_fails(kb, tmp_path):
    handler = "function invariant_PLE003() public { assertTrue(false); }"
    router = FakeRouter(chat_replies=[handler])
    runner = _scripted_runner([OK, FAIL])  # build=OK, test(invariant)=FAIL -> counterexample

    result = asyncio.run(
        forge_invariant(router, kb, _claim(), "// code", tmp_path, tmp_path / "test" / "bh", runner=runner)
    )

    assert result.status == "counterexample"
    assert "breaks the claimed property" in result.notes


def test_forge_invariant_repairs_then_gates(kb, tmp_path):
    broken = "function invariant_PLE003() public { broken }"
    fixed = "function invariant_PLE003() public { assertTrue(true); }"
    router = FakeRouter(chat_replies=[broken, fixed])
    runner = _scripted_runner([FAIL, OK, OK])  # build fails, [repair], build OK, test OK

    result = asyncio.run(
        forge_invariant(router, kb, _claim(), "// code", tmp_path, tmp_path / "test" / "bh", runner=runner)
    )

    assert result.status == "held"
    assert result.iterations == 1


def test_forge_invariant_compile_failed_without_invariant_function(kb, tmp_path):
    handler = "contract NotAnInvariantTest {}"
    router = FakeRouter(chat_replies=[handler])
    runner = _scripted_runner([OK])  # compiles fine, but no invariant_* function

    result = asyncio.run(
        forge_invariant(router, kb, _claim(), "// code", tmp_path, tmp_path / "test" / "bh", runner=runner)
    )

    assert result.status == "compile_failed"
    assert "no invariant_" in result.notes


def test_forge_invariant_generation_failure_is_compile_failed(kb, tmp_path):
    router = FakeRouter(chat_error=RuntimeError("all targets failed"))
    result = asyncio.run(
        forge_invariant(router, kb, _claim(), "// code", tmp_path, tmp_path / "test" / "bh", runner=_scripted_runner([]))
    )
    assert result.status == "compile_failed"
    assert "handler generation failed" in result.notes
