"""Step R: deep-fuzz escalation (Echidna/Medusa) on a claim the fast gate could not falsify.

Output parsing here mirrors real local runs of Echidna 2.3.3 / Medusa 1.5.1 captured during
development (see deepfuzz.py's module docstring) - no real subprocess calls in these tests."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from bloodhound.deepfuzz import (
    DeepFuzzResult,
    echidna_available,
    escalate,
    medusa_available,
    property_name,
    run_echidna,
    run_medusa,
    write_echidna_config,
    write_medusa_config,
)
from bloodhound.invariants import InvariantClaim
from hound.knowledge import KB


@pytest.fixture
def kb():
    return KB(principles="1. FALSIFICATION-FIRST-MARKER: find the cheapest disproof.", lenses=[])


def _claim(**overrides):
    base = dict(
        id="R-01",
        claim="total never exceeds the sum of deposits",
        property="total <= sum(deposits)",
        handler_targets=["deposit", "withdraw"],
    )
    base.update(overrides)
    return InvariantClaim(**base)


class FakeRouter:
    def __init__(self, chat_replies=None, chat_error=None):
        self.chat_replies = list(chat_replies) if chat_replies is not None else []
        self.chat_error = chat_error

    async def chat(self, role, system, user, *, temperature=0.3, max_tokens=2048, cache_salt=""):
        if self.chat_error is not None:
            raise self.chat_error
        return self.chat_replies.pop(0) if self.chat_replies else "contract DeepFuzz_R01 {}\n"


OK = SimpleNamespace(returncode=0, stdout="", stderr="")


def _scripted_runner(results):
    calls = {"i": 0}

    def runner(cmd, **kw):
        r = results[calls["i"]]
        calls["i"] += 1
        return r

    return runner


# --- property_name -----------------------------------------------------------


def test_property_name_sanitizes_invalid_identifier_characters():
    assert property_name("R-01") == "echidna_R_01"
    assert property_name("plain") == "echidna_plain"


# --- availability --------------------------------------------------------------


def test_availability_true_for_non_default_runner():
    # a scripted runner stands in for "the binary exists" in every other test here
    assert echidna_available(runner=lambda *a, **k: None) is True
    assert medusa_available(runner=lambda *a, **k: None) is True


def test_availability_false_when_binary_missing(monkeypatch):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert echidna_available() is False
    assert medusa_available() is False


# --- config writers -------------------------------------------------------------


def test_write_echidna_config_contains_property_mode_and_limits(tmp_path):
    path = tmp_path / "echidna.yaml"
    write_echidna_config(path, test_limit=1234, seq_len=56)
    text = path.read_text()
    assert "testMode: property" in text
    assert "testLimit: 1234" in text
    assert "seqLen: 56" in text


def test_write_medusa_config_forces_coverage_on_and_shares_echidna_prefix(tmp_path):
    path = tmp_path / "medusa.json"
    write_medusa_config(path, "DeepFuzz_R01", "echidna_R_01", timeout=99)
    config = json.loads(path.read_text())
    fz = config["fuzzing"]
    assert fz["coverageEnabled"] is True  # False crashed medusa 1.5.1 in a real local run
    assert fz["targetContracts"] == ["DeepFuzz_R01"]
    assert fz["timeout"] == 99
    assert fz["testing"]["propertyTesting"]["testPrefixes"] == ["echidna_"]
    assert fz["testing"]["assertionTesting"]["enabled"] is False


# --- run_echidna: parsing grounded in a real local run ------------------------


def test_run_echidna_unavailable_when_binary_missing(tmp_path, monkeypatch):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: None)
    result = run_echidna(tmp_path / "x.sol", "X", tmp_path / "c.yaml", "echidna_x", tmp_path)
    assert result.status == "unavailable"


def test_run_echidna_held_on_exit_zero_with_passing_line(tmp_path):
    passing = SimpleNamespace(returncode=0, stdout="echidna_R_01: passing\n", stderr="")
    result = run_echidna(tmp_path / "x.sol", "X", tmp_path / "c.yaml", "echidna_R_01", tmp_path,
                          runner=_scripted_runner([passing]))
    assert result.status == "held"


def test_run_echidna_counterexample_on_failed_line(tmp_path):
    failed = SimpleNamespace(returncode=1, stdout="echidna_R_01: failed!\n  Call sequence:\n", stderr="")
    result = run_echidna(tmp_path / "x.sol", "X", tmp_path / "c.yaml", "echidna_R_01", tmp_path,
                          runner=_scripted_runner([failed]))
    assert result.status == "counterexample"
    assert "echidna" in result.raw_output


def test_run_echidna_error_on_unparseable_nonzero_exit(tmp_path):
    crash = SimpleNamespace(returncode=1, stdout="", stderr="panic!")
    result = run_echidna(tmp_path / "x.sol", "X", tmp_path / "c.yaml", "echidna_R_01", tmp_path,
                          runner=_scripted_runner([crash]))
    assert result.status == "error"


# --- run_medusa: exit code is NOT trusted, only the summary line --------------


def test_run_medusa_held_when_summary_shows_zero_failed(tmp_path):
    passing = SimpleNamespace(returncode=0, stdout="Test summary: 1 test(s) passed, 0 test(s) failed\n", stderr="")
    result = run_medusa(tmp_path / "c.json", "echidna_R_01", tmp_path, runner=_scripted_runner([passing]))
    assert result.status == "held"


def test_run_medusa_counterexample_when_summary_shows_failures_even_at_exit_zero(tmp_path):
    # grounded in a real local run: medusa returned exit 0 even with a failing property test
    weird_pass_exit = SimpleNamespace(
        returncode=0, stdout="Test summary: 0 test(s) passed, 1 test(s) failed\n", stderr="",
    )
    result = run_medusa(tmp_path / "c.json", "echidna_R_01", tmp_path, runner=_scripted_runner([weird_pass_exit]))
    assert result.status == "counterexample"


def test_run_medusa_error_without_parseable_summary(tmp_path):
    crash = SimpleNamespace(returncode=2, stdout="", stderr="panic: nil pointer\n")
    result = run_medusa(tmp_path / "c.json", "echidna_R_01", tmp_path, runner=_scripted_runner([crash]))
    assert result.status == "error"


# --- escalate: orchestration ----------------------------------------------------


def test_escalate_compile_failed_short_circuits_both_tools(kb, tmp_path):
    router = FakeRouter(chat_replies=["contract Broken { function f( }"])
    build_fail = SimpleNamespace(returncode=1, stdout="", stderr="parse error")
    runner = _scripted_runner([build_fail] * 10)  # every repair attempt also fails

    results = asyncio.run(
        escalate(router, kb, _claim(), "// code", tmp_path, tmp_path / "out", tool="both",
                 max_repairs=1, runner=runner)
    )

    assert results["echidna"].status == "compile_failed"
    assert results["medusa"].status == "compile_failed"


def test_escalate_runs_both_tools_against_the_same_generated_contract(kb, tmp_path):
    router = FakeRouter(chat_replies=["contract DeepFuzz_R_01 { function echidna_R_01() public view returns (bool) { return true; } }"])
    build_ok = SimpleNamespace(returncode=0, stdout="", stderr="")
    echidna_pass = SimpleNamespace(returncode=0, stdout="echidna_R_01: passing\n", stderr="")
    medusa_pass = SimpleNamespace(returncode=0, stdout="Test summary: 1 test(s) passed, 0 test(s) failed\n", stderr="")
    runner = _scripted_runner([build_ok, echidna_pass, medusa_pass])

    results = asyncio.run(
        escalate(router, kb, _claim(), "// code", tmp_path, tmp_path / "out", tool="both", runner=runner)
    )

    assert results["echidna"].status == "held"
    assert results["medusa"].status == "held"
    assert (tmp_path / "out" / "DeepFuzz_R_01.sol").exists()


def test_escalate_single_tool_only_runs_that_one(kb, tmp_path):
    router = FakeRouter(chat_replies=["contract DeepFuzz_R_01 {}"])
    build_ok = SimpleNamespace(returncode=0, stdout="", stderr="")
    echidna_pass = SimpleNamespace(returncode=0, stdout="echidna_R_01: passing\n", stderr="")
    runner = _scripted_runner([build_ok, echidna_pass])

    results = asyncio.run(
        escalate(router, kb, _claim(), "// code", tmp_path, tmp_path / "out", tool="echidna", runner=runner)
    )

    assert set(results.keys()) == {"echidna"}
    assert results["echidna"].status == "held"
