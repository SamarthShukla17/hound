"""Step N: Dossier renderer — honest confidence line, verbatim evidence, no fabricated sections."""

import pytest

from bloodhound.dossier import render
from bloodhound.forger import ForgeResult
from bloodhound.novelty import NoveltyResult
from bloodhound.refute import PanelResult

FINDING = {
    "id": "HB-001",
    "title": "rounding splits a fresh payout",
    "severity": "high",
    "location": "Vault.sol:42-58",
    "root_cause": "closePosition rounds down then re-credits the remainder as a new claim",
    "impact": "a trader's payout is split, inflating total claims recorded",
}

FORGED = ForgeResult(
    status="forged",
    poc_code="function test_poc_HB001() public { assertEq(1, 2); }",
    control_code="function test_poc_HB001() public { assertEq(1, 1); }",
    attack_output="trace: assertion failed at line 1",
)


def test_render_rejects_a_non_forged_result():
    unforged = ForgeResult(status="unforged", poc_code="", attack_output="")
    with pytest.raises(ValueError, match="forged"):
        render(FINDING, unforged)


def test_render_includes_honest_confidence_and_commit():
    out = render(FINDING, FORGED, commit="abc1234")
    assert "CONFIDENCE:   Foundry-verified: 1 test passing on abc1234, unmodified contracts" in out


def test_render_without_commit_omits_the_on_clause():
    out = render(FINDING, FORGED)
    assert "Foundry-verified: 1 test passing, unmodified contracts" in out
    assert " on ," not in out


def test_render_quotes_poc_and_traces_verbatim():
    out = render(FINDING, FORGED)
    assert FORGED.poc_code.strip() in out
    assert FORGED.control_code.strip() in out
    assert "assertion failed at line 1" in out
    assert "Control (same test" in out


def test_render_never_fabricates_missing_sections():
    out = render(FINDING, FORGED)
    assert "[TODO - human:" in out
    assert "Threat Model" in out and "Production Parameters" in out
    assert "Recommendation" in out and "Duplicate Differentiation" in out


def test_render_includes_refutation_log_when_panel_given():
    panel = PanelResult(
        killed=False,
        role_verdicts={"refute1": {"verdict": "could-not-refute", "reason": "reachable, no guard found"}},
    )
    out = render(FINDING, FORGED, panel_result=panel)
    assert "Refutation Log" in out
    assert "refute1: could-not-refute - reachable, no guard found" in out
    assert "panel result: survived" in out


def test_render_includes_surviving_refutation_when_panel_killed():
    panel = PanelResult(killed=True, surviving_refutation="refute1: keeper-only path", role_verdicts={})
    out = render(FINDING, FORGED, panel_result=panel)
    assert "panel result: KILLED - refute1: keeper-only path" in out
    assert "no refuter role configured" in out


def test_render_omits_refutation_log_when_panel_not_given():
    out = render(FINDING, FORGED)
    assert "Refutation Log" not in out


def test_render_includes_novelty_with_nearest_match():
    novelty = NoveltyResult(verdict="known-pattern-new-mechanism", nearest=[{"id": "C1", "source": "solodit:9", "similarity": 0.81}])
    out = render(FINDING, FORGED, novelty_result=novelty)
    assert "Novelty" in out
    assert "known-pattern-new-mechanism (nearest: C1 solodit:9, similarity 0.81)" in out


def test_render_omits_novelty_when_not_given():
    out = render(FINDING, FORGED)
    assert "Novelty" not in out
