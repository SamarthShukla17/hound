"""Step 5: Finding/Verdict schemas validate per-entry, not per-batch."""

import pytest
from pydantic import ValidationError

from hound.schema import SEV_RANK, Finding, Verdict


def test_finding_valid_construction():
    f = Finding(
        title="Reentrancy in withdraw",
        severity="high",
        location="Vault.sol:20-25",
        root_cause="state updated after the external call",
        impact="attacker drains the vault",
        exploit_steps=["deposit", "call withdraw with a malicious receiver", "reenter"],
    )
    assert f.confidence == 0.5
    assert f.bug_class == ""


def test_finding_rejects_bad_severity():
    with pytest.raises(ValidationError):
        Finding(
            title="x",
            severity="apocalyptic",
            location="Vault.sol:1",
            root_cause="x",
            impact="x",
            exploit_steps=[],
        )


def test_finding_confidence_bounds():
    with pytest.raises(ValidationError):
        Finding(
            title="x",
            severity="low",
            location="Vault.sol:1",
            root_cause="x",
            impact="x",
            exploit_steps=[],
            confidence=1.5,
        )


def test_one_malformed_finding_does_not_discard_the_others():
    raw = [
        {"title": "ok one", "severity": "low", "location": "V.sol:1", "root_cause": "r", "impact": "i", "exploit_steps": []},
        {"title": "bad one", "severity": "not-a-severity", "location": "V.sol:1", "root_cause": "r", "impact": "i", "exploit_steps": []},
        {"title": "ok two", "severity": "medium", "location": "V.sol:2", "root_cause": "r", "impact": "i", "exploit_steps": []},
    ]
    good = []
    for entry in raw:
        try:
            good.append(Finding(**entry))
        except ValidationError:
            continue
    assert [f.title for f in good] == ["ok one", "ok two"]


def test_verdict_severity_is_optional():
    v = Verdict(verdict="kill", reason="citation gate", killed_by="citation gate")
    assert v.severity is None


def test_a_judge_kill_must_cite_where_the_disproof_lives():
    with pytest.raises(ValidationError, match="disproof_location"):
        Verdict(verdict="kill", reason="a guard prevents this", killed_by="onlyOwner")
    ok = Verdict(verdict="kill", reason="a guard prevents this", killed_by="onlyOwner",
                 disproof_location="Vault.sol:88")
    assert ok.disproof_location == "Vault.sol:88"


@pytest.mark.parametrize("marker", ["citation gate", "stale citation (file changed since hunt)"])
def test_deterministic_gate_kills_are_exempt_because_they_are_self_justifying(marker):
    v = Verdict(verdict="kill", reason="does not resolve", killed_by=marker)
    assert v.verdict == "kill" and v.disproof_location == ""


def test_keep_and_needs_poc_never_need_a_disproof_location():
    assert Verdict(verdict="keep", reason="r").disproof_location == ""
    assert Verdict(verdict="needs_poc", reason="r").disproof_location == ""


def test_sev_rank_orders_critical_first():
    assert SEV_RANK["critical"] < SEV_RANK["high"] < SEV_RANK["medium"] < SEV_RANK["low"]


@pytest.mark.parametrize("blank", ["null", "NULL", "None", "", "  ", None])
def test_verdict_coerces_blank_severity_to_none(blank):
    v = Verdict(verdict="keep", reason="r", severity=blank)
    assert v.severity is None


def test_verdict_still_rejects_a_genuinely_invalid_severity():
    with pytest.raises(ValidationError):
        Verdict(verdict="keep", reason="r", severity="catastrophic")


def test_verdict_coerces_null_killed_by_to_empty_string():
    assert Verdict(verdict="keep", reason="r", killed_by=None).killed_by == ""


def test_verdict_missing_verdict_is_still_a_validation_error():
    with pytest.raises(ValidationError):
        Verdict(**{"auditor": "Senior Smart-contract auditor", "evidence": []})
