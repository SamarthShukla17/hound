"""Step E: profit-vs-disruption classification - schema, deterministic warnings, prompts, report."""

import asyncio
import json
from pathlib import Path

import pytest

from hound.agents import hunter, judge, system
from hound.knowledge import KB, Lens, load_kb
from hound.pipeline import _render_report, _tier_line
from hound.schema import Finding, Verdict
from hound.tiers import normalise, stated_gain, tier_of, tier_warning

KB_DIR = Path(__file__).parent.parent / "kb"

BASE = dict(title="t", severity="high", location="A.sol:1", observation="o", invariant="i", violation="v",
            root_cause="r", impact="the reserve is drained", exploit_steps=["s"])


# --- deterministic helpers ---------------------------------------------------


def test_normalise_and_stated_gain():
    assert normalise("Profit") == "profit" and normalise("DISRUPTION ") == "disruption"
    assert normalise("theft") == "unclear" and normalise(None) == "unclear"
    assert stated_gain("+50.7 STABLE per 100 debt") is True
    assert all(stated_gain(x) is False for x in ("", "none", "None", "N/A", "-", None, "0"))


def test_tier_of_prefers_the_judges_recomputation():
    f = {"value_flow": "profit"}
    assert tier_of(f) == "profit"
    assert tier_of(f, Verdict(verdict="keep", reason="r", value_flow="disruption")) == "disruption"
    assert tier_of(f, Verdict(verdict="keep", reason="r")) == "profit"  # judge silent -> hunter's tier


def test_severity_warnings_follow_the_tier():
    assert tier_warning({}, "medium", "unclear") == ""  # only high/critical are policed
    assert "never accounted" in tier_warning({}, "high", "unclear")
    assert "not quantified" in tier_warning({"attacker_gain": "some profit"}, "critical", "profit")
    assert tier_warning({"attacker_gain": "+50 STABLE from the owner"}, "high", "profit") == ""
    assert "justify or lower" in tier_warning({"impact": "the keeper call reverts"}, "high", "disruption")
    assert tier_warning({"impact": "user collateral is permanently frozen"}, "high", "disruption") == ""
    assert tier_warning({"impact": "leaves 100k of debt with no reserve: insolvency"}, "critical", "disruption") == ""


# --- schema ------------------------------------------------------------------


def test_finding_defaults_to_unclear_and_roundtrips():
    f = Finding(**BASE)
    assert f.value_flow == "unclear" and f.attacker_gain == ""
    g = Finding(**BASE, value_flow="Profit", attacker_gain="+12 STABLE, taken from vault owners")
    assert g.value_flow == "profit"
    assert Finding(**json.loads(g.model_dump_json())).value_flow == "profit"


def test_profit_without_a_stated_gain_is_downgraded_not_dropped():
    assert Finding(**BASE, value_flow="profit", attacker_gain="").value_flow == "unclear"
    assert Finding(**BASE, value_flow="profit", attacker_gain="none").value_flow == "unclear"
    assert Finding(**BASE, value_flow="nonsense").value_flow == "unclear"
    assert Finding(**BASE, value_flow="disruption", attacker_gain="none").value_flow == "disruption"


def test_verdict_tier_is_optional_and_normalised():
    assert Verdict(verdict="keep", reason="r").value_flow is None
    assert Verdict(verdict="keep", reason="r", value_flow="null").value_flow is None
    assert Verdict(verdict="keep", reason="r", value_flow="Disruption").value_flow == "disruption"


# --- prompts -------------------------------------------------------------------


class FakeRouter:
    def __init__(self, reply):
        self.reply, self.calls = reply, []

    async def chat_json(self, role, system, user, **kw):
        self.calls.append({"role": role, "system": system, "user": user})
        return self.reply


@pytest.fixture
def kb():
    return KB(principles="P", lenses=[Lens(id="A1", kind="angle", title="T", body="B")], tiers="TIERS-DOC-MARKER")


def test_tier_doc_is_in_the_system_prompt_and_the_shipped_kb_provides_it():
    assert "TIERS-DOC-MARKER" in system(KB(principles="P", tiers="TIERS-DOC-MARKER"))
    assert "TIERS-DOC-MARKER" not in system(KB(principles="P"))
    shipped = load_kb(KB_DIR)
    assert "FINDING TIERS" in shipped.tiers and "equity test" in shipped.tiers.lower()
    assert "FINDING TIERS" in system(shipped)


def test_hunter_prompt_demands_the_equity_test_and_the_new_fields(kb):
    router = FakeRouter({"findings": []})
    asyncio.run(hunter(router, kb, kb.lenses[0], "code"))
    user = router.calls[0]["user"]
    assert "equity test" in user and "value_flow" in user and "attacker_gain" in user
    assert "profit|disruption|unclear" in user


def test_judge_prompt_recomputes_the_tier_instead_of_trusting_the_candidate(kb):
    router = FakeRouter({"verdict": "keep", "reason": "ok", "value_flow": "disruption"})
    v = asyncio.run(judge(router, kb, "judge", {"id": "c1", "value_flow": "profit"}, "code"))
    assert v.value_flow == "disruption"
    user = router.calls[0]["user"]
    assert "Recompute the equity test" in user and "Do not just repeat the candidate's claim" in user


# --- report ----------------------------------------------------------------------


def _cand(cid, tier, gain, sev="high", impact="reverts for keepers"):
    return {"id": cid, "title": f"finding {cid}", "severity": sev, "bug_class": "x", "location": "A.sol:1", "votes": 1,
            "lenses": ["A1"], "root_cause": "rc", "impact": impact, "exploit_steps": [], "falsification": "",
            "value_flow": tier, "attacker_gain": gain}


def test_report_shows_tier_gain_warning_and_counts():
    cands = [_cand("c1", "profit", "+50.7 STABLE from the owner"), _cand("c2", "disruption", "none"), _cand("c3", "unclear", "")]
    verdicts = {c["id"]: Verdict(verdict="keep", reason="r", severity="high") for c in cands}
    md = _render_report("t", cands, verdicts, [], "advisory")
    assert "Tiers: 1 profit, 1 disruption, 1 unclassified" in md
    assert "| tier |" in md and "| profit |" in md
    assert "Tier: PROFIT - attacker gain: +50.7 STABLE from the owner" in md
    assert "!! severity high/critical on a disruption-tier finding" in md  # c2: keeper revert, no permanent claim
    assert "UNCLASSIFIED" in md and "never accounted" in md


def test_tier_line_uses_the_judges_override():
    c = _cand("c1", "profit", "+5 STABLE")
    v = Verdict(verdict="keep", reason="r", severity="medium", value_flow="disruption")
    assert _tier_line(c, v).startswith("DISRUPTION")


# --- end to end ----------------------------------------------------------------


def test_scan_records_tier_and_warning_per_finding(tmp_path, monkeypatch):
    from hound.pipeline import scan
    from tests.mock_server import MockServer
    from tests.test_pipeline import FIXTURE_VAULT_SOL, _models_yaml, _scan_args

    monkeypatch.chdir(tmp_path)
    repo = tmp_path / "proj"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "Vault.sol").write_text(FIXTURE_VAULT_SOL)
    with MockServer() as mock:
        models = tmp_path / "models.yaml"
        models.write_text(_models_yaml(mock.base_url))
        out = tmp_path / "runs"
        args = _scan_args(target=str(repo), kb=str(KB_DIR), out=str(out), models=str(models))
        assert asyncio.run(scan(args)) == 0
    run = next(out.iterdir())
    data = json.loads((run / "findings.json").read_text())
    live = [f for f in data["findings"] if not f["hard_kill"]]
    assert live
    for f in live:
        assert f["tier"] == "unclear"  # the mock hunter never states a tier
        assert "never accounted" in f["tier_warning"]  # high severity with no equity accounting
    assert "Tiers: 0 profit, 0 disruption," in (run / "report.md").read_text()
