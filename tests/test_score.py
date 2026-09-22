"""Step 8: the score command, backed by the mock server (no real network)."""

import argparse
import asyncio
import json
import re
import textwrap

import pytest

from hound.score import (
    _candidate_summary, bug_locations, candidates_for_bug, score, select_scored, union_scores,
)
from tests.mock_server import MockServer


def _models_yaml(base_url: str) -> str:
    return textwrap.dedent(
        f"""
        providers:
          mock:
            base_url: {base_url}
            key_env: null
            rpm: 6000
            concurrency: 8
            timeout: 30

        roles:
          scorer: [{{provider: mock, model: mock-model}}]

        prices: {{}}
        budget: {{monthly_usd: 20, reserve_usd: 0.5}}
        """
    )


def _score_args(**overrides) -> argparse.Namespace:
    defaults = dict(run_dir=None, truth=None, include_killed=False, models=None, local_only=False,
                    repeats=None, pass_id=None, as_gate=False)
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


GROUND_TRUTH = """# Ground truth

### H-01 - First bug
The vault mis-handles something.

### M-01 - Second bug
A different thing is wrong.
"""


def _finding(fid, title, verdict):
    return {"id": fid, "title": title, "severity": "high", "location": f"V.sol:{fid[-1]}",
            "root_cause": f"rc {fid}", "impact": f"i {fid}", "verdict": {"verdict": verdict}}


@pytest.fixture
def run_dir(tmp_path):
    # F001-F005 are the ids the mock's fixed 3-EXACT/2-PARTIAL/5-MISS payload matches against;
    # F006 is the one the judge killed.
    findings = [_finding(f"F00{i}", "kept bug" if i == 1 else f"other kept {i}", "keep") for i in range(1, 6)]
    findings.append(_finding("F006", "killed bug", "kill"))
    (tmp_path / "findings.json").write_text(json.dumps(findings))
    truth_path = tmp_path / "truth.md"
    truth_path.write_text(GROUND_TRUTH)
    return tmp_path, truth_path


def test_score_computes_weighted_recall_correctly(run_dir, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out_dir, truth_path = run_dir
    with MockServer() as mock:
        models_path = tmp_path / "models.yaml"
        models_path.write_text(_models_yaml(mock.base_url))

        args = _score_args(run_dir=str(out_dir), truth=str(truth_path), models=str(models_path))
        import asyncio

        exit_code = asyncio.run(score(args))
        assert exit_code == 0

    result = json.loads((out_dir / "score.json").read_text())
    # the fixture key has 2 bugs; the mock matches H-01 and misses M-01
    assert result["counts"] == {"EXACT": 1, "PARTIAL": 0, "MISS": 1}
    assert result["weighted_recall_pct"] == pytest.approx(50.0)


def test_score_default_excludes_killed_findings(run_dir, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out_dir, truth_path = run_dir
    with MockServer() as mock:
        models_path = tmp_path / "models.yaml"
        models_path.write_text(_models_yaml(mock.base_url))

        args = _score_args(run_dir=str(out_dir), truth=str(truth_path), models=str(models_path))
        import asyncio

        asyncio.run(score(args))

        sent = mock.requests[-1]
        user_content = sent["messages"][-1]["content"]
        assert "kept bug" in user_content
        assert "killed bug" not in user_content


def test_score_include_killed_widens_the_scored_set(run_dir, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out_dir, truth_path = run_dir
    with MockServer() as mock:
        models_path = tmp_path / "models.yaml"
        models_path.write_text(_models_yaml(mock.base_url))

        args = _score_args(
            run_dir=str(out_dir), truth=str(truth_path), models=str(models_path), include_killed=True
        )
        import asyncio

        asyncio.run(score(args))

        sent = mock.requests[-1]
        user_content = sent["messages"][-1]["content"]
        assert "kept bug" in user_content
        assert "killed bug" in user_content


# --- prompt: coverage + finding_id contract --------------------------------


def test_score_prompt_demands_full_coverage_and_valid_finding_ids(run_dir, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out_dir, truth_path = run_dir
    with MockServer() as mock:
        models_path = tmp_path / "models.yaml"
        models_path.write_text(_models_yaml(mock.base_url))
        asyncio.run(score(_score_args(run_dir=str(out_dir), truth=str(truth_path), models=str(models_path))))
        system = mock.requests[-1]["messages"][0]["content"]

    flat = " ".join(system.split())
    assert "ONE bug from a ground-truth" in flat          # per-bug, not all-at-once
    assert "Consider EVERY candidate. Do not stop at the first plausible one." in flat
    assert "must be exactly one of the ids in CANDIDATE FINDINGS, or null" in flat


# --- unit tests with a fake router ------------------------------------------


class FakeScorerRouter:
    """Stands in for hound.score.Router. The scorer makes ONE call per ground-truth bug, so
    `per_bug` maps a gt_id to the reply for that bug; `sequence` (if set) is popped per call
    regardless of bug, for testing retries and aborts."""

    sequence = []
    calls = 0
    answered_by = "z-ai/glm-5.3-flash"
    per_bug = {}
    seen = []

    def __init__(self, models_path=None, local_only=False):
        self.roles = {"scorer": [{"provider": "openrouter", "model": "z-ai/glm-5.3-flash"},
                                 {"provider": "zai", "model": "glm-4.7-flash"}]}
        self.call_log = []

    def report(self):
        return {"models": [], "total_usd": 0.0, "calls": list(self.call_log)}

    async def chat_json(self, role, system, user, *, temperature=0.3, max_tokens=None,
                        ceiling=None, cache_salt=""):
        type(self).calls += 1
        self.call_log.append({"role": role, "model": type(self).answered_by})
        type(self).seen.append({"system": system, "user": user, "salt": cache_salt, "ceiling": ceiling})
        if type(self).sequence:
            item = type(self).sequence.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        m = re.search(r"GROUND-TRUTH BUG ([HM]-\d+)", user)
        gid = m.group(1) if m else ""
        return type(self).per_bug.get(gid, {"verdict": "MISS", "finding_id": None, "why": "no match"})


@pytest.fixture
def fake_router(monkeypatch):
    FakeScorerRouter.sequence, FakeScorerRouter.calls = [], 0
    FakeScorerRouter.answered_by = "z-ai/glm-5.3-flash"
    FakeScorerRouter.per_bug, FakeScorerRouter.seen = {}, []
    monkeypatch.setattr("hound.score.Router", FakeScorerRouter)
    slept = []

    async def fake_sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr("hound.score.asyncio.sleep", fake_sleep)
    FakeScorerRouter.slept = slept
    return FakeScorerRouter


def _run(run_dir, **overrides):
    out_dir, truth_path = run_dir
    args = _score_args(run_dir=str(out_dir), truth=str(truth_path), models="unused.yaml", **overrides)
    return asyncio.run(score(args))


def test_one_call_per_ground_truth_bug_per_repeat(run_dir, fake_router):
    """23 bugs x 3 repeats was the whole point: a per-bug call has a far smaller reasoning
    surface than grading every bug in one call."""
    assert _run(run_dir, repeats=3) == 0
    assert fake_router.calls == 2 * 3  # the fixture truth has 2 bugs
    asked = {re.search(r"GROUND-TRUTH BUG ([HM]-\d+)", c["user"]).group(1) for c in fake_router.seen}
    assert asked == {"H-01", "M-01"}


def test_each_repeat_uses_a_distinct_cache_salt_so_it_actually_re_samples(run_dir, fake_router):
    """Without a distinct salt every repeat is one cache hit, and the 'majority' is a single
    opinion counted three times."""
    _run(run_dir, repeats=3)
    salts = [c["salt"] for c in fake_router.seen if "H-01" in c["user"]]
    assert len(set(salts)) == 3


def test_the_majority_verdict_wins(run_dir, fake_router, monkeypatch):
    """Votes keyed off the attempt in the salt, not a call counter: the calls run
    concurrently, so completion order is not deterministic."""

    async def miss_on_attempt_1(self, role, system, user, *, cache_salt="", **kw):
        type(self).calls += 1
        self.call_log.append({"role": role, "model": type(self).answered_by})
        if "H-01" not in user:
            return {"verdict": "MISS", "finding_id": None, "why": "w"}
        attempt = cache_salt.rsplit("#", 1)[-1]
        if attempt == "1":
            return {"verdict": "MISS", "finding_id": None, "why": "w"}
        return {"verdict": "EXACT", "finding_id": "F001", "why": "w"}

    monkeypatch.setattr(FakeScorerRouter, "chat_json", miss_on_attempt_1)
    assert _run(run_dir, repeats=3) == 0

    result = json.loads((run_dir[0] / "score.json").read_text())
    h01 = next(s for s in result["scores"] if s["gt_id"] == "H-01")
    assert h01["verdict"] == "EXACT"                     # 2 EXACT (attempts 0,2) vs 1 MISS
    assert h01["votes"].count("EXACT") > h01["votes"].count("MISS")


def test_agreement_is_recorded_per_bug(run_dir, fake_router):
    fake_router.per_bug = {"H-01": {"verdict": "EXACT", "finding_id": "F001", "why": "w"}}
    assert _run(run_dir, repeats=3) == 0
    result = json.loads((run_dir[0] / "score.json").read_text())
    assert result["agreement"] == {"H-01": "3/3", "M-01": "3/3"}
    assert result["unanimous_bugs"] == 2
    assert result["repeats"] == 3


def test_a_hallucinated_finding_id_is_downgraded_to_a_miss(run_dir, fake_router, capsys):
    fake_router.per_bug = {"H-01": {"verdict": "EXACT", "finding_id": "F099", "why": "w"}}
    assert _run(run_dir) == 0
    result = json.loads((run_dir[0] / "score.json").read_text())
    h01 = next(s for s in result["scores"] if s["gt_id"] == "H-01")
    assert h01["verdict"] == "MISS" and h01["finding_id"] is None
    assert "not one of the supplied findings" in capsys.readouterr().out


def test_off_catalog_is_derived_not_asked_for(run_dir, fake_router):
    """Asking a model to list unmatched findings while grading produced boilerplate; a set
    difference needs no judgement."""
    fake_router.per_bug = {"H-01": {"verdict": "EXACT", "finding_id": "F001", "why": "w"}}
    assert _run(run_dir) == 0
    result = json.loads((run_dir[0] / "score.json").read_text())
    assert "F001" not in [o["finding_id"] for o in result["off_catalog"]]
    assert "F002" in [o["finding_id"] for o in result["off_catalog"]]


def test_a_429_is_retried_once_per_call(run_dir, fake_router):
    fake_router.sequence = [RuntimeError("Error code: 429 - overloaded"),
                            {"verdict": "EXACT", "finding_id": "F001", "why": "w"}]
    assert _run(run_dir, repeats=1) == 0
    assert fake_router.slept == [30]


def test_a_bug_that_cannot_be_graded_at_all_aborts_instead_of_counting_as_a_miss(run_dir, fake_router, capsys):
    """An ungraded bug scored MISS understates recall and is indistinguishable from a real
    miss."""
    fake_router.sequence = [RuntimeError("boom")] * 20
    assert _run(run_dir, repeats=1) == 1
    out = capsys.readouterr().out
    assert "could not be graded at all" in out
    assert not (run_dir[0] / "score.json").exists()


def test_a_non_429_error_is_not_retried(run_dir, fake_router):
    fake_router.sequence = [RuntimeError("Error code: 500 - server error"),
                            {"verdict": "MISS", "finding_id": None, "why": "w"},
                            {"verdict": "MISS", "finding_id": None, "why": "w"}]
    _run(run_dir, repeats=1)
    assert fake_router.slept == []


def test_missing_findings_json_fails_gracefully(tmp_path, capsys):
    truth = tmp_path / "truth.md"
    truth.write_text(GROUND_TRUTH)
    args = _score_args(run_dir=str(tmp_path / "nope"), truth=str(truth), models="unused.yaml")
    assert asyncio.run(score(args)) == 1
    assert "cannot read inputs" in capsys.readouterr().out


def test_a_truth_file_with_no_parseable_entries_is_refused(tmp_path, run_dir, fake_router, capsys):
    out_dir, _ = run_dir
    bad = tmp_path / "bad_truth.md"
    bad.write_text("no headings here")
    args = _score_args(run_dir=str(out_dir), truth=str(bad), models="unused.yaml")
    assert asyncio.run(score(args)) == 1
    assert "no '### <id> - <title>' ground-truth entries" in capsys.readouterr().out


# --- ground-truth splitting -------------------------------------------------------------------


def test_split_ground_truth_keeps_the_full_description_not_the_summary_line():
    from hound.score import split_ground_truth

    text = ("## High (1)\n### H-01 - Short summary line\n\n"
            "## Full descriptions\n### H-01 - Short summary line\n"
            "The long description with all the detail.\n")
    entries = split_ground_truth(text)
    assert set(entries) == {"H-01"}
    assert "long description" in entries["H-01"]


# --- which findings a score covers, per judge mode ---------------------------------


def _f(fid, verdict, hard=False):
    return {"id": fid, "verdict": {"verdict": verdict}, "hard_kill": hard}


FINDINGS = [_f("F001", "keep"), _f("F002", "kill"), _f("F003", "needs_poc"), _f("F004", "kill", hard=True)]


def _ids(fs):
    return [f["id"] for f in fs]


def test_advisory_default_scores_everything_except_deterministic_gate_kills():
    assert _ids(select_scored(FINDINGS, "advisory")) == ["F001", "F002", "F003"]


def test_gate_default_scores_only_what_the_judge_did_not_kill():
    assert _ids(select_scored(FINDINGS, "gate")) == ["F001", "F003"]


def test_as_gate_shows_what_a_gate_would_have_kept_even_on_an_advisory_run():
    assert _ids(select_scored(FINDINGS, "advisory", as_gate=True)) == ["F001", "F003"]


def test_include_killed_scores_literally_everything():
    assert _ids(select_scored(FINDINGS, "advisory", include_killed=True)) == ["F001", "F002", "F003", "F004"]


def test_a_legacy_run_with_no_hard_kill_flag_is_read_as_gate_mode(run_dir, fake_router, capsys):
    fake_router.per_bug = {"H-01": {"verdict": "EXACT", "finding_id": "F001", "why": "w"}}
    assert _run(run_dir) == 0  # run_dir fixture writes the legacy bare-list format
    assert "judge_mode=gate" in capsys.readouterr().out


# --- provenance + cost line ----------------------------------------------------------


def _modern_run(tmp_path, provenance):
    findings = [_finding("F001", "kept bug", "keep"), _finding("F002", "judge killed", "kill")]
    doc = {"judge_mode": "advisory", "provenance": provenance, "findings": findings}
    (tmp_path / "findings.json").write_text(json.dumps(doc))
    truth = tmp_path / "truth.md"
    truth.write_text(GROUND_TRUTH)
    return tmp_path, truth


def test_score_warns_loudly_when_the_working_tree_no_longer_matches_the_run(tmp_path, fake_router, capsys):
    target = tmp_path / "target"
    target.mkdir()
    (target / "V.sol").write_text("contract V {}\n")
    provenance = {"target": str(target), "commit": None, "dirty": None,
                  "files": {"V.sol": {"sha256": "0" * 64, "n_lines": 1}}}  # recorded hash != disk
    fake_router.per_bug = {}
    assert _run(_modern_run(tmp_path, provenance)) == 0

    out = capsys.readouterr().out
    assert "WARNING: run provenance does not match the working tree" in out
    assert "V.sol: content changed since it was read" in out
    stored = json.loads((tmp_path / "score.json").read_text())
    assert stored["provenance_mismatches"]


def test_score_is_quiet_when_provenance_matches(tmp_path, fake_router, capsys):
    from hound.codebase import file_sha256

    target = tmp_path / "target"
    target.mkdir()
    (target / "V.sol").write_text("contract V {}\n")
    provenance = {"target": str(target), "commit": None, "dirty": None,
                  "files": {"V.sol": {"sha256": file_sha256(target / "V.sol"), "n_lines": 1}}}
    fake_router.per_bug = {}
    assert _run(_modern_run(tmp_path, provenance)) == 0
    assert "WARNING: run provenance" not in capsys.readouterr().out


def test_score_prints_a_cost_line_like_scan(run_dir, fake_router, capsys):
    fake_router.per_bug = {}
    assert _run(run_dir) == 0
    out = capsys.readouterr().out
    assert '"total_usd"' in out and '"models"' in out


# --- union across seeds ---------------------------------------------------------------------


def _scored_run(tmp_path, name, seed, verdicts):
    d = tmp_path / name
    d.mkdir()
    (d / "findings.json").write_text(json.dumps({"seed": seed, "judge_mode": "advisory", "findings": []}))
    exact = sum(v == "EXACT" for v in verdicts.values())
    partial = sum(v == "PARTIAL" for v in verdicts.values())
    (d / "score.json").write_text(json.dumps({
        "weighted_recall_pct": (exact + 0.5 * partial) / len(verdicts) * 100,
        "scores": [{"gt_id": g, "verdict": v} for g, v in verdicts.items()],
    }))
    return d


def test_union_counts_a_bug_found_by_any_seed_at_its_best_verdict(tmp_path):
    a = _scored_run(tmp_path, "s1", 1, {"H-01": "EXACT", "M-01": "MISS", "M-02": "PARTIAL", "M-03": "MISS"})
    b = _scored_run(tmp_path, "s2", 2, {"H-01": "MISS", "M-01": "MISS", "M-02": "EXACT", "M-03": "MISS"})
    c = _scored_run(tmp_path, "s3", 3, {"H-01": "EXACT", "M-01": "MISS", "M-02": "MISS", "M-03": "PARTIAL"})

    result = union_scores([a, b, c])

    assert [r["weighted_recall_pct"] for r in result["per_run"]] == [pytest.approx(37.5), pytest.approx(25.0), pytest.approx(37.5)]
    assert result["best"] == {"H-01": "EXACT", "M-01": "MISS", "M-02": "EXACT", "M-03": "PARTIAL"}
    assert result["union"]["weighted_recall_pct"] == pytest.approx((2 + 0.5) / 4 * 100)
    # M-02 was caught by two seeds, M-03 by exactly one (s3), H-01 by two
    assert result["only_one_run"] == {"M-03": "s3 (seed 3)"}
    assert result["found_by"]["M-01"] == []


# --- aborts: out of credits, and a scorer that fell back --------------------------------------


def test_a_402_aborts_the_score_with_a_clear_message_and_no_score_file(run_dir, fake_router, capsys):
    from hound.llm import OutOfCredits

    fake_router.sequence = [OutOfCredits("openrouter/z-ai/glm-5.3-flash for role 'scorer': 402")]
    assert _run(run_dir) == 2  # distinct exit code, not the generic failure 1
    out = capsys.readouterr().out
    assert "OUT OF CREDITS — run aborted" in out
    assert not (run_dir[0] / "score.json").exists()


def test_a_402_is_never_retried_as_if_it_were_a_rate_limit(run_dir, fake_router):
    from hound.llm import OutOfCredits

    fake_router.sequence = [OutOfCredits("402")]
    assert _run(run_dir) == 2
    # per-bug calls are dispatched together, so others may already be in flight; what matters
    # is that the 402 was never retried the way a 429 is
    assert fake_router.slept == []


def test_a_score_graded_by_the_fallback_model_is_refused(run_dir, fake_router, capsys):
    fake_router.answered_by = "glm-4.7-flash"  # fell back off the configured paid scorer
    fake_router.per_bug = {"H-01": {"verdict": "EXACT", "finding_id": "F001", "why": "w"}}

    assert _run(run_dir) == 2
    out = capsys.readouterr().out
    assert "SCORE ABORTED" in out
    assert "not the configured 'z-ai/glm-5.3-flash'" in out
    assert not (run_dir[0] / "score.json").exists()  # no number rather than a misattributed one


def test_a_score_on_the_configured_model_is_written_normally(run_dir, fake_router):
    fake_router.per_bug = {"H-01": {"verdict": "EXACT", "finding_id": "F001", "why": "w"}}
    assert _run(run_dir) == 0
    assert (run_dir[0] / "score.json").exists()


def test_the_scorer_gets_a_generous_call_ceiling(run_dir, fake_router, monkeypatch):
    """One scoring call grades every candidate against every ground-truth bug — the longest
    single call the harness makes. It overran the default 300s ceiling on a real run."""
    from hound.score import SCORER_CALL_CEILING

    seen = {}

    async def capture(self, role, system, user, *, temperature=0.3, max_tokens=None, ceiling=None, cache_salt=""):
        seen["ceiling"] = ceiling
        return {"verdict": "MISS", "finding_id": None, "why": "w"}

    monkeypatch.setattr(FakeScorerRouter, "chat_json", capture)
    assert _run(run_dir) == 0
    assert seen["ceiling"] == SCORER_CALL_CEILING >= 900


# --- every claim about a candidate's lines reaches the scorer ---------------------------------


def test_a_replaced_diagnosis_is_still_offered_to_the_scorer():
    """Regression: M-10 was MATCHED before the diagnose stage and LOST after, because the
    diagnoser overwrote a correct reading. Scoring only the survivor throws that away."""
    summary = _candidate_summary({
        "id": "F001", "title": "diagnosed", "severity": "high", "location": "V.sol:20-30",
        "root_cause": "diagnosed cause", "impact": "diagnosed impact",
        "hunter_claim": {"title": "located", "root_cause": "located cause", "impact": "located impact"},
    })
    assert summary["root_cause"] == "diagnosed cause"          # primary is the diagnosis
    claims = summary["alternate_claims"]
    assert [c["root_cause"] for c in claims] == ["located cause"]
    assert claims[0]["source"] == "located (pre-diagnosis)"


def test_merged_duplicates_are_also_offered_as_claims():
    summary = _candidate_summary({
        "id": "F001", "root_cause": "primary", "impact": "i", "location": "V.sol:1",
        "alternates": [{"title": "t", "root_cause": "other reading", "impact": "other impact", "severity": "low"}],
    })
    assert [c["source"] for c in summary["alternate_claims"]] == ["merged duplicate"]


def test_an_empty_hunter_claim_adds_nothing():
    for hc in ({}, {"title": "t"}, None):
        assert "alternate_claims" not in _candidate_summary(
            {"id": "F1", "root_cause": "r", "impact": "i", "hunter_claim": hc})


def test_the_scorer_is_told_that_any_claim_matching_counts(run_dir, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out_dir, truth_path = run_dir
    with MockServer() as mock:
        models_path = tmp_path / "models.yaml"
        models_path.write_text(_models_yaml(mock.base_url))
        asyncio.run(score(_score_args(run_dir=str(out_dir), truth=str(truth_path), models=str(models_path))))
        system = mock.requests[-1]["messages"][0]["content"]
    flat = " ".join(system.split())  # the prompt is hard-wrapped
    assert "ALTERNATE CLAIMS" in flat
    assert "If ANY of them names the ground-truth defect, that is a match" in flat
    assert "an earlier pass's explanation that a later one replaced" in flat


# --- per-bug candidate filter -----------------------------------------------------------------

GT_WITH_LOC = "### M-10 - A bug\nhttps://example/contracts/Vault.sol#L216-L235\nText."


def _cand(fid, loc):
    return {"id": fid, "location": loc}


def test_bug_locations_parses_every_source_link():
    assert bug_locations(GT_WITH_LOC) == [("Vault.sol", 216, 235)]
    assert bug_locations("no links here") == []


def test_only_candidates_near_the_bug_are_graded_against_it():
    """Sending every candidate for every bug is what pushed a per-bug call back over the token
    cap; a candidate in another file cannot be the same defect."""
    cands = [_cand("F1", "Vault.sol:220-230"), _cand("F2", "Other.sol:220"),
             _cand("F3", "Vault.sol:900"), _cand("F4", "Vault.sol:270")]
    subset, why = candidates_for_bug(GT_WITH_LOC, cands)
    assert [c["id"] for c in subset] == ["F1", "F4"]   # F4 is within +/-60 of 216-235
    assert "near" in why


def test_it_widens_to_the_whole_file_rather_than_returning_nothing():
    """An over-narrow filter would manufacture MISSes."""
    subset, why = candidates_for_bug(GT_WITH_LOC, [_cand("F3", "Vault.sol:900")])
    assert [c["id"] for c in subset] == ["F3"]
    assert "same file" in why


def test_it_falls_back_to_every_candidate_when_none_cite_that_file():
    subset, why = candidates_for_bug(GT_WITH_LOC, [_cand("F2", "Other.sol:1")])
    assert [c["id"] for c in subset] == ["F2"]
    assert "none cite this file" in why


def test_a_bug_with_no_parseable_location_grades_against_everything():
    cands = [_cand("F1", "Vault.sol:1"), _cand("F2", "Other.sol:1")]
    subset, why = candidates_for_bug("### M-99 - No link here\nText.", cands)
    assert len(subset) == 2 and "no parseable bug location" in why


# --- pass id and adaptive repeats ---------------------------------------------------------------


def test_a_pass_id_changes_the_cache_key_so_a_repeat_pass_re_samples(run_dir, fake_router):
    """Without this, re-scoring the same run replays the previous pass's cached answers and
    'reproducibility' is measuring the cache."""
    _run(run_dir, repeats=1, pass_id="p1")
    first = [c["salt"] for c in fake_router.seen]
    FakeScorerRouter.seen = []
    _run(run_dir, repeats=1, pass_id="p2")
    second = [c["salt"] for c in fake_router.seen]

    assert all(sa.startswith("p1:") for sa in first)
    assert all(sa.startswith("p2:") for sa in second)
    assert not set(first) & set(second)


def test_two_agreeing_calls_cost_only_two(run_dir, fake_router):
    fake_router.per_bug = {"H-01": {"verdict": "EXACT", "finding_id": "F001", "why": "w"}}
    assert _run(run_dir, repeats=2) == 0
    assert fake_router.calls == 2 * 2   # 2 bugs x 2 calls, no tie-breaks
    result = json.loads((run_dir[0] / "score.json").read_text())
    assert result["agreement"]["H-01"] == "2/2"


def test_a_disagreement_buys_exactly_one_tie_breaker(run_dir, fake_router, monkeypatch, capsys):
    seq = {"n": 0}

    async def disagree_on_h01(self, role, system, user, **kw):
        type(self).calls += 1
        self.call_log.append({"role": role, "model": type(self).answered_by})
        if "H-01" not in user:
            return {"verdict": "MISS", "finding_id": None, "why": "w"}
        seq["n"] += 1
        return ({"verdict": "EXACT", "finding_id": "F001", "why": "w"} if seq["n"] != 2
                else {"verdict": "MISS", "finding_id": None, "why": "w"})

    monkeypatch.setattr(FakeScorerRouter, "chat_json", disagree_on_h01)
    assert _run(run_dir, repeats=2) == 0

    assert "tie-breaking 1 contested bug(s): H-01" in capsys.readouterr().out
    assert fake_router.calls == 5          # 2 bugs x 2, plus ONE tie-break
    result = json.loads((run_dir[0] / "score.json").read_text())
    h01 = next(s for s in result["scores"] if s["gt_id"] == "H-01")
    assert h01["verdict"] == "EXACT" and h01["agreement"] == "2/3"
