"""Step 8: the score command, backed by the mock server (no real network)."""

import argparse
import asyncio
import json
import textwrap

import pytest

from hound.score import score, select_scored
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
    defaults = dict(run_dir=None, truth=None, include_killed=False, models=None, local_only=False)
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


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
    truth_path.write_text("# Ground truth\n\n## GT1\nSome bug.\n")
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
    assert result["counts"] == {"EXACT": 3, "PARTIAL": 2, "MISS": 5}
    assert result["weighted_recall_pct"] == pytest.approx(40.0)


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

    assert "EVERY candidate finding for EVERY ground-truth bug" in system
    assert "exactly one of the ids in the CANDIDATE FINDINGS list, or null" in system


# --- unit tests with a fake router ------------------------------------------


class FakeScorerRouter:
    """Stands in for hound.score.Router; behaviour set per test via class attributes."""

    responses = []
    calls = 0

    def __init__(self, models_path=None, local_only=False):
        pass

    def report(self):
        return {"models": [], "total_usd": 0.0, "calls": []}

    async def chat_json(self, role, system, user, *, temperature=0.3, max_tokens=None):
        type(self).calls += 1
        item = type(self).responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture
def fake_router(monkeypatch):
    FakeScorerRouter.responses, FakeScorerRouter.calls = [], 0
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


def _scores(rows):
    return {"scores": [{"gt_id": f"GT{i}", "verdict": v, "finding_id": fid, "why": why}
                       for i, (v, fid, why) in enumerate(rows, 1)], "off_catalog": []}


def test_hallucinated_finding_id_is_downgraded_to_a_miss(run_dir, fake_router, capsys):
    fake_router.responses = [_scores([
        ("EXACT", "F001", "matches F001"),
        ("EXACT", "F099", "matches F099"),          # not a supplied id
        ("PARTIAL", None, "partial but no finding"),  # match without a finding
        ("MISS", "null", "nothing"),                  # the string "null" means no finding
    ])]
    assert _run(run_dir) == 0

    result = json.loads((run_dir[0] / "score.json").read_text())
    assert result["counts"] == {"EXACT": 1, "PARTIAL": 0, "MISS": 3}
    assert [s["finding_id"] for s in result["scores"]] == ["F001", None, None, None]
    out = capsys.readouterr().out
    assert "F099" in out and "not one of the supplied findings" in out


def test_pass_1_style_boilerplate_triggers_the_degeneration_warning(run_dir, fake_router, capsys):
    boiler = "F001 describes a WhitelistDeployer issue (arbitrary owner assignment) which is unrelated to bug {}."
    fake_router.responses = [_scores([("MISS", None, boiler.format(i)) for i in range(23)])]
    assert _run(run_dir) == 0

    assert "scorer likely degenerated" in capsys.readouterr().out
    assert json.loads((run_dir[0] / "score.json").read_text())["degenerate_warning"] is True


def test_generic_reasons_about_the_whole_range_are_not_flagged(run_dir, fake_router, capsys):
    rows = [("MISS", None, f"F001-F005 do not identify bug {i}.") for i in range(20)]
    rows += [("MISS", None, f"F003 is a different issue than bug {i}.") for i in range(3)]
    fake_router.responses = [_scores(rows)]
    assert _run(run_dir) == 0

    assert "degenerated" not in capsys.readouterr().out


def test_a_429_is_retried_once_after_a_pause(run_dir, fake_router):
    fake_router.responses = [
        RuntimeError("all targets failed for role 'scorer': Error code: 429 - overloaded"),
        _scores([("EXACT", "F001", "matches F001")]),
    ]
    assert _run(run_dir) == 0
    assert fake_router.calls == 2
    assert fake_router.slept == [30]


def test_two_429s_fail_gracefully_with_no_traceback_and_no_score_file(run_dir, fake_router, capsys):
    fake_router.responses = [RuntimeError("Error code: 429 - overloaded")] * 2
    assert _run(run_dir) == 1
    assert fake_router.calls == 2
    assert "score failed:" in capsys.readouterr().out
    assert not (run_dir[0] / "score.json").exists()


def test_a_non_429_error_is_not_retried(run_dir, fake_router, capsys):
    fake_router.responses = [RuntimeError("Error code: 402 - insufficient credits")]
    assert _run(run_dir) == 1
    assert fake_router.calls == 1
    assert "insufficient credits" in capsys.readouterr().out


def test_missing_findings_json_fails_gracefully(tmp_path, capsys):
    truth = tmp_path / "truth.md"
    truth.write_text("x")
    args = _score_args(run_dir=str(tmp_path / "nope"), truth=str(truth), models="unused.yaml")
    assert asyncio.run(score(args)) == 1
    assert "cannot read inputs" in capsys.readouterr().out


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
    fake_router.responses = [_scores([("EXACT", "F001", "matches F001")])]
    assert _run(run_dir) == 0  # run_dir fixture writes the legacy bare-list format
    assert "judge_mode=gate" in capsys.readouterr().out


# --- provenance + cost line ----------------------------------------------------------


def _modern_run(tmp_path, provenance):
    findings = [_finding("F001", "kept bug", "keep"), _finding("F002", "judge killed", "kill")]
    doc = {"judge_mode": "advisory", "provenance": provenance, "findings": findings}
    (tmp_path / "findings.json").write_text(json.dumps(doc))
    truth = tmp_path / "truth.md"
    truth.write_text("gt")
    return tmp_path, truth


def test_score_warns_loudly_when_the_working_tree_no_longer_matches_the_run(tmp_path, fake_router, capsys):
    target = tmp_path / "target"
    target.mkdir()
    (target / "V.sol").write_text("contract V {}\n")
    provenance = {"target": str(target), "commit": None, "dirty": None,
                  "files": {"V.sol": {"sha256": "0" * 64, "n_lines": 1}}}  # recorded hash != disk
    fake_router.responses = [_scores([("MISS", None, "nothing")])]
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
    fake_router.responses = [_scores([("MISS", None, "nothing")])]
    assert _run(_modern_run(tmp_path, provenance)) == 0
    assert "WARNING: run provenance" not in capsys.readouterr().out


def test_score_prints_a_cost_line_like_scan(run_dir, fake_router, capsys):
    fake_router.responses = [_scores([("MISS", None, "nothing")])]
    assert _run(run_dir) == 0
    out = capsys.readouterr().out
    assert '"total_usd"' in out and '"models"' in out
