"""Step 8: the score command, backed by the mock server (no real network)."""

import argparse
import json
import textwrap

import pytest

from hound.score import score
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


@pytest.fixture
def run_dir(tmp_path):
    findings = [
        {"id": "F001", "title": "kept bug", "severity": "high", "location": "V.sol:1", "root_cause": "rc1",
         "impact": "i1", "verdict": {"verdict": "keep"}},
        {"id": "F002", "title": "killed bug", "severity": "high", "location": "V.sol:2", "root_cause": "rc2",
         "impact": "i2", "verdict": {"verdict": "kill"}},
    ]
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
