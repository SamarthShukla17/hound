"""Step B: the upstream diff inside a real scan (mock server, stubbed fetch/diff, no network)."""

import asyncio
import json
from pathlib import Path

import pytest

import hound.pipeline as pipeline
from hound.deviation_review import UpstreamDiff
from hound.pipeline import scan
from tests.mock_server import MockServer
from tests.test_pipeline import FIXTURE_VAULT_SOL, _models_yaml, _scan_args

REVIEW = {
    "classification": "regression", "risk": "high", "summary": "the not-live guard was dropped",
    "deviations": [], "worth_hunting": True, "hunt_hint": "call frob after cage",
}


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Vault.sol").write_text(FIXTURE_VAULT_SOL)
    (tmp_path / "README.md").write_text("A fork of MakerDAO's dss (vat, vow): frob and bark.")
    return tmp_path


@pytest.fixture
def kb_dir():
    return str(Path(__file__).parent.parent / "kb")


def _stub_diff(with_review=True):
    async def fake(target, files, **kwargs):
        from hound.stmtdiff import FunctionPair, StmtDiff
        from hound.solfuncs import find_functions

        f = find_functions("contract A { function withdraw(uint256 a) external { balances[msg.sender] -= a; } }")[0]
        pair = FunctionPair(f, "src/Vault.sol", f, "src/vat.sol", 0.5,
                            [StmtDiff(["guard-removed"], 5, "require(live == 1)", "", 3, 0)])
        d = UpstreamDiff("maker-dss", "MakerDAO dss", result={"pairs": [pair], "removed_upstream": ["Vat.fork"],
                                                             "added_target": [], "contract_pairs": {}})
        if with_review:
            d.reviews = {0: REVIEW}
        return d
    return fake


def _hunter_prompts(mock):
    return [r["messages"][-1]["content"] for r in mock.requests if "TASK: HUNT" in r["messages"][-1]["content"]]


def test_dry_run_reports_detection_without_any_request(repo, kb_dir, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    with MockServer() as mock:
        models = tmp_path / "models.yaml"
        models.write_text(_models_yaml(mock.base_url))
        args = _scan_args(target=str(repo), kb=kb_dir, out=str(tmp_path / "runs"), models=str(models),
                          dry_run=True, upstream="auto")
        assert asyncio.run(scan(args)) == 0
        assert mock.request_count == 0
    assert "MakerDAO dss detected" in capsys.readouterr().out


def test_hunters_receive_the_deviation_block_and_artifacts_are_written(repo, kb_dir, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(pipeline, "upstream_diff", _stub_diff())
    with MockServer() as mock:
        models = tmp_path / "models.yaml"
        models.write_text(_models_yaml(mock.base_url))
        out = tmp_path / "runs"
        args = _scan_args(target=str(repo), kb=kb_dir, out=str(out), models=str(models), upstream="maker-dss")
        assert asyncio.run(scan(args)) == 0
        prompts = _hunter_prompts(mock)
        judge = [r["messages"][-1]["content"] for r in mock.requests if "TASK: FALSIFY" in r["messages"][-1]["content"]]
    assert prompts and all("UPSTREAM DEVIATIONS" in p and "call frob after cage" in p for p in prompts)
    assert judge and not any("UPSTREAM DEVIATIONS" in p for p in judge)  # the judge's notes are scope, not hints
    run = next(out.iterdir())
    data = json.loads((run / "upstream_diff.json").read_text())
    assert data["removed_upstream"] == ["Vat.fork"] and data["pairs"][0]["review"]["risk"] == "high"
    assert (run / "upstream_diff.md").exists()


def test_upstream_off_changes_nothing(repo, kb_dir, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    async def must_not_run(*a, **k):
        raise AssertionError("upstream_diff must not run when --upstream off")

    monkeypatch.setattr(pipeline, "upstream_diff", must_not_run)
    with MockServer() as mock:
        models = tmp_path / "models.yaml"
        models.write_text(_models_yaml(mock.base_url))
        args = _scan_args(target=str(repo), kb=kb_dir, out=str(tmp_path / "runs"), models=str(models), upstream="off")
        assert asyncio.run(scan(args)) == 0
        assert not any("UPSTREAM DEVIATIONS" in p for p in _hunter_prompts(mock))
    assert not (next((tmp_path / "runs").iterdir()) / "upstream_diff.json").exists()


def test_a_failing_diff_never_stops_the_scan(repo, kb_dir, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    async def boom(*a, **k):
        raise OSError("network is down")

    monkeypatch.setattr(pipeline, "upstream_diff", boom)
    with MockServer() as mock:
        models = tmp_path / "models.yaml"
        models.write_text(_models_yaml(mock.base_url))
        args = _scan_args(target=str(repo), kb=kb_dir, out=str(tmp_path / "runs"), models=str(models), upstream="auto")
        assert asyncio.run(scan(args)) == 0
    assert "upstream diff skipped: network is down" in capsys.readouterr().out
