"""Step C: the config cross-check inside a real scan (mock server, no network)."""

import asyncio
import json
import textwrap
from pathlib import Path

import pytest

from hound.pipeline import scan
from tests.mock_server import MockServer
from tests.test_pipeline import FIXTURE_VAULT_SOL, _models_yaml, _scan_args

CONFIGURED = textwrap.dedent(
    """\
    contract Tunable {
        uint256 public floor;
        function file(bytes32 what, uint256 data) external {
            if (what == "floor") { floor = data; }
        }
    }
    """
)
DEPLOY = 'const t = await hardhat.ethers.getContractAt("Tunable", a);\nawait t["file(bytes32,uint256)"](hardhat.ethers.encodeBytes32String("floor"), 500n);\n'
VERIFY = 'assertEq("Tunable.floor", await t.floor(), 400n);\n'


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Vault.sol").write_text(FIXTURE_VAULT_SOL)
    (tmp_path / "src" / "Tunable.sol").write_text(CONFIGURED)
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "deploy.js").write_text(DEPLOY)
    (tmp_path / "scripts" / "verify-config.js").write_text(VERIFY)
    return tmp_path


@pytest.fixture
def kb_dir():
    return str(Path(__file__).parent.parent / "kb")


def _prompts(mock, marker):
    return [r["messages"][-1]["content"] for r in mock.requests if marker in r["messages"][-1]["content"]]


def test_dry_run_counts_scripts_without_requests(repo, kb_dir, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    with MockServer() as mock:
        models = tmp_path / "models.yaml"
        models.write_text(_models_yaml(mock.base_url))
        args = _scan_args(target=str(repo), kb=kb_dir, out=str(tmp_path / "runs"), models=str(models),
                          dry_run=True, config_check="auto")
        assert asyncio.run(scan(args)) == 0
        assert mock.request_count == 0
    assert "config check: 2 deploy/verify/config scripts found" in capsys.readouterr().out


def test_flagged_deployed_values_reach_the_hunters_and_artifacts_are_written(repo, kb_dir, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with MockServer() as mock:
        models = tmp_path / "models.yaml"
        models.write_text(_models_yaml(mock.base_url))
        out = tmp_path / "runs"
        args = _scan_args(target=str(repo), kb=kb_dir, out=str(out), models=str(models), config_check="auto")
        assert asyncio.run(scan(args)) == 0
        hunt = _prompts(mock, "TASK: HUNT")
        judge = _prompts(mock, "TASK: FALSIFY")
    assert hunt and all("DEPLOYED CONFIGURATION CONCERNS" in p and "Tunable.floor" in p for p in hunt)
    assert "verify script expects 400" in hunt[0]  # the deterministic flag: deploy sets 500, verify expects 400
    assert judge and not any("DEPLOYED CONFIGURATION CONCERNS" in p for p in judge)
    run = next(out.iterdir())
    data = json.loads((run / "config_check.json").read_text())
    assert [r["param"] for r in data["rows"]] == ["floor"] and (run / "config_check.md").exists()


def test_config_check_off_and_no_scripts_change_nothing(repo, kb_dir, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with MockServer() as mock:
        models = tmp_path / "models.yaml"
        models.write_text(_models_yaml(mock.base_url))
        args = _scan_args(target=str(repo), kb=kb_dir, out=str(tmp_path / "runs"), models=str(models), config_check="off")
        assert asyncio.run(scan(args)) == 0
        assert not any("DEPLOYED CONFIGURATION CONCERNS" in p for p in _prompts(mock, "TASK: HUNT"))
    assert not (next((tmp_path / "runs").iterdir()) / "config_check.json").exists()
