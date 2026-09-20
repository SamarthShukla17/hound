"""Step 7: end-to-end scan against the mock OpenAI-compatible server. No real
network — every role in the temp models.yaml points at MockServer."""

import argparse
import json
import textwrap
from pathlib import Path

import pytest

from hound.pipeline import scan
from tests.mock_server import FIXTURE_LOCATION, MockServer

FIXTURE_VAULT_SOL = textwrap.dedent(
    """\
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    contract Vault {
        mapping(address => uint256) public balances;

        function deposit() external payable {
            balances[msg.sender] += msg.value;
        }

        function withdraw(uint256 amount) external {
            require(balances[msg.sender] >= amount, "insufficient");
            (bool ok, ) = msg.sender.call{value: amount}("");
            require(ok, "transfer failed");
            balances[msg.sender] -= amount;
        }
    }
    """
)


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
          mapper: [{{provider: mock, model: mock-model}}]
          hunter: [{{provider: mock, model: mock-model}}]
          judge: [{{provider: mock, model: mock-model}}]
          judge2: [{{provider: mock, model: mock-model}}]
          poc: [{{provider: mock, model: mock-model}}]
          scorer: [{{provider: mock, model: mock-model}}]

        prices: {{}}
        budget: {{monthly_usd: 20, reserve_usd: 0.5}}
        """
    )


def _scan_args(**overrides) -> argparse.Namespace:
    defaults = dict(
        target=None,
        kb="kb",
        scope=None,
        known=None,
        notes=None,
        lenses="A5",
        passes=1,
        budget=240_000,
        judge_budget=120_000,
        map_cap=12_000,
        max_judge=40,
        temp=0.3,
        seed=0,
        fresh=True,
        no_judge2=False,
        dry_run=False,
        out=None,
        models=None,
        local_only=False,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


@pytest.fixture
def fixture_repo(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Vault.sol").write_text(FIXTURE_VAULT_SOL)
    return tmp_path


@pytest.fixture
def kb_dir():
    return str(Path(__file__).parent.parent / "kb")


def test_scan_dry_run_makes_zero_http_requests(fixture_repo, kb_dir, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with MockServer() as mock:
        models_path = tmp_path / "models.yaml"
        models_path.write_text(_models_yaml(mock.base_url))

        args = _scan_args(
            target=str(fixture_repo), kb=kb_dir, out=str(tmp_path / "runs"),
            models=str(models_path), dry_run=True,
        )
        import asyncio

        exit_code = asyncio.run(scan(args))

        assert exit_code == 0
        assert mock.request_count == 0


def test_scan_end_to_end_against_mock_server(fixture_repo, kb_dir, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with MockServer() as mock:
        models_path = tmp_path / "models.yaml"
        models_path.write_text(_models_yaml(mock.base_url))
        run_dir = tmp_path / "runs"

        args = _scan_args(
            target=str(fixture_repo), kb=kb_dir, out=str(run_dir), models=str(models_path),
        )
        import asyncio

        exit_code = asyncio.run(scan(args))
        assert exit_code == 0
        assert mock.request_count > 0

        run_dirs = list(run_dir.iterdir())
        assert len(run_dirs) == 1
        out_dir = run_dirs[0]

        findings = json.loads((out_dir / "findings.json").read_text())
        by_title = {f["title"]: f for f in findings}

        # the valid finding survives to keep
        valid = by_title["Reentrancy in withdraw"]
        assert valid["location"] == FIXTURE_LOCATION
        assert valid["verdict"]["verdict"] == "keep"

        # the bad-path finding is killed by the citation gate
        bad_path = by_title["Bug in a file that does not exist"]
        assert bad_path["verdict"]["verdict"] == "kill"
        assert bad_path["verdict"]["killed_by"] == "citation gate"

        # the malformed entry never appears anywhere
        assert "Malformed entry missing required fields" not in by_title

        # findings.json contains the killed entry too (not silently dropped)
        assert any(f["verdict"]["verdict"] == "kill" for f in findings)

        report = (out_dir / "report.md").read_text()
        assert report

        poc_files = list((out_dir / "pocs").glob(f"{valid['id']}.t.sol"))
        assert len(poc_files) == 1
        assert "// ASSUME:" in poc_files[0].read_text()


def test_rerun_resumes_entirely_from_the_disk_cache(fixture_repo, kb_dir, tmp_path, monkeypatch):
    """If a scan dies on rate limits, a rerun must not re-spend requests: the cache
    key can't depend on anything that changes between runs (timestamps, run dir...)."""
    import asyncio

    monkeypatch.chdir(tmp_path)
    with MockServer() as mock:
        models_path = tmp_path / "models.yaml"
        models_path.write_text(_models_yaml(mock.base_url))

        args = _scan_args(
            target=str(fixture_repo), kb=kb_dir, out=str(tmp_path / "runs"),
            models=str(models_path), fresh=False, passes=2,
        )
        assert asyncio.run(scan(args)) == 0
        after_first = mock.request_count
        assert after_first > 0

        assert asyncio.run(scan(args)) == 0
        assert mock.request_count == after_first
