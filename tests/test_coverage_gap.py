"""Step D: lcov parsing, per-function gap ranking, forge invocation and the scan hook. No real forge."""

import asyncio
import json
import subprocess
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from hound.codebase import load
from hound.coverage_gap import analyse, function_gaps, hunter_notes, parse_lcov, render, run_forge_coverage
from hound.pipeline import scan
from tests.mock_server import MockServer
from tests.test_pipeline import FIXTURE_VAULT_SOL, _models_yaml, _scan_args

SOL = textwrap.dedent(
    """\
    contract Auction {
        function take(uint256 amt) external {
            if (amt == 0) {
                _revert(ZeroAmount.selector);
            }
            if (lot == 0) {
                _remove(id);
            }
            token.transfer(msg.sender, amt);
        }
        function price() external view returns (uint256) {
            return top;
        }
        function file(bytes32 what, uint256 data) external {
            if (what == "tail") { tail = data; }
        }
        function rpow(uint256 x) internal pure returns (uint256 z) {
            assembly { z := x }
        }
        function wired() external {
            counter += 1;
        }
    }
    """
)

# line numbers in SOL: take 2-9, `if (amt == 0)` L3, `if (lot == 0)` L6, price 10-12, file 13-15, rpow 16-18, wired 19-21
LCOV = textwrap.dedent(
    """\
    TN:
    SF:contracts/Auction.sol
    DA:3,5
    DA:4,0
    DA:6,5
    DA:7,0
    DA:9,5
    DA:11,0
    DA:14,3
    DA:17,0
    DA:20,4
    BRDA:3,0,0,5
    BRDA:3,0,1,0
    BRDA:6,0,0,5
    BRDA:6,0,1,-
    BRDA:14,0,0,3
    BRDA:14,0,1,0
    BRDA:17,0,0,0
    BRDA:17,0,1,0
    end_of_record
    SF:tests/Other.t.sol
    DA:1,1
    end_of_record
    """
)


def _gaps():
    return function_gaps({"contracts/Auction.sol": SOL}, parse_lcov(LCOV))


def test_parse_lcov_reads_lines_and_branches_and_dash_means_not_taken():
    rec = parse_lcov(LCOV)["contracts/Auction.sol"]
    assert rec["da"][3] == 5 and rec["da"][4] == 0
    assert rec["br"][6] == [5, 0]  # '-' (never evaluated) counts as not taken
    assert "tests/Other.t.sol" in parse_lcov(LCOV)


def test_state_transition_branch_is_not_filed_as_a_trivial_zero_check():
    g = {x.function: x for x in _gaps()}["Auction.take"]
    by_line = {ln: trivial for ln, _t, trivial in g.uncovered}
    assert by_line[3] is True  # `if (amt == 0) { _revert }` is a guard: trivial
    assert by_line[6] is False  # `if (lot == 0) { _remove }` drives a transition: NOT trivial
    assert g.moves_value and g.externally_callable and g.state_changing


def test_ranking_prefers_value_moving_state_changing_code_over_getters_assembly_and_config():
    ranked = [g.function for g in _gaps()]
    assert ranked[0] == "Auction.take"
    scores = {g.function: g.score for g in _gaps()}
    assert scores["Auction.price"] < scores["Auction.take"] / 4  # unexercised getter
    assert scores["Auction.rpow"] < scores["Auction.file"]  # inline assembly: a tooling artifact
    assert scores["Auction.file"] < scores["Auction.take"]  # config setter
    assert "Auction.wired" not in scores or scores["Auction.wired"] < scores["Auction.take"]


def test_paths_match_by_suffix_and_unknown_files_are_ignored():
    gaps = function_gaps({"src/contracts/Auction.sol": SOL, "src/Untested.sol": "contract U { function f() external {} }"},
                         parse_lcov(LCOV))
    assert {g.file for g in gaps} == {"src/contracts/Auction.sol"}


def test_render_and_hunter_notes_mark_trivial_and_skip_pure_noise():
    gaps = _gaps()
    md = render(gaps)
    assert "L3*" in md and "L6:" in md and "## Auction.take" in md
    notes = hunter_notes(gaps)
    assert notes.startswith("LOW TEST COVERAGE") and "lot == 0" in notes and "amt == 0" not in notes


# --- forge invocation ------------------------------------------------------


def test_forge_needs_a_foundry_project(tmp_path):
    path, msg = run_forge_coverage(tmp_path, tmp_path / "o.lcov")
    assert path is None and "foundry.toml" in msg


def test_forge_run_uses_ir_minimum_lcov_and_returns_the_file(tmp_path):
    (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    out = tmp_path / "o.lcov"
    seen = {}

    def fake(cmd, **kw):
        seen["cmd"], seen["cwd"] = cmd, kw["cwd"]
        out.write_text(LCOV)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    path, msg = run_forge_coverage(tmp_path, out, runner=fake)
    assert path == out and msg == "ok"
    assert seen["cmd"][:3] == ["forge", "coverage", "--ir-minimum"] and "lcov" in seen["cmd"]
    assert seen["cwd"] == str(tmp_path)


def test_forge_failure_and_timeout_degrade_to_no_signal(tmp_path):
    (tmp_path / "foundry.toml").write_text("")
    bad = lambda cmd, **kw: SimpleNamespace(returncode=1, stdout="", stderr="compile error\nboom")  # noqa: E731
    path, msg = run_forge_coverage(tmp_path, tmp_path / "o", runner=bad)
    assert path is None and "boom" in msg

    def hang(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 1)

    path, msg = run_forge_coverage(tmp_path, tmp_path / "o", runner=hang)
    assert path is None and "did not complete" in msg


def test_analyse_accepts_a_precomputed_lcov_and_reports_a_missing_one(tmp_path):
    root = tmp_path / "p"
    (root / "contracts").mkdir(parents=True)
    (root / "contracts" / "Auction.sol").write_text(SOL)
    files, _ = load(root)
    lcov = tmp_path / "lcov.info"
    lcov.write_text(LCOV)
    gaps, msg = analyse(root, files, spec=str(lcov))
    assert msg == "ok" and gaps[0].function == "Auction.take"
    assert analyse(root, files, spec=str(tmp_path / "nope"))[1].startswith("lcov file not found")


# --- scan hook -------------------------------------------------------------


@pytest.fixture
def kb_dir():
    return str(Path(__file__).parent.parent / "kb")


def test_hunters_get_the_low_coverage_block_when_an_lcov_is_given(kb_dir, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo = tmp_path / "proj"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "Vault.sol").write_text(FIXTURE_VAULT_SOL)
    lcov = tmp_path / "vault.lcov"
    lcov.write_text("SF:src/Vault.sol\nDA:12,0\nDA:14,0\nBRDA:12,0,0,0\nBRDA:12,0,1,-\nend_of_record\n")
    with MockServer() as mock:
        models = tmp_path / "models.yaml"
        models.write_text(_models_yaml(mock.base_url))
        out = tmp_path / "runs"
        args = _scan_args(target=str(repo), kb=kb_dir, out=str(out), models=str(models), coverage=str(lcov))
        assert asyncio.run(scan(args)) == 0
        hunt = [r["messages"][-1]["content"] for r in mock.requests if "TASK: HUNT" in r["messages"][-1]["content"]]
    assert hunt and all("LOW TEST COVERAGE" in p and "Vault.withdraw" in p for p in hunt)
    run = next(out.iterdir())
    assert json.loads((run / "coverage_gaps.json").read_text())[0]["function"] == "Vault.withdraw"


def test_coverage_off_and_absent_change_nothing(kb_dir, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo = tmp_path / "proj"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "Vault.sol").write_text(FIXTURE_VAULT_SOL)
    with MockServer() as mock:
        models = tmp_path / "models.yaml"
        models.write_text(_models_yaml(mock.base_url))
        args = _scan_args(target=str(repo), kb=kb_dir, out=str(tmp_path / "runs"), models=str(models))
        assert asyncio.run(scan(args)) == 0
        assert not any("LOW TEST COVERAGE" in r["messages"][-1]["content"] for r in mock.requests)
