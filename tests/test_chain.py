"""Step F: footprints, pair ranking, the model review and the scan hook. No network."""

import asyncio
import json
import textwrap
from pathlib import Path

import pytest

import hound.chain as chain
import hound.pipeline as pipeline
from hound.chain import ChainResult, Candidate, footprints, hits, live_findings, rank_pairs, render, run, write_artifacts
from hound.codebase import load
from hound.pipeline import scan
from tests.mock_server import MockServer
from tests.test_pipeline import FIXTURE_VAULT_SOL, _models_yaml, _scan_args

SOL = textwrap.dedent(
    """\
    contract Pool {
        uint256 public reserve;
        uint256 public escrow;
        uint256 public unrelated;
        mapping(address => uint256) public balances;

        function redeem(uint256 x) external {
            require(x <= reserve - escrow);
            reserve -= x;
        }
        function commit(uint256 loss) external {
            escrow = loss;
        }
        function deposit(uint256 x) external {
            reserve += x;
            balances[msg.sender] += x;
        }
        function setOther() external {
            unrelated = 1;
        }
    }
    """
)


def _line(text, needle):
    return next(i for i, l in enumerate(text.split("\n"), 1) if needle in l)


def _finding(fid, needle, tier="unclear", sev="high", gain=""):
    n = _line(SOL, needle)
    return {"id": fid, "title": f"finding {fid}", "severity": sev, "location": f"contracts/Pool.sol:{n}-{n}",
            "observation": "o", "invariant": "i", "violation": "v", "impact": "the cap is defeated",
            "exploit_steps": ["s"], "value_flow": tier, "attacker_gain": gain, "verdict": {"verdict": "keep", "reason": "r"},
            "hard_kill": False}


@pytest.fixture
def files(tmp_path):
    root = tmp_path / "proj"
    (root / "contracts").mkdir(parents=True)
    (root / "contracts" / "Pool.sol").write_text(SOL)
    loaded, _ = load(root)
    return root, loaded


def test_footprint_maps_cited_lines_to_functions_and_storage(files):
    root, fs = files
    fp = footprints([_finding("F1", "reserve -= x"), _finding("F2", "escrow = loss")], fs, root)
    assert fp["F1"].functions == {"Pool.redeem"} and fp["F1"].state == {"Pool.reserve", "Pool.escrow"}
    assert fp["F2"].functions == {"Pool.commit"} and fp["F2"].state == {"Pool.escrow"}
    assert "reserve -= x" in fp["F1"].snippets["Pool.redeem"] and fp["F1"].snippets["Pool.redeem"].startswith("contracts/Pool.sol:")


def test_pairs_sharing_state_are_ranked_and_unrelated_findings_are_not_paired(files):
    root, fs = files
    findings = [_finding("F1", "reserve -= x"), _finding("F2", "escrow = loss"), _finding("F3", "unrelated = 1")]
    prints = footprints(findings, fs, root)
    tiers = {f["id"]: "unclear" for f in findings}
    cands = rank_pairs(findings, prints, tiers)
    assert [(c.a, c.b) for c in cands] == [("F1", "F2")]  # F3 shares nothing
    assert cands[0].shared_state == ["Pool.escrow"]


def test_disruption_findings_are_prioritised_and_double_profits_are_not(files):
    root, fs = files
    findings = [_finding("F1", "reserve -= x"), _finding("F2", "escrow = loss"), _finding("F4", "reserve += x")]
    prints = footprints(findings, fs, root)
    plain = {c.a + c.b: c.score for c in rank_pairs(findings, prints, {f["id"]: "unclear" for f in findings})}
    disr = {c.a + c.b: c.score for c in rank_pairs(findings, prints, {"F1": "disruption", "F2": "unclear", "F4": "unclear"})}
    assert disr["F1F2"] > plain["F1F2"]
    prof = {c.a + c.b: c.score for c in rank_pairs(findings, prints, {"F1": "profit", "F2": "unclear", "F4": "profit"})}
    assert prof["F1F4"] < plain["F1F4"]


# --- the model review ---------------------------------------------------------


class FakeRouter:
    def __init__(self, reply, roles=("judge",)):
        self.reply, self.roles, self.calls = reply, set(roles), []

    def has(self, role):
        return role in self.roles

    async def chat_json(self, role, system, user, **kw):
        self.calls.append({"role": role, "system": system, "user": user})
        return self.reply


CHAIN_HIT = {"verdict": "chain_profit", "shared_mechanism": "escrow feeds the free-slack check",
             "sequence": ["inflate escrow", "redeem"], "attacker_gain": "+5 STABLE from the reserve",
             "reason": "A supplies the position B needs", "falsification": "check the capital returns"}


def _two(files):
    return [_finding("F1", "reserve -= x", tier="disruption"), _finding("F2", "escrow = loss")]


def test_review_shows_both_findings_shared_state_code_and_protocol(files):
    root, fs = files
    router = FakeRouter(CHAIN_HIT)
    res = asyncio.run(run(_two(files), fs, root, router=router, kb_dir="kb"))
    call = router.calls[0]
    assert "Chaining findings" in call["system"]  # kb/CHAINING.md
    for marker in ("FINDING A", "FINDING B", "Pool.escrow", "reserve -= x", "escrow = loss", '"tier": "disruption"'):
        assert marker in call["user"]
    assert hits(res) == ["F1+F2"]
    md = render(res, _two(files))
    assert "chain_profit" in md and "+5 STABLE from the reserve" in md and "inflate escrow" in md


def test_no_gain_is_recorded_but_not_a_hit_and_errors_are_not_fatal(files):
    root, fs = files
    ng = asyncio.run(run(_two(files), fs, root, router=FakeRouter({"verdict": "chain_no_gain", "reason": "nets to zero"}), kb_dir="kb"))
    assert hits(ng) == [] and ng.results["F1+F2"]["verdict"] == "chain_no_gain"
    bad = asyncio.run(run(_two(files), fs, root, router=FakeRouter({"verdict": "banana"}), kb_dir="kb"))
    assert "error" in bad.results["F1+F2"] and "error:" in render(bad, _two(files))


def test_fewer_than_two_findings_or_no_reviewer_role_is_a_noop_review(files):
    root, fs = files
    assert asyncio.run(run(_two(files)[:1], fs, root, router=FakeRouter(CHAIN_HIT))).candidates == []
    res = asyncio.run(run(_two(files), fs, root, router=FakeRouter(CHAIN_HIT, roles=())))
    assert res.candidates and res.results == {}  # ranked, not reviewed


def test_live_findings_drop_gate_and_judge_kills(tmp_path):
    good = {"id": "a", "hard_kill": False, "verdict": {"verdict": "keep"}}
    gated = {"id": "b", "hard_kill": True, "verdict": {"verdict": "kill"}}
    judged = {"id": "c", "hard_kill": False, "verdict": {"verdict": "kill", "killed_by": "guard"}}
    run_dir = tmp_path / "r"
    run_dir.mkdir()
    (run_dir / "findings.json").write_text(json.dumps({"judge_mode": "advisory", "findings": [good, gated, judged]}))
    assert [f["id"] for f in live_findings(run_dir)] == ["a"]


def test_artifacts_and_no_llm_command(files, tmp_path):
    root, fs = files
    res = asyncio.run(run(_two(files), fs, root, router=FakeRouter(CHAIN_HIT), kb_dir="kb"))
    out = tmp_path / "out"
    out.mkdir()
    write_artifacts(out, res, _two(files))
    assert json.loads((out / "chains.json").read_text())["results"]["F1+F2"]["verdict"] == "chain_profit"
    assert (out / "chains.md").read_text().startswith("# Chained-finding check")

    # `hound chain RUN --no-llm` ranks the pairs without a router
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "findings.json").write_text(json.dumps(
        {"judge_mode": "advisory", "provenance": {"target": str(root)}, "findings": _two(files)}))
    args = type("A", (), dict(run_dir=str(run_dir), target=None, kb="kb", max_pairs=12, no_llm=True, models=None, local_only=False))()
    assert asyncio.run(chain.chain_command(args)) == 0
    assert json.loads((run_dir / "chains.json").read_text())["candidates"][0]["shared_state"] == ["Pool.escrow"]


# --- the scan hook ---------------------------------------------------------------


def test_scan_runs_the_chain_check_and_writes_its_artifacts(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    repo = tmp_path / "proj"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "Vault.sol").write_text(FIXTURE_VAULT_SOL)
    seen = {}

    async def fake_run(findings, files, root, **kw):
        seen["n"] = len(findings)
        return ChainResult(candidates=[Candidate("A", "B", ["V.x"], [], 1.0)], results={"A+B": {**CHAIN_HIT}}, considered=len(findings))

    monkeypatch.setattr(pipeline.chainmod, "run", fake_run)
    with MockServer() as mock:
        models = tmp_path / "models.yaml"
        models.write_text(_models_yaml(mock.base_url))
        out = tmp_path / "runs"
        args = _scan_args(target=str(repo), kb=str(Path(__file__).parent.parent / "kb"), out=str(out),
                          models=str(models), chain="auto")
        assert asyncio.run(scan(args)) == 0
    run_dir = next(out.iterdir())
    assert seen["n"] >= 1 and (run_dir / "chains.json").exists()
    printed = capsys.readouterr().out
    assert "chain check:" in printed and "1 chain(s) found" in printed


def test_scan_without_the_chain_flag_does_not_run_it(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo = tmp_path / "proj"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "Vault.sol").write_text(FIXTURE_VAULT_SOL)

    async def boom(*a, **k):
        raise AssertionError("chain must not run")

    monkeypatch.setattr(pipeline.chainmod, "run", boom)
    with MockServer() as mock:
        models = tmp_path / "models.yaml"
        models.write_text(_models_yaml(mock.base_url))
        args = _scan_args(target=str(repo), kb=str(Path(__file__).parent.parent / "kb"), out=str(tmp_path / "runs"), models=str(models))
        assert asyncio.run(scan(args)) == 0


# --- findings that meet only through another contract --------------------------------

CROSS = textwrap.dedent(
    """\
    contract Ledger {
        uint256 public totalReserve;
        uint256 public committed;
        function freeSlack() external view returns (uint256) {
            return totalReserve - committed;
        }
        function record(uint256 x) external {
            totalReserve -= x;
        }
    }
    contract Module {
        Ledger public LEDGER;
        function buy(uint256 x) external {
            require(x <= LEDGER.freeSlack());
            LEDGER.record(x);
        }
        function surplus() external {
            require(LEDGER.totalReserve() >= 1);
        }
        function other() external {
            counter += 1;
        }
    }
    """
)


def test_findings_that_meet_only_through_external_calls_still_pair(tmp_path):
    root = tmp_path / "p"
    (root / "c").mkdir(parents=True)
    (root / "c" / "X.sol").write_text(CROSS)
    fs, _ = load(root)

    def cite(fid, needle):
        n = _line(CROSS, needle)
        return {"id": fid, "location": f"c/X.sol:{n}-{n}"}

    buy, surplus, other = cite("F1", "LEDGER.freeSlack()"), cite("F2", "LEDGER.totalReserve()"), cite("F3", "counter += 1")
    src_lines = CROSS.split("\n")
    prints = footprints([buy, surplus, other], fs, root)
    # neither Module function has a storage variable of its own in common ...
    assert "Ledger.totalReserve" in prints["F1"].state  # reached through freeSlack()'s body
    assert "Ledger.totalReserve" in prints["F1"].writes  # ... and WRITTEN by the record() call it makes
    assert "Ledger.totalReserve" in prints["F2"].state and "Ledger.totalReserve" not in prints["F2"].writes  # a getter read
    cands = rank_pairs([buy, surplus, other], prints, {f: "unclear" for f in ("F1", "F2", "F3")})
    assert [(c.a, c.b) for c in cands] == [("F1", "F2")]
    assert cands[0].shared_writes == ["Ledger.totalReserve"]


def test_state_both_sides_only_read_is_not_a_lead():
    src = textwrap.dedent(
        """\
        contract Gate {
            bool public paused;
            uint256 public a;
            uint256 public b;
            function one() external { require(!paused); a += 1; }
            function two() external { require(!paused); b += 1; }
        }
        """
    )
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "c").mkdir()
        (root / "c" / "G.sol").write_text(src)
        fs, _ = load(root)

        def cite(fid, needle):
            n = next(i for i, l in enumerate(src.split("\n"), 1) if needle in l)
            return {"id": fid, "location": f"c/G.sol:{n}-{n}"}

        f1, f2 = cite("F1", "a += 1"), cite("F2", "b += 1")
        prints = footprints([f1, f2], fs, root)
        assert "Gate.paused" in prints["F1"].state and "Gate.paused" not in prints["F1"].writes
        assert rank_pairs([f1, f2], prints, {"F1": "unclear", "F2": "unclear"}) == []  # share `paused`, but only read it


def test_guard_flags_are_a_weak_link_and_solvency_state_is_not():
    src = textwrap.dedent(
        """\
        contract Gate {
            bool public paused;
            uint256 public breached;
            uint256 public a;
            uint256 public b;
            uint256 public c;
            function pause() external { paused = true; }
            function buy() external { require(!paused); a += 1; breached = a; }
            function sell() external { require(breached == 0); b += 1; breached = b; }
            function pauseUser() external { require(!paused); c += 1; }
        }
        """
    )
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "c").mkdir()
        (root / "c" / "G.sol").write_text(src)
        fs, _ = load(root)

        def cite(fid, needle):
            n = next(i for i, l in enumerate(src.split("\n"), 1) if needle in l)
            return {"id": fid, "location": f"c/G.sol:{n}-{n}"}

        fnd = [cite("BUY", "a += 1"), cite("SELL", "b += 1"), cite("PAUSE", "paused = true"), cite("USER", "c += 1")]
        cands = rank_pairs(fnd, footprints(fnd, fs, root), {f["id"]: "unclear" for f in fnd})
        by = {(c.a, c.b): c.score for c in cands}
        assert by[("BUY", "SELL")] > by[("BUY", "PAUSE")] * 3  # shared breached beats a shared pause flag
