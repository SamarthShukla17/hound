"""Step 7: end-to-end scan against the mock OpenAI-compatible server. No real
network — every role in the temp models.yaml points at MockServer."""

import argparse
import json
import textwrap
from pathlib import Path

import pytest

from hound.codebase import check_provenance, file_sha256, load
from hound.pipeline import _cited_salt, citation_gate, rejudge, scan, verify_disproofs
from hound.runs import CITATION_GATE, STALE_CITATION
from hound.schema import Verdict
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
        judge_mode="advisory",
        scope_profile="contest",
        scope_rules=None,
        cache_any_model=None,
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

        doc = json.loads((out_dir / "findings.json").read_text())
        assert doc["judge_mode"] == "advisory"
        findings = doc["findings"]
        by_title = {f["title"]: f for f in findings}

        # the valid finding survives to keep
        valid = by_title["Reentrancy in withdraw"]
        assert valid["location"] == FIXTURE_LOCATION
        assert valid["verdict"]["verdict"] == "keep"

        # the bad-path finding is killed by the citation gate
        bad_path = by_title["Bug in a file that does not exist"]
        assert bad_path["verdict"]["verdict"] == "kill"
        assert bad_path["verdict"]["killed_by"] == CITATION_GATE
        assert bad_path["hard_kill"] is True and valid["hard_kill"] is False

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


# --- provenance -------------------------------------------------------------------------


def _run_scan(fixture_repo, kb_dir, tmp_path, monkeypatch, mock, **overrides):
    monkeypatch.chdir(tmp_path)
    models_path = tmp_path / "models.yaml"
    models_path.write_text(_models_yaml(mock.base_url))
    out = tmp_path / "runs"
    args = _scan_args(target=str(fixture_repo), kb=kb_dir, out=str(out), models=str(models_path), **overrides)
    import asyncio

    assert asyncio.run(scan(args)) == 0
    out_dir = next(out.iterdir())
    return out_dir, json.loads((out_dir / "findings.json").read_text())


def test_provenance_round_trips_through_findings_json_and_map_json(fixture_repo, kb_dir, tmp_path, monkeypatch):
    with MockServer() as mock:
        out_dir, doc = _run_scan(fixture_repo, kb_dir, tmp_path, monkeypatch, mock)

    vault = fixture_repo / "src" / "Vault.sol"
    expected = {"sha256": file_sha256(vault), "n_lines": len(FIXTURE_VAULT_SOL.splitlines())}

    # findings.json: provenance names exactly the cited file(s), with hash + line count
    assert doc["provenance"]["files"] == {"src/Vault.sol": expected}
    assert doc["provenance"]["commit"] is None and doc["provenance"]["dirty"] is None  # tmp dir, no repo
    assert doc["provenance"]["target"] == str(fixture_repo.resolve())

    # every finding carries the hash of what it cited, captured at hunt time
    by_title = {f["title"]: f for f in doc["findings"]}
    assert by_title["Reentrancy in withdraw"]["cited"] == {"src/Vault.sol": expected["sha256"]}
    assert by_title["Bug in a file that does not exist"]["cited"] == {}

    # map.json carries provenance for everything the mapper read, plus the full (valid JSON) map
    map_doc = json.loads((out_dir / "map.json").read_text())
    assert map_doc["provenance"]["files"] == {"src/Vault.sol": expected}
    assert map_doc["map"]["summary"]

    # and the recorded provenance checks clean against the untouched tree, dirty once edited
    assert check_provenance(doc["provenance"]) == []
    vault.write_text(FIXTURE_VAULT_SOL + "// edited later\n")
    assert check_provenance(doc["provenance"]) == ["src/Vault.sol: content changed since it was read"]


def test_a_file_edited_between_hunt_and_gate_is_killed_as_a_stale_citation(fixture_repo, kb_dir, tmp_path, monkeypatch):
    import hound.pipeline as pipeline

    real_load = pipeline.load
    calls = {"n": 0}

    def load_then_edit_before_the_gate_reload(*a, **kw):
        calls["n"] += 1
        if calls["n"] == 2:  # the gate's fresh reload: the file changed after the hunter read it
            (fixture_repo / "src" / "Vault.sol").write_text(FIXTURE_VAULT_SOL + "// someone added a guard\n")
        return real_load(*a, **kw)

    monkeypatch.setattr(pipeline, "load", load_then_edit_before_the_gate_reload)
    with MockServer() as mock:
        out_dir, doc = _run_scan(fixture_repo, kb_dir, tmp_path, monkeypatch, mock)

    valid = {f["title"]: f for f in doc["findings"]}["Reentrancy in withdraw"]
    assert valid["verdict"]["verdict"] == "kill"
    assert valid["verdict"]["killed_by"] == STALE_CITATION == "stale citation (file changed since hunt)"
    assert valid["hard_kill"] is True
    assert not list((out_dir / "pocs").glob("*"))  # never judged, never given a PoC


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _cand(loc, cited):
    return {"id": "F001", "location": loc, "cited": cited}


def test_gate_same_path_edited_content_is_stale(tmp_path):
    f = tmp_path / "src" / "Vault.sol"
    _write(f, FIXTURE_VAULT_SOL)
    cited = {"src/Vault.sol": load(tmp_path)[0][0].sha256}

    _write(f, FIXTURE_VAULT_SOL.replace("insufficient", "insufficient balance"))  # same path, new content
    queue, hard = citation_gate([_cand("src/Vault.sol:12-14", cited)], load(tmp_path)[0])

    assert queue == [] and hard["F001"].killed_by == STALE_CITATION


def test_gate_same_content_at_a_different_path_still_resolves(tmp_path):
    _write(tmp_path / "old" / "Vault.sol", FIXTURE_VAULT_SOL)
    cited = {"old/Vault.sol": load(tmp_path)[0][0].sha256}

    (tmp_path / "old" / "Vault.sol").unlink()
    _write(tmp_path / "moved" / "core" / "Vault.sol", FIXTURE_VAULT_SOL)  # identical bytes, new path
    queue, hard = citation_gate([_cand("Vault.sol:12-14", cited)], load(tmp_path)[0])

    assert len(queue) == 1 and hard == {}


def test_gate_distinguishes_unresolvable_from_stale(tmp_path):
    _write(tmp_path / "src" / "Vault.sol", FIXTURE_VAULT_SOL)
    files = load(tmp_path)[0]
    queue, hard = citation_gate([_cand("NoSuchFile.sol:5", {}), _cand("src/Vault.sol:9999", {})], files)
    assert queue == []
    assert {v.killed_by for v in hard.values()} == {CITATION_GATE}


def test_cited_salt_tracks_the_cited_file_contents():
    a = {"cited": {"src/A.sol": "h1", "src/B.sol": "h2"}}
    assert _cited_salt(a) == _cited_salt({"cited": {"src/B.sol": "h2", "src/A.sol": "h1"}})  # order-free
    assert _cited_salt(a) != _cited_salt({"cited": {"src/A.sol": "h1-edited", "src/B.sol": "h2"}})
    assert _cited_salt({"cited": {}}) == "" == _cited_salt({})


def test_the_judge_is_called_with_a_cache_salt_derived_from_the_cited_file(fixture_repo, kb_dir, tmp_path, monkeypatch):
    import hound.pipeline as pipeline

    seen = []

    async def spy_judge(router, kb, role, cand, code, **kw):
        seen.append((role, kw.get("cache_salt")))
        return Verdict(verdict="keep", reason="ok")

    monkeypatch.setattr(pipeline, "judge", spy_judge)
    with MockServer() as mock:
        _run_scan(fixture_repo, kb_dir, tmp_path, monkeypatch, mock, no_judge2=True)

    assert seen and all(salt for _, salt in seen)


# --- judge modes ------------------------------------------------------------------------


def _kill_everything(monkeypatch):
    import hound.pipeline as pipeline

    async def judge_that_kills(router, kb, role, cand, code, **kw):
        return Verdict(verdict="kill", reason="a guard at line 5 prevents this", killed_by="require at line 5",
                       disproof_location="src/Vault.sol:5")

    monkeypatch.setattr(pipeline, "judge", judge_that_kills)


def test_advisory_mode_annotates_but_removes_nothing(fixture_repo, kb_dir, tmp_path, monkeypatch):
    _kill_everything(monkeypatch)
    with MockServer() as mock:
        out_dir, doc = _run_scan(fixture_repo, kb_dir, tmp_path, monkeypatch, mock, judge_mode="advisory")

    valid = {f["title"]: f for f in doc["findings"]}["Reentrancy in withdraw"]
    assert doc["judge_mode"] == "advisory"
    assert valid["verdict"]["verdict"] == "kill" and valid["hard_kill"] is False  # opinion, not removal

    report = (out_dir / "report.md").read_text()
    assert "Judge mode: **advisory**" in report
    assert "| id | judge |" in report
    assert "## F001 — Reentrancy in withdraw" in report  # detail section still shown
    assert "Judge: kill — a guard at line 5 prevents this" in report
    assert "## Killed by the judge" not in report
    assert "## Removed by deterministic gates" in report  # the hallucinated-path finding


def test_gate_mode_removes_judge_kills_from_the_report_detail(fixture_repo, kb_dir, tmp_path, monkeypatch):
    _kill_everything(monkeypatch)
    with MockServer() as mock:
        out_dir, doc = _run_scan(fixture_repo, kb_dir, tmp_path, monkeypatch, mock, judge_mode="gate")

    assert doc["judge_mode"] == "gate"
    report = (out_dir / "report.md").read_text()
    assert "## F001 — Reentrancy in withdraw" not in report
    assert "## Killed by the judge" in report and "F001" in report


def test_advisory_report_orders_by_votes_then_severity(tmp_path):
    from hound.pipeline import _render_report

    files = load(tmp_path)[0]
    cands = [
        {"id": "F001", "title": "few votes critical", "severity": "critical", "votes": 1, "lenses": ["A1"],
         "location": "x.sol:1", "root_cause": "", "impact": "", "exploit_steps": []},
        {"id": "F002", "title": "many votes medium", "severity": "medium", "votes": 3, "lenses": ["A1", "P1", "P2"],
         "location": "x.sol:1", "root_cause": "", "impact": "", "exploit_steps": []},
        {"id": "F003", "title": "many votes high", "severity": "high", "votes": 3, "lenses": ["A1", "P1", "P3"],
         "location": "x.sol:1", "root_cause": "", "impact": "", "exploit_steps": []},
    ]
    verdicts = {c["id"]: Verdict(verdict="kill", reason="r", disproof_location="x.sol:1") for c in cands}
    report = _render_report("t", cands, verdicts, files, "advisory", frozenset())
    table_ids = [line.split("|")[1].strip() for line in report.splitlines() if line.startswith("| F")]
    assert table_ids == ["F003", "F002", "F001"]


# --- scope profile ------------------------------------------------------------------------


def _by_task(mock, marker):
    return [r for r in mock.requests if marker in r["messages"][-1]["content"]]


def test_the_scope_profile_reaches_hunters_and_judge_and_is_recorded_in_findings_json(fixture_repo, kb_dir, tmp_path, monkeypatch):
    with MockServer() as mock:
        out_dir, doc = _run_scan(fixture_repo, kb_dir, tmp_path, monkeypatch, mock, scope_profile="bounty", seed=7)
        hunts, judges = _by_task(mock, "TASK: HUNT"), _by_task(mock, "TASK: FALSIFY")

    assert hunts and judges
    for req in hunts + judges:
        system = req["messages"][0]["content"]
        assert "SCOPE RULES (bounty profile)" in system and "SCOPE RULES (contest profile)" not in system

    assert doc["scope"]["name"] == "bounty" and doc["scope"]["source"] == "builtin"
    assert "Privileged-only paths are usually excluded" in doc["scope"]["text"]
    assert doc["seed"] == 7 and doc["lenses"] == "A5" and doc["passes"] == 1


def test_default_scope_is_contest(fixture_repo, kb_dir, tmp_path, monkeypatch):
    with MockServer() as mock:
        _, doc = _run_scan(fixture_repo, kb_dir, tmp_path, monkeypatch, mock)
        judges = _by_task(mock, "TASK: FALSIFY")
    assert doc["scope"]["name"] == "contest"
    assert "SCOPE RULES (contest profile)" in judges[0]["messages"][0]["content"]


def test_a_scope_rules_file_replaces_the_profile(fixture_repo, kb_dir, tmp_path, monkeypatch):
    rules = tmp_path / "readme_scope.md"
    rules.write_text("Only the Vault contract is in scope.\n")
    with MockServer() as mock:
        _, doc = _run_scan(fixture_repo, kb_dir, tmp_path, monkeypatch, mock, scope_rules=str(rules))
        system = _by_task(mock, "TASK: HUNT")[0]["messages"][0]["content"]
    assert doc["scope"]["name"] == "custom"
    assert "Only the Vault contract is in scope." in system
    assert "SCOPE RULES (contest profile)" not in system


def test_scope_notes_now_reach_the_hunters_and_the_judge(fixture_repo, kb_dir, tmp_path, monkeypatch):
    notes = tmp_path / "notes.md"
    notes.write_text("The s2Admin role is trusted.\n")
    with MockServer() as mock:
        _run_scan(fixture_repo, kb_dir, tmp_path, monkeypatch, mock, notes=str(notes))
        for marker in ("TASK: HUNT", "TASK: FALSIFY"):
            assert "The s2Admin role is trusted." in _by_task(mock, marker)[0]["messages"][-1]["content"]


# --- rejudge ------------------------------------------------------------------------------


def _rejudge_args(src_dir, tmp_path, mock, **overrides):
    import argparse

    defaults = dict(
        run_dir=str(src_dir), kb=str(Path(__file__).parent.parent / "kb"), known=None, notes=None,
        scope_profile="contest", scope_rules=None, judge_mode="advisory", judge_budget=120_000,
        map_cap=12_000, max_judge=40, no_judge2=False, fresh=True, out=str(tmp_path / "rejudged"),
        models=str(tmp_path / "models.yaml"), local_only=False, cache_any_model=None,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def test_rejudge_reruns_only_the_judge_stage_and_writes_a_new_run_dir(fixture_repo, kb_dir, tmp_path, monkeypatch):
    import asyncio

    with MockServer() as mock:
        src_dir, before = _run_scan(fixture_repo, kb_dir, tmp_path, monkeypatch, mock)
        requests_before = len(mock.requests)

        assert asyncio.run(rejudge(_rejudge_args(src_dir, tmp_path, mock, scope_profile="bounty"))) == 0
        new_requests = mock.requests[requests_before:]

    # nothing but judge calls: no mapping, no hunting, no PoC
    assert new_requests and all("TASK: FALSIFY" in r["messages"][-1]["content"] for r in new_requests)
    assert all("SCOPE RULES (bounty profile)" in r["messages"][0]["content"] for r in new_requests)

    out_dirs = list((tmp_path / "rejudged").iterdir())
    assert len(out_dirs) == 1 and out_dirs[0].name.endswith("-rejudge")
    after = json.loads((out_dirs[0] / "findings.json").read_text())

    assert after["rejudged_from"] == str(src_dir)
    assert after["scope"]["name"] == "bounty" and before["scope"]["name"] == "contest"
    assert after["provenance"] == before["provenance"] and after["seed"] == before["seed"]
    assert [f["id"] for f in after["findings"]] == [f["id"] for f in before["findings"]]  # ids preserved for scoring
    assert (out_dirs[0] / "report.md").exists() and (out_dirs[0] / "map.json").exists()
    assert not (out_dirs[0] / "pocs").exists()
    assert all("poc_path" not in f for f in after["findings"])

    # the deterministic gate kill is carried over untouched, not re-judged
    hard = [f for f in after["findings"] if f["hard_kill"]]
    assert [f["verdict"]["killed_by"] for f in hard] == [CITATION_GATE]


def test_rejudge_refuses_when_the_code_changed_since_the_hunter_read_it(fixture_repo, kb_dir, tmp_path, monkeypatch, capsys):
    import asyncio

    with MockServer() as mock:
        src_dir, _ = _run_scan(fixture_repo, kb_dir, tmp_path, monkeypatch, mock)
        (fixture_repo / "src" / "Vault.sol").write_text(FIXTURE_VAULT_SOL + "// edited\n")
        requests_before = len(mock.requests)

        assert asyncio.run(rejudge(_rejudge_args(src_dir, tmp_path, mock))) == 1
        assert len(mock.requests) == requests_before  # refused before spending anything

    out = capsys.readouterr().out
    assert "rejudge REFUSED" in out and "src/Vault.sol: content changed since it was read" in out
    assert not (tmp_path / "rejudged").exists()


def test_rejudge_refuses_a_run_that_predates_provenance(tmp_path, capsys):
    import asyncio

    legacy = tmp_path / "old_run"
    legacy.mkdir()
    (legacy / "findings.json").write_text(json.dumps([{"id": "F001", "verdict": {"verdict": "keep"}}]))
    (legacy / "map.json").write_text("{}")
    args = _rejudge_args(legacy, tmp_path, None)
    assert asyncio.run(rejudge(args)) == 1
    assert "predates provenance" in capsys.readouterr().out


# --- a kill must cite a disproof that actually resolves ---------------------------------------


def _verdicts(**kw):
    return {k: v for k, v in kw.items()}


def test_a_kill_citing_a_real_guard_stands(tmp_path):
    (tmp_path / "Vault.sol").write_text(FIXTURE_VAULT_SOL)
    files = load(tmp_path)[0]
    v = {"F001": Verdict(verdict="kill", reason="guarded", killed_by="require",
                         disproof_location="Vault.sol:12")}
    assert verify_disproofs(v, files) == 0
    assert v["F001"].verdict == "kill"


def test_a_kill_citing_a_nonexistent_file_is_downgraded_to_needs_poc(tmp_path):
    (tmp_path / "Vault.sol").write_text(FIXTURE_VAULT_SOL)
    files = load(tmp_path)[0]
    v = {"F001": Verdict(verdict="kill", reason="a guard prevents this", killed_by="onlyOwner",
                         disproof_location="NoSuchFile.sol:5")}
    assert verify_disproofs(v, files) == 1
    assert v["F001"].verdict == "needs_poc"
    assert "KILL NOT ACCEPTED" in v["F001"].reason
    assert "NoSuchFile.sol:5" in v["F001"].reason


def test_a_kill_citing_an_out_of_range_line_is_downgraded(tmp_path):
    (tmp_path / "Vault.sol").write_text(FIXTURE_VAULT_SOL)
    files = load(tmp_path)[0]
    v = {"F001": Verdict(verdict="kill", reason="guarded", killed_by="g", disproof_location="Vault.sol:99999")}
    assert verify_disproofs(v, files) == 1
    assert v["F001"].verdict == "needs_poc"


def test_deterministic_gate_kills_are_never_downgraded(tmp_path):
    (tmp_path / "Vault.sol").write_text(FIXTURE_VAULT_SOL)
    files = load(tmp_path)[0]
    v = {
        "F001": Verdict(verdict="kill", reason="does not resolve", killed_by=CITATION_GATE),
        "F002": Verdict(verdict="kill", reason="file changed", killed_by=STALE_CITATION),
    }
    assert verify_disproofs(v, files) == 0
    assert all(x.verdict == "kill" for x in v.values())


def test_keeps_and_needs_poc_are_untouched(tmp_path):
    files = load(tmp_path)[0]
    v = {"F001": Verdict(verdict="keep", reason="r"), "F002": Verdict(verdict="needs_poc", reason="r")}
    assert verify_disproofs(v, files) == 0
