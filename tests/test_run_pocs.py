"""Step J/K: run-pocs command — selecting forgeable candidates, forging, and panel wiring."""

import asyncio
import json

import bloodhound.run_pocs as run_pocs_mod
from bloodhound.forger import ForgeResult
from bloodhound.novelty import NoveltyResult
from bloodhound.refute import PanelResult
from bloodhound.run_pocs import forgeable, run_pocs_command


def _args(run_dir, **overrides):
    base = dict(
        run_dir=str(run_dir), target=None, kb="kb", max_repairs=4, no_llm=True, no_panel=False,
        corpus=None, embed_role="embed", models=None, local_only=False,
    )
    base.update(overrides)
    return type("A", (), base)()


def test_forgeable_drops_hard_kills_judge_kills_and_rust_and_missing_poc():
    findings = [
        {"id": "a", "hard_kill": False, "verdict": {"verdict": "keep"}, "poc_path": "/r/pocs/a.t.sol"},
        {"id": "b", "hard_kill": True, "verdict": {"verdict": "kill"}, "poc_path": "/r/pocs/b.t.sol"},
        {"id": "c", "hard_kill": False, "verdict": {"verdict": "kill"}, "poc_path": "/r/pocs/c.t.sol"},
        {"id": "d", "hard_kill": False, "verdict": {"verdict": "keep"}, "poc_path": "/r/pocs/d.rs"},
        {"id": "e", "hard_kill": False, "verdict": {"verdict": "keep"}},
    ]
    meta = {}
    assert [f["id"] for f in forgeable(meta, findings)] == ["a"]


def test_run_pocs_command_no_llm_skips_everything_and_preserves_other_findings(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    pocs_dir = tmp_path / "run" / "pocs"
    pocs_dir.mkdir(parents=True)
    poc_path = pocs_dir / "a.t.sol"
    poc_path.write_text("function test_x() public {}")

    run_dir = tmp_path / "run"
    findings = [
        {"id": "a", "hard_kill": False, "verdict": {"verdict": "keep"}, "poc_path": str(poc_path)},
        {"id": "b", "hard_kill": False, "verdict": {"verdict": "kill"}, "poc_path": None},
    ]
    (run_dir / "findings.json").write_text(json.dumps(
        {"judge_mode": "advisory", "provenance": {"target": str(target)}, "findings": findings}
    ))

    args = _args(run_dir)

    assert asyncio.run(run_pocs_command(args)) == 0

    out = json.loads((run_dir / "findings.json").read_text())
    assert out["judge_mode"] == "advisory"
    assert out["provenance"]["target"] == str(target)
    out_ids = {f["id"]: f for f in out["findings"]}
    assert "forge" not in out_ids["a"]  # --no-llm: nothing was forged, nothing fabricated
    assert out_ids["b"]["verdict"]["verdict"] == "kill"  # untouched


def test_run_pocs_command_no_target_fails_cleanly(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True)
    (run_dir / "findings.json").write_text(json.dumps({"judge_mode": "gate", "findings": []}))
    args = _args(run_dir)
    assert asyncio.run(run_pocs_command(args)) == 1


def test_run_pocs_command_runs_panel_only_on_forged_and_writes_both_verdicts(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    pocs_dir = tmp_path / "run" / "pocs"
    pocs_dir.mkdir(parents=True)
    forged_poc = pocs_dir / "a.t.sol"
    forged_poc.write_text("function test_poc_a() public {}")
    unforged_poc = pocs_dir / "b.t.sol"
    unforged_poc.write_text("function test_poc_b() public {}")

    run_dir = tmp_path / "run"
    findings = [
        {"id": "a", "hard_kill": False, "verdict": {"verdict": "keep"}, "poc_path": str(forged_poc)},
        {"id": "b", "hard_kill": False, "verdict": {"verdict": "keep"}, "poc_path": str(unforged_poc)},
    ]
    (run_dir / "findings.json").write_text(json.dumps(
        {"judge_mode": "advisory", "provenance": {"target": str(target)}, "findings": findings}
    ))

    async def fake_forge_candidate(router, kb, finding, poc_code, target_root, forge_dir, **kw):
        if finding["id"] == "a":
            return ForgeResult(status="forged", poc_code=poc_code)
        return ForgeResult(status="unforged", notes="attack run did not pass")

    panel_calls = []

    async def fake_run_panel(router, kb, finding, forge_result, target_root, forge_dir, **kw):
        panel_calls.append(finding["id"])
        return PanelResult(killed=True, surviving_refutation="refute1: keeper-only")

    monkeypatch.setattr(run_pocs_mod, "forge_candidate", fake_forge_candidate)
    monkeypatch.setattr(run_pocs_mod, "run_panel", fake_run_panel)

    args = _args(run_dir, no_llm=False, models="models.yaml")
    assert asyncio.run(run_pocs_command(args)) == 0

    assert panel_calls == ["a"]  # the panel never ran on "b" (unforged)
    out = {f["id"]: f for f in json.loads((run_dir / "findings.json").read_text())["findings"]}
    assert out["a"]["forge"]["status"] == "forged"
    assert out["a"]["refute"]["killed"] is True
    assert out["a"]["refute"]["surviving_refutation"] == "refute1: keeper-only"
    assert out["b"]["forge"]["status"] == "unforged"
    assert "refute" not in out["b"]


def test_run_pocs_command_no_panel_flag_skips_the_panel(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    pocs_dir = tmp_path / "run" / "pocs"
    pocs_dir.mkdir(parents=True)
    forged_poc = pocs_dir / "a.t.sol"
    forged_poc.write_text("function test_poc_a() public {}")

    run_dir = tmp_path / "run"
    findings = [{"id": "a", "hard_kill": False, "verdict": {"verdict": "keep"}, "poc_path": str(forged_poc)}]
    (run_dir / "findings.json").write_text(json.dumps(
        {"judge_mode": "advisory", "provenance": {"target": str(target)}, "findings": findings}
    ))

    async def fake_forge_candidate(router, kb, finding, poc_code, target_root, forge_dir, **kw):
        return ForgeResult(status="forged", poc_code=poc_code)

    panel_calls = []

    async def fake_run_panel(*a, **kw):
        panel_calls.append(1)
        return PanelResult(killed=False)

    monkeypatch.setattr(run_pocs_mod, "forge_candidate", fake_forge_candidate)
    monkeypatch.setattr(run_pocs_mod, "run_panel", fake_run_panel)

    args = _args(run_dir, no_llm=False, no_panel=True, models="models.yaml")
    assert asyncio.run(run_pocs_command(args)) == 0
    assert panel_calls == []


def test_run_pocs_command_classifies_novelty_only_when_panel_survives_and_corpus_given(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    pocs_dir = tmp_path / "run" / "pocs"
    pocs_dir.mkdir(parents=True)
    forged_poc = pocs_dir / "a.t.sol"
    forged_poc.write_text("function test_poc_a() public {}")

    run_dir = tmp_path / "run"
    findings = [{"id": "a", "hard_kill": False, "verdict": {"verdict": "keep"}, "poc_path": str(forged_poc)}]
    (run_dir / "findings.json").write_text(json.dumps(
        {"judge_mode": "advisory", "provenance": {"target": str(target)}, "findings": findings}
    ))
    corpus_path = tmp_path / "corpus.json"
    corpus_path.write_text(json.dumps([{"id": "C1", "title": "known bug"}]))

    async def fake_forge_candidate(router, kb, finding, poc_code, target_root, forge_dir, **kw):
        return ForgeResult(status="forged", poc_code=poc_code)

    async def fake_run_panel(*a, **kw):
        return PanelResult(killed=False)

    novelty_calls = []

    async def fake_classify(router, role, finding, corpus):
        novelty_calls.append((role, finding["id"], len(corpus)))
        return NoveltyResult(verdict="no-corpus-match")

    monkeypatch.setattr(run_pocs_mod, "forge_candidate", fake_forge_candidate)
    monkeypatch.setattr(run_pocs_mod, "run_panel", fake_run_panel)
    monkeypatch.setattr(run_pocs_mod, "classify", fake_classify)

    args = _args(run_dir, no_llm=False, corpus=str(corpus_path), models="models.yaml")
    assert asyncio.run(run_pocs_command(args)) == 0

    assert novelty_calls == [("embed", "a", 1)]
    out = {f["id"]: f for f in json.loads((run_dir / "findings.json").read_text())["findings"]}
    assert out["a"]["novelty"]["verdict"] == "no-corpus-match"


def test_run_pocs_command_skips_novelty_when_panel_kills_the_finding(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    pocs_dir = tmp_path / "run" / "pocs"
    pocs_dir.mkdir(parents=True)
    forged_poc = pocs_dir / "a.t.sol"
    forged_poc.write_text("function test_poc_a() public {}")

    run_dir = tmp_path / "run"
    findings = [{"id": "a", "hard_kill": False, "verdict": {"verdict": "keep"}, "poc_path": str(forged_poc)}]
    (run_dir / "findings.json").write_text(json.dumps(
        {"judge_mode": "advisory", "provenance": {"target": str(target)}, "findings": findings}
    ))
    corpus_path = tmp_path / "corpus.json"
    corpus_path.write_text(json.dumps([{"id": "C1", "title": "known bug"}]))

    async def fake_forge_candidate(router, kb, finding, poc_code, target_root, forge_dir, **kw):
        return ForgeResult(status="forged", poc_code=poc_code)

    async def fake_run_panel(*a, **kw):
        return PanelResult(killed=True, surviving_refutation="refute1: x")

    novelty_calls = []

    async def fake_classify(*a, **kw):
        novelty_calls.append(1)
        return NoveltyResult(verdict="no-corpus-match")

    monkeypatch.setattr(run_pocs_mod, "forge_candidate", fake_forge_candidate)
    monkeypatch.setattr(run_pocs_mod, "run_panel", fake_run_panel)
    monkeypatch.setattr(run_pocs_mod, "classify", fake_classify)

    args = _args(run_dir, no_llm=False, corpus=str(corpus_path), models="models.yaml")
    assert asyncio.run(run_pocs_command(args)) == 0
    assert novelty_calls == []


def test_run_pocs_command_writes_a_dossier_only_for_forged_panel_surviving_findings(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    pocs_dir = tmp_path / "run" / "pocs"
    pocs_dir.mkdir(parents=True)
    forged_poc = pocs_dir / "a.t.sol"
    forged_poc.write_text("function test_poc_a() public {}")
    killed_poc = pocs_dir / "b.t.sol"
    killed_poc.write_text("function test_poc_b() public {}")

    run_dir = tmp_path / "run"
    findings = [
        {"id": "a", "hard_kill": False, "verdict": {"verdict": "keep"}, "poc_path": str(forged_poc), "title": "t-a"},
        {"id": "b", "hard_kill": False, "verdict": {"verdict": "keep"}, "poc_path": str(killed_poc), "title": "t-b"},
    ]
    (run_dir / "findings.json").write_text(json.dumps(
        {"judge_mode": "advisory", "provenance": {"target": str(target), "commit": "deadbee"}, "findings": findings}
    ))

    async def fake_forge_candidate(router, kb, finding, poc_code, target_root, forge_dir, **kw):
        return ForgeResult(status="forged", poc_code=poc_code, attack_output="trace")

    async def fake_run_panel(router, kb, finding, forge_result, target_root, forge_dir, **kw):
        return PanelResult(killed=(finding["id"] == "b"))

    monkeypatch.setattr(run_pocs_mod, "forge_candidate", fake_forge_candidate)
    monkeypatch.setattr(run_pocs_mod, "run_panel", fake_run_panel)

    args = _args(run_dir, no_llm=False, models="models.yaml")
    assert asyncio.run(run_pocs_command(args)) == 0

    assert (run_dir / "dossiers" / "a.md").is_file()
    assert "on deadbee" in (run_dir / "dossiers" / "a.md").read_text()
    assert not (run_dir / "dossiers" / "b.md").exists()

    out = {f["id"]: f for f in json.loads((run_dir / "findings.json").read_text())["findings"]}
    assert out["a"]["dossier_path"] == str(run_dir / "dossiers" / "a.md")
    assert "dossier_path" not in out["b"]
