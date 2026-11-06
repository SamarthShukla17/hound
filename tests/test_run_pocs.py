"""Step J: run-pocs command — selecting forgeable candidates and writing the forge verdict back."""

import asyncio
import json

from bloodhound.run_pocs import forgeable, run_pocs_command


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

    args = type(
        "A", (), dict(run_dir=str(run_dir), target=None, kb="kb", max_repairs=4, no_llm=True, models=None, local_only=False)
    )()

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
    args = type(
        "A", (), dict(run_dir=str(run_dir), target=None, kb="kb", max_repairs=4, no_llm=True, models=None, local_only=False)
    )()
    assert asyncio.run(run_pocs_command(args)) == 1
