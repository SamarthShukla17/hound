"""Step L/O: invariants command — code-context assembly, artifact rendering, cost ceiling."""

import asyncio
import json
import yaml
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import bloodhound.run_invariants as run_invariants_mod
from bloodhound.run_invariants import code_context, invariants_command, render, to_dict


@dataclass
class _Src:
    path: Path
    lines: list


def test_code_context_headers_each_file_and_respects_budget(tmp_path):
    files = [_Src(path=tmp_path / "A.sol", lines=["contract A {}"]), _Src(path=tmp_path / "B.sol", lines=["contract B {}"])]
    ctx = code_context(tmp_path, files, budget=10_000)
    assert "FILE: A.sol" in ctx and "contract A {}" in ctx
    assert "FILE: B.sol" in ctx and "contract B {}" in ctx

    # a tiny budget admits the first file only, never a half-written one
    tight = code_context(tmp_path, files, budget=10)
    assert "FILE: A.sol" not in tight or "FILE: B.sol" not in tight


def test_to_dict_and_render_cover_every_claim():
    results = {
        "A1": SimpleNamespace(status="held", iterations=0, notes="", trace=""),
        "A2": SimpleNamespace(status="counterexample", iterations=2, notes="see trace", trace="call sequence..."),
    }
    d = to_dict(results)
    assert d["A1"]["status"] == "held"
    assert d["A2"]["notes"] == "see trace"

    md = render(results)
    assert "A1: held" in md
    assert "A2: counterexample" in md
    assert "call sequence..." in md


def test_invariants_command_stops_on_cost_ceiling_and_exits_3(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    (target / "A.sol").write_text("contract A {}")
    claims_path = tmp_path / "invariants.yaml"
    claims_path.write_text(yaml.dump([
        {"id": "A1", "claim": "never splits", "property": "p == c xor p == q"},
        {"id": "A2", "claim": "never splits (2)", "property": "p == c xor p == q"},
    ]))

    forge_calls = []

    async def fake_forge_invariant(router, kb, claim, ctx, target_root, handler_dir, **kw):
        forge_calls.append(claim.id)
        return SimpleNamespace(status="held", iterations=0, notes="", trace="")

    monkeypatch.setattr(run_invariants_mod, "forge_invariant", fake_forge_invariant)

    class SpentRouter:
        def report(self):
            return {"total_usd": 999.0}

    import hound.llm as llm_mod

    monkeypatch.setattr(llm_mod, "Router", lambda **kw: SpentRouter())

    out_dir = tmp_path / "runs"
    args = type(
        "A", (),
        dict(target=str(target), invariants=str(claims_path), claim=None, kb="kb", max_repairs=4,
             out=str(out_dir), max_cost=1.0, models="models.yaml", local_only=False),
    )()

    assert asyncio.run(invariants_command(args)) == 3
    assert forge_calls == []  # already over the ceiling before the first claim

    run_dirs = list(out_dir.glob("invariants-*"))
    assert len(run_dirs) == 1
    manifest = json.loads((run_dirs[0] / "manifest.json").read_text())
    assert manifest["breached"] is True
    assert manifest["max_cost_usd"] == 1.0


def test_invariants_command_escalates_only_held_claims_when_deep_fuzz_opted_in(tmp_path, monkeypatch):
    """Step R: --deep-fuzz is opt-in and only ever fires on a 'held' fast-gate result — a
    counterexample is already falsified and compile_failed has nothing to fuzz."""
    target = tmp_path / "target"
    target.mkdir()
    claims_path = tmp_path / "invariants.yaml"
    claims_path.write_text(yaml.dump([
        {"id": "HELD", "claim": "c1", "property": "p1"},
        {"id": "CE", "claim": "c2", "property": "p2"},
        {"id": "FAIL", "claim": "c3", "property": "p3"},
    ]))

    statuses = {"HELD": "held", "CE": "counterexample", "FAIL": "compile_failed"}

    async def fake_forge_invariant(router, kb, claim, ctx, target_root, handler_dir, **kw):
        return SimpleNamespace(status=statuses[claim.id], iterations=0, notes="", trace="")

    monkeypatch.setattr(run_invariants_mod, "forge_invariant", fake_forge_invariant)

    escalated = []

    async def fake_escalate(router, kb, claim, ctx, target_root, out_dir, **kw):
        escalated.append(claim.id)
        return {"echidna": SimpleNamespace(status="held", notes="", raw_output="")}

    monkeypatch.setattr(run_invariants_mod.deepfuzz, "escalate", fake_escalate)

    class FreeRouter:
        def report(self):
            return {"total_usd": 0.0}

    import hound.llm as llm_mod

    monkeypatch.setattr(llm_mod, "Router", lambda **kw: FreeRouter())

    out_dir = tmp_path / "runs"
    args = type(
        "A", (),
        dict(target=str(target), invariants=str(claims_path), claim=None, kb="kb", max_repairs=4,
             out=str(out_dir), max_cost=None, models="models.yaml", local_only=False,
             deep_fuzz="echidna", deep_fuzz_timeout=300),
    )()

    assert asyncio.run(invariants_command(args)) == 0
    assert escalated == ["HELD"]  # never CE or FAIL

    run_dirs = list(out_dir.glob("invariants-*"))
    doc = json.loads((run_dirs[0] / "invariants.json").read_text())
    assert doc["HELD"]["deep_fuzz"]["echidna"]["status"] == "held"
    assert "deep_fuzz" not in doc["CE"]
    assert "deep_fuzz" not in doc["FAIL"]


def test_invariants_command_never_escalates_when_deep_fuzz_off(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    claims_path = tmp_path / "invariants.yaml"
    claims_path.write_text(yaml.dump([{"id": "HELD", "claim": "c1", "property": "p1"}]))

    async def fake_forge_invariant(router, kb, claim, ctx, target_root, handler_dir, **kw):
        return SimpleNamespace(status="held", iterations=0, notes="", trace="")

    monkeypatch.setattr(run_invariants_mod, "forge_invariant", fake_forge_invariant)

    escalated = []

    async def fake_escalate(*a, **kw):
        escalated.append(1)
        return {}

    monkeypatch.setattr(run_invariants_mod.deepfuzz, "escalate", fake_escalate)

    class FreeRouter:
        def report(self):
            return {"total_usd": 0.0}

    import hound.llm as llm_mod

    monkeypatch.setattr(llm_mod, "Router", lambda **kw: FreeRouter())

    out_dir = tmp_path / "runs"
    args = type(
        "A", (),
        dict(target=str(target), invariants=str(claims_path), claim=None, kb="kb", max_repairs=4,
             out=str(out_dir), max_cost=None, models="models.yaml", local_only=False),
    )()  # no deep_fuzz attr at all -> getattr default "off"

    assert asyncio.run(invariants_command(args)) == 0
    assert escalated == []
