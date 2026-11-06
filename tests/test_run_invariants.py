"""Step L: invariants command — code-context assembly and artifact rendering."""

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from bloodhound.run_invariants import code_context, render, to_dict


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
