"""Step 3: kb/*.md -> Lens parsing, against the real kb files (no fixtures —
these are the actual taxonomy files the harness ships with)."""

from pathlib import Path

import pytest

from hound.knowledge import KB, Lens, load_kb, poc_refs, select

KB_DIR = Path(__file__).parent.parent / "kb"


@pytest.fixture(scope="module")
def kb() -> KB:
    return load_kb(KB_DIR)


def _ids(lenses, prefix):
    return [lens.id for lens in lenses if lens.id.startswith(prefix)]


def test_class_lenses_C1_to_C6(kb):
    ids = _ids(kb.lenses, "C")
    assert ids == [f"C{i}" for i in range(1, 7)]


def test_angle_lenses_A1_to_A7(kb):
    ids = _ids(kb.lenses, "A")
    assert ids == [f"A{i}" for i in range(1, 8)]


def test_pattern_lenses_at_least_7(kb):
    ids = _ids(kb.lenses, "P")
    assert len(ids) >= 7
    # numbered headings P1..P6, plus at least one trailing "Pattern: X — ..." paragraph
    assert ids[:6] == [f"P{i}" for i in range(1, 7)]


def test_principles_come_from_section_0(kb):
    assert kb.principles
    assert "Falsification-first" in kb.principles
    assert kb.principles.startswith("1.")  # heading text itself is excluded from the body


def test_p1_poc_contains_a_foundry_test_function(kb):
    p1 = next(lens for lens in kb.lenses if lens.id == "P1")
    assert "function test_" in p1.poc


def test_pattern_without_a_code_fence_has_no_poc(kb):
    p6 = next(lens for lens in kb.lenses if lens.id == "P6")
    assert p6.poc == ""


def test_select_all_returns_every_lens(kb):
    assert select(kb.lenses, "all") == kb.lenses


def test_select_by_ids(kb):
    result = select(kb.lenses, "A5,P1")
    assert [lens.id for lens in result] == ["A5", "P1"]


def test_select_by_kind(kb):
    result = select(kb.lenses, "A,P")
    assert all(lens.kind in ("angle", "pattern") for lens in result)
    assert len(result) == len(_ids(kb.lenses, "A")) + len(_ids(kb.lenses, "P"))


def test_poc_refs_joins_only_lenses_with_a_poc(kb):
    result = select(kb.lenses, "P1,P6")
    refs = poc_refs(result)
    assert "P1" in refs
    assert "function test_" in refs
    assert "P6" not in refs  # P6 has no poc, so it contributes nothing


def test_load_kb_finds_files_recursively(tmp_path):
    nested = tmp_path / "nested" / "deeper"
    nested.mkdir(parents=True)
    for name in ("METHODOLOGY.md", "ATTACK_ANGLES.md", "BUG_PATTERNS.md"):
        (nested / name).write_text((KB_DIR / name).read_text(encoding="utf-8"), encoding="utf-8")

    # The point is that the recursive lookup finds all three files and loses no lens; the expected
    # count is whatever the kb itself parses to, so adding a pattern to kb/ never breaks this test.
    found = load_kb(tmp_path)
    assert len(found.lenses) == len(load_kb(KB_DIR).lenses)
    assert len(found.lenses) >= 6 + 7 + 7
