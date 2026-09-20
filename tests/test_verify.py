"""Step 5: the deterministic gates — location parsing, citation resolution,
snippeting, and dedup. No LLM calls anywhere in this file."""

import pytest

from hound.codebase import Src
from hound.verify import dedup, judge_context, parse_locations, snippets, spans


@pytest.fixture
def vault():
    return Src(path="src/Vault.sol", lines=[f"line_{i}" for i in range(1, 301)])


@pytest.fixture
def files(vault):
    return [vault]


# --- parse_locations ---------------------------------------------------


def test_parse_single_line():
    assert parse_locations("Vault.sol:12") == [("Vault.sol", 12, 12)]


def test_parse_hyphen_range():
    assert parse_locations("Vault.sol:12-30") == [("Vault.sol", 12, 30)]


def test_parse_l_prefixed_line():
    assert parse_locations("Vault.sol:L12") == [("Vault.sol", 12, 12)]


def test_parse_en_dash_range():
    assert parse_locations("Vault.sol:12–30") == [("Vault.sol", 12, 30)]


def test_parse_comma_separated_same_path():
    assert parse_locations("Vault.sol:12,45-50") == [
        ("Vault.sol", 12, 12),
        ("Vault.sol", 45, 50),
    ]


def test_parse_multiple_paths():
    assert parse_locations("Vault.sol:12-30, Token.sol:5") == [
        ("Vault.sol", 12, 30),
        ("Token.sol", 5, 5),
    ]


# --- spans / citation resolution ----------------------------------------


def test_spans_empty_for_nonexistent_path(files):
    assert spans("Nope.sol:12", files) == []


def test_spans_empty_for_out_of_range_line(files):
    assert spans("Vault.sol:99999", files) == []


def test_spans_resolves_unique_basename(files, vault):
    assert spans("Vault.sol:12-15", files) == [(vault, 12, 15)]


def test_spans_none_when_two_dirs_share_a_basename(vault):
    other = Src(path="other/Vault.sol", lines=vault.lines)
    files = [vault, other]
    assert spans("Vault.sol:12", files) == []  # ambiguous -> unresolved -> no span


def test_spans_exact_path_still_works_when_ambiguous_by_basename(vault):
    other = Src(path="other/Vault.sol", lines=vault.lines)
    files = [vault, other]
    assert spans("src/Vault.sol:12", files) == [(vault, 12, 12)]


def test_myvault_does_not_suffix_match_vault(vault):
    my_vault = Src(path="src/MyVault.sol", lines=vault.lines)
    files = [vault, my_vault]
    # "Vault.sol" must resolve only to Vault.sol, never to MyVault.sol
    assert spans("Vault.sol:12", files) == [(vault, 12, 12)]


# --- snippets / judge_context --------------------------------------------


def test_snippets_are_headed_and_clamped_to_file_bounds(files, vault):
    text = snippets("Vault.sol:5", files, pad=40, cap=160)
    assert text.startswith("// src/Vault.sol:1-45  (cited 5-5)")
    assert "    1| line_1" in text


def test_judge_context_returns_whole_file_under_large_budget(files, vault):
    ctx = judge_context("Vault.sol:12-15", files, budget=100_000)
    assert ctx.startswith("// ===== FILE: src/Vault.sol =====")
    assert "line_300" in ctx  # whole file, not just the cited window


def test_judge_context_falls_back_to_snippets_under_tiny_budget(files):
    ctx = judge_context("Vault.sol:12-15", files, budget=10)
    assert ctx.startswith("// src/Vault.sol:")
    assert "(cited 12-15)" in ctx


def test_judge_context_empty_when_nothing_resolves(files):
    assert judge_context("Nope.sol:1", files, budget=100_000) == ""


# --- dedup -----------------------------------------------------------------


def _cand(**kwargs):
    base = {
        "title": "default title",
        "severity": "medium",
        "location": "src/Vault.sol:1",
        "root_cause": "default root cause",
        "lenses": ["X"],
        "votes": 1,
    }
    base.update(kwargs)
    return base


def test_overlapping_same_bug_merges_with_votes_and_lenses(files):
    cands = [
        _cand(
            title="Reentrancy in withdraw",
            severity="high",
            location="src/Vault.sol:20-25",
            root_cause="state updated after the external call",
            lenses=["A5"],
        ),
        _cand(
            title="Reentrancy bug in withdraw fn",
            severity="high",
            location="src/Vault.sol:22-24",
            root_cause="state update happens after the external call completes",
            lenses=["P1"],
        ),
    ]
    result = dedup(cands, files)
    assert len(result) == 1
    assert result[0]["votes"] == 2
    assert result[0]["lenses"] == ["A5", "P1"]


def test_bugs_200_lines_apart_stay_separate(files):
    cands = [
        _cand(title="Bug A", severity="high", location="src/Vault.sol:20-25", root_cause="cause one"),
        _cand(title="Bug B", severity="high", location="src/Vault.sol:220-225", root_cause="totally unrelated cause"),
    ]
    result = dedup(cands, files)
    assert len(result) == 2


def test_ids_assigned_in_severity_order(files):
    cands = [
        _cand(title="low sev", severity="low", location="src/Vault.sol:1", root_cause="rc low"),
        _cand(title="critical sev", severity="critical", location="src/Vault.sol:100", root_cause="rc critical"),
        _cand(title="medium sev", severity="medium", location="src/Vault.sol:200", root_cause="rc medium"),
    ]
    result = dedup(cands, files)
    assert [(o["id"], o["severity"]) for o in result] == [
        ("F001", "critical"),
        ("F002", "medium"),
        ("F003", "low"),
    ]


def test_dedup_does_not_mutate_input_candidates(files):
    original = [_cand(title="A", location="src/Vault.sol:20-25")]
    dedup(original, files)
    assert "id" not in original[0]
    assert "votes" in original[0] and original[0]["votes"] == 1


# --- expected_hash: staleness ---------------------------------------------------------


def test_spans_with_matching_expected_hash_resolves(files, vault):
    assert spans("Vault.sol:12", files, expected_hash=vault.sha256) == [(vault, 12, 12)]


def test_spans_with_a_different_expected_hash_is_stale_and_dropped(files, vault):
    # the cited line exists and is in range, but the file is not what the hunter read
    assert spans("Vault.sol:12", files) == [(vault, 12, 12)]
    assert spans("Vault.sol:12", files, expected_hash="deadbeef" * 8) == []


def test_expected_hash_may_be_a_collection_of_hashes(files, vault):
    assert spans("Vault.sol:12", files, expected_hash={"other", vault.sha256}) == [(vault, 12, 12)]
    assert spans("Vault.sol:12", files, expected_hash={"other"}) == []


def test_same_content_at_a_different_path_still_resolves_with_the_hash():
    lines = [f"line_{i}" for i in range(1, 50)]
    original = Src(path="src/Vault.sol", lines=lines)
    moved = Src(path="contracts/core/Vault.sol", lines=list(lines))
    assert moved.sha256 == original.sha256
    assert spans("Vault.sol:12", [moved], expected_hash=original.sha256) == [(moved, 12, 12)]


def test_edited_content_at_the_same_path_is_stale():
    original = Src(path="src/Vault.sol", lines=[f"line_{i}" for i in range(1, 50)])
    edited = Src(path="src/Vault.sol", lines=[f"line_{i}" for i in range(1, 50)] + ["// a new guard"])
    assert edited.sha256 != original.sha256
    assert spans("src/Vault.sol:12", [edited], expected_hash=original.sha256) == []
