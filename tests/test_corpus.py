"""Step 8/9: the human-confirmed false-positive corpus."""

import json
from pathlib import Path

import pytest

from hound.corpus import append, default_path, kill_finding, recent


@pytest.fixture
def corpus_path(tmp_path):
    return tmp_path / "corpus" / "killed.jsonl"


def test_default_path_lives_under_home_not_the_cwd(monkeypatch):
    monkeypatch.delenv("HOUND_CORPUS", raising=False)
    assert default_path() == Path.home() / ".hound" / "killed.jsonl"


def test_default_path_honors_hound_corpus_override(tmp_path, monkeypatch):
    override = tmp_path / "elsewhere" / "killed.jsonl"
    monkeypatch.setenv("HOUND_CORPUS", str(override))
    assert default_path() == override


def test_append_and_recent_use_the_resolved_default_path(tmp_path, monkeypatch):
    override = tmp_path / "killed.jsonl"
    monkeypatch.setenv("HOUND_CORPUS", str(override))

    append({"title": "t", "location": "l", "root_cause": "r", "reason": "reason"})

    assert override.exists()
    assert "killed by reason" in recent()


def test_corpus_is_one_file_regardless_of_invocation_directory(tmp_path, monkeypatch):
    override = tmp_path / "killed.jsonl"
    monkeypatch.setenv("HOUND_CORPUS", str(override))

    other_cwd = tmp_path / "some" / "other" / "project"
    other_cwd.mkdir(parents=True)
    monkeypatch.chdir(other_cwd)

    append({"title": "t", "location": "l", "root_cause": "r", "reason": "reason"})

    # written to HOUND_CORPUS, not to ./corpus/killed.jsonl under the cwd
    assert override.exists()
    assert not (other_cwd / "corpus").exists()


def test_empty_corpus_renders_empty_string(corpus_path):
    assert recent(path=corpus_path) == ""


def test_append_then_recent_formats_the_expected_string(corpus_path):
    append({"title": "Missing slippage check", "location": "Swap.sol:40", "root_cause": "no minOut", "reason": "acknowledged by team"}, path=corpus_path)
    append({"title": "Reentrancy in claim", "location": "Staking.sol:88", "root_cause": "state after call", "reason": "guarded by nonReentrant, verified"}, path=corpus_path)

    text = recent(path=corpus_path)
    assert text == (
        "- Missing slippage check @ Swap.sol:40 :: killed by acknowledged by team\n"
        "- Reentrancy in claim @ Staking.sol:88 :: killed by guarded by nonReentrant, verified"
    )


def test_recent_respects_n(corpus_path):
    for i in range(5):
        append({"title": f"bug{i}", "location": f"F.sol:{i}", "root_cause": "x", "reason": "x"}, path=corpus_path)
    text = recent(n=2, path=corpus_path)
    assert text.count("\n") == 1
    assert "bug3" in text and "bug4" in text
    assert "bug0" not in text


def test_kill_finding_appends_exactly_one_line(tmp_path, corpus_path):
    findings = [
        {"id": "F001", "title": "Reentrancy", "location": "Vault.sol:10", "root_cause": "state after call"},
        {"id": "F002", "title": "Other bug", "location": "Vault.sol:50", "root_cause": "unrelated"},
    ]
    (tmp_path / "findings.json").write_text(json.dumps(findings))

    entry = kill_finding(tmp_path, "F001", "acknowledged, has an onlyOwner guard", path=corpus_path)

    assert entry == {
        "title": "Reentrancy",
        "location": "Vault.sol:10",
        "root_cause": "state after call",
        "reason": "acknowledged, has an onlyOwner guard",
    }
    lines = corpus_path.read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0]) == entry


def test_kill_finding_twice_appends_two_consistently_formatted_lines(tmp_path, corpus_path):
    findings = [
        {"id": "F001", "title": "Bug A", "location": "A.sol:1", "root_cause": "cause a"},
        {"id": "F002", "title": "Bug B", "location": "B.sol:1", "root_cause": "cause b"},
    ]
    (tmp_path / "findings.json").write_text(json.dumps(findings))

    kill_finding(tmp_path, "F001", "reason a", path=corpus_path)
    kill_finding(tmp_path, "F002", "reason b", path=corpus_path)

    lines = corpus_path.read_text().splitlines()
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert all(set(p.keys()) == {"title", "location", "root_cause", "reason"} for p in parsed)


def test_kill_finding_raises_for_unknown_id(tmp_path, corpus_path):
    (tmp_path / "findings.json").write_text(json.dumps([{"id": "F001", "title": "x", "location": "x", "root_cause": "x"}]))
    with pytest.raises(ValueError):
        kill_finding(tmp_path, "F999", "no such finding", path=corpus_path)
