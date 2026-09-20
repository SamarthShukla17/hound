"""Step 4: file loading, scope gate, and chunking."""

import re

import pytest

import hashlib
import subprocess

from hound.codebase import Src, build_provenance, check_provenance, chunk, file_sha256, git_info, load


@pytest.fixture
def fixture_repo(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "test").mkdir()
    (tmp_path / "script").mkdir()
    (tmp_path / "lib" / "oz").mkdir(parents=True)
    (tmp_path / "node_modules" / "foo").mkdir(parents=True)
    (tmp_path / "programs").mkdir()

    (tmp_path / "src" / "Vault.sol").write_text("contract Vault {}\n")
    (tmp_path / "src" / "Token.sol").write_text("contract Token {}\n")
    (tmp_path / "test" / "VaultTest.t.sol").write_text("contract VaultTest {}\n")
    (tmp_path / "script" / "Deploy.s.sol").write_text("contract Deploy {}\n")
    (tmp_path / "lib" / "oz" / "ERC20.sol").write_text("contract ERC20 {}\n")
    (tmp_path / "node_modules" / "foo" / "bar.sol").write_text("contract Bar {}\n")
    (tmp_path / "README.md").write_text("not source\n")
    (tmp_path / "programs" / "lib.rs").write_text("fn main() {}\n")
    # a stray non-UTF-8 byte must not crash the scan
    (tmp_path / "src" / "Weird.sol").write_bytes(b"contract Weird { \xff } \n")

    return tmp_path


def _relnames(paths, root):
    return sorted(str(p.relative_to(root)) for p in paths)


def test_skip_dirs_are_never_loaded_or_refused(fixture_repo):
    files, refused = load(fixture_repo)
    all_paths = [f.path for f in files] + refused
    names = _relnames(all_paths, fixture_repo)
    assert not any(n.startswith(("test/", "script/", "lib/", "node_modules/")) for n in names)


def test_load_picks_up_in_scope_extensions(fixture_repo):
    files, refused = load(fixture_repo)
    assert _relnames([f.path for f in files], fixture_repo) == [
        "programs/lib.rs",
        "src/Token.sol",
        "src/Vault.sol",
        "src/Weird.sol",
    ]
    assert refused == []


def test_scope_gate_refuses_out_of_scope_files(fixture_repo):
    files, refused = load(fixture_repo, scope_globs=["src/**/*.sol"])
    assert _relnames([f.path for f in files], fixture_repo) == [
        "src/Token.sol",
        "src/Vault.sol",
        "src/Weird.sol",
    ]
    assert _relnames(refused, fixture_repo) == ["programs/lib.rs"]


def test_stray_non_utf8_byte_is_replaced_not_crashed(fixture_repo):
    files, _ = load(fixture_repo)
    weird = next(f for f in files if f.path.name == "Weird.sol")
    assert "�" in weird.lines[0]


def test_numbered_line_numbers_match_true_1_based_file_lines():
    lines = [f"stmt_{i}" for i in range(1, 51)]
    src = Src(path="Vault.sol", lines=lines)

    text = src.numbered(1, len(lines))
    for formatted_line in text.splitlines():
        num_str, _, content = formatted_line.partition("| ")
        n = int(num_str.strip())
        assert content == lines[n - 1]

    # an arbitrary sub-range too
    sub = src.numbered(10, 12)
    assert sub.splitlines() == [
        "   10| stmt_10",
        "   11| stmt_11",
        "   12| stmt_12",
    ]


def test_oversized_file_is_split_with_continuous_line_numbers():
    lines = [f"x = {i};" for i in range(1, 301)]
    src = Src(path="Big.rs", lines=lines)

    blocks = chunk([src], budget_chars=500)
    assert len(blocks) > 1
    assert all(len(block) <= 500 for block in blocks)

    seen = []
    for block in blocks:
        seen.extend(int(m.group(1)) for m in re.finditer(r"^\s*(\d+)\|", block, re.MULTILINE))
    assert seen == list(range(1, 301))


def test_whole_small_files_are_greedy_packed_together():
    files = [
        Src(path="A.sol", lines=["a"]),
        Src(path="B.sol", lines=["b"]),
        Src(path="C.sol", lines=["c"]),
    ]
    assert len(chunk(files, budget_chars=10_000)) == 1
    assert len(chunk(files, budget_chars=1)) == 3  # too small to combine any two


# --- provenance -------------------------------------------------------------------------


def test_load_records_the_sha256_of_the_raw_file_bytes(fixture_repo):
    files, _ = load(fixture_repo)
    vault = next(f for f in files if f.path.name == "Vault.sol")
    assert vault.sha256 == hashlib.sha256((fixture_repo / "src" / "Vault.sol").read_bytes()).hexdigest()
    assert vault.n_lines == 1


def test_a_hand_built_src_still_gets_a_deterministic_hash():
    a = Src(path="a.sol", lines=["x", "y"])
    assert a.sha256 == Src(path="elsewhere/b.sol", lines=["x", "y"]).sha256  # content, not path
    assert a.sha256 != Src(path="a.sol", lines=["x", "z"]).sha256


def test_build_provenance_lists_every_file_with_hash_and_line_count(fixture_repo):
    files, _ = load(fixture_repo)
    prov = build_provenance(fixture_repo, files)
    assert prov["files"]["src/Vault.sol"] == {"sha256": file_sha256(fixture_repo / "src" / "Vault.sol"), "n_lines": 1}
    assert prov["commit"] is None and prov["dirty"] is None  # tmp_path is not a git repo


def test_check_provenance_is_clean_then_flags_an_edit_and_a_deletion(fixture_repo):
    files, _ = load(fixture_repo)
    prov = build_provenance(fixture_repo, files)
    assert check_provenance(prov) == []

    (fixture_repo / "src" / "Vault.sol").write_text("contract Vault { /* edited */ }\n")
    (fixture_repo / "src" / "Token.sol").unlink()
    problems = check_provenance(prov)
    assert "src/Vault.sol: content changed since it was read" in problems
    assert "src/Token.sol: file no longer exists" in problems


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *args],
                   check=True, capture_output=True)


def test_git_info_reports_commit_and_dirty_flag(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "A.sol").write_text("contract A {}\n")
    _git(repo, "init", "-q")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")

    clean = git_info(repo)
    assert len(clean["commit"]) == 40 and clean["dirty"] is False

    (repo / "A.sol").write_text("contract A { uint x; }\n")
    assert git_info(repo)["dirty"] is True


def test_check_provenance_flags_a_moved_git_commit(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "A.sol").write_text("contract A {}\n")
    _git(repo, "init", "-q")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "one")
    files, _ = load(repo)
    prov = build_provenance(repo, files)

    (repo / "B.sol").write_text("contract B {}\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "two")
    assert any(p.startswith("git commit changed") for p in check_provenance(prov))
