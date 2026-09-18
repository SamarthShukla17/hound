"""Step 4: file loading, scope gate, and chunking."""

import re

import pytest

from hound.codebase import Src, chunk, load


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
