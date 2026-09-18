"""Codebase loader, scope gate, and chunking for LLM context windows."""

from dataclasses import dataclass
from pathlib import Path

EXTENSIONS = {".sol", ".rs", ".vy", ".move", ".cairo", ".go"}

SKIP_DIR_NAMES = {
    "test", "tests",
    "mock", "mocks",
    "script", "scripts",
    "lib", "node_modules", "target", "out", "cache", "broadcast",
    "artifacts", "fuzz", "benches", ".git",
}


@dataclass
class Src:
    path: Path
    lines: list

    def numbered(self, lo: int, hi: int) -> str:
        out = []
        for n in range(lo, hi + 1):
            if 1 <= n <= len(self.lines):
                out.append(f"{n:>5}| {self.lines[n - 1]}")
        return "\n".join(out)


def _is_in_skip_dir(rel_path: Path) -> bool:
    return any(part in SKIP_DIR_NAMES for part in rel_path.parts[:-1])


def _is_skipped_suffix(name: str) -> bool:
    return name.endswith(".t.sol") or name.endswith(".s.sol")


def _read_lines(path: Path) -> list:
    # errors="replace" so one stray non-UTF-8 byte can't crash a whole scan.
    return path.read_bytes().decode("utf-8", errors="replace").splitlines()


def load(root, scope_globs=None):
    """Walk `root` for in-scope source files.

    Returns (files, refused): `files` are Src objects that passed the
    extension/dir/suffix filters and, if `scope_globs` is given, matched one
    of them. `refused` are candidates that passed those filters but fell
    outside `scope_globs` — they are never read into a Src, never analysed.
    """
    root = Path(root)

    scope_paths = None
    if scope_globs:
        scope_paths = set()
        for pattern in scope_globs:
            scope_paths.update(p.resolve() for p in root.glob(pattern) if p.is_file())

    candidates = sorted(
        (p for p in root.rglob("*") if p.is_file()),
        key=lambda p: str(p.relative_to(root)),
    )

    files = []
    refused = []
    for path in candidates:
        if path.suffix not in EXTENSIONS:
            continue
        rel = path.relative_to(root)
        if _is_in_skip_dir(rel):
            continue
        if _is_skipped_suffix(path.name):
            continue
        if scope_paths is not None and path.resolve() not in scope_paths:
            refused.append(path)
            continue
        files.append(Src(path=path, lines=_read_lines(path)))

    return files, refused


def _file_header(path, lo: int, hi: int) -> str:
    return f"// ===== FILE: {path} (lines {lo}-{hi}) ====="


def _file_units(src: Src, budget_chars: int):
    """One Src -> one or more header-prefixed text units, each <= budget_chars
    where at all possible. A file that fits whole is a single unit; an
    oversized file is split into contiguous, non-overlapping line ranges."""
    n = len(src.lines)
    whole = _file_header(src.path, 1, n) + "\n" + src.numbered(1, n)
    if n == 0 or len(whole) <= budget_chars:
        return [whole]

    units = []
    lo = 1
    while lo <= n:
        hi = lo
        unit = _file_header(src.path, lo, hi) + "\n" + src.numbered(lo, hi)
        while hi + 1 <= n:
            candidate = _file_header(src.path, lo, hi + 1) + "\n" + src.numbered(lo, hi + 1)
            if len(candidate) > budget_chars:
                break
            hi += 1
            unit = candidate
        units.append(unit)
        lo = hi + 1
    return units


def chunk(files, budget_chars: int):
    """Greedy-pack files (in the given order) into blocks of <= budget_chars.
    A whole file is one unit if it fits; an oversized file becomes several
    line-range units. Units are then bin-packed into blocks in order."""
    units = []
    for src in files:
        units.extend(_file_units(src, budget_chars))

    blocks = []
    current = []
    current_len = 0
    for unit in units:
        sep = 2 if current else 0  # "\n\n" between units already in this block
        if current and current_len + sep + len(unit) > budget_chars:
            blocks.append("\n\n".join(current))
            current = [unit]
            current_len = len(unit)
        else:
            current.append(unit)
            current_len += sep + len(unit)
    if current:
        blocks.append("\n\n".join(current))
    return blocks
