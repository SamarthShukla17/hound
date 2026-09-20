"""Codebase loader, scope gate, and chunking for LLM context windows."""

import hashlib
import os
import subprocess
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


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Src:
    path: Path
    lines: list
    # sha256 of the file's raw bytes when loaded from disk. A Src built by hand (tests)
    # falls back to hashing its lines, so it is never empty.
    sha256: str = ""

    def __post_init__(self):
        if not self.sha256:
            self.sha256 = _sha256_bytes("\n".join(self.lines).encode("utf-8", errors="replace"))

    @property
    def n_lines(self) -> int:
        return len(self.lines)

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


def _decode_lines(raw: bytes) -> list:
    # errors="replace" so one stray non-UTF-8 byte can't crash a whole scan.
    return raw.decode("utf-8", errors="replace").splitlines()


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
        raw = path.read_bytes()
        files.append(Src(path=path, lines=_decode_lines(raw), sha256=_sha256_bytes(raw)))

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


# --- provenance -------------------------------------------------------------
# The citation gate proves a cited line EXISTS, not that the file is unchanged since
# the hunter read it. Provenance records what was read so a later stage can tell.


def file_sha256(path) -> str:
    return _sha256_bytes(Path(path).read_bytes())


def _git(root: Path, *args: str):
    try:
        out = subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, text=True, timeout=20
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def git_info(root) -> dict:
    """{"commit", "dirty"} for the repo enclosing `root`, or both None if it isn't one."""
    root = Path(root)
    commit = _git(root, "rev-parse", "HEAD")
    if commit is None:
        return {"commit": None, "dirty": None}
    status = _git(root, "status", "--porcelain", "--", ".")
    return {"commit": commit, "dirty": bool(status)}


def rel_path(root, path) -> str:
    return Path(os.path.relpath(path, root)).as_posix()


def build_provenance(root, files) -> dict:
    """What was read: the target's git commit + dirty flag, and per-file sha256/n_lines."""
    root = Path(root)
    return {
        "target": str(root.resolve()),
        **git_info(root),
        "files": {rel_path(root, f.path): {"sha256": f.sha256, "n_lines": f.n_lines} for f in files},
    }


def check_provenance(provenance: dict) -> list:
    """Compare a recorded provenance block to the working tree. Returns a list of
    human-readable mismatches (empty means the tree still matches what was read)."""
    problems = []
    root = Path(provenance.get("target", "."))
    for rel, meta in (provenance.get("files") or {}).items():
        path = root / rel
        if not path.exists():
            problems.append(f"{rel}: file no longer exists")
        elif file_sha256(path) != meta["sha256"]:
            problems.append(f"{rel}: content changed since it was read")
    recorded = provenance.get("commit")
    if recorded:
        current = git_info(root)["commit"]
        if current and current != recorded:
            problems.append(f"git commit changed: {recorded[:10]} -> {current[:10]}")
    return problems
