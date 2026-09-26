"""Test-coverage gaps as a lead-generation signal.

Theory: code the team's tests never exercise was probably also read less carefully. This is not a
regression check. It turns an lcov report into a ranked list of functions worth a manual read,
saying WHICH branches are unexercised, because that is what a reader needs.

Ranking matters more than listing. In practice most uncovered branches are trivial guards
(zero-address checks, integer-cast overflow checks); the useful ones are state-transition branches
inside state-changing functions that move value. So: trivial guard branches are down-weighted,
state-changing external functions and value-moving bodies are up-weighted.

lcov is the interchange format: `forge coverage --report lcov`, Hardhat's solidity-coverage and
most other tools emit it, so the same code serves any of them. Running forge is one optional
convenience; a precomputed file works everywhere.
"""

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .solfuncs import find_functions

_TRIVIAL_RE = re.compile(
    r"address\s*\(\s*0\s*\)|==\s*0\b|!=\s*0\b|<\s*0\b|>\s*0\b|type\s*\(\s*int256\s*\)|2\s*\*\*\s*255|"
    r"InvalidAddress|InvalidAmount|Overflow|int256\(",
)
_MOVES_VALUE_RE = re.compile(
    r"\.(?:transfer|transferFrom|safeTransfer|safeTransferFrom|call|mint|burn|slip|move|flux|frob|grab|suck|heal|join|exit|kick)\s*\(|"
    r"\b(?:transfer|mint|burn|withdraw|deposit|redeem|liquidate)\w*\s*\(",
)
COVERAGE_TIMEOUT_SECONDS = 900


@dataclass
class Gap:
    file: str
    function: str
    start: int
    end: int
    externally_callable: bool
    state_changing: bool
    moves_value: bool
    lines_total: int
    lines_hit: int
    branches_total: int
    branches_hit: int
    uncovered: list = field(default_factory=list)  # [(line, source text, trivial)]
    score: float = 0.0

    @property
    def loc(self) -> str:
        return f"{self.file}:{self.start}-{self.end}"


def parse_lcov(text: str) -> dict:
    """{source file: {"da": {line: hits}, "br": {line: [taken, ...]}}}. A branch reported as `-`
    (never evaluated) counts as not taken."""
    out, cur = {}, None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("SF:"):
            cur = out.setdefault(line[3:], {"da": {}, "br": {}})
        elif cur is None:
            continue
        elif line.startswith("DA:"):
            ln, hits = line[3:].split(",")[:2]
            cur["da"][int(ln)] = cur["da"].get(int(ln), 0) + int(hits)
        elif line.startswith("BRDA:"):
            ln, _blk, _br, taken = line[5:].split(",")[:4]
            cur["br"].setdefault(int(ln), []).append(0 if taken == "-" else int(taken))
        elif line == "end_of_record":
            cur = None
    return out


def _is_guard(lines: list, ln: int) -> bool:
    """A branch line is guard-shaped when the statement it opens (this line and the next two) reverts."""
    window = " ".join(lines[ln - 1: ln + 2]) if 0 < ln <= len(lines) else ""
    return bool(re.search(r"\b_?revert\s*\(|\brequire\s*\(|\bthrow\b", window))


def _score(g: Gap, has_assembly: bool = False, is_config_setter: bool = False) -> float:
    base = sum(0.5 if trivial else 3.0 for _l, _t, trivial in g.uncovered)
    if g.lines_total and g.lines_hit == 0:
        base += 5  # the team's tests never enter this function at all
    if g.state_changing and g.externally_callable:
        base *= 1.5
    if g.moves_value:
        base *= 1.3
    if not g.state_changing:
        base *= 0.3  # an unexercised getter is rarely where a bug lives
    if has_assembly:
        base *= 0.3  # coverage tools cannot instrument inline assembly: 0 hits is an artifact, not a gap
    if is_config_setter:
        base *= 0.6  # file()/set*() parameter branches: worth a look, rarely the bug
    return round(base, 2)


def function_gaps(sources: dict, lcov: dict) -> list:
    """Per-function gaps for every function with executable code. `sources` = {path: text} using
    the same paths as the lcov `SF:` entries (matched by suffix so a leading directory is tolerated)."""
    gaps = []
    for path, text in sources.items():
        record = next((v for k, v in lcov.items() if k == path or k.endswith("/" + path) or path.endswith("/" + k)), None)
        if record is None:
            continue
        lines = text.split("\n")
        for f in find_functions(text):
            if f.kind in ("modifier", "constructor") or not f.has_body:
                continue
            rng = range(f.start_line, f.end_line + 1)
            da = {ln: h for ln, h in record["da"].items() if ln in rng}
            br = {ln: t for ln, t in record["br"].items() if ln in rng}
            total_b = sum(len(t) for t in br.values())
            hit_b = sum(1 for t in br.values() for x in t if x > 0)
            uncovered = []
            for ln in sorted(br):
                misses = sum(1 for x in br[ln] if x == 0)
                if misses:
                    src = lines[ln - 1].strip() if 0 < ln <= len(lines) else ""
                    # trivial only if it is BOTH guard-shaped and a zero/address/cast check: `if (lot == 0)`
                    # that drives a state transition must not be filed as a trivial zero-check
                    uncovered.append((ln, src, _is_guard(lines, ln) and bool(_TRIVIAL_RE.search(src))))
            g = Gap(
                file=path, function=f"{f.contract}.{f.name or f.kind}", start=f.start_line, end=f.end_line,
                externally_callable=f.externally_callable(), state_changing=f.state_changing(),
                moves_value=bool(_MOVES_VALUE_RE.search(f.body)), lines_total=len(da),
                lines_hit=sum(1 for h in da.values() if h > 0), branches_total=total_b, branches_hit=hit_b,
                uncovered=uncovered,
            )
            g.score = _score(g, has_assembly=bool(re.search(r"\bassembly\b", f.body)),
                             is_config_setter=f.name == "file" or f.name.startswith("set"))
            if g.score > 0:
                gaps.append(g)
    return sorted(gaps, key=lambda g: -g.score)


def run_forge_coverage(root, out_file, runner=subprocess.run) -> tuple:
    """(lcov path or None, message). Never raises: a target whose tests do not run simply has no signal."""
    root = Path(root)
    if not (root / "foundry.toml").is_file():
        return None, "no foundry.toml (pass a precomputed lcov file with --coverage FILE)"
    if runner is subprocess.run and shutil.which("forge") is None:
        return None, "forge is not installed"
    cmd = ["forge", "coverage", "--ir-minimum", "--report", "lcov", "--report-file", str(out_file)]
    try:
        proc = runner(cmd, cwd=str(root), capture_output=True, text=True, timeout=COVERAGE_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"forge coverage did not complete: {exc}"
    if getattr(proc, "returncode", 1) != 0 or not Path(out_file).is_file():
        tail = (getattr(proc, "stderr", "") or getattr(proc, "stdout", "") or "").strip().splitlines()[-1:]
        return None, f"forge coverage failed ({tail[0][:120] if tail else 'no output'})"
    return Path(out_file), "ok"


def render(gaps: list, top: int = 30) -> str:
    lines = ["# Test-coverage gaps (leads, not findings)", "",
             "Functions whose branches the team's own tests never exercise, ranked. Trivial guard branches "
             "(zero-address, int-cast) are down-weighted; `*` marks a trivial guard.", ""]
    for g in gaps[:top]:
        flags = ", ".join(x for x, on in (("external", g.externally_callable), ("state-changing", g.state_changing),
                                          ("moves value", g.moves_value)) if on)
        lines += [f"## {g.function}  (score {g.score})", f"- {g.loc} | {flags}",
                  f"- lines {g.lines_hit}/{g.lines_total}, branches {g.branches_hit}/{g.branches_total}"]
        lines += [f"  - L{ln}{'*' if trivial else ''}: `{txt[:110]}`" for ln, txt, trivial in g.uncovered[:8]]
        lines.append("")
    if not gaps:
        lines.append("_no uncovered branches in functions with executable code_")
    return "\n".join(lines) + "\n"


def hunter_notes(gaps: list, top: int = 8, cap: int = 2800) -> str:
    rows = []
    for g in gaps[:top]:
        real = [f"L{ln} `{txt[:70]}`" for ln, txt, trivial in g.uncovered if not trivial][:3]
        if real:
            rows.append(f"- {g.function} ({g.loc}): branches {g.branches_hit}/{g.branches_total}; unexercised: " + "; ".join(real))
    if not rows:
        return ""
    return ("LOW TEST COVERAGE (the team's tests never exercise these branches - low team scrutiny is likely; read each as "
            "carefully as if it were flagged):\n" + "\n".join(rows))[:cap]


def analyse(target_root, files, *, spec: str = "auto", runner=subprocess.run) -> tuple:
    """(gaps, message). spec: 'auto' (run forge when it is a foundry project), or a path to an lcov file."""
    from .codebase import rel_path

    root = Path(target_root)
    sources = {rel_path(root, f.path): "\n".join(f.lines) for f in files}
    if spec not in ("auto", "off"):
        p = Path(spec)
        if not p.is_file():
            return [], f"lcov file not found: {spec}"
        lcov_path, msg = p, "ok"
    else:
        lcov_path, msg = run_forge_coverage(root, root / ".hound_cache" / "coverage.lcov", runner)
        if lcov_path is None:
            return [], msg
    lcov = parse_lcov(Path(lcov_path).read_text(encoding="utf-8", errors="replace"))
    return function_gaps(sources, lcov), msg


def write_artifacts(run_dir, gaps: list) -> None:
    import json

    run_dir = Path(run_dir)
    (run_dir / "coverage_gaps.md").write_text(render(gaps))
    (run_dir / "coverage_gaps.json").write_text(json.dumps(
        [{"function": g.function, "loc": g.loc, "score": g.score, "lines": [g.lines_hit, g.lines_total],
          "branches": [g.branches_hit, g.branches_total],
          "uncovered": [{"line": ln, "text": t, "trivial": tr} for ln, t, tr in g.uncovered]} for g in gaps], indent=2))


async def coverage_command(args) -> int:
    """`hound coverage TARGET [--lcov FILE]`: the gap report on its own."""
    from datetime import datetime

    from .codebase import load
    from .pipeline import _read_scope_globs

    files, _ = load(args.target, _read_scope_globs(args.scope))
    gaps, msg = analyse(args.target, files, spec=args.lcov or "auto")
    if not gaps and msg != "ok":
        print(f"no coverage signal: {msg}")
        return 1
    out = Path(args.out) / datetime.now().strftime("coverage-%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    write_artifacts(out, gaps)
    print(f"{len(gaps)} functions with unexercised branches; top: " + ", ".join(g.function for g in gaps[:5]))
    print(f"wrote {out}")
    return 0
