"""Deterministic gates: location parsing, citation verification, dedup.

Pure functions over data, no LLM calls. These are the checks that stay
trustworthy precisely because a model can't talk them out of a verdict.
"""

import re
from difflib import SequenceMatcher
from pathlib import PurePosixPath

from .schema import SEV_RANK

# path: word chars, dot, slash, hyphen, ending in a "." + extension.
_PATH_RE = r"[\w./-]+\.\w+"
# one line-ref: optional "L" prefix, digits, optional -/– range with another
# optional "L" prefix. A location can list several of these per path, comma-
# separated ("Vault.sol:12,45-50"), and/or cite several different paths.
_LINEREF_RE = r"L?\d+(?:[-–]L?\d+)?"
_CITATION_RE = re.compile(
    rf"(?P<path>{_PATH_RE}):(?P<refs>{_LINEREF_RE}(?:\s*,\s*{_LINEREF_RE})*)"
)
_RANGE_RE = re.compile(r"L?(?P<start>\d+)(?:[-–]L?(?P<end>\d+))?")

MERGE_LINE_TOLERANCE = 8
TITLE_SIMILARITY_THRESHOLD = 0.4
ROOT_CAUSE_SIMILARITY_THRESHOLD = 0.6


def parse_locations(location: str):
    """Parse a Finding.location string into (path, start, end) tuples."""
    results = []
    for m in _CITATION_RE.finditer(location):
        path = m.group("path")
        for ref in m.group("refs").split(","):
            rm = _RANGE_RE.fullmatch(ref.strip())
            if not rm:
                continue
            start = int(rm.group("start"))
            end = int(rm.group("end")) if rm.group("end") else start
            results.append((path, start, end))
    return results


def _norm(path) -> str:
    return str(path).replace("\\", "/")


def _basename(path) -> str:
    return PurePosixPath(_norm(path)).name


def _suffix_match(a: str, b: str) -> bool:
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def _find(path: str, files):
    """Resolve a cited path against loaded Src objects: exact match, then
    unique suffix match, then unique basename. Ambiguous (>1) -> None."""
    target = _norm(path)

    tiers = (
        lambda f: _norm(f.path) == target,
        lambda f: _suffix_match(_norm(f.path), target),
        lambda f: _basename(f.path) == _basename(target),
    )
    for matches_tier in tiers:
        matches = [f for f in files if matches_tier(f)]
        if not matches:
            continue
        return matches[0] if len(matches) == 1 else None
    return None


def spans(location: str, files, expected_hash=None):
    """(src, a, b) for every citation in `location` that resolves to a real
    file and an in-range line span. Everything else is dropped silently.

    `expected_hash` (a sha256 string or a collection of them) is what the file
    hashed to when the hunter read it. If given, a span whose resolved file now
    hashes to something else is STALE and is dropped like any other invalid span:
    the cited line still exists, but it is not the code that was cited. Matching
    is on content, so the same content at a different path still resolves.
    """
    if isinstance(expected_hash, str):
        expected_hash = {expected_hash}
    elif expected_hash is not None:
        expected_hash = set(expected_hash)

    result = []
    for path, a, b in parse_locations(location):
        src = _find(path, files)
        if src is None:
            continue
        if expected_hash and src.sha256 not in expected_hash:
            continue
        if 1 <= a <= b <= len(src.lines):
            result.append((src, a, b))
    return result


def snippets(location: str, files, pad: int = 40, cap: int = 160) -> str:
    """Numbered code windows around each verifiable citation, clamped to file
    bounds and capped at `cap` lines."""
    parts = []
    for src, a, b in spans(location, files):
        lo = max(1, a - pad)
        hi = min(len(src.lines), b + pad)
        if hi - lo + 1 > cap:
            hi = lo + cap - 1
        header = f"// {src.path}:{lo}-{hi}  (cited {a}-{b})"
        parts.append(header + "\n" + src.numbered(lo, hi))
    return "\n\n".join(parts)


def judge_context(location: str, files, budget: int) -> str:
    """Full text of every cited file if it fits `budget`, else snippets().

    The guard that kills a false positive (a modifier, a require in a
    different function, a constant) usually lives outside the +/-40-line
    window, so give the judge the whole file when it's affordable.
    """
    matched = spans(location, files)
    if not matched:
        return ""

    seen_ids = set()
    cited_srcs = []
    for src, _, _ in matched:
        if id(src) not in seen_ids:
            seen_ids.add(id(src))
            cited_srcs.append(src)

    whole = "\n\n".join(
        f"// ===== FILE: {src.path} =====\n{src.numbered(1, len(src.lines))}"
        for src in cited_srcs
    )
    if len(whole) <= budget:
        return whole
    return snippets(location, files)


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def _span_distance(a1: int, b1: int, a2: int, b2: int) -> int:
    if a1 <= b2 and a2 <= b1:
        return 0
    return a2 - b1 if b1 < a2 else a1 - b2


def _spans_close(spans_a, spans_b, tolerance: int = MERGE_LINE_TOLERANCE) -> bool:
    for src_a, a1, b1 in spans_a:
        for src_b, a2, b2 in spans_b:
            if src_a is src_b and _span_distance(a1, b1, a2, b2) <= tolerance:
                return True
    return False


def _should_merge(c: dict, o: dict, files) -> bool:
    if _spans_close(spans(c["location"], files), spans(o["location"], files)):
        if _similarity(c.get("title", ""), o.get("title", "")) > TITLE_SIMILARITY_THRESHOLD:
            return True
    if _similarity(c.get("root_cause", ""), o.get("root_cause", "")) > ROOT_CAUSE_SIMILARITY_THRESHOLD:
        return True
    return False


def dedup(cands, files):
    """Merge candidates describing the same bug; assign ids F001.. in the
    resulting (severity-major) order. `cands` and its dicts are not mutated."""
    ordered = sorted(cands, key=lambda c: SEV_RANK[c["severity"]])

    merged = []
    for c in ordered:
        target = next((o for o in merged if _should_merge(c, o, files)), None)
        if target is not None:
            target["lenses"] = sorted(set(target.get("lenses", [])) | set(c.get("lenses", [])))
            target["votes"] = target.get("votes", 1) + c.get("votes", 1)
        else:
            merged.append(dict(c))

    for i, o in enumerate(merged, start=1):
        o["id"] = f"F{i:03d}"

    return merged
