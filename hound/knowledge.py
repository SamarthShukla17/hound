"""Parse kb/*.md (METHODOLOGY, ATTACK_ANGLES, BUG_PATTERNS) into Lens objects.

Lenses are never hardcoded: every hunter prompt is built from what's parsed
out of the kb markdown at runtime, so editing the kb files changes the audit
without touching code.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path

_FENCE_RE = re.compile(r"```[a-zA-Z0-9]*\n(.*?)```", re.DOTALL)
_TRAILING_DASHES_RE = re.compile(r"\n?-{3,}\s*\Z")

_NUMBERED_BOLD_RE = re.compile(
    r"^(?P<num>\d+)\.\s+\*\*(?P<title>.+?)\*\*\s*—\s*(?P<body>.+?)(?=\n\d+\.\s+\*\*|\Z)",
    re.MULTILINE | re.DOTALL,
)
_ANGLE_HEADING_RE = re.compile(r"^Angle\s+(?P<num>\d+)\s*[—-]\s*(?P<title>.+)$")
_PATTERN_HEADING_RE = re.compile(r"^Pattern\s+(?P<num>\d+)\s*[—-]\s*(?P<title>.+)$")
_TRAILING_PATTERN_RE = re.compile(
    r"^Pattern:\s*(?P<title>[^\n—]+?)\s*—\s*(?P<body>.+?)(?=\n\s*\n|\Z)",
    re.MULTILINE | re.DOTALL,
)


@dataclass
class Lens:
    id: str
    kind: str  # "angle" | "pattern" | "class"
    title: str
    body: str
    poc: str = ""


@dataclass
class KB:
    principles: str
    lenses: list = field(default_factory=list)


def _find_file(directory: Path, name: str) -> Path:
    matches = sorted(directory.rglob(name))
    if not matches:
        raise FileNotFoundError(f"{name} not found under {directory}")
    return matches[0]


def _clean_body(text: str) -> str:
    """Strip surrounding whitespace and a trailing '---' divider left over
    from slicing right up to the next '## ' heading."""
    text = text.strip()
    text = _TRAILING_DASHES_RE.sub("", text)
    return text.strip()


def _h2_sections(text: str):
    """Split markdown into (heading, body) pairs on top-level '## ' headings."""
    heading_re = re.compile(r"^## (.+)$", re.MULTILINE)
    matches = list(heading_re.finditer(text))
    sections = []
    for i, m in enumerate(matches):
        heading = m.group(1).strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        sections.append((heading, text[start:end]))
    return sections


def _extract_poc(body: str) -> tuple[str, str]:
    """Pull ``` fenced code blocks out of body; return (body_without_code, poc)."""
    poc = "\n\n".join(m.strip() for m in _FENCE_RE.findall(body))
    body_without_code = _FENCE_RE.sub("", body)
    return _clean_body(body_without_code), poc


def _parse_methodology(text: str):
    """Section '## 0.' body -> principles; '## 2.' numbered bold items -> C1..C6."""
    principles = ""
    class_lenses = []
    for heading, body in _h2_sections(text):
        if heading.startswith("0."):
            principles = _clean_body(body)
        elif heading.startswith("2."):
            for m in _NUMBERED_BOLD_RE.finditer(body):
                class_lenses.append(
                    Lens(
                        id=f"C{m.group('num')}",
                        kind="class",
                        title=m.group("title").strip(),
                        body=_clean_body(m.group("body")),
                    )
                )
    return principles, class_lenses


def _parse_angles(text: str):
    """'## Angle N — Title' headings -> A1..A7. Non-angle H2s are ignored."""
    lenses = []
    for heading, body in _h2_sections(text):
        m = _ANGLE_HEADING_RE.match(heading)
        if not m:
            continue
        lenses.append(
            Lens(
                id=f"A{m.group('num')}",
                kind="angle",
                title=m.group("title").strip(),
                body=_clean_body(body),
            )
        )
    return lenses


def _parse_patterns(text: str):
    """'## Pattern N — Title' headings -> P1..Pn, plus trailing 'Pattern: X — ...'
    paragraphs (not headings) as extra patterns numbered after the last one."""
    lenses = []
    max_num = 0
    for heading, body in _h2_sections(text):
        m = _PATTERN_HEADING_RE.match(heading)
        if not m:
            continue
        num = int(m.group("num"))
        max_num = max(max_num, num)
        clean_body, poc = _extract_poc(body)
        lenses.append(
            Lens(id=f"P{num}", kind="pattern", title=m.group("title").strip(), body=clean_body, poc=poc)
        )

    for m in _TRAILING_PATTERN_RE.finditer(text):
        max_num += 1
        clean_body, poc = _extract_poc(m.group("body"))
        lenses.append(
            Lens(id=f"P{max_num}", kind="pattern", title=m.group("title").strip(), body=clean_body, poc=poc)
        )

    return lenses


def load_kb(directory) -> KB:
    directory = Path(directory)
    methodology_text = _find_file(directory, "METHODOLOGY.md").read_text(encoding="utf-8")
    angles_text = _find_file(directory, "ATTACK_ANGLES.md").read_text(encoding="utf-8")
    patterns_text = _find_file(directory, "BUG_PATTERNS.md").read_text(encoding="utf-8")

    principles, class_lenses = _parse_methodology(methodology_text)
    angle_lenses = _parse_angles(angles_text)
    pattern_lenses = _parse_patterns(patterns_text)

    return KB(principles=principles, lenses=[*class_lenses, *angle_lenses, *pattern_lenses])


def load_doc(directory, name: str, required: bool = False) -> str:
    """Text of a standalone kb document (e.g. DEVIATION_REVIEW.md). These are prompt material for
    a specific feature, not lenses, so they are returned whole. Missing -> '' unless required."""
    try:
        return _find_file(Path(directory), name).read_text(encoding="utf-8")
    except FileNotFoundError:
        if required:
            raise
        return ""


def select(lenses, spec: str):
    """"all" | kinds "A,P" | ids "A1,P4". A single-letter token selects a kind
    prefix (all ids starting with that letter); anything else must match an
    exact lens id. Order follows `lenses`, duplicates are dropped."""
    spec = spec.strip()
    if spec.lower() == "all":
        return list(lenses)

    tokens = [t.strip() for t in spec.split(",") if t.strip()]
    seen = set()
    result = []
    for token in tokens:
        if len(token) == 1:
            matches = (l for l in lenses if l.id.startswith(token))
        else:
            matches = (l for l in lenses if l.id == token)
        for lens in matches:
            if lens.id not in seen:
                seen.add(lens.id)
                result.append(lens)
    return result


def poc_refs(lenses) -> str:
    """Joined PoC skeletons for every lens in `lenses` that has one."""
    parts = [f"# {lens.id} — {lens.title}\n{lens.poc}" for lens in lenses if lens.poc]
    return "\n\n".join(parts)
