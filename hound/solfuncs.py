"""Minimal Solidity structure extraction: contracts, functions (with exact line ranges) and
state variables.

Three features share this primitive and must agree on it: the upstream diff (function bodies),
the coverage-gap signal (which function does an uncovered line belong to) and the finding
chainer (which state variables does a function touch). It is deliberately not a parser: it
masks comments and string literals, matches braces, and reads headers. That is enough to cut
a file into functions with correct line numbers, which is all any of them need.
"""

import re
from dataclasses import dataclass, field

_CONTRACT_RE = re.compile(r"\b(contract|library|interface|abstract\s+contract)\s+([A-Za-z_]\w*)")
_FUNC_RE = re.compile(r"\b(function|constructor|modifier|fallback|receive)\b\s*([A-Za-z_]\w*)?\s*\(")
_VISIBILITY = ("external", "public", "internal", "private")
_MUTABILITY = ("view", "pure", "payable")
_STATE_VAR_RE = re.compile(
    r"^\s*(?P<type>mapping\s*\(.*?\)|[A-Za-z_][\w.]*(?:\[[^\]]*\])*)\s+"
    r"(?P<mods>(?:public|private|internal|immutable|constant|override)\s+)*"
    r"(?P<name>[A-Za-z_]\w*)\s*(?:=[^;]*)?;",
    re.MULTILINE | re.DOTALL,
)
_NOT_A_TYPE = {"return", "emit", "using", "import", "pragma", "event", "error", "struct", "enum", "delete", "revert"}


@dataclass
class SolFunc:
    contract: str
    kind: str  # function | constructor | modifier | fallback | receive
    name: str
    header: str  # everything from the keyword up to (not including) the opening brace or ';'
    params: str
    visibility: str
    mutability: str
    start_line: int  # 1-based, inclusive
    end_line: int
    body: str  # text between the braces ('' for a declaration without a body)
    has_body: bool = True
    modifiers: list = field(default_factory=list)
    body_line: int = 0  # 1-based line of the opening brace; body text starts on this line

    @property
    def key(self) -> str:
        return f"{self.contract}.{self.name or self.kind}"

    def state_changing(self) -> bool:
        return self.kind != "modifier" and self.mutability not in ("view", "pure")

    def externally_callable(self) -> bool:
        return self.visibility in ("external", "public") or self.kind in ("constructor", "fallback", "receive")


def mask(source: str) -> str:
    """Replace comments and string-literal contents with spaces, keeping every newline and every
    character position, so offsets and line numbers still match the original file."""
    out = []
    i, n = 0, len(source)
    while i < n:
        c = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = source.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
        elif c == "/" and nxt == "*":
            j = source.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append("".join("\n" if ch == "\n" else " " for ch in source[i:j]))
            i = j
        elif c in ('"', "'"):
            j = i + 1
            while j < n and source[j] != c and source[j] != "\n":
                j += 2 if source[j] == "\\" else 1
            closed = j < n and source[j] == c
            end = j + 1 if closed else j
            # keep the quotes, blank the contents (no newline can be inside a Solidity string)
            out.append(c + " " * max(end - i - (2 if closed else 1), 0) + (c if closed else ""))
            i = end
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _line_of(offsets: list, pos: int) -> int:
    """1-based line number of character offset `pos` (binary search over line-start offsets)."""
    lo, hi = 0, len(offsets)
    while lo < hi:
        mid = (lo + hi) // 2
        if offsets[mid] <= pos:
            lo = mid + 1
        else:
            hi = mid
    return lo


def _line_starts(text: str) -> list:
    starts = [0]
    for m in re.finditer("\n", text):
        starts.append(m.end())
    return starts


def _match_brace(text: str, open_pos: int) -> int:
    """Offset of the '}' matching the '{' at open_pos (or len(text) if unbalanced)."""
    depth = 0
    for i in range(open_pos, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(text)


def _header_end(text: str, start: int):
    """Position of the '{' or ';' that ends a function header, skipping parenthesised groups."""
    depth = 0
    for i in range(start, len(text)):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif depth == 0 and c in "{;":
            return i, c
    return len(text), ";"


_NOT_MODIFIERS = set(_VISIBILITY + _MUTABILITY) | {"returns", "override", "virtual", "memory", "storage", "calldata"}


def _header_modifiers(tail: str) -> list:
    """Modifier invocations in a function header tail, arguments kept: `onlyRole(_WARD_ROLE)`,
    `isStopped(3)`, `nonReentrant`. The returns(...) clause is dropped first."""
    m = re.search(r"\breturns\s*\(", tail)
    if m:
        depth, j = 0, m.end() - 1
        while j < len(tail):
            depth += tail[j] == "("
            depth -= tail[j] == ")"
            if depth == 0:
                break
            j += 1
        tail = tail[:m.start()] + " " + tail[j + 1:]
    mods = []
    for mm in re.finditer(r"([A-Za-z_]\w*)\s*(\([^()]*\))?", tail):
        if mm.group(1) not in _NOT_MODIFIERS:
            mods.append(mm.group(1) + ("".join(mm.group(2).split()) if mm.group(2) else ""))
    return mods


def contracts(source: str) -> list:
    """[(kind, name, body_start, body_end)] for every top-level contract/library/interface."""
    text = mask(source)
    found = []
    pos = 0
    while True:
        m = _CONTRACT_RE.search(text, pos)
        if not m:
            break
        brace = text.find("{", m.end())
        if brace == -1:
            break
        end = _match_brace(text, brace)
        found.append((m.group(1).split()[-1], m.group(2), brace + 1, end))
        pos = end + 1
    return found


def find_functions(source: str) -> list:
    """Every function, constructor, modifier, fallback and receive with exact line ranges."""
    text = mask(source)
    starts = _line_starts(text)
    result = []
    for kind_c, cname, bstart, bend in contracts(source):
        pos = bstart
        while pos < bend:
            m = _FUNC_RE.search(text, pos, bend)
            if not m:
                break
            hend, terminator = _header_end(text, m.end() - 1)
            header = text[m.start():hend].strip()
            has_body = terminator == "{"
            end = _match_brace(text, hend) if has_body else hend
            kw = m.group(1)
            name = m.group(2) or ""
            params_open = m.end() - 1
            depth, k = 0, params_open
            while k < len(text):
                if text[k] == "(":
                    depth += 1
                elif text[k] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            params = " ".join(text[params_open + 1:k].split())
            tail = text[k + 1:hend]
            words = re.findall(r"[A-Za-z_]\w*", tail)
            vis = next((w for w in words if w in _VISIBILITY), "public" if kw == "function" else "")
            mut = next((w for w in words if w in _MUTABILITY), "")
            mods = _header_modifiers(tail)
            result.append(
                SolFunc(
                    contract=cname, kind=kw, name=name, header=" ".join(header.split()), params=params,
                    visibility=vis, mutability=mut, start_line=_line_of(starts, m.start()),
                    end_line=_line_of(starts, end), body=source[hend + 1:end] if has_body else "",
                    has_body=has_body, modifiers=mods, body_line=_line_of(starts, hend),
                )
            )
            pos = end + 1
    return result


def state_variables(source: str) -> set:
    """Names of contract-level storage variables (depth 1, outside any function body)."""
    text = mask(source)
    names = set()
    for _kind, _cname, bstart, bend in contracts(source):
        depth = 0
        chars = []
        for i in range(bstart, bend):  # blank out everything nested deeper than the contract body
            c = text[i]
            if c == "{":
                depth += 1
                chars.append(" ")
            elif c == "}":
                depth -= 1
                chars.append(" ")
            else:
                chars.append(c if depth == 0 or c == "\n" else " ")
        flat = "".join(chars)
        for m in _STATE_VAR_RE.finditer(flat):
            first = m.group("type").split()[0]
            if first in _NOT_A_TYPE or m.group("name") in _NOT_A_TYPE:
                continue
            names.add(m.group("name"))
    return names


def touched_state(func: SolFunc, state_vars: set) -> set:
    """Which of `state_vars` the function body (or its header modifiers) mentions."""
    haystack = mask(func.body) + " " + " ".join(func.modifiers)
    return {v for v in state_vars if re.search(rf"\b{re.escape(v)}\b", haystack)}


def function_at(funcs: list, line: int):
    """The function whose line range contains `line` (innermost = smallest range), else None."""
    hits = [f for f in funcs if f.start_line <= line <= f.end_line]
    return min(hits, key=lambda f: f.end_line - f.start_line) if hits else None
