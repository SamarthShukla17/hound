"""Literal statement-level diff between a fork and its upstream.

Why statements and not text: a fork renames everything (vat -> VAULT_ENGINE, `require` -> `if ...
revert`, `_add(a, b)` -> `a + b`), so a text diff is all noise. This module reduces each function
to a list of statement SKELETONS: identifiers become ID, literals become NUM/STR, and every guard
(require, or `if (c) revert`) is rewritten to the same "must hold" form, so `require(a <= b)` and
`if (a > b) revert` compare equal. What is left after that is a real difference: a flipped
comparison, a reordered multiply/divide (rounding direction), a dropped guard, a changed call.

The output is a set of candidate deviations for review, never a verdict: whether a difference is
cosmetic or a bug is for the reviewer (deviation_review.py) to decide, with both bodies in hand.
"""

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from .solfuncs import SolFunc, find_functions, mask

# how much a kind of difference matters when ranking pairs for review
KIND_WEIGHT = {
    "guard-removed": 5, "comparator": 5, "arith-order": 4, "guard-changed": 4, "guard-replaced": 3,
    "call": 3, "removed": 3, "guard-added": 2, "added": 1, "other": 1, "modifier": 4,
}

_TYPE_DECL_RE = re.compile(r"\b(?:uint\d*|int\d*|bytes\d*|bool|address|string)\b(?:\s+(?:memory|storage|calldata))?(?=\s+[A-Za-z_]\w*\s*=)")
_NOISE_WORDS_RE = re.compile(r"\b(?:unchecked|memory|storage|calldata|payable|view|pure)\b")
_TOKEN_RE = re.compile(r"0x[0-9a-fA-F]+|\d[\w.]*|[A-Za-z_]\w*|\*\*|<<|>>|<=|>=|==|!=|&&|\|\||[-+*/%<>=!&|^~?:,.;(){}\[\]]")
_CONST_RE = re.compile(r"^_*[A-Z][A-Z0-9_]+$")
_KEEP_MEMBERS = {"msg", "block", "tx"}
_COMPARATORS = ("<=", ">=", "==", "!=", "<", ">")
_FLIP = {"<=": ">", ">=": "<", "==": "!=", "!=": "==", "<": ">=", ">": "<="}
_ARITH = ("**", "+", "-", "*", "/", "%")
_REVERT_ONLY_RE = re.compile(r"^\s*(?:_?revert\b[^;]*|_revert\s*\([^;]*)\s*;?\s*$")


@dataclass
class Stmt:
    text: str
    skeleton: str
    kind: str  # guard | if | loop | ret | asm | revert | stmt
    line: int
    calls: list = field(default_factory=list)  # member-call names in order (.foo( ...)
    comps: list = field(default_factory=list)
    ops: list = field(default_factory=list)


@dataclass
class StmtDiff:
    kinds: list
    priority: int
    upstream: str  # original text ('' when the statement only exists in the target)
    target: str
    upstream_line: int = 0
    target_line: int = 0


@dataclass
class FunctionPair:
    target: SolFunc
    target_file: str
    upstream: SolFunc
    upstream_file: str
    similarity: float
    diffs: list
    cross_contract: bool = False

    @property
    def priority(self) -> int:
        if not self.diffs:
            return 0
        return max(d.priority for d in self.diffs) * 10 + min(len(self.diffs), 9)


# ----------------------------------------------------------------- skeletons


def _split_top(s: str, sep: str) -> list:
    """Split on `sep` at bracket depth 0."""
    parts, depth, cur, i = [], 0, [], 0
    while i < len(s):
        c = s[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if depth == 0 and s.startswith(sep, i):
            parts.append("".join(cur).strip())
            cur = []
            i += len(sep)
            continue
        cur.append(c)
        i += 1
    parts.append("".join(cur).strip())
    return parts


def _strip_outer_parens(s: str) -> str:
    s = s.strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        for i, c in enumerate(s):
            depth += c == "("
            depth -= c == ")"
            if depth == 0 and i < len(s) - 1:
                return s
        s = s[1:-1].strip()
    return s


def _top_comparators(s: str) -> list:
    """[(index, op)] of comparison operators at depth 0 (ignoring << and >>)."""
    found, depth, i = [], 0, 0
    while i < len(s):
        c = s[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0:
            two = s[i:i + 2]
            if two in ("<<", ">>"):
                i += 2
                continue
            for op in ("<=", ">=", "==", "!=", "<", ">"):
                if s.startswith(op, i):
                    found.append((i, op))
                    i += len(op) - 1
                    break
        i += 1
    return found


def negate(skel: str) -> str:
    """Logical negation of a condition skeleton, pushed inward so `!(a > b)` and `a <= b` agree."""
    s = _strip_outer_parens(skel)
    ors = _split_top(s, "||")
    if len(ors) > 1:
        return " && ".join(negate(p) for p in ors)
    ands = _split_top(s, "&&")
    if len(ands) > 1:
        return " || ".join(negate(p) for p in ands)
    if s.startswith("!") and not s.startswith("!="):
        return _strip_outer_parens(s[1:].strip())
    comps = _top_comparators(s)
    if len(comps) == 1:
        idx, op = comps[0]
        return f"{s[:idx].strip()} {_FLIP[op]} {s[idx + len(op):].strip()}"
    return f"! ( {s} )"


_LIB_CALL_RE = re.compile(r"\b[A-Z][a-z][A-Za-z0-9]*\s*\.\s*([A-Za-z_]\w*)\s*\(")


def _strip_lib_calls(text: str) -> str:
    """`Math.add(x, y)` / `SafeERC20.safeTransfer(...)` are helper calls on a library, not external
    calls on another contract: normalise them to a plain `add(x, y)` so `_add(x, y)` in the upstream
    and `Math.add(x, y)` in the fork compare equal. ALLCAPS receivers (VAULT_ENGINE.slip) are
    contract instances and stay external calls."""
    return _LIB_CALL_RE.sub(r"\1(", text)


def _expand_bool_helpers(text: str) -> str:
    """Maker's `either(a, b)` / `both(a, b)` are `||` / `&&` in disguise; expand them (innermost
    first) so a fork that wrote the operators compares equal."""
    while True:
        m = re.search(r"\b(either|both)\s*\(", text)
        if not m:
            return text
        inner, after = _read_parens(text, m.end() - 1)
        args = _split_top(inner, ",")
        if len(args) != 2:
            return text[:m.start()] + "BOOLHELPER" + text[after:]
        op = "||" if m.group(1) == "either" else "&&"
        text = f"{text[:m.start()]}(({args[0]}) {op} ({args[1]})){text[after:]}"


_MATH_OPS = {"add": "+", "sub": "-", "mul": "*", "umul": "*"}


def _expand_math_helpers(text: str) -> str:
    """Safe-math helpers are operators: `_add(x, y)`, `Math.add(x, y)` and `x + y` are one thing.
    Only the plain two-argument arithmetic ones; rmul/wmul/rdiv are left alone (their scale matters)."""
    while True:
        m = re.search(r"(?<![\w.])_?(add|sub|mul|umul)\s*\(", text)
        if not m:
            return text
        inner, after = _read_parens(text, m.end() - 1)
        args = _split_top(inner, ",")
        if len(args) != 2:
            return text[:m.start()] + "MATHHELPER" + text[after:]
        text = f"{text[:m.start()]}(({args[0]}) {_MATH_OPS[m.group(1)]} ({args[1]})){text[after:]}"


def canon(cond_skel: str) -> str:
    """Canonical form of a condition: negating twice pushes every negation inward and strips
    redundant parentheses, so `!(a || (b))` and `(a) || b` end up textually identical."""
    return negate(negate(cond_skel))


_COMPOUND_RE = re.compile(r"^(?P<lhs>[^=;<>!]+?)\s*(?P<op>[+\-*/%])=(?!=)\s*(?P<rhs>.+)$", re.DOTALL)


def _expand_compound(text: str) -> str:
    """`a -= b` -> `a = a - b` (parenthesising a compound right-hand side), so a fork's `tab -= owe`
    compares equal to the upstream's `tab = tab - owe`."""
    m = _COMPOUND_RE.match(text.strip())
    if not m:
        return text
    rhs = m.group("rhs").strip()
    if len(_split_top(rhs, "+")) > 1 or len(_split_top(rhs, "-")) > 1:
        rhs = f"({rhs})"
    return f"{m.group('lhs').strip()} = {m.group('lhs').strip()} {m.group('op')} {rhs}"


def skeleton(text: str) -> str:
    """Identifiers -> ID (constants and msg/block/tx members kept), literals -> NUM/STR, types
    dropped, member chains collapsed, member calls -> CALL. Whitespace-insensitive."""
    t = re.sub(r'"[^"\n]*"|\'[^\'\n]*\'', "STR", _expand_math_helpers(_expand_bool_helpers(_strip_lib_calls(_expand_compound(text)))))
    t = _TYPE_DECL_RE.sub("", t)
    t = _NOISE_WORDS_RE.sub("", t)
    tokens = _TOKEN_RE.findall(t)
    out = []
    for i, tok in enumerate(tokens):
        prev = tokens[i - 1] if i else ""
        prev2 = tokens[i - 2] if i > 1 else ""
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
        if tok[0].isdigit():
            out.append(tok if tok in ("0", "1", "2") else "NUM")
        elif tok[0].isalpha() or tok[0] == "_":
            if tok in _KEEP_MEMBERS and nxt == ".":
                out.append(tok)
            elif prev == "." and prev2 in _KEEP_MEMBERS:
                out.append(f".{tok}")
            elif prev == "." and nxt == "(":
                # the method name of an external call is semantics (transfer vs transferFrom), keep it
                out.append("CALL." + tok.lower().strip("_"))
            elif _CONST_RE.match(tok) and len(tok.strip("_")) <= 4 and nxt != ".":
                out.append(tok.lstrip("_"))  # RAY/WAD/RAD/ONE/BLN: scale constants are semantics
            elif re.match(r"^u?int\d*$", tok):
                out.append("INT")
            elif tok in ("true", "false", "return", "new", "delete"):
                out.append(tok)
            else:
                out.append("ID")
        else:
            out.append(tok)
    s = " ".join(out)
    s = re.sub(r"(?:ID|[A-Z][A-Z0-9]+)(?: \. (?:ID|[A-Z][A-Z0-9]+))* \. (CALL\.\w+)", r"\1", s)  # a.b.c.CALL.x -> CALL.x
    s = re.sub(r"ID( \. ID)+", "ID", s)  # x.y.z -> ID
    s = re.sub(r"(msg|block|tx) \. ", r"\1", s)
    prev = None
    while prev != s:  # ( ID ) -> ID, repeatedly
        prev = s
        s = re.sub(r"\( (ID|NUM|[0-2]|[A-Z]{2,4}|msg\.\w+|CALL\.\w+ \( [^()]* \)) \)", r"\1", s)
    s = re.sub(r"\s+", " ", s).strip()
    m = re.match(r"^(.*?[^=<>!]) = (.*)$", s)  # `x = ( a + b )` is `x = a + b`
    if m and "==" not in m.group(1):
        s = f"{m.group(1)} = {_strip_outer_parens(m.group(2))}"
    return s


def _features(original: str, skel: str) -> tuple:
    calls = re.findall(r"\.\s*([A-Za-z_]\w*)\s*\(", _strip_lib_calls(original))
    comps = [op for _, op in _top_comparators_all(skel)]
    ops = [tok for tok in skel.split() if tok in _ARITH]
    return calls, comps, ops


def _top_comparators_all(skel: str) -> list:
    """Every comparison operator anywhere in the skeleton (order preserved)."""
    return [(m.start(), m.group()) for m in re.finditer(r"<=|>=|==|!=|(?<![<>])[<>](?![<>])", skel)]


# ----------------------------------------------------------------- statements


def _read_parens(m: str, i: int):
    """(inner text, index after ')') for the parenthesised group starting at m[i] == '('."""
    depth = 0
    for j in range(i, len(m)):
        if m[j] == "(":
            depth += 1
        elif m[j] == ")":
            depth -= 1
            if depth == 0:
                return m[i + 1:j], j + 1
    return m[i + 1:], len(m)


def _match_brace(m: str, i: int) -> int:
    depth = 0
    for j in range(i, len(m)):
        if m[j] == "{":
            depth += 1
        elif m[j] == "}":
            depth -= 1
            if depth == 0:
                return j
    return len(m) - 1


def _read_statement(m: str, i: int) -> tuple:
    """(text, index after ';') reading to the next ';' at bracket depth 0."""
    depth = 0
    for j in range(i, len(m)):
        c = m[j]
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == ";" and depth == 0:
            return m[i:j], j + 1
        elif c in "{}" and depth == 0:
            return m[i:j], j
    return m[i:], len(m)


def _guard(cond_original: str, must_skel: str, line: int, text: str) -> Stmt:
    calls, comps, ops = _features(cond_original, must_skel)
    return Stmt(text=" ".join(text.split()), skeleton=f"MUST ( {must_skel} )", kind="guard", line=line,
                calls=calls, comps=comps, ops=ops)


def statements(func: SolFunc) -> list:
    """The function body as an ordered list of Stmt, blocks flattened, guards normalised."""
    body = func.body
    m = mask(body)
    out = []
    n = len(m)
    i = 0

    def line_at(pos: int) -> int:
        return func.body_line + body.count("\n", 0, pos)

    while i < n:
        c = m[i]
        if c.isspace() or c in "{}":
            i += 1
            continue
        word = re.match(r"[A-Za-z_]\w*", m[i:])
        w = word.group() if word else ""
        start = i
        if w in ("unchecked", "else"):
            i += len(w)
            continue
        if w == "if":
            j = m.index("(", i)
            cond, k = _read_parens(m, j)
            cond_orig = body[j + 1:j + 1 + len(cond)]
            while k < n and m[k].isspace():
                k += 1
            reverts = False
            end = k
            if k < n and m[k] == "{":
                close = _match_brace(m, k)
                reverts = bool(_REVERT_ONLY_RE.match(m[k + 1:close]))
                end = close + 1
            else:
                stmt_text, after = _read_statement(m, k)
                reverts = bool(_REVERT_ONLY_RE.match(stmt_text))
                end = after
            if reverts:
                out.append(_guard(cond_orig, canon(negate(skeleton(cond_orig))), line_at(start), f"if ({cond_orig.strip()}) revert"))
                i = end
            else:
                sk = skeleton(cond_orig)
                calls, comps, ops = _features(cond_orig, sk)
                out.append(Stmt(" ".join(f"if ({cond_orig.strip()})".split()), f"IF ( {sk} )", "if", line_at(start), calls, comps, ops))
                i = k  # keep scanning inside the branch
            continue
        if w in ("for", "while"):
            j = m.index("(", i)
            cond, k = _read_parens(m, j)
            cond_orig = body[j + 1:j + 1 + len(cond)]
            out.append(Stmt(" ".join(f"{w} ({cond_orig.strip()})".split()), "LOOP", "loop", line_at(start)))
            i = k
            continue
        if w == "assembly":
            j = m.index("{", i)
            close = _match_brace(m, j)
            out.append(Stmt("assembly { ... }", "ASM", "asm", line_at(start)))
            i = close + 1
            continue
        text, after = _read_statement(m, i)
        orig = body[i:i + len(text)]
        i = after
        stripped = orig.strip()
        if not stripped or stripped.startswith("emit "):
            continue
        rm = re.match(r"(?:require|assert)\s*\((.*)\)\s*$", stripped, re.DOTALL)
        if rm:
            args = _split_top(rm.group(1), ",")
            cond_o = args[0]
            out.append(_guard(cond_o, canon(skeleton(cond_o)), line_at(start), stripped))
            continue
        if _REVERT_ONLY_RE.match(stripped):
            out.append(Stmt(" ".join(stripped.split()), "REVERT", "revert", line_at(start)))
            continue
        if re.fullmatch(r"(?:uint\d*|int\d*|bytes\d*|bool|address|string)(?:\s+(?:memory|storage))?\s+\w+(?:\s*,\s*\w+)*", stripped):
            continue  # `uint256 x;` declares, it does not do anything
        sk = skeleton(stripped)
        kind = "ret" if stripped.startswith("return") else "stmt"
        calls, comps, ops = _features(stripped, sk)
        out.append(Stmt(" ".join(stripped.split()), sk, kind, line_at(start), calls, comps, ops))
    return out


# ----------------------------------------------------------------- diffing


def _classify(u, t) -> tuple:
    kinds = set()
    if u and t:
        if u.kind == "guard" and t.kind == "guard":
            kinds.add("guard-changed")
        elif u.kind == "guard" or t.kind == "guard":
            kinds.add("guard-replaced")
        if sorted(u.comps) != sorted(t.comps):
            kinds.add("comparator")
        if u.ops != t.ops:
            kinds.add("arith-order")
        if u.calls != t.calls:
            kinds.add("call")
        if not kinds:
            kinds.add("other")
    elif u:
        kinds.add("guard-removed" if u.kind == "guard" else "removed")
    else:
        kinds.add("guard-added" if t.kind == "guard" else "added")
    return sorted(kinds), max(KIND_WEIGHT[k] for k in kinds)


def _pair_block(block_up: list, block_tg: list) -> tuple:
    """Within a changed block, pair statements by best skeleton similarity (>= 0.5) instead of by
    position, so one inserted statement does not turn every later one into a false 'changed'."""
    scored = []
    for a, u in enumerate(block_up):
        for b, t in enumerate(block_tg):
            r = SequenceMatcher(None, u.skeleton.split(), t.skeleton.split(), autojunk=False).ratio()
            scored.append((r, a, b))
    scored.sort(key=lambda x: (-x[0], x[1], x[2]))
    used_u, used_t, pairs = set(), set(), []
    for r, a, b in scored:
        if r < 0.5:
            break
        if a in used_u or b in used_t:
            continue
        used_u.add(a)
        used_t.add(b)
        pairs.append((block_up[a], block_tg[b]))
    removed = [u for a, u in enumerate(block_up) if a not in used_u]
    added = [t for b, t in enumerate(block_tg) if b not in used_t]
    return pairs, removed, added


def diff_statements(up: list, tg: list) -> list:
    sm = SequenceMatcher(None, [s.skeleton for s in up], [s.skeleton for s in tg], autojunk=False)
    diffs = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        pairs, removed, added = _pair_block(up[i1:i2], tg[j1:j2])
        for u, t in pairs:
            kinds, prio = _classify(u, t)
            diffs.append(StmtDiff(kinds, prio, u.text, t.text, u.line, t.line))
        for u in removed:
            kinds, prio = _classify(u, None)
            diffs.append(StmtDiff(kinds, prio, u.text, "", u.line, 0))
        for t in added:
            kinds, prio = _classify(None, t)
            diffs.append(StmtDiff(kinds, prio, "", t.text, 0, t.line))
    return diffs


_MOD_EQUIV = {"auth": "ward", "lock": "nonreentrant"}


def _mod_norm(mods: list) -> list:
    """Modifier names normalised so equivalent access/reentrancy guards compare equal:
    Maker's `auth`, `onlyRole(_WARD_ROLE)` -> ward; `lock`, `nonReentrant` -> nonreentrant."""
    out = []
    for m in mods:
        name = m.split("(")[0].lower()
        if name in ("note", "stoppable"):
            continue
        if name == "onlyrole" and "ward" in m.lower():
            out.append("ward")
        else:
            out.append(_MOD_EQUIV.get(name, m.lower()))
    return sorted(out)


def diff_modifiers(up_func: SolFunc, tg_func: SolFunc) -> list:
    """Header modifiers are guards too (`isStopped(3)`, `onlyRole(...)`, `nonReentrant`)."""
    u, t = _mod_norm(up_func.modifiers), _mod_norm(tg_func.modifiers)
    if u == t:
        return []
    gone = [m for m in u if m not in t]
    new = [m for m in t if m not in u]
    return [StmtDiff(["modifier"], KIND_WEIGHT["modifier"], "modifiers: " + " ".join(gone) if gone else "",
                     "modifiers: " + " ".join(new) if new else "", up_func.start_line, tg_func.start_line)]


# ----------------------------------------------------------------- pairing


def _norm(name: str) -> str:
    return name.lower().strip("_")


def _by_contract(sources: dict) -> tuple:
    """({contract: [SolFunc]}, {contract: file}) over {path: source}."""
    funcs, files = {}, {}
    for path, text in sources.items():
        for f in find_functions(text):
            if f.kind in ("function", "constructor", "modifier") and f.has_body:
                funcs.setdefault(f.contract, []).append(f)
                files.setdefault(f.contract, path)
    return funcs, files


def pair_contracts(target: dict, upstream: dict, hints: dict) -> dict:
    """{target contract: [upstream contracts]} from explicit hints, else by shared function names."""
    pairs = {}
    for tname, tfuncs in target.items():
        if tname in hints:
            wanted = [u for u in hints[tname] if u in upstream]
            if wanted:
                pairs[tname] = wanted
            continue
        tnames = {_norm(f.name) for f in tfuncs if f.name}
        best, score = None, 0.25
        for uname, ufuncs in upstream.items():
            unames = {_norm(f.name) for f in ufuncs if f.name}
            union = tnames | unames
            jac = len(tnames & unames) / len(union) if union else 0
            if jac >= score:
                best, score = uname, jac
        if best:
            pairs[tname] = [best]
    return pairs


_AUTH_BOILERPLATE = frozenset({"rely", "deny"})


def compare(target_sources: dict, upstream_sources: dict, hints: dict = None, aliases: dict = None,
            ignore=_AUTH_BOILERPLATE) -> dict:
    """The full literal comparison. target_sources / upstream_sources are {path: source_text}.

    A target contract with no upstream counterpart (no hint, no shared function names) is reported
    as entirely added: pairing unrelated contracts by name only produces confident nonsense.

    Returns {"pairs": [FunctionPair], "removed_upstream": [...], "added_target": [...],
    "contract_pairs": {...}}."""
    hints = hints or {}
    ignore = {_norm(n) for n in ignore}
    aliases = {_norm(k): _norm(v) for k, v in (aliases or {}).items()}
    tfuncs, tfiles = _by_contract(target_sources)
    ufuncs, ufiles = _by_contract(upstream_sources)
    cpairs = pair_contracts(tfuncs, ufuncs, hints)

    pairs, matched_upstream, added = [], set(), []
    for tname, fs in tfuncs.items():
        paired = cpairs.get(tname, [])
        for tf in fs:
            label = f"{tname}.{tf.name or tf.kind}"
            if not paired:
                added.append(label)
                continue
            want = aliases.get(_norm(tf.name), _norm(tf.name))
            if tf.kind == "constructor":
                continue  # constructor differences are deployment wiring, not behaviour
            cands = [(c, f) for c in paired for f in ufuncs.get(c, []) if f.kind != "constructor" and _norm(f.name) == want]
            cross = False
            if not cands:
                added.append(label)
                continue
            tst = statements(tf)
            # A fork that merged several upstream contracts (GemJoin + DaiJoin -> one adapter) is
            # compared against the best same-named function in EACH of them; overloads inside one
            # contract collapse to the best match.
            best_per_contract = {}
            for c, uf in cands:
                ust = statements(uf)
                ratio = SequenceMatcher(None, [x.skeleton for x in ust], [x.skeleton for x in tst], autojunk=False).ratio()
                if c not in best_per_contract or ratio > best_per_contract[c][0]:
                    best_per_contract[c] = (ratio, uf, ust)
            for c, (ratio, uf, ust) in best_per_contract.items():
                matched_upstream.add((c, uf.name, uf.start_line))
                diffs = diff_modifiers(uf, tf) + diff_statements(ust, tst)
                pairs.append(FunctionPair(tf, tfiles[tname], uf, ufiles[c], ratio, diffs, len(best_per_contract) > 1))

    paired_upstream = {u for us in cpairs.values() for u in us}
    removed = [
        f"{c}.{f.name}" for c, fs in ufuncs.items() if c in paired_upstream
        for f in fs
        if f.kind == "function" and f.externally_callable() and _norm(f.name) not in ignore
        and (c, f.name, f.start_line) not in matched_upstream
    ]
    return {"pairs": sorted(pairs, key=lambda p: -p.priority), "removed_upstream": sorted(set(removed)),
            "added_target": sorted(added), "contract_pairs": cpairs}
