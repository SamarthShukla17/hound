"""Deterministic extraction for the deploy/config cross-check: what the deploy scripts SET, and what
the contracts' setters ACCEPT.

Two halves, joined by parameter name:

* deploy side - every `file(...)`/`set*(...)` call in JS/TS/Solidity deploy scripts, and every
  `assertEq("Contract.param", actual, expected)` in verify scripts, with the value expression
  evaluated against the script's own constants (`1000n * RAD` -> an integer);
* contract side - every `what == "name"` branch of a `file` setter (the checks it applies and
  which functions read the variable), plus hard-coded `constant`/`immutable` parameters and
  constructor defaults.

Nothing here judges anything. It produces the table the reviewer reasons over, and the plain
facts that need no model: parameters the deploy never sets, mismatches between a verify script and
a deploy script, and gaps against an upstream's reference values.
"""

import ast
import operator
import re
from dataclasses import dataclass, field
from pathlib import Path

from .solfuncs import find_functions, mask, state_variables, touched_state

_SKIP_DIRS = {"node_modules", "lib", "out", "cache", "cache_forge", "artifacts", "typechain-types", ".git"}
_SCRIPT_SUFFIXES = {".js", ".ts", ".mjs", ".cjs", ".s.sol"}
_ALLOWED = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.FloorDiv: operator.floordiv,
            ast.Pow: operator.pow, ast.Mod: operator.mod}


@dataclass
class Setting:
    path: str
    line: int
    kind: str  # param | assert | call
    contract: str  # resolved contract name, or the instance variable if unresolved
    name: str  # parameter / method name
    scope: str  # ilk or other first argument for 3-arg file(), else ''
    expr: str  # value expression as written
    value: int | None  # evaluated integer when the expression is plain arithmetic


@dataclass
class ParamSpec:
    contract: str
    name: str
    kind: str  # setter | constant | default
    variable: str = ""
    checks: list = field(default_factory=list)
    readers: list = field(default_factory=list)
    line: int = 0
    path: str = ""
    default_expr: str = ""
    default_value: int | None = None


# ------------------------------------------------------------------ value evaluation


def _normalise_number(expr: str) -> str:
    e = re.sub(r"(?<![\w.])(\d[\d_]*)n\b", r"\1", expr)  # 1000n -> 1000
    e = e.replace("_", "")
    e = re.sub(r"\b(\d+)e(\d+)\b", lambda m: str(int(m.group(1)) * 10 ** int(m.group(2))), e)  # 1e18
    e = re.sub(r"\b(\d+)\s*(seconds?|minutes?|hours?|days?|weeks?)\b",
               lambda m: str(int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)[0]]), e)
    e = re.sub(r"\b(\d+)\s*(ether|gwei)\b", lambda m: str(int(m.group(1)) * (10 ** 18 if m.group(2) == "ether" else 10 ** 9)), e)
    return re.sub(r"(?<![*/])/(?!/)", "//", e)


def evaluate(expr: str, consts: dict | None = None) -> int | None:
    """Integer value of a plain arithmetic expression (BigInt syntax, `1e18`, script constants);
    None if it involves anything else. Never executes code: an ast walk over + - * // ** %."""
    consts = consts or {}
    try:
        tree = ast.parse(_normalise_number(expr.strip()), mode="eval")
    except SyntaxError:
        return None

    def walk(node):
        if isinstance(node, ast.Expression):
            return walk(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
            return node.value
        if isinstance(node, ast.Name) and node.id in consts and consts[node.id] is not None:
            return consts[node.id]
        if isinstance(node, ast.BinOp) and type(node.op) in _ALLOWED:
            left, right = walk(node.left), walk(node.right)
            if left is None or right is None or (isinstance(node.op, ast.Pow) and right > 4096):
                return None
            try:
                return _ALLOWED[type(node.op)](left, right)
            except ZeroDivisionError:
                return None
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            v = walk(node.operand)
            return -v if v is not None else None
        return None

    return walk(tree)


def script_constants(text: str) -> dict:
    """`const WAD = 10n ** 18n;` / `uint256 constant RAD = 1e45;` -> {name: int}, resolved in order."""
    consts = {}
    for m in re.finditer(r"(?:const|let|var|constant)\s+(?:\w+\s+)?([A-Za-z_]\w*)\s*=\s*([^;\n]+)", text):
        val = evaluate(m.group(2), consts)
        if val is not None:
            consts[m.group(1)] = val
    return consts


def scale_label(value: int | None) -> str:
    """Human reading of a fixed-point value in the first unit that reads naturally (0.001 <= q < 1e12):
    RAD (1e45), RAY (1e27), WAD (1e18). Empty for small plain integers (seconds, counts)."""
    if not value or value < 10 ** 15:
        return ""
    for name, unit in (("RAD", 10 ** 45), ("RAY", 10 ** 27), ("WAD", 10 ** 18)):
        q = value / unit
        if 1e-3 <= q < 1e12:
            return f"{q:,.10g} {name}"
    return ""


# ------------------------------------------------------------------ deploy side


def find_config_files(root) -> list:
    root = Path(root)
    found = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or any(part in _SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        name = p.name.lower()
        in_script_dir = any(part in ("scripts", "script", "deploy", "deployments") for part in p.relative_to(root).parts[:-1])
        if any(name.endswith(s) for s in _SCRIPT_SUFFIXES) and (in_script_dir or any(k in name for k in ("deploy", "verify", "config", "setup"))):
            found.append(p)
    return found


def _split_args(s: str) -> list:
    args, depth, cur = [], 0, []
    for c in s:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
    if "".join(cur).strip():
        args.append("".join(cur).strip())
    return args


def _paren_group(text: str, i: int) -> tuple:
    depth = 0
    for j in range(i, len(text)):
        depth += text[j] == "("
        depth -= text[j] == ")"
        if depth == 0:
            return text[i + 1:j], j + 1
    return text[i + 1:], len(text)


def _instance_map(text: str, contract_names: set) -> dict:
    """{instance variable: contract name} from getContractAt / `new X(...)` / typed declarations."""
    names = dict(re.findall(r'\bconst\s+(\w+)\s*=\s*"([A-Za-z_]\w*)"', text))  # const fooName = "Foo"
    out = {}
    for var, ref in re.findall(r"(?:const|let)\s+(\w+)\s*=\s*await\s+\w+(?:\.\w+)*\.getContractAt\(\s*(\w+|\"[^\"]+\")", text):
        out[var] = names.get(ref, ref.strip('"'))
    for typ, var in re.findall(r"\b([A-Z]\w+)\s+(?:public\s+)?(\w+)\s*=\s*(?:new\s+\1|\1\()", text):
        out[var] = typ
    return out


def _resolve_contract(var: str, mapping: dict, contract_names: set) -> str:
    if var in mapping:
        return mapping[var]
    base = re.sub(r"(instance|contract|c)$", "", var, flags=re.I).lower()
    for cn in contract_names:
        if cn.lower() == base:
            return cn
    return var


def extract_settings(text: str, path: str, contract_names: set) -> list:
    """Every parameter-setting call and verify assertion in one script."""
    consts = script_constants(text)
    inst = _instance_map(text, contract_names)
    out = []
    starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def line_of(pos):
        return sum(1 for s in starts if s <= pos)

    for m in re.finditer(r"(\w+)\s*(?:\[\s*[\"']([\w(),\[\]\s]+)[\"']\s*\]|\.(\w+))\s*\(", text):
        var, sig, dot = m.group(1), m.group(2), m.group(3)
        method = (sig or dot or "").split("(")[0]
        if not re.match(r"(file|set[A-Z_]\w*|init|exemptFee|addVolatileIlk|removeVolatileIlk|change|schedule)$", method):
            continue
        inner, _ = _paren_group(text, m.end() - 1)
        args = _split_args(inner)
        names = [re.search(r"encodeBytes32String\(\s*[\"']([^\"']+)[\"']\s*\)", a) or re.fullmatch(r"(?:bytes32\()?[\"']([^\"']+)[\"']\)?", a) for a in args]
        contract = _resolve_contract(var, inst, contract_names)
        if method == "file":
            str_idx = [i for i, n in enumerate(names) if n]
            if not str_idx:
                continue
            i = str_idx[0]
            value_expr = args[i + 1] if i + 1 < len(args) else ""
            scope = args[i - 1] if i > 0 else ""
            out.append(Setting(path, line_of(m.start()), "param", contract, names[i].group(1), scope, value_expr,
                               evaluate(value_expr, consts)))
        elif method.startswith("set"):
            out.append(Setting(path, line_of(m.start()), "param", contract, method, "", ", ".join(args), evaluate(args[0], consts) if args else None))
        else:
            out.append(Setting(path, line_of(m.start()), "call", contract, method, "", ", ".join(args), None))

    for m in re.finditer(r"\bassertEq\(\s*[`\"']([^`\"']+)[`\"']\s*,", text):
        inner, _ = _paren_group(text, m.start() + len("assertEq"))
        args = _split_args(inner)
        if len(args) >= 3:
            label = m.group(1)
            contract, _, param = label.partition(".")
            out.append(Setting(path, line_of(m.start()), "assert", contract, param.split("(")[0] or label, "", args[2],
                               evaluate(args[2], consts)))
    return out


# ------------------------------------------------------------------ contract side


def extract_specs(sources: dict) -> list:
    """{path: solidity text} -> ParamSpec for every `file` branch, hard-coded constant and
    constructor default."""
    specs = []
    for path, text in sources.items():
        masked = mask(text)
        funcs = find_functions(text)
        svars = state_variables(text)
        for f in funcs:
            if f.kind == "function" and f.name == "file" and f.has_body:
                body = f.body
                branches = list(re.finditer(r'what\s*==\s*"([^"]+)"', body))
                for i, bm in enumerate(branches):
                    seg = body[bm.end(): branches[i + 1].start() if i + 1 < len(branches) else len(body)]
                    checks = [" ".join(c.split()) for c in re.findall(r"if\s*\(([^)]*(?:data|value)[^)]*)\)", seg)]
                    reverts = re.findall(r"_?revert\(\s*([A-Za-z_.]+)", seg)
                    assigned = re.search(r"([A-Za-z_]\w*(?:\[[^\]]+\])*(?:\.\w+)?)\s*=\s*(?:\w+\()?(?:data|value)", seg)
                    var = assigned.group(1).split("[")[0].split(".")[0] if assigned else bm.group(1)
                    readers = [g.key for g in funcs if g.contract == f.contract and g is not f and g.has_body
                               and var in touched_state(g, svars | {var})]
                    line = f.body_line + body.count("\n", 0, bm.start())
                    specs.append(ParamSpec(f.contract, bm.group(1), "setter", var, checks + [f"reverts {r}" for r in reverts],
                                           readers, line, path))
        for m in re.finditer(r"\b(?:uint\d*|int\d*|bytes\d*|address)\s+(?:public\s+|private\s+|internal\s+)?(constant|immutable)\s+([A-Za-z_]\w*)\s*=\s*([^;]+);", masked):
            owner = next((c for c in _contract_spans(text) if c[1] <= m.start() < c[2]), None)
            specs.append(ParamSpec(owner[0] if owner else "", m.group(2), "constant", m.group(2),
                                   default_expr=" ".join(m.group(3).split()), default_value=evaluate(m.group(3)),
                                   line=text.count("\n", 0, m.start()) + 1, path=path))
        for f in funcs:
            if f.kind == "constructor" and f.has_body:
                for m in re.finditer(r"^\s*([A-Za-z_]\w*)\s*=\s*([^;]+);", f.body, re.MULTILINE):
                    if m.group(1) in svars:
                        specs.append(ParamSpec(f.contract, m.group(1), "default", m.group(1), default_expr=" ".join(m.group(2).split()),
                                               default_value=evaluate(m.group(2), {"_WAD": 10 ** 18, "_RAY": 10 ** 27, "_RAD": 10 ** 45}),
                                               line=f.body_line + f.body.count("\n", 0, m.start()), path=path))
    return specs


def _contract_spans(text: str) -> list:
    from .solfuncs import contracts

    return [(name, start, end) for _k, name, start, end in contracts(text)]
