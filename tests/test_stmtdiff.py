"""Step B: literal statement diff (Maker-style upstream vs a renamed, re-guarded fork)."""

import textwrap

from hound.solfuncs import find_functions
from hound.stmtdiff import compare, diff_statements, negate, skeleton, statements

UPSTREAM = textwrap.dedent(
    """\
    contract Vat {
        function frob(bytes32 i, int dink, int dart) external {
            require(live == 1, "Vat/not-live");
            urn.ink = _add(urn.ink, dink);
            require(dart <= 0 || debt <= Line, "Vat/ceiling-exceeded");
            require(tab <= _mul(urn.ink, ilk.spot), "Vat/not-safe");
            uint256 z = x * y / RAY;
            token.transfer(usr, z);
        }
        function fork(bytes32 ilk, address src, address dst) external {
            require(wish(src, msg.sender), "Vat/not-allowed");
        }
        function heal(uint rad) external {
            sin[msg.sender] = _sub(sin[msg.sender], rad);
        }
    }
    """
)

# identical semantics, renamed and re-guarded: must produce ZERO deviations for frob
FORK_CLEAN = textwrap.dedent(
    """\
    contract VaultEngine {
        function frob(uint256 vaultId, int256 dink, int256 dart) external {
            if (live != 1) {
                _revert(NotLive.selector);
            }
            urn.ink = Math.add(urn.ink, dink);
            if (!(dart <= 0 || debt <= globalLine)) {
                _revert(CeilingExceeded.selector);
            }
            if (tab > Math.umul(urn.ink, ilk.spot)) _revert(NotSafe.selector);
            uint256 z = a * b / _RAY;
            asset.transfer(user, z);
        }
        function open(bytes32 ilkId, address usr) external returns (uint256) {
            return 1;
        }
        function heal(uint256 rad) external {
            sin[msg.sender] = Math.sub(sin[msg.sender], rad);
        }
    }
    """
)

# one real deviation of each kind
FORK_BUGGY = textwrap.dedent(
    """\
    contract VaultEngine {
        function frob(uint256 vaultId, int256 dink, int256 dart) external {
            urn.ink = Math.add(urn.ink, dink);
            if (!(dart <= 0 || debt <= globalLine)) {
                _revert(CeilingExceeded.selector);
            }
            if (tab >= Math.umul(urn.ink, ilk.spot)) _revert(NotSafe.selector);
            uint256 z = x / RAY * y;
            asset.transferFrom(user, z);
        }
    }
    """
)


def _stmts(src, name):
    return statements(next(f for f in find_functions(src) if f.name == name))


def test_skeleton_ignores_names_but_keeps_constants_and_operators():
    assert skeleton("z = a * b / _RAY") == skeleton("out = vat * price / RAY")
    assert skeleton("x * RAY / WAD") != skeleton("x * WAD / RAY")
    assert skeleton("x / RAY * y") != skeleton("x * y / RAY")
    assert skeleton("a <= b") != skeleton("a < b")


def test_negate_pushes_negation_inward():
    assert negate("a > b") == "a <= b"
    assert negate("! ( a )") == "a"
    assert negate("a > b || c == d") == "a <= b && c != d"
    assert negate("a > b && c") == "a <= b || ! ( c )"


def test_require_and_if_revert_normalise_to_the_same_guard():
    up = [s for s in _stmts(UPSTREAM, "frob") if s.kind == "guard"]
    tg = [s for s in _stmts(FORK_CLEAN, "frob") if s.kind == "guard"]
    assert [s.skeleton for s in up] == [s.skeleton for s in tg]
    assert len(up) == 3


def test_clean_rename_and_reguard_has_no_deviations():
    up = _stmts(UPSTREAM, "frob")
    tg = _stmts(FORK_CLEAN, "frob")
    assert diff_statements(up, tg) == []


def test_each_real_deviation_is_flagged_with_the_right_kind():
    diffs = diff_statements(_stmts(UPSTREAM, "frob"), _stmts(FORK_BUGGY, "frob"))
    kinds = {k for d in diffs for k in d.kinds}
    assert "guard-removed" in kinds  # require(live == 1) dropped
    assert "comparator" in kinds  # <= became >= in the safety guard
    assert "arith-order" in kinds  # x * y / RAY -> x / RAY * y
    assert "call" in kinds  # transfer -> transferFrom
    top = max(diffs, key=lambda d: d.priority)
    assert top.priority == 5


def test_statement_lines_are_absolute_file_lines():
    f = next(f for f in find_functions(FORK_BUGGY) if f.name == "frob")
    lines = FORK_BUGGY.split("\n")
    for s in statements(f):
        assert lines[s.line - 1].strip().startswith(s.text.split()[0][:6])


def test_compare_pairs_functions_and_reports_removed_and_added():
    result = compare({"VaultEngine.sol": FORK_CLEAN}, {"vat.sol": UPSTREAM}, hints={"VaultEngine": ["Vat"]})
    names = {p.target.name: p for p in result["pairs"]}
    assert set(names) == {"frob", "heal"}
    assert all(p.diffs == [] for p in names.values())
    assert result["removed_upstream"] == ["Vat.fork"]  # the fork dropped fork()
    assert result["added_target"] == ["VaultEngine.open"]  # and added open()
    assert result["contract_pairs"] == {"VaultEngine": ["Vat"]}


def test_compare_ranks_the_deviating_pair_first_and_honours_aliases():
    up = UPSTREAM + textwrap.dedent(
        """\
        contract End {
            function snip(bytes32 ilk, uint256 id) external {
                uint256 art = tab / rate;
            }
        }
        """
    )
    tg = FORK_BUGGY + textwrap.dedent(
        """\
        contract End {
            function skip(bytes32 ilk, uint256 id) external {
                uint256 art = tab * rate;
            }
        }
        """
    )
    result = compare({"a.sol": tg}, {"b.sol": up}, hints={"VaultEngine": ["Vat"], "End": ["End"]}, aliases={"skip": "snip"})
    assert {p.target.name for p in result["pairs"]} == {"frob", "skip"}
    assert result["pairs"][0].priority >= result["pairs"][-1].priority
    skip = next(p for p in result["pairs"] if p.target.name == "skip")
    assert "arith-order" in {k for d in skip.diffs for k in d.kinds}


def test_contracts_pair_by_shared_function_names_without_hints():
    result = compare({"a.sol": FORK_CLEAN}, {"b.sol": UPSTREAM})
    assert result["contract_pairs"] == {"VaultEngine": ["Vat"]}


def test_compound_assignment_equals_expanded_form():
    assert skeleton("tab -= owe") == skeleton("tab = tab - owe")
    assert skeleton("total += a + b") == skeleton("total = total + (a + b)")


def test_only_short_scale_constants_are_kept_instance_names_are_not():
    assert skeleton("VAULT_ENGINE.flux(ILK_ID, this, who, slice)") == skeleton("vat.flux(ilk, this, who, slice)")
    assert "RAY" in skeleton("x * _RAY") and "WAD" in skeleton("x / WAD")
    assert skeleton("x * RAY / WAD") != skeleton("x * WAD / RAY")


def test_modifier_equivalence_auth_and_ward_role_and_reentrancy_lock():
    from hound.stmtdiff import diff_modifiers
    up = next(f for f in find_functions("contract A { function f() external auth lock isStopped(3) { } }"))
    same = next(f for f in find_functions("contract B { function f() external onlyRole(_WARD_ROLE) nonReentrant { } }"))
    assert [m for d in diff_modifiers(up, same) for m in d.upstream.split()] == ["modifiers:", "isstopped(3)"]
    equal = next(f for f in find_functions("contract B { function f() external onlyRole(_WARD_ROLE) nonReentrant isStopped(3) { } }"))
    assert diff_modifiers(up, equal) == []


def test_safe_math_helpers_equal_operators():
    assert skeleton("owe = mul(slice, price)") == skeleton("owe = slice * price")
    assert skeleton("z = _add(x, y)") == skeleton("z = Math.add(x, y)") == skeleton("z = x + y")
    assert skeleton("z = _sub(x, y)") != skeleton("z = x + y")


def test_a_function_merged_from_two_upstream_contracts_is_compared_to_both():
    up = """
        contract GemJoin { function join(uint256 wad) external { require(live == 1); slip(wad); } }
        contract DaiJoin { function join(uint256 wad) external { move(this, wad); burn(wad); } }
    """
    tg = "contract Adapter { function join(uint256 wad) external { move(this, wad); burn(wad); } }"
    result = compare({"a.sol": tg}, {"b.sol": up}, hints={"Adapter": ["GemJoin", "DaiJoin"]})
    assert {p.upstream.contract for p in result["pairs"]} == {"GemJoin", "DaiJoin"}
    assert result["removed_upstream"] == []  # neither upstream join is falsely reported as removed
    clean = next(p for p in result["pairs"] if p.upstream.contract == "DaiJoin")
    assert clean.diffs == []
