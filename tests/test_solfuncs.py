"""Step A: the shared Solidity function/state extractor. Pure text in, structure out."""

import textwrap

from hound.solfuncs import (
    contracts, find_functions, function_at, mask, state_variables, touched_state,
)

SRC = textwrap.dedent(
    '''\
    // SPDX-License-Identifier: MIT
    pragma solidity 0.8.30;

    interface IThing {
        function ping() external view returns (uint256);
    }

    /* a comment with a { brace and a function fake() external { } inside */
    contract Vault is IThing {
        uint256 public total;
        mapping(address => uint256) public balances;
        address private immutable owner;
        string constant NOTE = "has a } brace and // slashes";

        modifier onlyOwner() {
            require(msg.sender == owner, "no } here");
            _;
        }

        constructor(address o) {
            owner = o;
        }

        function ping() external view returns (uint256) {
            return total;
        }

        function deposit(uint256 amt) external payable {
            if (amt > 0) {
                balances[msg.sender] += amt; // trailing { comment
                total += amt;
            }
        }

        function sweep(address to) external onlyOwner {
            (bool ok, ) = to.call{value: address(this).balance}("");
            require(ok);
        }

        function _helper() internal pure returns (uint256) { return 1; }
    }
    '''
)


def test_mask_keeps_line_numbers_and_blanks_comments_and_strings():
    masked = mask(SRC)
    assert len(masked) == len(SRC)
    assert masked.count("\n") == SRC.count("\n")
    assert "fake" not in masked  # inside a block comment
    assert "trailing" not in masked  # inside a line comment
    assert "no } here" not in masked  # inside a string literal
    assert "function deposit" in masked  # real code survives


def test_contracts_are_found_with_kinds():
    found = contracts(SRC)
    assert [(k, n) for k, n, _, _ in found] == [("interface", "IThing"), ("contract", "Vault")]


def test_functions_have_exact_line_ranges_and_bodies():
    funcs = {f.key: f for f in find_functions(SRC)}
    dep = funcs["Vault.deposit"]
    lines = SRC.split("\n")
    assert lines[dep.start_line - 1].strip().startswith("function deposit")
    assert lines[dep.end_line - 1].strip() == "}"
    assert "balances[msg.sender] += amt" in dep.body
    assert dep.visibility == "external" and dep.mutability == "payable"
    assert dep.state_changing() and dep.externally_callable()


def test_braces_in_strings_and_comments_do_not_break_matching():
    funcs = {f.key: f for f in find_functions(SRC)}
    # onlyOwner's body contains a string with '}' — sweep must still be found after it
    assert "Vault.onlyOwner" in funcs and funcs["Vault.onlyOwner"].kind == "modifier"
    assert "Vault.sweep" in funcs
    assert "Vault.fake" not in funcs  # only present inside a comment


def test_kinds_visibility_and_modifiers():
    funcs = {f.key: f for f in find_functions(SRC)}
    assert funcs["Vault.constructor"].kind == "constructor" if "Vault.constructor" in funcs else True
    ctor = next(f for f in find_functions(SRC) if f.kind == "constructor")
    assert ctor.contract == "Vault"
    assert funcs["Vault.ping"].mutability == "view"
    assert funcs["Vault._helper"].visibility == "internal" and not funcs["Vault._helper"].externally_callable()
    assert "onlyOwner" in funcs["Vault.sweep"].modifiers
    # the interface declaration has no body
    decl = next(f for f in find_functions(SRC) if f.contract == "IThing")
    assert not decl.has_body


def test_state_variables_ignore_locals_and_constants_in_functions():
    names = state_variables(SRC)
    assert {"total", "balances", "owner", "NOTE"} <= names
    assert "amt" not in names and "ok" not in names and "to" not in names


def test_touched_state_maps_function_to_storage():
    funcs = {f.key: f for f in find_functions(SRC)}
    names = state_variables(SRC)
    assert touched_state(funcs["Vault.deposit"], names) == {"balances", "total"}
    assert touched_state(funcs["Vault.ping"], names) == {"total"}
    assert "owner" in touched_state(funcs["Vault.sweep"], names) or "owner" in touched_state(funcs["Vault.onlyOwner"], names)


def test_function_at_returns_the_containing_function():
    funcs = find_functions(SRC)
    dep = next(f for f in funcs if f.name == "deposit")
    inner_line = dep.start_line + 2
    assert function_at(funcs, inner_line).name == "deposit"
    assert function_at(funcs, 1) is None


def test_written_state_separates_writes_from_reads():
    from hound.solfuncs import written_state
    funcs = {f.key: f for f in find_functions(SRC)}
    names = state_variables(SRC)
    assert written_state(funcs["Vault.deposit"], names) == {"balances", "total"}  # `balances[k] += ` and `total +=`
    assert written_state(funcs["Vault.ping"], names) == set()  # reads total, writes nothing
    src = "contract C { uint256 x; uint256 y; uint256[] q; function f() external { y = x + 1; x++; delete y; q.push(1); if (x == y) {} } }"
    f = find_functions(src)[0]
    assert written_state(f, state_variables(src)) == {"x", "y", "q"}
    assert written_state(find_functions("contract C { uint256 x; function g() external { require(x == 2); } }")[0], {"x"}) == set()
