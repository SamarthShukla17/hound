"""Step C: deploy/config extraction, the join, deterministic flags and the reviewer. No network."""

import asyncio
import json
import textwrap

import pytest

from hound.codebase import load
from hound.config_check import ConfigCheck, build, notes_for_hunters, render, review, run, write_artifacts
from hound.config_extract import (
    evaluate, extract_settings, extract_specs, find_config_files, scale_label, script_constants,
)

DEPLOY_JS = textwrap.dedent(
    """\
    const WAD = 10n ** 18n;
    const RAY = 10n ** 27n;
    const RAD = 10n ** 45n;
    const vaultName = "Vault";
    const testIlk = hardhat.ethers.encodeBytes32String("TEST-A");

    const run = async () => {
        const vaultInstance = await hardhat.ethers.getContractAt(vaultName, vaultAddress);
        const gateInstance = await hardhat.ethers.getContractAt("Gate", gateAddress);
        await (
            await vaultInstance["file(bytes32,uint256)"](hardhat.ethers.encodeBytes32String("floor"), 7000n * RAD)
        ).wait();
        await (
            await vaultInstance["file(bytes32,bytes32,uint256)"](
                testIlk,
                hardhat.ethers.encodeBytes32String("line"),
                (WAD * 125n) / 100n
            )
        ).wait();
        await (await gateInstance["file(bytes32,address)"](hardhat.ethers.encodeBytes32String("vault"), vaultAddress)).wait();
        await (await vaultInstance.init(testIlk)).wait();
        await (await gateInstance["file(bytes32,uint256)"](hardhat.ethers.encodeBytes32String("typo"), 1n)).wait();
    };
    """
)

VERIFY_JS = textwrap.dedent(
    """\
    const RAD = 10n ** 45n;
    assertEq("Vault.floor", await vault.floor(), 5000n * RAD);
    assertEq("Vault.line", await vault.line(), 1n);
    """
)

VAULT_SOL = textwrap.dedent(
    """\
    contract Vault {
        uint256 public floor;
        uint256 public line;
        uint256 public ceiling;
        uint16 public constant HOP = 1800;
        uint256 private constant MAX = 100 * 10 ** 18;

        constructor() {
            ceiling = _WAD / 4;
        }

        function file(bytes32 what, uint256 data) external onlyRole(_WARD_ROLE) {
            if (what == "floor") {
                floor = data;
            } else if (what == "line") {
                if (data == 0 || data > _WAD) {
                    _revert(OutOfBounds.selector);
                }
                line = data;
            } else if (what == "ceiling") {
                ceiling = data;
            }
        }

        function distribute() external returns (uint256) {
            if (surplus <= floor) return 0;
            return surplus - floor;
        }
    }
    contract Gate {
        address public vault;
        function file(bytes32 what, address data) external {
            if (what == "vault") { vault = data; }
        }
    }
    """
)


@pytest.fixture
def project(tmp_path):
    (tmp_path / "contracts").mkdir()
    (tmp_path / "scripts").mkdir()
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "deploy-x.js").write_text("nope")
    (tmp_path / "contracts" / "Vault.sol").write_text(VAULT_SOL)
    (tmp_path / "scripts" / "deploy-vault.js").write_text(DEPLOY_JS)
    (tmp_path / "scripts" / "verify-config.js").write_text(VERIFY_JS)
    return tmp_path


# --- evaluation -----------------------------------------------------------


def test_evaluate_handles_bigint_scientific_units_and_constants():
    consts = {"WAD": 10 ** 18, "RAD": 10 ** 45}
    assert evaluate("7000n * RAD", consts) == 7000 * 10 ** 45
    assert evaluate("(WAD * 125n) / 100n", consts) == 125 * 10 ** 16
    assert evaluate("1e18 + 5") == 10 ** 18 + 5
    assert evaluate("72 hours") == 259200 and evaluate("1 days") == 86400
    assert evaluate("100_000n * 2n") == 200000


def test_evaluate_never_executes_anything():
    assert evaluate("__import__('os').system('true')") is None
    assert evaluate("open('/etc/passwd')") is None
    assert evaluate("2 ** 100000") is None  # exponent cap
    assert evaluate("foo * 2") is None  # unknown name
    assert evaluate("1 / 0") is None


def test_script_constants_resolve_in_order():
    c = script_constants("const WAD = 10n ** 18n;\nconst RAY = WAD * WAD * 10n ** 9n;\nlet x = unknown();")
    assert c["WAD"] == 10 ** 18 and c["RAY"] == 10 ** 45 and "x" not in c


def test_scale_label_reads_naturally():
    assert scale_label(7_000 * 10 ** 45) == "7,000 RAD"
    assert scale_label(4 * 10 ** 26) == "0.4 RAY"
    assert scale_label(65 * 10 ** 16) == "0.65 WAD"
    assert scale_label(1800) == ""


# --- deploy side ----------------------------------------------------------


def test_extract_settings_reads_calls_scopes_values_and_resolves_contracts():
    got = {(s.contract, s.name, s.scope): s for s in extract_settings(DEPLOY_JS, "scripts/deploy-vault.js", {"Vault", "Gate"})}
    floor = got[("Vault", "floor", "")]
    assert floor.value == 7000 * 10 ** 45 and floor.kind == "param" and floor.line > 0
    line = got[("Vault", "line", "testIlk")]  # 3-arg file(ilk, what, value): scope is the ilk
    assert line.value == 125 * 10 ** 16
    assert got[("Gate", "vault", "")].value is None  # an address, not arithmetic
    assert ("Vault", "init", "") in got and got[("Vault", "init", "")].kind == "call"


def test_verify_asserts_are_extracted_with_expected_values():
    asserts = [s for s in extract_settings(VERIFY_JS, "scripts/verify-config.js", {"Vault"}) if s.kind == "assert"]
    assert {(a.contract, a.name): a.value for a in asserts} == {("Vault", "floor"): 5000 * 10 ** 45, ("Vault", "line"): 1}


def test_config_files_skip_node_modules_and_find_scripts(project):
    names = {p.name for p in find_config_files(project)}
    assert names == {"deploy-vault.js", "verify-config.js"}


# --- contract side --------------------------------------------------------


def test_extract_specs_reads_setter_checks_readers_constants_and_defaults():
    specs = {(s.contract, s.name, s.kind): s for s in extract_specs({"Vault.sol": VAULT_SOL})}
    line = specs[("Vault", "line", "setter")]
    assert any("data > _WAD" in c for c in line.checks) and "reverts OutOfBounds.selector" in line.checks
    floor = specs[("Vault", "floor", "setter")]
    assert "Vault.distribute" in floor.readers  # traced to where the variable is read
    assert specs[("Vault", "HOP", "constant")].default_value == 1800
    assert specs[("Vault", "MAX", "constant")].default_value == 100 * 10 ** 18
    assert specs[("Vault", "ceiling", "default")].default_expr == "_WAD / 4"


# --- the join and the flags ----------------------------------------------


def test_build_joins_flags_unset_mismatch_and_unmatched(project):
    check = build(project, {"contracts/Vault.sol": VAULT_SOL})
    rows = {(r.contract, r.param): r for r in check.rows}
    floor = rows[("Vault", "floor")]
    assert floor.human == "7,000 RAD" and floor.source == "scripts/deploy-vault.js:" + floor.source.split(":")[1]
    assert any("verify script expects" in f and "deploys" not in f for f in floor.flags)  # 5k asserted vs 7k deployed
    assert [u["param"] for u in check.unset] == ["ceiling"]
    assert "constructor sets _WAD / 4" in check.unset[0]["default"]
    assert any("Gate.typo" in u or "typo" in u for u in check.unmatched)
    assert any("Gate.vault" in w for w in check.wiring)  # an address argument is wiring, not a parameter


def test_reference_gap_is_flagged_only_beyond_tolerance(project):
    refs = [{"contract": "Vault", "param": "line", "value": "1.25", "context": "ref"},
            {"contract": "Vault", "param": "floor", "value": "1000", "context": "ref"}]
    check = build(project, {"contracts/Vault.sol": VAULT_SOL}, refs=refs)
    flags = {r.param: r.flags for r in check.rows}
    assert not any("upstream reference" in f for f in flags["line"])  # 1.25 vs 1.25: same
    assert any("upstream reference 1000" in f for f in flags["floor"])


# --- reviewer -------------------------------------------------------------


class FakeRouter:
    def __init__(self, reply, roles=("judge",)):
        self.reply, self.roles, self.calls = reply, set(roles), []

    def has(self, role):
        return role in self.roles

    async def chat_json(self, role, system, user, **kw):
        self.calls.append((role, system, user))
        return self.reply


REPLY = {
    "rows": [{"contract": "Vault", "param": "floor", "verdict": "flag", "reason": "unreachable buffer"}],
    "combinations": [{"params": ["Vault.floor", "Vault.line"], "concern": "floor exceeds line", "numbers": "7000 > 1.25"}],
    "magnitude_checks": [{"param": "Vault.floor", "threshold": "7,000", "max_reachable": "2,000", "reachable": False,
                          "reason": "income is 2,000/yr"}],
}


def test_review_sends_the_table_and_checklist_and_parses_the_reply(project):
    check = build(project, {"contracts/Vault.sol": VAULT_SOL})
    router = FakeRouter(REPLY)
    check.review = asyncio.run(review(router, "CHECKLIST-MARKER", check))
    role, system, user = router.calls[0]
    assert "CHECKLIST-MARKER" in system and '"humpFloor"' not in user
    assert '"param": "floor"' in user and "never_set_by_deploy" in user and "7,000 RAD" in user
    assert check.review["magnitude_checks"][0]["reachable"] is False
    md = render(check)
    assert "NOT REACHABLE" in md and "floor exceeds line" in md and "| Vault | floor |" in md


def test_notes_for_hunters_state_the_deployed_concerns(project):
    check = build(project, {"contracts/Vault.sol": VAULT_SOL})
    check.review = REPLY
    notes = notes_for_hunters(check)
    assert notes.startswith("DEPLOYED CONFIGURATION CONCERNS") and "NOT reachable" in notes and "unreachable buffer" in notes


def test_review_failure_is_recorded_and_no_role_is_a_noop(project):
    check = build(project, {"contracts/Vault.sol": VAULT_SOL})
    assert "error" in asyncio.run(review(FakeRouter({"rows": "bad"}), "", check))
    assert asyncio.run(review(FakeRouter(REPLY, roles=()), "", check)) == {}


def test_run_returns_none_without_scripts_and_writes_artifacts_with_them(project, tmp_path):
    files, _ = load(project)
    check = asyncio.run(run(project, files, router=FakeRouter(REPLY), kb_dir="kb"))
    assert isinstance(check, ConfigCheck) and check.review["combinations"]
    out = tmp_path / "out"
    out.mkdir()
    write_artifacts(out, check)
    assert json.loads((out / "config_check.json").read_text())["rows"]
    assert (out / "config_check.md").read_text().startswith("# Deploy / config cross-check")

    bare = tmp_path / "bare"
    (bare / "contracts").mkdir(parents=True)
    (bare / "contracts" / "A.sol").write_text("contract A {}")
    files, _ = load(bare)
    assert asyncio.run(run(bare, files, router=None)) is None
