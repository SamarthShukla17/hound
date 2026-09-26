"""Step B: upstream detection, cached fetch, the review orchestration and its artifacts.
No network: the fetcher is injected and the router is a fake."""

import asyncio
import json
import textwrap

import pytest

from hound.codebase import load
from hound.deviation_review import (
    _vendored_filter, hunter_notes, render_report, resolve_upstream, to_dict, upstream_diff, write_artifacts,
)
from hound.upstream import detect, fetch, gather_target_text, load_registry

REGISTRY = textwrap.dedent(
    """\
    upstreams:
      maker-dss:
        name: MakerDAO dss
        min_hits: 2
        detect: ['makerdao|maker\\s*dao|\\bdss\\b', '\\bvat\\b|\\bvow\\b', '\\bfrob\\b|\\bbark\\b']
        sources:
          - repo: makerdao/dss
            ref: master
            files: [src/vat.sol]
        contract_hints: {VaultEngine: [Vat]}
        function_aliases: {}
        reference_params: []
      openzeppelin:
        name: OpenZeppelin
        vendored_only: true
        min_hits: 1
        detect: ['openzeppelin']
        sources:
          - repo: OpenZeppelin/openzeppelin-contracts
            ref: master
            files: [contracts/utils/math/Math.sol]
    """
)

UPSTREAM_VAT = textwrap.dedent(
    """\
    contract Vat {
        function frob(int dink, int dart) external {
            require(live == 1, "Vat/not-live");
            require(tab <= _mul(urn.ink, ilk.spot), "Vat/not-safe");
        }
    }
    """
)

FORK = textwrap.dedent(
    """\
    contract VaultEngine {
        function frob(int256 dink, int256 dart) external {
            if (tab >= Math.umul(urn.ink, ilk.spot)) _revert(NotSafe.selector);
        }
    }
    """
)

REVIEW_REPLY = {
    "classification": "regression", "risk": "high",
    "summary": "the not-live guard was dropped and the safety comparison flipped",
    "deviations": [
        {"upstream": "src/vat.sol:3", "target": "src/VaultEngine.sol:3", "what": "live guard removed",
         "why_it_matters": "frob works after shutdown", "invariant_at_risk": "no debt after cage"},
    ],
    "worth_hunting": True, "hunt_hint": "call frob after cage",
}


class FakeRouter:
    def __init__(self, reply=REVIEW_REPLY, roles=("judge",), error=None):
        self.reply, self.roles, self.error, self.calls = reply, set(roles), error, []

    def has(self, role):
        return role in self.roles

    async def chat_json(self, role, system, user, *, temperature=0.3, **_):
        self.calls.append({"role": role, "system": system, "user": user})
        if self.error:
            raise self.error
        return self.reply


@pytest.fixture
def registry_file(tmp_path):
    p = tmp_path / "upstreams.yaml"
    p.write_text(REGISTRY)
    return p


@pytest.fixture
def target(tmp_path):
    root = tmp_path / "proj"
    (root / "src").mkdir(parents=True)
    (root / "README.md").write_text("A fork of MakerDAO's dss: vat and vow, with frob and bark.")
    (root / "src" / "VaultEngine.sol").write_text(FORK)
    files, _ = load(root)
    return root, files


def _fetcher(calls):
    def fetch_one(url):
        calls.append(url)
        return UPSTREAM_VAT
    return fetch_one


# --- detection / registry ------------------------------------------------


def test_registry_loads_and_builds_raw_urls(registry_file):
    reg = load_registry(registry_file)
    assert set(reg) == {"maker-dss", "openzeppelin"}
    assert reg["maker-dss"].raw_urls() == [
        ("src/vat.sol", "https://raw.githubusercontent.com/makerdao/dss/master/src/vat.sol")
    ]


def test_shipped_registry_is_valid_and_detects_a_maker_fork():
    reg = load_registry()
    assert "maker-dss" in reg and reg["maker-dss"].reference_params
    text = "Direct adaptation of MakerDAO. VaultEngine is the vat, BalanceSheet is the vow; frob and bark."
    assert detect(text, reg)[0][0].key == "maker-dss"
    assert detect("An ERC721 marketplace with royalties.", reg) == []


def test_detection_needs_min_hits_not_one_stray_word(registry_file):
    reg = load_registry(registry_file)
    assert detect("we mention vat once", reg) == []
    assert detect("makerdao fork with frob", reg)[0][0].key == "maker-dss"


def test_target_text_includes_readme_and_source_comments(tmp_path):
    root = tmp_path / "p"
    (root / "src").mkdir(parents=True)
    (root / "README.md").write_text("hello")
    (root / "src" / "A.sol").write_text("// adapted from Maker's vat\ncontract A {}\n")
    files, _ = load(root)
    text = gather_target_text(root, files)
    assert "hello" in text and "adapted from Maker's vat" in text


def test_resolve_upstream_off_auto_and_named(registry_file):
    reg = load_registry(registry_file)
    assert resolve_upstream("off", "makerdao vat frob", reg) is None
    assert resolve_upstream("auto", "makerdao vat frob", reg).key == "maker-dss"
    assert resolve_upstream("auto", "nothing relevant", reg) is None
    assert resolve_upstream("openzeppelin", "", reg).key == "openzeppelin"
    with pytest.raises(ValueError):
        resolve_upstream("nope", "", reg)


# --- fetch ---------------------------------------------------------------


def test_fetch_caches_and_second_call_makes_no_request(registry_file, tmp_path):
    up = load_registry(registry_file)["maker-dss"]
    calls = []
    sources, failures = fetch(up, tmp_path / "cache", _fetcher(calls))
    assert sources == {"src/vat.sol": UPSTREAM_VAT} and failures == [] and len(calls) == 1
    fetch(up, tmp_path / "cache", _fetcher(calls))
    assert len(calls) == 1  # served from the cache


def test_fetch_failure_is_reported_never_guessed(registry_file, tmp_path):
    import urllib.error

    def boom(url):
        raise urllib.error.URLError("offline")

    sources, failures = fetch(load_registry(registry_file)["maker-dss"], tmp_path / "c", boom)
    assert sources == {} and "src/vat.sol" in failures[0]


def test_vendored_filter_keeps_only_files_the_target_ships_itself():
    ups = {"contracts/utils/math/Math.sol": "x"}
    tg = {"src/Math.sol": "a", "node_modules/@oz/Math.sol": "b", "src/Other.sol": "c", "lib/x/Math.sol": "d"}
    assert set(_vendored_filter(tg, ups)) == {"src/Math.sol"}


# --- orchestration -------------------------------------------------------


def _run(target, registry_file, tmp_path, **kw):
    root, files = target
    return asyncio.run(
        upstream_diff(root, files, kb_dir="kb", cache_dir=tmp_path / "cache", registry_path=registry_file,
                      fetcher=_fetcher([]), **kw)
    )


def test_end_to_end_review_flags_the_regression(target, registry_file, tmp_path):
    router = FakeRouter()
    diff = _run(target, registry_file, tmp_path, router=router)
    assert diff.upstream_key == "maker-dss"
    assert len(router.calls) == 1
    call = router.calls[0]
    assert "Vat/not-live" in call["user"] or "live == 1" in call["user"]  # the real upstream body is shown
    assert "DETERMINISTIC STATEMENT DIFFERENCES" in call["user"]
    assert "Deviation Review" in call["system"]  # kb/DEVIATION_REVIEW.md is loaded

    d = to_dict(diff)
    assert d["pairs"][0]["review"]["risk"] == "high"
    assert d["pairs"][0]["target_loc"].startswith("src/VaultEngine.sol:")
    report = render_report(diff)
    assert "Deviations that need a human" in report and "live guard removed" in report
    assert "call frob after cage" in report


def test_hunter_notes_carry_the_flagged_deviations(target, registry_file, tmp_path):
    notes = hunter_notes(_run(target, registry_file, tmp_path, router=FakeRouter()))
    assert notes.startswith("UPSTREAM DEVIATIONS")
    assert "VaultEngine.frob" in notes and "regression/high" in notes


def test_no_reviewer_role_still_produces_the_deterministic_report(target, registry_file, tmp_path):
    diff = _run(target, registry_file, tmp_path, router=FakeRouter(roles=()))
    assert diff.reviews == {}
    report = render_report(diff)
    assert "Not reviewed by a model" in report and "VaultEngine.frob" in report
    assert hunter_notes(diff) == ""  # nothing reviewed -> nothing claimed


def test_reviewer_error_is_recorded_not_fatal(target, registry_file, tmp_path):
    diff = _run(target, registry_file, tmp_path, router=FakeRouter(reply={"nonsense": True}))
    assert "error" in diff.reviews[0]
    assert "Not reviewed by a model" in render_report(diff)


def test_review_cap_reports_what_it_skipped(target, registry_file, tmp_path):
    diff = _run(target, registry_file, tmp_path, router=FakeRouter(), max_pairs=0)
    assert diff.reviews == {} and diff.skipped == ["VaultEngine.frob"]
    assert "beyond the review cap" in render_report(diff)


def test_off_and_undetected_return_none(target, registry_file, tmp_path):
    root, files = target
    kw = dict(kb_dir="kb", cache_dir=tmp_path / "c", registry_path=registry_file, fetcher=_fetcher([]))
    assert asyncio.run(upstream_diff(root, files, choice="off", **kw)) is None
    (root / "README.md").write_text("an unrelated NFT marketplace")
    files, _ = load(root)
    (root / "src" / "VaultEngine.sol").write_text("contract Nft { }")
    files, _ = load(root)
    assert asyncio.run(upstream_diff(root, files, **kw)) is None


def test_artifacts_are_written(target, registry_file, tmp_path):
    diff = _run(target, registry_file, tmp_path, router=FakeRouter())
    out = tmp_path / "run"
    out.mkdir()
    write_artifacts(out, diff)
    data = json.loads((out / "upstream_diff.json").read_text())
    assert data["upstream"] == "maker-dss" and data["pairs"][0]["review"]["risk"] == "high"
    assert (out / "upstream_diff.md").read_text().startswith("# Upstream diff vs MakerDAO dss")
