"""Third-party findings adapter: import without provenance, but never without checking that
the citations point at real code."""

import json

import pytest

from hound.codebase import Src
from hound.external import (
    EXTERNAL_MARK, SEVERITY_BUCKETS, load_entries, resolve_citations, to_findings, write_run_dir,
)


@pytest.fixture
def files():
    return [Src(path="src/Vault.sol", lines=[f"line_{i}" for i in range(1, 301)])]


ENTRIES = [
    {"title": "Real one", "severity": "critical", "location": "src/Vault.sol:12-14", "root_cause": "rc1"},
    {"title": "Points nowhere", "severity": "high", "location": "src/NoSuch.sol:5", "root_cause": "rc2"},
    {"title": "Past the end", "severity": "low", "location": "src/Vault.sol:99999", "root_cause": "rc3"},
]


def test_load_entries_accepts_a_bare_list_and_a_wrapped_object(tmp_path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps(ENTRIES))
    assert len(load_entries(p)) == 3
    p.write_text(json.dumps({"findings": ENTRIES}))
    assert len(load_entries(p)) == 3


def test_unresolvable_citations_are_reported_not_silently_accepted(files):
    """Our own runs kill a finding whose citation does not resolve. An import skips that gate,
    so the count must at least be measurable or the comparison flatters the imported set."""
    resolved, unresolved = resolve_citations(ENTRIES, files)
    assert [e["title"] for e, _ in resolved] == ["Real one"]
    assert {e["title"] for e, _ in unresolved} == {"Points nowhere", "Past the end"}


def test_findings_are_marked_external_and_unverified(files):
    out = to_findings(ENTRIES, files, source="pashov")
    assert all(f["external"] and f["provenance_verified"] is False for f in out)
    assert all(f["source"] == "pashov" for f in out)
    assert out[0]["verdict"]["reason"] == EXTERNAL_MARK


def test_citation_resolution_is_recorded_per_finding(files):
    out = to_findings(ENTRIES, files, source="x")
    assert [f["citation_resolves"] for f in out] == [True, False, False]
    assert out[0]["cited"] and not out[1]["cited"]


def test_ids_are_assigned_in_input_order(files):
    assert [f["id"] for f in to_findings(ENTRIES, files, source="x")] == ["F001", "F002", "F003"]


def test_mechanism_fields_are_left_empty_not_invented(files):
    """The third party supplied title/location/root_cause only. Filling observation/invariant/
    violation would put words in their mouth and could earn credit they did not claim."""
    f = to_findings(ENTRIES, files, source="x")[0]
    assert f["observation"] == "" and f["invariant"] == "" and f["violation"] == ""
    assert f["root_cause"] == "rc1"


def test_written_run_dir_is_readable_by_the_scorer_and_declares_no_provenance(tmp_path, files):
    from hound.runs import read_findings

    out = write_run_dir(tmp_path / "ext", to_findings(ENTRIES, files, source="pashov"),
                        source="pashov", bucket="high")
    meta, findings = read_findings(out)
    assert meta["provenance"] is None      # so score's provenance check WARNS, as it should
    assert meta["external"] is True and meta["source"] == "pashov"
    assert len(findings) == 3


def test_findings_survive_score_s_advisory_selection(tmp_path, files):
    """advisory + keep verdict + not hard_kill => every imported finding is actually graded."""
    from hound.score import select_scored

    findings = to_findings(ENTRIES, files, source="x")
    assert len(select_scored(findings, "advisory", False, False)) == 3


def test_severity_buckets_split_the_scored_leads_from_the_low_noise():
    assert SEVERITY_BUCKETS["high"] == ("critical", "high", "medium")
    assert SEVERITY_BUCKETS["low"] == ("low",)
