"""Step O: manifest — persists what Router.report() already computes, plus ceiling/breach state."""

import json

from bloodhound.costgov import CostGovernor
from bloodhound.manifest import build, write


class FakeRouter:
    def __init__(self, report):
        self._report = report

    def report(self):
        return self._report


def test_build_with_no_router_has_null_cost_report():
    m = build("run-pocs", {"run_dir": "/r"}, router=None)
    assert m == {"command": "run-pocs", "args": {"run_dir": "/r"}, "cost_report": None}


def test_build_includes_router_report_verbatim():
    router = FakeRouter({"total_usd": 1.23, "models": []})
    m = build("run-pocs", {"run_dir": "/r"}, router)
    assert m["cost_report"] == {"total_usd": 1.23, "models": []}
    assert "max_cost_usd" not in m  # no governor given -> no ceiling fields


def test_build_includes_governor_ceiling_and_breach_state():
    router = FakeRouter({"total_usd": 5.0})
    gov = CostGovernor(router, max_cost_usd=1.0)
    gov.check()  # breaches
    m = build("invariants", {}, router, gov)
    assert m["max_cost_usd"] == 1.0
    assert m["breached"] is True


def test_write_round_trips_to_disk(tmp_path):
    router = FakeRouter({"total_usd": 0.5})
    path = tmp_path / "manifest.json"
    write(path, "run-pocs", {"run_dir": "/r"}, router)
    out = json.loads(path.read_text())
    assert out["command"] == "run-pocs"
    assert out["cost_report"]["total_usd"] == 0.5
