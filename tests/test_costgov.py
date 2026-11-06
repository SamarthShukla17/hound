"""Step O: cost governor — latches breached, never un-breaches, no-router/no-ceiling is a noop."""

from bloodhound.costgov import CostGovernor


class FakeRouter:
    def __init__(self, spend_sequence):
        self.spend_sequence = list(spend_sequence)

    def report(self):
        return {"total_usd": self.spend_sequence.pop(0)}


def test_no_ceiling_always_allows():
    gov = CostGovernor(FakeRouter([0.0, 100.0]), max_cost_usd=None)
    assert gov.check() is True
    assert gov.check() is True
    assert gov.breached is False


def test_no_router_always_allows():
    gov = CostGovernor(None, max_cost_usd=1.0)
    assert gov.check() is True
    assert gov.spent() == 0.0


def test_allows_while_under_ceiling_then_breaches():
    gov = CostGovernor(FakeRouter([0.5, 0.9, 1.5]), max_cost_usd=1.0)
    assert gov.check() is True
    assert gov.check() is True
    assert gov.check() is False
    assert gov.breached is True


def test_breach_latches_even_if_a_later_spend_looks_lower():
    router = FakeRouter([2.0])
    gov = CostGovernor(router, max_cost_usd=1.0)
    assert gov.check() is False
    assert gov.breached is True
    # once breached, check() short-circuits and never calls report() again
    assert gov.check() is False
    assert router.spend_sequence == []  # report() was never consulted a second time


def test_exactly_at_ceiling_is_not_a_breach():
    gov = CostGovernor(FakeRouter([1.0]), max_cost_usd=1.0)
    assert gov.check() is True
    assert gov.breached is False
