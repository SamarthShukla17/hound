"""Cost governor: a per-invocation dollar ceiling for bloodhound's own commands.

hound/llm.py's Router already computes exact cost via `report()` (usage tracked by model,
priced from models.yaml) - this module adds no new cost accounting, it only reads that number
after each unit of work and decides whether to keep going. The Forger's repair loops, the
Panel's swapped refuter pairs, and the Invariant Engine's handler generation are the most
LLM-call-heavy things bloodhound does, and had no ceiling at all before this - hound's own scan
has never needed one written down because a human watches it run in real time, but a bloodhound
command can walk many candidates unattended.

On breach: stop starting new work, keep whatever already finished, exit code 3 (distinct from
1, "ordinary failure", so a caller can tell "ran out of money" from "broke").
"""

BUDGET_EXCEEDED_EXIT_CODE = 3


class CostGovernor:
    """Call `check()` after each unit of work (one candidate, one claim). Once breached, stays
    breached - a report() that exceeds the ceiling once must not later look "fine" just because
    a cheaper candidate came next."""

    def __init__(self, router, max_cost_usd: float | None):
        self.router = router
        self.max_cost_usd = max_cost_usd
        self.breached = False

    def spent(self) -> float:
        return self.router.report().get("total_usd", 0.0) if self.router is not None else 0.0

    def check(self) -> bool:
        """True if work may continue."""
        if self.max_cost_usd is None or self.router is None:
            return True
        if self.breached or self.spent() > self.max_cost_usd:
            self.breached = True
            return False
        return True
