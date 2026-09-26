# FINDING TIERS: does the attacker END UP WITH MORE?

> Loaded into every hunter and judge prompt. Every finding must be classified at write-time, not
> only when someone asks. The classification changes how a finding is triaged, how it is scored and
> how much it can honestly claim.

## The question

After the attack, does the attacker hold **strictly more value than they started with, taken from
the protocol or from other users**? Answer by equity accounting, not by intuition.

- **profit** - yes. The attacker's net gain is positive after everything they paid.
- **disruption** - no. The protocol is degraded, frozen, breached, mis-accounted or someone else
  loses, but the attacker does not come out ahead (griefing, DoS, invariant violation).
- **unclear** - you could not complete the accounting. Say so; do not guess a tier.

## The equity test (write it into `attacker_gain`)

1. List everything the attacker holds BEFORE, in one unit (USD or the protocol's stable).
2. List everything they hold AFTER. Count locked collateral at what it costs to unlock it; count
   debt they still owe as a negative; count assets received.
3. Subtract every cost: capital they must lock or borrow, fees, penalties, rewards forgone, gas.
4. Name the SOURCE of any gain: whose loss is it?
5. State the result as one line with numbers, e.g. `+50.7 STABLE per 100 debt liquidated, taken from a named counterparty` or `none: equity change 0 at par`.

A gain that exists only if an external market price differs from the protocol's assumption (a
depeg, a rebound, a favourable rate) is CONDITIONAL. Classify it `disruption`, and state the
condition and the size in `attacker_gain`: it cannot be proven on-chain and must not be sold as
theft.

## Severity follows the tier

- **profit**: severity scales with the size of the gain and whether it repeats. Quantify both.
  A gain that needs an extreme market move to exist is not the same as one that needs none.
- **disruption**: `high`/`critical` requires a PERMANENT freeze of user funds or realized
  insolvency, stated and traced. Otherwise medium at most. "Temporary", "recoverable by governance"
  and "recoverable by anyone repaying" are all reasons to stay at low/medium.

## Patterns that decided real cases (learn the shape, not the protocol)

- Exceed a limit by transiently inflating an aggregate, then reversing it: the equity change is ZERO. Disruption (the limit is defeated), with a conditional profit only if an external price later differs from the protocol's assumption.
- Liquidate your own position and buy your own collateral: NET LOSS (the penalty), never a profit.
- Atomic trigger-and-buy against a stale reference price, when the market has since moved: PROFIT, paid by the counterparty, sized by how far the market moved.
- Unrecorded liability that trips a consistency check: disruption, and recoverable by whoever settles it.

## Output

Add to the finding: `"value_flow": "profit|disruption|unclear"` and `"attacker_gain": "one line
with numbers, or 'none'"`. A `profit` classification with no stated gain is downgraded to `unclear`.
