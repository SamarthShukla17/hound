# Deploy / Config Parameter Cross-Check

> Loaded by the config cross-check. You are given a table of every parameter the deploy scripts
> set (with the evaluated value and its source line), what each contract setter accepts, where the
> variable is read, the parameters the deploy NEVER sets (they run on constructor defaults), and
> any upstream reference values. A parameter is only safe if it is safe TOGETHER with the others.
> Code that is correct for every value can still be dangerous at the values actually deployed.

## 1. Magnitude and reachability (the check machines skip)

For every threshold, floor, cap, target or buffer parameter, compute what the rest of the
configuration can actually produce and ask whether the threshold is reachable:

- A minimum/target buffer larger than the most the protocol can ever accumulate (income per year
  = ceiling x rate; a liquidation penalty x the liquidatable amount) is a function that never
  fires. State the arithmetic: the threshold, the maximum reachable quantity, the ratio.
- A ceiling smaller than a single legitimate operation, a dust floor above the ceiling, a rate
  that overflows a bound within the horizon the code documents.
- A time window compared against another time window (delay vs auction lifetime vs cooldown vs
  timelock vs pause maximum): state the ordering the code assumes and whether the values keep it.

## 2. Pairs and triples

Each value can be reasonable alone and dangerous together. Check at least:

- Every pair/triple that appears in one comparison, one formula, or one state machine.
- Sum-of-parts vs whole: per-asset ceilings against the global ceiling, per-item limits against
  a total limit.
- A start price/premium against the oracle's delay and the asset's volatility; a discount curve
  against the auction lifetime; a penalty against a threshold ratio.
- Anything configured in one script and asserted in another with a different value.

## 3. What is not set

Every setter branch the deploy never calls runs on a constructor default or zero. For each, say
whether the default is safe at the deployed scale, and whether "unset" is intended.

## 4. Against an upstream reference

Where a reference value is given (the upstream's real deployed or governance-approved number),
compare it and state the direction of the difference and what protection the reference value
provided that the deployed value does not. A difference is only a finding if the protection
matters in THIS system - say why.

## 5. Ranges the code assumes

For each setter, compare the bounds it enforces with the deployed value, and note any value the
setter accepts that would break a reader (zero, max, off-by-one at a bound).

## Output contract

Return ONLY a JSON object:
`{"rows": [{"contract": "...", "param": "...", "verdict": "safe|flag|unverified", "reason": "..."}],
"combinations": [{"params": ["A.x", "B.y"], "concern": "...", "numbers": "the arithmetic",
"verify": "how to confirm"}], "magnitude_checks": [{"param": "...", "threshold": "...",
"max_reachable": "...", "reachable": true|false, "reason": "..."}]}`.
Every number you state must be derivable from the table; never invent a deployed value.
