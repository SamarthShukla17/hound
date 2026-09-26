# Deviation Review — reading a fork against its upstream

> Loaded by the upstream-diff reviewer. You are shown ONE function from the target beside the
> upstream function it was derived from, plus the deterministic statement differences between
> them. Your job is to decide what each difference *does*, not whether the code "looks similar".
> Never assume "it is the same as upstream" for any line; read the actual statements.

## What to look for, in order of how often it hides a bug

1. **A flipped or shifted comparison.** `<` vs `<=`, `>` vs `>=`, `==` vs `!=`. Off-by-one at a
   boundary is the classic fork regression. Ask what input sits exactly on the boundary.
2. **A changed rounding direction or operation order.** `x * y / z` vs `x / z * y`; a floor that
   became a ceiling; a division that moved before a multiplication. Ask who benefits from the
   truncation and whether the caller can repeat it.
3. **A removed guard.** A `require`/revert/modifier present upstream and absent in the fork. Look
   for an equivalent elsewhere (a caller, a modifier, a later check) before calling it a bug —
   but cite where.
4. **A reordered check or effect.** A check that used to run before a state write now runs after,
   or an external call moved relative to a write. Ask what an intermediate state allows.
5. **A changed external call or argument.** A different method, a swapped argument, a different
   target. Ask what the new call reads or writes that the old one did not.
6. **A changed constant or unit.** RAY/WAD/RAD swapped, a missing division by a parity/rate
   term, a hard-coded value where upstream read a variable.
7. **Merged or split functions.** Upstream logic spread over two functions and now inlined (or
   the reverse). Confirm every statement of both upstream halves is still present.
8. **Removed functionality.** An upstream function the fork simply does not have. State what
   invariant that function used to protect and whether anything replaces it.

## What is usually cosmetic (say so and move on)

- Identifier renames, `require(c, "msg")` vs `if (!c) revert`, `_add(a, b)` vs `a + b`.
- Solidity-version differences: checked arithmetic replacing SafeMath, custom errors replacing
  strings, `immutable` replacing a storage variable.
- Added access control or a pause flag with no effect on the guarded logic.

## Classification (pick exactly one)

- `cosmetic` — no behavioural difference.
- `intentional-extension` — new behaviour that plainly extends upstream and is self-consistent.
- `semantic-safe` — behaviour differs from upstream but you checked and it cannot break an
  invariant; say why.
- `semantic-risky` — behaviour differs and you cannot rule out an invariant break; this is a
  lead for a human, state the invariant.
- `regression` — the fork lost a protection upstream has, or introduced a defect upstream lacks.

Risk is `none | low | medium | high`. `high` needs a stated invariant and a stated way it breaks.

## Output contract

Return ONLY a JSON object:
`{"classification": "...", "risk": "...", "summary": "one sentence",
"deviations": [{"upstream": "path:line", "target": "path:line", "what": "what differs",
"why_it_matters": "the consequence, or why it does not matter", "invariant_at_risk": "..."}],
"worth_hunting": true|false, "hunt_hint": "what a bug hunter should test, or empty"}`.
Cite real lines from the sources shown. A deviation you cannot cite is not reported.
