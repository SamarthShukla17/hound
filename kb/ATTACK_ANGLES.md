# Attack Angles — how to look, not what to look for

> Load alongside METHODOLOGY.md and BUG_PATTERNS.md.
> BUG_PATTERNS is a library of known bug *shapes*. This is a library of *vantage
> points* — ways to position the analysis so bugs become visible that a single
> per-function read cannot see. Run a target through MULTIPLE angles; the same code
> yields different findings depending on where you stand. A "clean" result from one
> angle is not clean until the other angles have also been walked.

---

## Why angles matter

A per-function invariant check (the default) asks "is THIS function correct in
isolation?" Most real, non-duplicate findings answer a different question — one that
only appears when you change vantage point:
- correct functions composed in a bad *order*
- correct functions sharing *state* that one corrupts for another
- a function that's safe for the caller but weaponizable against a *third party*
- a value that's fine at normal magnitude but breaks at an *extreme* the tests
  never probed

Auditors who only find duplicates use one angle. Auditors who find the unique bug
switched vantage points. Walk every target through the checklist below; note which
angles a given pass actually exercised, so "negative" means "negative from all
angles," not "negative from the obvious one."

---

## Angle 1 — State-machine / sequencing

**Stand here:** ignore individual functions; look at the contract as a state machine.
Enumerate its states (uninitialized, active, frozen, paused, round-1, round-2, vesting,
claimed, closed…) and the transitions between them. Then ask: what happens if calls
arrive in an order the developer didn't picture?

**Questions:**
- Can a function meant for state X be called in state Y with a harmful effect?
- At each transition boundary (freeze, round-switch, pause, upgrade), is every
  value that carried over still valid under the new state's assumptions?
- Can a transition be triggered early, skipped, repeated, or reversed?
- Is there a state a value gets *stuck* in (→ permanent lock)?

**Why it finds what per-function misses:** each function can be individually correct
while the *sequence* violates an invariant no single function owns.

---

## Angle 2 — Cross-subsystem interaction

**Stand here:** the contract has ≥2 subsystems (sale + vesting, deposit + rewards,
collateral + liquidation). Each may be internally sound. Play them against each other.

**Questions:**
- Does subsystem A write state that subsystem B reads under a different assumption?
- Is there a shared resource (a balance, a reserve, a counter) both draw on, where
  A's legitimate use starves or corrupts B?
- Can a sequence that crosses subsystems (vest → claim → burn → re-vest) reach an
  accounting state no single subsystem guards?

**Why it finds what per-function misses:** the invariant lives *between* subsystems;
no single function's checks cover the seam.

---

## Angle 3 — Adversarial third-party (weaponize a function against someone else)

**Stand here:** stop asking "can I profit by calling this?" Ask "can I HARM another
user by calling this, or by making them call it in a state I control?"

**Questions:**
- Can I front-run/grief a victim's action to make it fail or misprice? (front-run may
  be out of scope — check — but the *griefing/lock* result may still be in scope)
- Can I put a shared contract into a state where a victim's normal call now hurts them
  (reverts permanently, mints them zero, locks their funds)?
- Can I register/set something on a victim's behalf that constrains them later?
- Is there any "anyone can call this for account X" function I can abuse against X?

**Why it finds what per-function misses:** self-profit analysis misses pure-harm bugs;
"griefing / permanent lock with no attacker profit" is a real in-scope impact class.

---

## Angle 4 — Extreme values & boundaries

**Stand here:** the happy-path tests used normal numbers. Stand at the edges.

**Questions:**
- First actor (empty pool, zero supply, first mint), last actor (draining to zero).
- 1 wei, 1 unit, `type(uint).max`, exactly-at-a-cap, one-over, one-under.
- Tokens with unusual decimals (2, 0, 24) if in scope; dust amounts; a value that
  rounds to zero.
- Time at boundaries: exactly at a deadline, one second before/after, zero elapsed,
  a very long elapsed.
- What reverts that shouldn't (→ lock), what succeeds that shouldn't (→ theft)?

**Why it finds what per-function misses:** correctness at normal magnitude ≠
correctness at the boundary; rounding, precision, and off-by-one live only at edges.

---

## Angle 5 — The permanent-lock lens (impact-first, not vector-first)

**Stand here:** most auditors hunt *theft* and underweight *permanent lock*, which is
usually an equally-rewarded in-scope impact. Flip it: assume you don't want to steal,
you want to *trap* — funds, or the contract itself, forever.

**Questions:**
- Can an unprivileged actor drive any counter/flag/state to a value that blocks a
  withdrawal path permanently?
- Is there an `exists`/`initialized`/`claimed` flag that, once set wrong, can never be
  cleared, stranding funds?
- Can a required precondition for withdrawal be made permanently unsatisfiable?
- Can the contract be forced into a paused/frozen/reverting state with no recovery?
- DoS that doesn't self-heal — a loop that can be made unbounded, a call that always
  reverts after a certain point.

**Why it finds what per-function misses:** theft-focused passes structurally skip the
lock class; the bug is in what *can't happen anymore*, not in a value that moved.

---

## Angle 6 — Trust-edge / assumption audit (the systemic lens)

**Stand here:** list every place this code believes something without verifying it —
every input, every value read from another contract, every "the caller wouldn't do
that." Each unverified belief is a candidate.

**Questions:**
- What does this function take on faith about its arguments? (a passed amount matching
  a real transfer, an address being what it claims, a flag being honestly set)
- What does it read from another contract and treat as truth? Can that be controlled?
- What does it assume about *when* it's called, or *who* has called something else
  first?
- For each belief: is it enforced, or just assumed? An unenforced assumption is the
  bug.

**Why it finds what per-function misses:** the vulnerability isn't in the code that's
present — it's in the *check that's absent* because a belief went unquestioned.

---

## Angle 7 — Griefer-with-no-profit-motive

**Stand here:** assume an attacker who gains nothing financially and only wants to
break the protocol or a user. Removes the "is it economically rational?" filter that
makes you dismiss real bugs.

**Questions:**
- What's the cheapest action that causes damage disproportionate to its cost?
- Can I permanently break a mechanism for everyone by sacrificing a small amount?
- Is there a "poison" input I can plant that makes a later legitimate operation fail?

**Why it finds what per-function misses:** economic-rationality analysis wrongly
discards attacks where the attacker's payoff is someone else's loss, not their gain —
and "griefing / damage to protocol" is often explicitly in-scope.

---

## How to run a target through angles (the discipline)

1. Do the default per-function invariant pass first (BUG_PATTERNS shapes).
2. Then EXPLICITLY re-walk the target through each angle above, one at a time.
   Changing vantage point is the point — don't merge them into one blurry read.
3. For each angle, note: exercised? what did it surface? Anything that survives its
   falsification → candidate.
4. "Clean negative" is only earned when EVERY angle has been walked and each came
   back clean. A negative from angle 0 alone is not a negative — it's an unfinished
   audit.
5. Time-box per angle on low-EV targets; a fresh angle that comes back clean twice is
   telling you the target is solid — bank the negative and move on rather than
   inventing angle 8.

---

## Note on target choice (unchanged truth)

Angles sharpen the AUDIT; they don't fix a bad TARGET. A freshly-audited single
contract has little surface for any angle — that's why it closes negative from every
direction. These angles pay off most on multi-subsystem protocols with real state
machines and cross-component trust edges. Use them to go deeper where depth is
warranted, not to manufacture findings where the code is simply solid.
