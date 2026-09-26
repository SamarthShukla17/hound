# Hound Calibration Notes — contest-A Run (2026-09-25)

> Lessons from the 23-finding run where ALL findings were killed by the judge.
> Use these to tune hunter prompts and judge thresholds for future runs.

---

## False Positive Categories (23 findings, 0 survived)

| Category              | Count | Finding IDs           | Pattern                                                    |
|-----------------------|-------|-----------------------|------------------------------------------------------------|
| Trusted-admin powers  | 2     | F001, F008            | "ward can do X" — X is the intended admin capability       |
| By-design behavior    | 3     | F002, F009, F015      | Feature misread as bug (grab accounting, fee recipient)    |
| Known/duplicate       | 2     | F004, F020            | Matched KNOWN-1 (stale spot) and KNOWN-2 (thaw deadlock)  |
| Logic error in claim  | 8     | F003,F010-F013,F017,F021,F022 | Hunter's own reasoning was wrong (math inverted, wrong line) |
| Scope exclusion       | 2     | F005, F014            | Admin misconfiguration / centralization risk (out of scope)|
| Misread code          | 4     | F006,F007,F016,F019   | Claimed missing check that actually exists                 |
| Sequence impossible   | 2     | F018, F023            | Described attack sequence can't execute (blocked by prior check) |

---

## Key Failure Modes

### 1. "Ward can do X" (F001, F005, F008, F017)
Hunters repeatedly flag ward-gated functions as vulnerabilities. The judge correctly
kills these, but they waste budget. **Fix:** Add a pre-filter in the hunter prompt:
"If the function is ward-gated (onlyRole(_WARD_ROLE)), the caller is a trusted admin.
Admin exercising intended powers is NOT a finding unless it violates a documented
invariant even when used correctly."

### 2. Math/logic errors in the hunter's own reasoning (F003, F012, F013, F021)
The hunter constructs a plausible-sounding attack narrative but gets the arithmetic
wrong (e.g., claims a ledger function mints more than it should, but the actual calculation
shows exact accounting). **Fix:** Require hunters to show the concrete numerical
example: "Given art=X, rate=Y, dart=Z, the resulting debt is W, but the credited
amount is V, so the discrepancy is W-V." Force the numbers before the narrative.

### 3. Claiming a missing check that exists (F006, F007, F016, F022)
Hunter says "no X check" when the check is present on a different line than expected.
**Fix:** When a hunter claims "missing check," the citation gate should verify: grep
for the check keyword in the function AND its callers. If found, kill before judge.

### 4. Known issues not filtered (F004, F020)
Two findings matched known issues that should have been filtered by the scope gate.
**Fix:** Feed the FULL known.md file to the scope gate (see memory: feed-full-known-file),
including DEAD ENDS. Don't summarize — the summary drops the dead ends and causes
the hunter to re-derive the same (falsified) angle.

---

## What the Hound MISSED

The one confirmed novel finding (a gateway bypass through a permissionless lower-level operation) was NOT found by any
of the 23 hound findings. This is significant because:

1. It requires cross-subsystem reasoning (a permissionless ledger operation + the gateway's reserve accounting) — the hound's per-function lens doesn't naturally surface this.
2. It's a **griefing/lock** impact, not theft — the hound's hunters are biased toward
   theft-class findings (reflected in severity assignments of "critical" on most FPs).
3. The bypass is through an ABSENCE (no role gate on the lower-level operation) rather than
   a PRESENCE (buggy code). Absence bugs require the hunter to reason about what
   SHOULD be there, not what IS there.

**Fix for future runs:**
- Add Attack Angle 2 (cross-subsystem) and Angle 5 (permanent-lock lens) as explicit
  hunter lenses, not just methodology advice.
- Add Pattern 7 (permissionless gateway bypass) to BUG_PATTERNS.md [DONE].
- Add a "griefing/DoS" severity tier to hunter prompts — currently hunters jump to
  "critical" because they're primed for theft, which the judge then kills as
  overwseverity.

---

## Judge Performance

The judge killed all 23 correctly (100% precision on kills). One finding (F018)
timed out the judge (300s budget exhausted) and required manual falsification.

**Recommendation:** Increase judge timeout to 600s or add a "needs_manual_review"
tier for timeout cases instead of leaving them as false negatives.

---

## Pashov External Run — Scope Failure

The Pashov skill's external run produced findings about vesting/marketplace contracts
instead of contest-A contracts. Root cause: likely misconfigured scope or wrong target
directory passed to the skill.

**Fix:** Add a scope-verification pre-flight step: after the Pashov skill produces
findings, check that every finding's file path is within the configured scope glob.
If >50% of findings reference out-of-scope files, abort and report the scope mismatch.


---

## Update: profit-vs-disruption classification (contest-A follow-up hunt)

**What changed the assessment.** The first pass hunted "what breaks" and produced a family of findings
that all disrupted the protocol (a limit defeated, a consistency check tripped, a function reverting). A second pass asked one explicit question instead - *does the attacker end with more
value than they started with, taken from someone else?* - and answered it with equity accounting, not
intuition. Three things followed that the disruption lens had missed or overstated:

- One mechanism that looked like theft had an attacker equity change of **exactly zero at par**: it was
  disruption, with a profit that exists only if an external price later differs from the protocol's
  assumption. It was reclassified, and its severity lowered, on that basis.
- One mechanism was a
  **real, quantified profit at another user's expense** that the disruption lens had never surfaced.
- A "self-liquidation profit" hypothesis had a **negative** equity change (the penalty) and died in one
  test.

**Now structural.** Every finding carries `value_flow` (profit | disruption | unclear) and
`attacker_gain` (the equity accounting in one line). The definition and the equity test live in
`kb/FINDING_TIERS.md` and are in every hunter and judge system prompt; the judge recomputes the tier
instead of trusting the candidate; `hound/tiers.py` flags a high/critical severity that its tier does
not support (a disruption finding with no permanent-freeze, theft or insolvency claim; a profit
finding with no quantified gain). A profit claim with no stated gain is downgraded to `unclear`, never
dropped: a dropped finding is lost recall.

**Read the tier counts in `report.md` first.** A run whose findings are all `disruption` or
`unclassified` has not been hunted for profit; rerun with attention on value flow, not more lenses.

## Update: things a scan can now do that the contest-A run had to do by hand

| Capability | Command / flag | What it found or closed in practice |
|---|---|---|
| Literal upstream diff | `hound diff`, `scan --upstream` | The deviations from the upstream (a dropped division, a changed level ordering, a renamed factor, removed functions); closed a "regression?" thread with the upstream source as proof |
| Deploy/config cross-check | `hound config-check`, `scan --config-check` | A configured floor that the quantity it bounds could never reach; a premium parameter far thinner than the upstream's; several parameters left on defaults |
| Coverage gaps | `hound coverage`, `scan --coverage` | Untested state-transition branches (auction bookkeeping, liquidation dust rules) ranked above trivial guards |
| Chained findings | `hound chain RUN_DIR` | Mechanical check that two findings on one mechanism do not combine into a profit |
