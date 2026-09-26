# Submission report template

> Not loaded into prompts; the write-up skeleton to use for any confirmed finding. Every section
> exists because leaving it out caused a rework or a downgrade in practice.

```
TITLE:        [concise, technical]
SEVERITY:     [as justified by the tier: see FINDING_TIERS.md]
CONFIDENCE:   [Foundry-verified: N tests passing on <commit>, unmodified contracts
               | logically argued, NOT executed]   <- state it; never imply execution you did not do
TARGET:       [Contract.sol:function / ...]

Summary
[2-3 sentences: what breaks, in plain terms.]

Threat Model
[Who is the attacker; what capital and access they need; which trust assumption or invariant is
violated; whether any privileged role is involved. One paragraph, so a triager can categorise
before reading Root Cause.]

Root Cause
[Technical explanation, file:line for every claim.]

Production Parameters
[Every configuration value the finding depends on, sourced from the deploy/verify scripts with
file:line - NOT test defaults. State where the PoC deviates from production values and whether the
finding still holds. Include the parameters that CAP the impact (a floor, a ceiling, a delay).]

Impact
[ONE sentence: the worst concrete outcome in plain terms.]
[Then the numbers from the actual PoC runs.]
[Value flow: profit or disruption, with the equity accounting (attacker_gain).]
[In-scope categories quoted verbatim from the program's list, primary first. State what is NOT
claimed: theft, insolvency, permanent freeze.]

Proof of Concept
[The full test, verbatim, and the run output with gas.]

Atomicity (if applicable)
[Single-transaction attacker and measured gas.]

Recommendation
[The fix and its trade-off. Label each fix tested or untested. Name the insufficient fixes.]

Duplicate Differentiation
[One sentence against each relevant known/excluded item and each sibling report.]

Relationship (if applicable)
[Cross-references to sibling reports; the reference ID once known, never a placeholder.]
```

## Rules that came from mistakes

- Re-verify a claim from source before writing it; a remembered claim may be stale.
- "Permanent" needs a proof that no permissionless or governance path restores the state.
- A production parameter can make an impact unreachable (a threshold above anything the system
  can produce); check reachability before claiming impact.
- Trim the PoC to the tests one report needs, verify it in a clean clone, and quote the gas from
  THAT file: gas figures change with the surrounding test file.
