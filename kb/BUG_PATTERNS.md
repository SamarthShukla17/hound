# Bug Pattern Library + PoC Scaffolds

> Load alongside METHODOLOGY.md. This is the recognition layer: recurring
> exploitable-bug shapes drawn from published Code4rena/Sherlock findings, each
> with (a) how to SPOT it in code, (b) the FALSIFICATION check that kills it fast,
> and (c) a Foundry PoC skeleton so reproduction is fill-in-the-blanks, not
> from-scratch. Use these as hypothesis-generators during the ATTACK phase — never
> as a checklist substitute for stating the protocol's own invariants.

---

## How to use this during an audit

For each contract in scope, walk the patterns below and ask "could this shape live
here?" When a candidate matches:
1. Run the pattern's **falsification check** first (cheapest disproof).
2. If it survives, fill in the pattern's **PoC skeleton** against the real contract.
3. A green PoC (exploit succeeds) is the finding; a red PoC (exploit reverts /
   nets zero) is a clean kill. Either way you have evidence, not a guess.

Recognition beats coverage: the auditors who place don't read every line — they
pattern-match these shapes onto the trust edges and math, then prove/kill fast.

---

## Pattern 1 — First-depositor / share-inflation (ERC4626-style)

**Shape:** A vault mints shares as `shares = assets * totalSupply / totalAssets`.
The first depositor mints 1 wei of shares, then *donates* assets directly to the
vault (raising `totalAssets` without minting shares), so the share price balloons.
A later depositor's `assets * totalSupply / totalAssets` truncates to few or zero
shares — their deposit is effectively stolen.

**Spot it:** share/asset conversion that reads a live pool balance ratio, with no
minimum-shares mint, no dead-shares burn (Uniswap-V2 sends first 1000 LP to
`address(0)`), and no virtual-offset (OZ ERC4626 `_decimalsOffset`). If the
conversion keys off a globally-set multiplier/index instead of a donateable pool
balance (like Paxos SharesLib did), the foothold is absent — falsified.

**Falsify fast:** does `deposit` enforce a nonzero-shares-out check or mint dead
shares on first deposit? Is `totalAssets` derived from a balance an attacker can
inflate by direct transfer? If protected → dead.

**PoC skeleton:**
```solidity
function test_firstDepositorInflation() public {
    // 1. attacker deposits 1 wei
    vm.prank(attacker); vault.deposit(1, attacker);
    // 2. attacker donates to inflate share price
    vm.prank(attacker); asset.transfer(address(vault), 1e18);
    // 3. victim deposits, receives rounded-down (near-zero) shares
    vm.prank(victim); uint256 got = vault.deposit(2e18, victim);
    // 4. assert victim was robbed: shares worth < deposited
    assertLt(vault.convertToAssets(got), 2e18); // victim lost value
}
```

---

## Pattern 2 — Reward accounting: claim more than accrued / double-claim

**Shape:** `claimable` computed from a snapshot the attacker can straddle — deposit
right before an accrual/reward snapshot, claim, withdraw — collecting rewards they
didn't earn. Or state not updated before transfer → reentrancy/double-claim. Or
`amount_claimable_per_share` accounting that lets sum(claims) > deposited rewards
(vault insolvency).

**Spot it:** reward index / per-share accumulator updated on a path the user
controls the timing of; `claim` transferring before zeroing the claimable balance;
"immediately start earning rewards on stake" with no elapsed-time gate (lets a
staker capture rewards belonging to prior stakers).

**Falsify fast:** is the reward checkpoint updated (accrual settled) *before* the
user's balance change takes effect? Is claimable zeroed before the transfer? Is
there an elapsed-time or checkpoint gate between stake and first-earn? If all yes
→ dead.

**PoC skeleton:**
```solidity
function test_rewardStraddle() public {
    // fund rewards, advance to just before a snapshot
    // 1. attacker deposits right before snapshot
    vm.prank(attacker); pool.deposit(bigAmount);
    // 2. trigger/settle the reward snapshot
    pool.notifyReward(rewardAmount);
    // 3. attacker claims immediately
    vm.prank(attacker); uint256 got = pool.claim();
    // 4. attacker withdraws
    vm.prank(attacker); pool.withdraw(bigAmount);
    // assert attacker captured rewards for time they weren't staked
    assertGt(got, fairShareForZeroElapsed);
}
```

---

## Pattern 3 — Fee-on-transfer / rebasing token accounting mismatch

**Shape:** Protocol does internal bookkeeping assuming `amount` sent == `amount`
received. A fee-on-transfer or deflationary token delivers less than stated, so the
attacker is credited more than they actually deposited → drains the difference over
many cycles.

**Spot it:** `token.transferFrom(user, this, amt)` followed by crediting `amt`
internally, with no measure-balance-before-and-after. Any internal balance
tracking on arbitrary ERC20s not asserted against real balance delta.

**Falsify fast:** does the code credit `balanceAfter - balanceBefore` rather than
the passed `amount`? If yes → dead. (Also check scope: many contests exclude FoT
tokens explicitly in the README — read that first, it may be out of scope.)

**PoC skeleton:**
```solidity
function test_feeOnTransferMismatch() public {
    // deploy a FoT token (e.g. 1% fee), fund attacker
    // 1. attacker deposits 100 (only 99 arrives, but credited 100)
    vm.prank(attacker); pool.deposit(100);
    assertEq(pool.balanceOf(attacker), 100);      // credited full
    assertEq(token.balanceOf(address(pool)), 99); // actually received less
    // repeat / withdraw to realize the drain
}
```

---

## Pattern 4 — Cross-component price/data trust (the systemic one)

**Shape:** Contract A consumes a price/balance/rate from contract B and treats it as
truth. If the attacker can move B's output within one transaction (thin-liquidity
AMM spot price, manipulable oracle, a balance they control), A acts on a lie —
over-borrow, under-collateralize, mis-liquidate, mint unbacked. (Mango/Cashio
shape.)

**Spot it:** any `A` that reads `B.getPrice()` / `B.balanceOf()` / a spot ratio and
uses it for a value decision, where B's value is attacker-influenceable in the same
tx. Spot AMM reserves used as an oracle is the canonical tell. Cached-vs-actual
value divergence that can be arbitraged.

**Falsify fast:** is the consumed value from a manipulation-resistant source (TWAP,
Chainlink with staleness/deviation checks, a value set by governance not markets)?
Is there a same-tx reentrancy/flash-loan path to move it? If the source is robust
→ dead.

**PoC skeleton:**
```solidity
function test_crossComponentPriceManip() public {
    // 1. flash-loan / large swap to move B's spot value
    manipulate(poolB); // e.g. swap to skew reserves
    // 2. call A which reads B's now-false value
    vm.prank(attacker); uint256 borrowed = A.borrowAgainst(collateral);
    // 3. assert attacker extracted more than collateral honestly backs
    assertGt(borrowed, honestValue(collateral));
    // 4. unwind the manipulation (repay flash loan), keep profit
}
```

---

## Pattern 5 — Rounding-direction / non-associativity extraction

**Shape:** A conversion rounds in a direction, or the same operation split into N
pieces yields more than done once (non-associativity — the accrual/associativity
class). If mint rounds up and redeem rounds down in the caller's favor, or floor
division is *super*additive on a path, the attacker extracts dust that compounds.

**Spot it:** paired mint/redeem or deposit/withdraw where the two directions round
inconsistently; any per-call linear formula applied repeatedly to a base that grows
between calls (compounds when it should be simple, or vice versa).

**Falsify fast:** do both directions floor consistently in the PROTOCOL's favor?
(floor both ways is subadditive → splitting HURTS the attacker → dead). Prove it
algebraically before coding: `floor(a/d)+floor(b/d) <= floor((a+b)/d)` — wrong
direction for an attacker. Only a rounding pair that favors the CALLER, or a genuine
super-additive/compounding path, survives.

**PoC skeleton:**
```solidity
function test_splitExtraction() public {
    // baseline: do the op once
    uint256 lump = doOnce(amount);
    // split: do it in N pieces
    uint256 split; for (uint i; i<N; i++) split += doOnce(amount/N);
    // finding ONLY if split > lump (attacker gains by fragmenting)
    assertGt(split, lump); // if this reverts, it's a clean kill
}
```

---

## Pattern 6 — Missing slippage / min-out on value-moving ops

**Shape:** A swap/redeem/fill executes at whatever on-chain price without a
user-supplied minimum-out or maximum-in, so a stale quote or a sandwich fills at a
bad price silently. (Note: pure front-running is out of scope on many programs —
check. But a *missing safeguard* that lets value leak beyond front-running can
still be in scope.)

**Spot it:** external-facing swap/redeem/liquidate with no `minOut`/`maxIn`
parameter and no internal bound. Cross-check against the protocol's own acknowledged
findings — "no slippage protection" is frequently already acknowledged (was on OnRe
ONR-5), which makes it a duplicate unless a later change invalidated the team's
stated justification.

**Falsify fast:** does the function accept and enforce a min-out/max-in? Is it
already an acknowledged finding in the audits (→ likely duplicate)? If protected or
known → dead.

---

## Meta-notes

- **Duplicate risk:** patterns 1, 3, 6 are the most commonly-found ("everyone checks
  these"). On a contest they'll have many finders → scaled-down reward. Patterns 2,
  4, 5 in their non-obvious forms are where UNIQUE findings (big reward) live —
  spend depth there.
- **Scope-check every pattern against the README:** FoT-token issues, front-running,
  and admin-error footguns are frequently declared out of scope. A real bug in an
  out-of-scope class pays nothing.
- **The PoC is the deliverable.** A pattern-match without a green Foundry PoC is a
  note, not a finding. Keep these skeletons ready so reproduction is minutes, not
  hours — that speed is what lets you submit before the window closes and claim the
  first-submission bonus.



---

## Pattern 7 — Permissionless gateway bypass

**Shape:** A module (the "gateway") is the INTENDED entry point for an action. It enforces
side-effects: accounting or reserve updates, solvency or role checks, fee collection. The
lower-level ledger operation underneath is permissionless and does not enforce those
side-effects, because it was designed for a different class of asset or position. Calling the
ledger directly produces the same state change without the gateway's side-effects, so the
gateway's bookkeeping drifts from the ledger's.

**Spot it:** a high-level module that wraps a lower-level call AND adds side-effects. Check:
can an unprivileged caller invoke the lower-level operation directly, on the same class and with
the same parameters the gateway uses? Does the ledger treat the gateway's class like any other at
the raw-operation level (no role gate, no allowlist)?

**Key signals:**
- The operation that creates or opens the position is permissionless for every class
- A safety or solvency check in the ledger is conditional on the class (skipped for some)
- The accounting layer lives in the gateway, not in the ledger
- Classes with a fixed rate make the direct path cost-free for the attacker

**Falsify fast:** Can a non-gateway address call the raw operation on the gateway's class? Does
the ledger enforce any check on that path (allowlist, role gate, solvency check)? Does the ledger
itself update the accounting layer, or only the gateway? If any of these blocks the path -> dead.

**Impact class:** one counter (debt, supply) is inflated without the matching backing counter
moving. Any invariant that compares the two can then fail permanently, so the usual impact is a
griefing / permanent-lock, not theft. Cost to the attacker is near-zero when the class has a
fixed rate.

**PoC skeleton:**
```solidity
function test_gatewayBypass() public {
    uint256 backingBefore = accounting.backing();
    // attacker skips the gateway and uses the ledger's raw operations directly
    ledger.open(GATEWAY_CLASS, attacker);
    ledger.rawOperation(GATEWAY_CLASS, attacker, amount);
    // the counter moved but the backing the gateway would have recorded did not
    assertGt(ledger.counter(), accounting.counterSeen());
    assertEq(accounting.backing(), backingBefore);
    // a function that compares the two now fails
    vm.expectRevert();
    accounting.dependentFunction();
}
```

**Meta:** This generalizes to any system where a privileged gateway wraps a permissionless
ledger and the accounting invariant lives in the gateway layer only. The bug appears when a
bookkeeping layer is added on top of a permissionless ledger without also adding ledger-level
restrictions on the classes the gateway serves.
---

Pattern: Signature-digest incompleteness — a valid signature authorizes a transfer, but a security-critical field (recipient/destination token account, program id, chain) is NOT in the signed digest, so the submitter/facilitator substitutes it post-signature. Check: does the digest bind recipient + amount + mint + nonce + deadline + program-id + chain? Anything outside the hash is attacker-controllable.