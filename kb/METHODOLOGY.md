# Audit Methodology & Toolkit

> Living document. This is the portable source of truth for how I audit web3 code.
> A new session (human or AI) pointed at this repo should read this file first, then
> the harness scripts it references. Memory/chat context is only a pointer to this.

---

## 0. Operating principles (read these first)

1. **Falsification-first.** For every candidate bug, identify the single cheapest test
   that would prove it *wrong*, and run that before deepening. Most candidates die here.
   This is what keeps the false-positive rate down and makes negatives trustworthy.
2. **Liveness before depth.** Do not spend effort on dormant/uninvoked code. Check whether
   the relevant accounts/state exist on-chain and whether the instruction is actually
   reachable *before* analyzing it. A real bug in unreachable code is not payable.
3. **PoC-or-it-doesn't-count.** A candidate without a runnable PoC is a note, not a finding.
   On PoC-required programs, treat "can I PoC this?" as part of triage, not a later step.
4. **Verify AI claims against source.** Never submit on an AI's narration of the code.
   Read the cited lines yourself. (Learned the hard way — a fabricated-code incident once.)
5. **Calibrate tools against ground truth.** Before trusting any harness on a new target,
   reproduce a conclusion you've already verified by hand. If the tool disagrees, stop and
   reconcile before relying on it.
6. **Judgment is mine, mechanics are the tool's.** AI/harness does extraction, navigation,
   and grunt tracing. Scope calls, exploitability, severity, and duplicate judgment are mine.
   Nothing gets submitted if I can't explain the bug unaided.

---

## 1. The core method (target-agnostic)

```
0. SCOPE-GATE   — confirm the file/program is actually in scope (exact program IDs / repos /
                  commit). Refuse to analyze out-of-scope code. Note the in-scope IMPACT
                  buckets and the OUT-of-scope exclusions before reading for bugs.

1. MAP          — every external/public entry point, every state variable, every
                  fund-movement path, every trust boundary (who is allowed to do what),
                  every CPI / external call and whether its target is pinned or attacker-
                  supplied.

2. AUDIT HISTORY— pull every prior audit report. List each finding + its remediation.
                  The payable bug most often lives in the SEAM the audits didn't cover:
                  post-audit modules, incomplete/regressed remediations, cross-repo or
                  cross-chain consistency that no single-repo audit was structured to check.

3. INVARIANTS   — state, as falsifiable sentences, what MUST always be true. At minimum:
                  value conservation (no one ends with more than they put in), no unbacked
                  mint, authority integrity, no permanent lock reachable by an unprivileged
                  actor. List the instructions that could threaten each.

4. ATTACK       — try to break each invariant using the six machine-UNauditable classes
                  (section 2). For each: which class, exact sequence, cite file:line.

5. FILTER       — drop anything that isn't an in-scope impact, isn't reachable by an
                  unprivileged attacker (privileged-only / admin-error = usually excluded),
                  or can't be PoC'd. Match survivors against known/acknowledged findings.

6. REPORT       — positive: root-cause defect as headline, traced chain as mechanism,
                  impact honestly bounded, runnable PoC, suggested fix, and pre-empt the
                  triager's strongest objection in your own words.
                  negative: say so plainly — a well-reasoned negative is a real result.
```

---

## 2. The six machine-unauditable bug classes (where real exploitable bugs concentrate)

Tools and the standard checklist already catch the "machine-auditable ~20%" (reentrancy,
overflow, unchecked calls, missing modifiers). On audited code that class is usually already
closed. Exploitable bugs concentrate in the semantic ~80% below — use these as a **coverage
check** (did I consider each?), not a substitute for stating the protocol's own invariants.

1. **Price manipulation** — any price/rate consumed by a live path; can it be moved in-tx,
   and does anything trust it as truth? (Mango/oracle shape.)
2. **ID / access violation** — PDA substitution, wrong-account, seed collision, identity
   confusion (maker vs taker, owner vs signer).
3. **Erroneous state update** — stale state after a transition, a value read from the wrong
   source, a field an attacker controls treated as trusted.
4. **Atomicity violation** — two value-moving ops composed in one tx to cross a price/accounting
   boundary; missing per-block/cooldown/rate limits. (Nirvana/Cashio shape.)
5. **Privilege escalation** — an unprivileged actor reaching a privileged role via a
   lifecycle/re-init/close path.
6. **Erroneous accounting** — a mint/fee/balance computation that fails to conserve value
   across a sequence. (Associativity breaks, rounding that accrues to the caller.)

---

## 3. Toolkit (the harnesses — actual scripts live alongside this file)

- **Scope-gated inventory harness** — STEP 0 checks a file against exact in-scope program
  IDs/repos before analyzing; refuses out-of-scope input. Mechanical account/CPI/arithmetic
  extraction. Judgment stays with me.
- **LiteSVM invariant/fuzz harness** — standalone Rust crate *outside* the target's Anchor
  workspace (hand-declare instruction/account layouts from the committed IDL to dodge broken
  transitive deps). State N invariants, run a randomized loop, corroborate manual findings.
- **rust-analyzer LSP navigation harness (`lsp_query.py`)** — drives rust-analyzer over stdio
  (hand-rolled JSON-RPC, Content-Length framing). Modes: `find` / `refs` / `callers` /
  `callees` (recursive call hierarchy to `--depth`) / `sig`. Use `--pos file:line:char` to
  bypass fuzzy symbol search when names are ambiguous. Semantic navigation, NOT dataflow/taint.
- **Second-AI sanity check** — run key prompts/outputs past a second model (z.ai / GLM) to
  catch confident-but-wrong reasoning before it reaches a report.

**Reachability techniques (Solana):** derive PDAs with a real ed25519 lib (`solders`), never
hand-roll the off-curve check. Probe deployment liveness without an IDL by simulating a raw
tx carrying only an 8-byte Anchor discriminator and reading the error class. Parse `#[account]`
layouts manually: 8-byte discriminator, then fields in declaration order, `Pubkey` = 32 bytes.

---

## 4. Strategic lessons (paid for in clean negatives)

- **Audit COUNT is the signal, not program age/size.** A bounty target is audited before it's
  listed, almost by definition. "Newer/smaller bounty" never meant "less audited."
- **The bug is in the seam the audit didn't cover** — post-audit code, remediation
  regressions, cross-repo/cross-chain consistency.
- **Contests > long-running bounties for a first win.** Contest code enters *because* it isn't
  yet audited, and everyone starts at the same gun. On a bounty with hundreds of hunters,
  being first is a coin-flip you can lose to a stuck transfer.
- **Read the reward/dedup rules before investing.** Duplicate splits, submission stakes/fees,
  rep-point penalties for no-PoC, and severity floors change the real expected value a lot.
- **A duplicate ruling is not a failure** — it means the bug was real and independently found.
  It's a competence signal, banked as portfolio, even at $0.

---

## 5. Track record (portfolio — keep current)

- Deep audits closed with reasoned negatives: OnRe, KAST, Orca (Whirlpools + xORCA), GMTrade,
  Kamino (klend/kvault/kfarms/scope), 1inch Solana (crosschain + fusion), Midas.
- Findings: Drift V2 liquidation-evasion (submitted High); Hyperbridge OP-client missing
  dispute-window check (real critical-class, live-chain-confirmed, PoC'd — resolved DUPLICATE,
  i.e. independently valid), with Arbitrum shown to share the defect systemically.
- Public methodology + findings writeup covering the negative-closed targets (portfolio piece).
