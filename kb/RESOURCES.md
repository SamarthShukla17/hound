# Growth & Resources — toward top-tier web3 auditing

> Living document. What to study, where to compete, who to learn from. Add to it as you go.
> Pair with METHODOLOGY.md (the how) — this is the what-to-learn and where-to-apply-it.

---

## 0. The honest frame

Becoming one of the best is not a reading list you finish — it's reps on real code plus a
tight feedback loop. The resources below are in service of that loop, not a substitute for it.
The single highest-leverage activity is: audit real in-scope code, submit, get judged, and
integrate the verdict. Everything here feeds that.

---

## 1. Foundations to be fluent in (not just aware of)

**Solana / Rust / Anchor**
- Anchor account model, PDAs & seeds, CPI, `#[account]` constraints, Token / Token-2022
  (extensions: transfer hooks, permanent delegate, close authority — a rich, under-scrutinized
  surface).
- Sealevel runtime semantics: transaction atomicity, account locks, compute budget.
- The classic Solana bug classes: missing owner/signer checks, account substitution, arbitrary
  CPI, type confusion — as the *floor*, not the ceiling.

**EVM / Solidity**
- Storage layout, delegatecall/proxy patterns, reentrancy in its non-obvious forms, ERC-20
  edge cases (fee-on-transfer, rebasing, non-standard returns), approval/permit flows.
- Foundry to fluency — it's the PoC lingua franca for contests. Fork tests, cheatcodes,
  invariant/fuzz testing.

**Cross-cutting**
- Oracle designs and their manipulation surface; AMM math; lending/liquidation mechanics;
  bridge trust models (consensus proofs, light clients, HTLC/atomic-swap correctness,
  cross-chain timelock symmetry).

---

## 2. The canon (reports & writing to read deeply, not skim)

- **Neodyme** Solana security blog + their paradigm/CTF material.
- **Sealevel Attacks** repo (the exercises — do them, don't just read).
- Public audit reports: **OtterSec, Zellic, Trail of Bits, Sec3, SlowMist, Hexens, Spearbit/
  Cantina, OpenZeppelin, Quantstamp, Ackee, SRLabs.** Read the *reasoning*, not just the finding.
- **Solodit** — aggregated findings across contests/firms; search by category to build pattern
  intuition (and to check for duplicates/precedent).
- **Web3Bugs dataset** (ZhangZhuoSJTU/Web3Bugs) — the machine-auditable vs. semantic taxonomy
  that anchors the six-class coverage check in METHODOLOGY.md. ~80% of exploitable bugs need
  semantic understanding, not tooling.
- **rekt.news** and major post-mortems — reverse the incident to the missing invariant.

---

## 3. Where to compete (level-start > head-start)

- **Sherlock, Cantina, Code4rena, CodeHawks** — contest platforms; fresh (pre-audit) code, a
  level start for everyone, real pools. This is the structurally winnable path for ranked payouts.
- **Immunefi, HackenProof** — live bounties on deployed code. Higher ceilings but usually
  already audited and crowded; the seam (post-audit modules, remediations) is where value hides.
- Watch specifically for: **newly-launched programs** and **scope expansions on existing
  programs** (a module added after the last audit = live unaudited code — the delta play).

---

## 4. Skills to compound over time

- **PoC speed.** The faster you can turn a hypothesis into a runnable Foundry/LiteSVM PoC, the
  more candidates you can actually validate. This is a direct multiplier on findings.
- **Reading audited code fast.** Diffing HEAD against the audited commit; finding what changed
  since the last review is often the whole game.
- **Writing reports triagers trust.** Lead with the code defect, bound impact honestly, pre-empt
  the strongest objection, attach a PoC. A report that surfaces its own weakness gets trusted.
- **Second-tool discipline.** Cross-check AI reasoning with a second model; verify narrated code
  against source every time.
- **Economic reasoning.** Whether an attack is *rational* (cost of capital/bond vs. extractable
  value) often decides real severity — trace it, don't assume.

---

## 5. Habits that separate top auditors

- Close threads by *mechanism* ("safe because X forecloses it"), never by fatigue.
- Treat a clean, well-reasoned negative as a real deliverable.
- Time-box per target; don't let a target you understand eat weeks past its yield.
- Keep a personal corpus of every candidate you killed and the check that killed it — it becomes
  a false-positive filter that speeds up every future audit.
- Publish. Writeups (including honest negatives and where a method failed) build the credibility
  that leads to paid private audit work — which is where the money and the level playing field are.

---

## 6. Personal next steps (edit freely)

- [ ] Keep METHODOLOGY.md and this file in the repo so any new session starts equipped.
- [ ] Publish the methodology + findings writeup as a public portfolio piece.
- [ ] Build the "killed candidates" corpus into a reusable false-positive filter.
- [ ] Bias target selection toward fresh contests with a level start.
- [ ] Set up monitoring for scope expansions / new listings (the delta play).
