# hound

## Cloud-only

hound has no offline/local mode. Local mode (Ollama) was tried and removed: on a 16 GB Mac,
a 14B-class model spills out of Metal's ~11.8 GiB budget and drops to 0.09 tok/s (vs 28 tok/s
for a 7B model that fits) — and a 7B model is too weak to hunt or judge usefully anyway.
Rather than ship a local mode that quietly produces worse audits, it was removed. `--local-only`
now fails immediately with that explanation instead of silently routing to a model that can't
do the job.

**Routing (see `models.yaml`):**
- **mapper / hunter / poc** (the 20-lens fan-out, run over every chunk): free GLM Flash
  (`zai`), falling back to OpenRouter's free pool.
- **judge**: cheap GLM-5.3-Flash, falling back to GPT with high reasoning effort.
- **judge2**: Grok 4.6 — a different model family from the judge, on purpose, for an
  independent second opinion. It only runs on candidates that already survived judge, so the
  call count stays small.

**Budget:** `--budget 240000` (chars per chunk) matches these models' ~128K context.

## Known limitation

**No offline mode.** Every scan sends code to a cloud API (zai, OpenRouter, OpenAI, or xAI,
per `models.yaml`). Code under NDA or a bounty program's confidentiality clause cannot be
scanned with hound as currently configured — there is no local fallback that's actually
capable of doing the job. Public contest code, where sending it to a well-known API provider
carries no additional exposure, is fine.

## Modes added from the contest-A session

Each is also a standalone command and a `scan` flag; all degrade gracefully (a failure never stops a scan).

| Mode | Command / flag | What it does |
|---|---|---|
| Upstream diff | `hound diff TARGET`, `scan --upstream auto\|off\|NAME` | Detects a fork from the README/comments (`upstreams.yaml`), fetches the real upstream source (cached in `.hound_cache/`, network on first use), diffs statement by statement (guards normalised), has a model classify each deviation (`kb/DEVIATION_REVIEW.md`), and hands the flagged ones to the hunters. |
| Config cross-check | `hound config-check TARGET`, `scan --config-check auto\|off` | Reads every deploy/verify script, evaluates each configured value, joins it to the contract setter's checks and read sites, lists parameters never set, verify-vs-deploy mismatches and gaps against upstream reference values; a model checks magnitude/reachability and parameter combinations (`kb/CONFIG_CHECKS.md`). |
| Coverage gaps | `hound coverage TARGET [--lcov FILE]`, `scan --coverage auto\|off\|FILE` | Ranks functions whose branches the team's tests never exercise (trivial guards down-weighted); `forge coverage` or any lcov file. |
| Profit vs disruption | every finding | `value_flow` + `attacker_gain` (equity accounting) required; judge recomputes; report shows tiers and warns when severity outruns the tier (`kb/FINDING_TIERS.md`, `kb/REPORT_TEMPLATE.md`). |
| Chain check | `hound chain RUN_DIR`, `scan --chain auto\|off` | Pairs standing findings that share state one side writes, and has a model test whether they combine into a profit (`kb/CHAINING.md`). |

## Bloodhound: execution-gated verification (`bloodhound/`)

A sibling package, not a fork of `hound/`: judge/judge2 are still LLM opinions, and an LLM can be
argued into or out of one. Bloodhound never adds another opinion on top of a candidate — it tries
to kill it with a compiled, executed Foundry test, and only lets a finding read as confirmed if it
survives that.

| Stage | Command / flag | What it does |
|---|---|---|
| PoC Forger | `hound run-pocs RUN_DIR [--target T] [--max-repairs N]` | Compiles each live candidate's existing PoC scaffold against the real target, LLM-repairs compile errors (bounded rounds), then only marks it `forged` if the attack run demonstrates the bug **and** an LLM-written control variant (same test, attack step removed) does not — the differential gate that kills a tautological assertion. |
| Refutation Panel | same command, `--no-panel` to skip | Up to 3 configurable roles (`refute1`/`refute2`/`refute3` in `models.yaml`; unconfigured ones are just skipped) each answer a binary checklist against a forged PoC, asked twice with the claim/code order swapped (disagreement discarded as unreliable). A "refuted" verdict must give a `require()`/`vm.assume()` statement that gets injected into the real test and re-run — it only counts if the attack actually stops passing. |
| Invariant Engine | `hound invariants TARGET --invariants FILE.yaml [--claim ID]` | Loads a **human-curated** claims file (never mapper-derived — see `hound/agents.py`'s `_invariant_checklist` docstring for why that measured worse), generates a Foundry invariant-test handler per claim, repairs/compiles it, and runs Foundry's fast fuzz gate. A counterexample is a lead, not a confirmed finding — it still goes through the Forger/Panel. |
| Deep-fuzz escalation | same command, `--deep-fuzz echidna\|medusa\|both [--deep-fuzz-timeout N]` | Opt-in, off by default. A claim the fast gate marked `held` (not already falsified, not uncompilable) can be escalated to a real, time-boxed Echidna/Medusa campaign against a separately-generated self-deploying contract exposing the same property as one `echidna_<id>()` function — a much larger run/depth budget than Foundry's own fuzzer, same "clean negative, not proof" epistemic weight. Never runs on `counterexample`/`compile_failed`. |
| Novelty classifier | same command, `--corpus FILE.json [--embed-role ROLE]` | Embeds a panel-surviving finding and ranks it against a human-maintained corpus (a target's own prior audits and/or your own accumulated findings, same `{"findings": [...]}` shape `external.py` uses) via a new `embed` role — no new dependency, no MCP/Solodit client (that stays a flagged gap, not a fake). |
| Dossier | same command (automatic for anything forged + panel-surviving) | Renders `kb/REPORT_TEMPLATE.md`'s own section shape at `runs/<run>/dossiers/<id>.md`, with an honest `CONFIDENCE: Foundry-verified: 1 test passing on <commit>` line and the PoC/trace quoted verbatim — sections with no underlying data (Threat Model, Production Parameters, Recommendation, Duplicate Differentiation) are left as explicit TODOs, never fabricated. |

New optional `models.yaml` roles this layer can use, each degrading gracefully if absent:
`refute1`, `refute2`, `refute3` (Refutation Panel), `embed` (Novelty classifier, an
OpenAI-compatible `/embeddings` endpoint — OpenRouter or OpenAI both work through the existing
`openai` SDK client).

Cost governance: `run-pocs`/`invariants --max-cost N` stop (exit code `3`) once
`Router.report()`'s running total crosses `N`; every hound and bloodhound command now writes
its cost report to `<run_dir>/manifest.json`, not just to stdout. See [COSTS.md](COSTS.md) for
which model each role actually bills to, at what price, and what's been measured so far.
