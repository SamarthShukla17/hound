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
