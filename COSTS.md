# Costs: what a run actually spends, and on what

No new cost accounting exists anywhere in this repo. Every number below comes from
`hound/llm.py`'s `Router.report()` — it already tracks `prompt_tokens`/`completion_tokens`
per model from the real API responses and multiplies by `prices:` in `models.yaml`
(`$ per million tokens: [input, output]`). This doc is a read of that math, not a new one.

Until `step P`, that report was only ever printed to stdout for `scan`/`rejudge`/`rediagnose`
and lost once the terminal scrolled — only `score`'s cost line was persisted. As of step P,
every hound and bloodhound command writes it to `<run_dir>/manifest.json`, so from now on
"what did this run cost" is a file read, not a terminal-scrollback hunt:

```bash
python -m json.tool < runs/<run>/manifest.json   # or: jq .cost_report.total_usd runs/<run>/manifest.json
```

Prices and model IDs drift (OpenRouter/provider list prices change, roles get repinned) —
`models.yaml`'s own `prices:` table is the live source of truth; treat the numbers here as
"how to read it," not as a frozen price sheet.

## Hound pipeline — role → model chain → price

Each role below is a **fallback chain**: the router tries the first target, falls through on
failure (rate limit, out of credit, timeout), and only the model that actually answered gets
billed. Prices are `$/M tokens [input, output]` from `models.yaml`.

| Role | Stage | Chain (primary → fallbacks) | Price ($/M in, out) |
|---|---|---|---|
| `mapper` | builds the per-chunk code map every hunter reads | `openrouter/z-ai/glm-4.7-flash` → `openrouter/anthropic/claude-sonnet-5` | $0.061/$0.400 → $3.00/$15.00 |
| `hunter` | one call per lens × chunk × pass | `openrouter/z-ai/glm-4.7-flash` (no fallback — see models.yaml's note on why) | $0.061/$0.400 |
| `diagnose` | re-reads one cited region cold | `openrouter/z-ai/glm-5.3-flash` → `openrouter/z-ai/glm-4.7-flash` → `openrouter/z-ai/glm-5.3` | $0.09/$0.30 → $0.061/$0.400 → $1.40/$4.40 |
| `judge` | falsifies each surviving candidate | `openai/gpt-5.6-luna` → `openrouter/z-ai/glm-5.3-flash` | $0.20/$1.20 → $0.09/$0.30 |
| `judge2` | dissent checkpoint, distinct model from judge | `zai/glm-5.3` (direct) | not in `prices:` yet — zai direct billing isn't tracked by this report |
| `poc` | PoC scaffold text (not recall-measured) | `openrouter/cohere/north-mini-code:free` → `zai/glm-4.7-flash` | $0/$0 → $0/$0 (zai direct, untracked) |
| `scorer` | grades a run against ground truth | `openrouter/z-ai/glm-5.3-flash` → `anthropic/claude-sonnet-5` → `openai/o3` | $0.09/$0.30 → $3.00/$15.00 → $2.00/$8.00 |

`judge2` and the `zai`-direct legs of `diagnose`/`poc`/`judge` aren't in `prices:` (defaults to
`(0, 0)` in `Router.report()`), so a run that falls through to one of those under-reports —
flagged here rather than silently treated as free; the fix is adding `glm-5.3` /
`z-ai/glm-4.7-flash` entries for the zai-direct billing rate once that account has real pricing.

### What's actually been measured

Only `scorer`'s cost was persisted before step P (`score.json`'s `cost` field). Across the
**22 real local runs with a non-zero scorer cost in this repo's `runs/`**:

| | |
|---|---|
| mean | $0.054 |
| median | $0.054 |
| min / max | $0.0008 / $0.151 |

That's one role, not a full-pipeline number — `mapper`/`hunter`/`judge`/`judge2`/`diagnose`
were never persisted until step P, so there's no honest historical figure for a full
`scan` yet. Run a scan now and read its `manifest.json` for the first real one; don't trust
an estimate here instead.

## Bloodhound layer — role → model chain → price

| Role | Stage | Chain | Price ($/M in, out) | Status |
|---|---|---|---|---|
| `poc` (reused) | PoC Forger's generation step (`hound.agents.poc()`) | same chain as hound's `poc` role above | $0/$0 → $0/$0 (zai direct, untracked) | configured |
| `refute1` / `refute2` / `refute3` | Refutation Panel, up to 3 roles, each asked twice (swap-and-discard) | — | — | **not configured** — each unconfigured role is skipped, not an error |
| `embed` | Novelty classifier's `.embeddings.create()` call | — | — | **not configured** — classifier returns `"unclassified"` with no embed role, never fabricates a comparison |

The Forger's repair rounds (`compile_with_repairs`, up to `--max-repairs`, default 4) and the
Invariant Engine's handler generation (`forge_invariant`) are both LLM-free at the retry level
— only the one generation call per candidate/claim goes through a role above; the repair loop
itself is deterministic Solidity patching (`forger.deterministic_repair`), not another model
call, so repairs don't multiply the LLM cost.

### Cost governor and the manifest

`bloodhound run-pocs ... --max-cost N` / `bloodhound invariants ... --max-cost N` wrap every
unit of work in `CostGovernor.check()` (`bloodhound/costgov.py`), which reads
`Router.report()`'s already-computed `total_usd` — no separate accounting — and once spend
crosses `N`, latches `breached=True` permanently (a later lower-looking spend never un-breaches
it) and the command exits `3` instead of `0` or `1`. `manifest.json` records
`max_cost_usd`/`breached` alongside the cost report either way, so a cut-short run is
distinguishable on disk from one that simply finished.

## Monthly budget (unrelated mechanism — don't conflate the two)

`models.yaml`'s `budget: {monthly_usd: 20, reserve_usd: 0.5}` is the x402 wallet-spend ledger
(`hound/budget.py`), a different, not-yet-wired-up mechanism: it gates **x402 crypto-payment**
API calls against a monthly wallet cap, not the `prices:`-based cost tracked above. The `hound
budget` CLI command that would show it is still `_not_implemented`. Don't read `monthly_usd: 20`
as "this is what a month of hound costs" — it's an unrelated, unused ceiling on a payment
rail that has no live gateway yet (`x402gw`'s `base_url` is a placeholder).

## Getting your own numbers

1. Run anything — `hound scan`, `hound rejudge`, `hound rediagnose`, `hound run-pocs`,
   `hound invariants` — all five now write `<run_dir>/manifest.json`.
2. `jq '.cost_report.total_usd'` it, or `.cost_report.models` for the per-model breakdown
   (`prompt_tokens`, `completion_tokens`, `calls`, `cost_usd` each).
3. Aggregate across `runs/*/manifest.json` + `runs/*/score.json`'s `.cost` field (the only
   pre-step-P source) for a real historical trend — there is no code to do this for you yet;
   it's a `jq`/`python -c` one-liner against files that are now guaranteed to exist.
