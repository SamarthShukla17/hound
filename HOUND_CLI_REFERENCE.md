# hound CLI reference

Run these from the hound project root, with the venv active:

    cd /path/to/hound
    source .venv/bin/activate
    python -m hound --help

All commands below assume that. Paths shown match this session's contest-A
layout — swap in your own target/scope/known/notes paths as needed.

---

## check — verify provider config before spending anything

    python -m hound check

Pings every configured role (mapper, hunter, judge, judge2, diagnose, poc,
scorer) with a trivial prompt and reports which provider/model answered,
or which failed. Free or near-free. Run this first whenever you've edited
models.yaml, or before a scan on a target you haven't touched in a while.

---

## scan — the main audit run

    python -m hound scan <target_dir> \
      --scope <scope.txt> \
      --known <known.md> \
      --notes <notes.md> \
      --scope-profile contest \
      --judge-mode advisory \
      --dry-run

Then drop `--dry-run` to actually spend:

    python -m hound scan <target_dir> \
      --scope <scope.txt> \
      --known <known.md> \
      --notes <notes.md> \
      --scope-profile contest \
      --judge-mode advisory

Flags that matter:
- `<target_dir>` — the source directory to scan (e.g. contracts/ or a pinned worktree).
- `--scope <file>` — glob patterns, one per line, restricting which files are in scope.
  Paths are relative to <target_dir> itself.
- `--known <file>` — markdown describing findings you already know about (your own
  prior submissions, refuted arguments, dead ends). Hunters and the judge read this
  to avoid re-finding or re-litigating what's already settled. This is the single
  highest-leverage file for a live re-audit — keep it current.
- `--notes <file>` — free-text scope/context notes: in-scope vs out-of-scope
  vulnerability classes, trusted roles, protocol-specific assumptions. Fed into
  every prompt.
- `--scope-profile {contest,bounty}` — contest treats a ward/admin exercising a
  documented power as generally out of scope unless it breaks an invariant; bounty
  is stricter. Match whatever the program you're auditing actually is.
- `--judge-mode {advisory,strict}` — advisory annotates every candidate with the
  judge's opinion but keeps it in report.md regardless of verdict (recommended —
  lets you see and manually verify judge kills instead of losing them silently).
  strict drops anything the judge kills.
- `--lenses <list>` — comma-separated subset of hunter lenses (angles A1-A8,
  patterns P1-P15, classes C1-C7; as of 2026-10-10 — the set is whatever `kb/` parses to.
  P7-P10 were renumbered that day, see the PATTERN_MIGRATION table in `kb/BUG_PATTERNS.md`) instead of `all`. Cuts cost/time; use when you
  want a targeted re-scan rather than a full pass.
  Example: `--lenses A,P` runs every angle and pattern lens, skips classes.
- `--passes N` — number of hunt passes (default varies by config). More passes,
  more coverage, more cost.
- `--seed N` — vary this to get a different sample from a stochastic scan; useful
  for running multiple seeds and comparing/unioning results.
- `--dry-run` — prints file/chunk/call-count estimates and stops. Always run this
  once before a real scan on a new target or after a scope change.
- `--budget N` — max chars per chunk sent to the model (affects how the source is
  split). Increase for models with larger context windows.

Output lands in `runs/<timestamp>/`, including `report.md` (the human-readable
lead list), `findings.json`, `map.json`, and per-lens/per-candidate detail.

---

## rejudge — re-run only the judge stage on an existing scan

    python -m hound rejudge runs/<timestamp> \
      --known <known.md> \
      --notes <notes.md>

Use this when hunting/diagnosis already produced good candidates but judging
failed, was degraded (provider errors, wrong model), or you've updated known.md
and want stale verdicts refreshed — without re-running the (usually much more
expensive) hunt stage. Writes a new run directory; does not overwrite the original.

---

## diagnose / rediagnose — deeper per-candidate analysis

    python -m hound rediagnose runs/<timestamp>

Re-runs the diagnose stage (deeper reasoning on each surviving candidate) on an
existing run, same idea as rejudge but for diagnosis instead of judging.

---

## union — combine multiple scan runs

    python -m hound union runs/<run1> runs/<run2> runs/<run3>

Merges findings across several runs (e.g. multiple seeds), deduplicating and
reporting which findings showed up in more than one run. Useful for measuring
run-to-run variance or building confidence in a candidate that recurs.

---

## score — grade findings against a ground-truth answer key

    python -m hound score runs/<timestamp> <ground_truth.md>

Only relevant for benchmark targets where you have a known answer key (e.g.
SecondSwap/GROUND_TRUTH.md). Not applicable to live, un-scored targets like a
real contest — there, report.md is the deliverable, not a recall score.

---

## Typical live-audit workflow (what this session actually did)

    # 1. One-time setup per target
    #    - clone/checkout the target at the exact scoped commit
    #    - write scope.txt (in-scope globs)
    #    - write notes.md (in-scope/out-of-scope vuln classes, trusted roles)
    #    - write known.md (your own prior findings + refuted arguments, with a
    #      "DEAD ENDS" section per finding so the judge doesn't reconstruct them)

    # 2. Sanity check config
    python -m hound check

    # 3. Estimate cost/scope before spending
    python -m hound scan <target>/contracts --scope scope.txt --known known.md \
      --notes notes.md --scope-profile contest --dry-run

    # 4. Real scan
    python -m hound scan <target>/contracts --scope scope.txt --known known.md \
      --notes notes.md --scope-profile contest --judge-mode advisory

    # 5. If judging failed/degraded (check report.md for "needs_poc" entries whose
    #    reason is an API error, not an actual judge opinion):
    python -m hound rejudge runs/<timestamp> --known known.md --notes notes.md

    # 6. Read report.md yourself. For anything that survived or looks interesting
    #    even if killed — verify at source, by hand, independent of the judge's
    #    stated reasoning. Write a Foundry/PoC test to confirm before trusting
    #    any conclusion, yours or the model's.

---

## Cost/reliability notes worth keeping in mind

- Free-tier endpoints (zai direct, some OpenRouter free models) are the main
  source of scan instability — 429s, timeouts, silent truncation. Check
  models.yaml's provider/role config and comments before assuming a null result
  means "nothing found" rather than "the scan didn't work."
- A judge/scorer/diagnose call hitting its max_tokens ceiling while producing no
  usable output ("reasoning-only burn") is a config problem, not evidence of
  anything about the code. Check the run log for TRUNCATED / burn warnings before
  trusting a run's findings.
- advisory judge-mode + manual source verification of anything that matters is
  the reliable path — treat every "kill" and every "keep" as a hypothesis to
  check yourself, not a final answer.
