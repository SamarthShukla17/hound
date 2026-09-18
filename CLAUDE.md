# hound

A model-agnostic, multi-agent smart-contract audit harness in Python 3.12.

## Pipeline

```
scope gate -> mapper -> hunters (one per lens x chunk x pass) -> dedup -> citation gate
  -> judge -> judge2 -> PoC scaffolds -> report -> score vs ground truth
```

Knowledge comes from `kb/*.md` (METHODOLOGY, ATTACK_ANGLES, BUG_PATTERNS). **Never hardcode
lens text** — lenses are parsed out of the kb files at runtime, not embedded in code or prompts.

## Rules

- I own this harness. Explain the reasoning before writing code, keep modules small and
  commented, and ask me one check-question per step. I'll say when I'm ready to move on.
- Only OpenAI-compatible APIs via the `openai` SDK. No LangChain or other agent frameworks.
- Secrets live only in `.env`. Never print, log, or commit keys. `.env`, `.hound_cache/`,
  `runs/`, `corpus/`, and `~/.hound/` stay out of git.
- Every step ends with `pytest` passing and a git commit `"step N: ..."`.
- No real network calls in tests: use the mock OpenAI server introduced in step 7.
- `reference/` is read-only. Don't copy from it blindly; tell me whenever you consult it.
- Minimal dependencies: `openai`, `pydantic`, `pyyaml`, `python-dotenv`, `pytest`.
  Optional: `x402[httpx,evm,svm]`.

## Notes

- `reference/` (the unzipped `hound.zip`) was not provided when this project was scaffolded,
  so it does not exist yet in this repo. If it's added later, treat it as read-only per the
  rule above.
- `.venv` runs Python 3.12 (installed via `brew install python@3.12`).
