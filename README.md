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
