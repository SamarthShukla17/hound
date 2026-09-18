# hound

## Local mode, 16 GB Apple silicon

Local mode (`--local-only`) is the NDA fallback and judge2's second opinion, not the daily
driver — a 16 GB Mac has real ceilings here (see `models.yaml`'s comment on the Ollama
provider for the measured numbers).

**Start the server with an explicit context length, before `ollama serve` runs:**

```bash
OLLAMA_CONTEXT_LENGTH=16384 OLLAMA_KEEP_ALIVE=30m OLLAMA_FLASH_ATTENTION=1 OLLAMA_KV_CACHE_TYPE=q8_0 ollama serve
```

Context has to be set before `serve` starts — it can't be changed per-request. Ollama's
default context is 4096 tokens, and it truncates silently past that: the hunter ends up
being told to cite lines that were never actually in what it saw, and every citation fails
the citation gate for a reason that looks like a model problem but is actually a config one.

**Sizing for 16 GB:** `qwen2.5-coder:7b` at `OLLAMA_CONTEXT_LENGTH=16384` pairs with
`--budget 40000`. After starting a scan, check `ollama ps` — it should show 100% GPU.
Anything like `27%/73% CPU/GPU` means the model spilled out of Metal's ~11.8 GiB budget and
partially offloaded to CPU; the scan will take hours instead of minutes.

**The general rule, always:** `--budget` (in characters) must stay `<= context_tokens * 2.5`.
Going over this means the prompt gets silently truncated by Ollama before the model ever
sees it — same failure mode as an unset context length, just from the other side.
