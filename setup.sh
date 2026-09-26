#!/usr/bin/env bash
# Bootstrap hound in a fresh (e.g. Claude Code cloud) environment.
# Installs Python deps and CHECKS that API-key env vars are present. Never prints their values.
set -euo pipefail
cd "$(dirname "$0")"

PY="$(command -v python3.12 || command -v python3 || true)"
[ -n "$PY" ] || { echo "ERROR: python3 not found"; exit 1; }
echo "python: $($PY --version)"

if [ ! -d .venv ]; then "$PY" -m venv .venv; fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt
echo "deps: installed from requirements.txt"

missing=0
for var in OPENROUTER_API_KEY ANTHROPIC_API_KEY OPENAI_API_KEY XAI_API_KEY ZAI_API_KEY; do
  if [ -z "${!var:-}" ]; then echo "WARNING: $var not set"; missing=$((missing+1)); else echo "ok: $var present"; fi
done
[ "$missing" -eq 0 ] || echo "note: only set the keys for providers you use (see models.yaml); hound also reads .env"

command -v forge >/dev/null 2>&1 && echo "forge: $(forge --version | head -1)" || echo "note: forge not installed (only needed for 'hound coverage')"

python -m pytest -q -x --no-header 2>&1 | tail -3 || true
echo "hound ready: activate with 'source .venv/bin/activate'"
