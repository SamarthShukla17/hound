"""Novelty classifier: is a confirmed finding a known pattern, or something new?

Embeddings-based, over a cloud provider already configured in models.yaml - no new dependency.
The `openai` SDK Router already manages these provider objects for chat roles (hound/llm.py);
this module just calls the SAME client's `.embeddings.create()` instead of `.chat.completions`,
through a new role ("embed" by default) you wire into models.yaml yourself, same as judge2 or
the refuter roles. No local embedding model, no MCP/Solodit client: live Solodit lookup is a
deliberate, clearly-flagged gap here, not a silent skip - it would need its own HTTP/MCP client,
which is a dependency decision for you to make (CLAUDE.md's minimal-dependency rule), not one
this module makes for you.

Two corpus sources, both human-maintained JSON files, NEITHER ever auto-written by this module:
- A target's own prior audits, pre-extracted into records (parsing a PDF/markdown audit report
  into {"title", "root_cause"} entries is a one-time manual/LLM task per target - the
  masterplan's own Day-1 action - not something this module does on every run).
- A local corpus of past confirmed findings you accumulate across targets and contests.

Both load through the same `load_records()`, using the same {"findings": [...]} shape
external.py already uses for third-party findings, so one file format serves every corpus role.
"""

import json
import math
from dataclasses import dataclass, field
from pathlib import Path

# Thresholds are a starting point, not a measured calibration (cf. kb/CALIBRATION_NOTES.md's
# convention of recording what was actually measured) - revisit once real contest/corpus data
# exists to tune against, the same way verify.py's dedup thresholds were tuned over real runs.
HIGH_SIMILARITY = 0.92  # same pattern, same mechanism: likely a dupe
MEDIUM_SIMILARITY = 0.75  # same pattern, different mechanism: still worth leading with the mechanism


def load_records(path) -> list:
    """A JSON file: a list of {"id","title","root_cause"/"summary","source"} records, or
    {"findings": [...]} (external.py's shape). A missing file is NOT an error - an empty
    corpus is a legitimate, common state, not a misconfiguration."""
    path = Path(path)
    if not path.is_file():
        return []
    data = json.loads(path.read_text())
    return data if isinstance(data, list) else data.get("findings", [])


def _text(record: dict) -> str:
    return f"{record.get('title', '')} {record.get('root_cause') or record.get('summary') or ''}".strip()


def _cosine(a: list, b: list) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


async def embed_texts(router, role: str, texts: list) -> list:
    """Try each configured target for `role`, in the same fallback order chat roles use; the
    first provider whose embeddings call succeeds wins. Raises if every target fails - callers
    treat that as "embeddings unavailable", never as a crash."""
    last_error = None
    for target, provider in router.targets(role):
        try:
            resp = await provider.client.embeddings.create(model=target["model"], input=texts)
            return [d.embedding for d in resp.data]
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            continue
    raise RuntimeError(f"no embedding target succeeded for role {role!r}: {last_error}")


@dataclass
class NoveltyResult:
    """verdict:
    - "known-pattern": nearest corpus match is close enough to read as the same bug - likely a
      dupe, low standalone contest value.
    - "known-pattern-new-mechanism": the pattern is known but the mechanism differs enough to be
      worth submitting on its own - lead the writeup with the mechanism, not the pattern name.
    - "no-corpus-match": nothing close was found - flag for extra manual verification before
      submitting, per the masterplan (a classifier finding nothing is not proof of novelty).
    - "unclassified": the comparison itself didn't happen (no corpus, no embed role configured,
      or the embedding call failed) - never conflate this with "no-corpus-match", which implies
      a real comparison ran and came back empty.
    """

    verdict: str
    nearest: list = field(default_factory=list)
    notes: str = ""


async def classify(router, role: str, finding: dict, corpus: list) -> NoveltyResult:
    """Embed `finding` and every corpus record, rank by cosine similarity, bucket by threshold."""
    if not corpus:
        return NoveltyResult(verdict="unclassified", notes="no corpus provided")
    if not router.has(role):
        return NoveltyResult(verdict="unclassified", notes=f"no {role!r} role configured - embeddings unavailable")

    texts = [_text(finding)] + [_text(r) for r in corpus]
    try:
        vectors = await embed_texts(router, role, texts)
    except Exception as exc:  # noqa: BLE001
        return NoveltyResult(verdict="unclassified", notes=f"embedding call failed: {exc}")

    # A provider that drops or reorders an embedding in the batch must not silently zip a
    # vector against the wrong corpus record - treat a count mismatch as a failed comparison,
    # never as a partial one.
    if len(vectors) != len(texts):
        return NoveltyResult(
            verdict="unclassified",
            notes=f"embedding count mismatch: sent {len(texts)} texts, got {len(vectors)} vectors back",
        )

    target_vec, corpus_vecs = vectors[0], vectors[1:]
    ranked = sorted(
        (
            {
                "source": r.get("source", ""),
                "id": r.get("id", ""),
                "title": r.get("title", ""),
                "similarity": _cosine(target_vec, v),
            }
            for r, v in zip(corpus, corpus_vecs)
        ),
        key=lambda e: -e["similarity"],
    )
    nearest = ranked[:5]
    top = nearest[0]["similarity"] if nearest else 0.0

    if top >= HIGH_SIMILARITY:
        verdict = "known-pattern"
    elif top >= MEDIUM_SIMILARITY:
        verdict = "known-pattern-new-mechanism"
    else:
        verdict = "no-corpus-match"
    return NoveltyResult(verdict=verdict, nearest=nearest)
