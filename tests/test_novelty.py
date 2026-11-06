"""Step M: Novelty classifier — corpus loading, cosine ranking, threshold buckets. No real network."""

import asyncio
import json

import pytest

from bloodhound.novelty import classify, embed_texts, load_records


def test_load_records_missing_file_is_empty_corpus(tmp_path):
    assert load_records(tmp_path / "nope.json") == []


def test_load_records_accepts_bare_list_and_findings_wrapper(tmp_path):
    a = tmp_path / "a.json"
    a.write_text(json.dumps([{"id": "X1", "title": "t"}]))
    assert load_records(a) == [{"id": "X1", "title": "t"}]

    b = tmp_path / "b.json"
    b.write_text(json.dumps({"findings": [{"id": "X2", "title": "u"}]}))
    assert load_records(b) == [{"id": "X2", "title": "u"}]


class FakeProvider:
    def __init__(self, vectors=None, error=None):
        self.client = self
        self.vectors = vectors
        self.error = error
        self.embeddings = self  # provider.client.embeddings.create(...)
        self.calls = 0

    async def create(self, model, input):
        self.calls += 1
        if self.error is not None:
            raise self.error
        from types import SimpleNamespace

        return SimpleNamespace(data=[SimpleNamespace(embedding=v) for v in self.vectors])


class FakeRouter:
    def __init__(self, role_targets: dict, configured_roles=None):
        self.role_targets = role_targets  # role -> [(target, provider), ...]
        self.configured_roles = configured_roles if configured_roles is not None else set(role_targets)

    def has(self, role):
        return role in self.configured_roles

    def targets(self, role):
        return self.role_targets[role]


def test_embed_texts_falls_back_to_next_target_on_failure():
    bad = FakeProvider(error=RuntimeError("down"))
    good = FakeProvider(vectors=[[1.0, 0.0]])
    router = FakeRouter({"embed": [({"model": "bad-model"}, bad), ({"model": "good-model"}, good)]})
    vectors = asyncio.run(embed_texts(router, "embed", ["hello"]))
    assert vectors == [[1.0, 0.0]]
    assert bad.calls == 1 and good.calls == 1


def test_embed_texts_raises_when_every_target_fails():
    bad = FakeProvider(error=RuntimeError("down"))
    router = FakeRouter({"embed": [({"model": "bad-model"}, bad)]})
    with pytest.raises(RuntimeError):
        asyncio.run(embed_texts(router, "embed", ["hello"]))


# --- classify: corpus/role gating -------------------------------------------


def test_classify_no_corpus_is_unclassified():
    router = FakeRouter({})
    result = asyncio.run(classify(router, "embed", {"title": "x"}, []))
    assert result.verdict == "unclassified"
    assert "no corpus" in result.notes


def test_classify_no_embed_role_is_unclassified():
    router = FakeRouter({}, configured_roles=set())
    result = asyncio.run(classify(router, "embed", {"title": "x"}, [{"id": "C1", "title": "y"}]))
    assert result.verdict == "unclassified"
    assert "no 'embed' role" in result.notes


def test_classify_embedding_failure_is_unclassified_not_a_crash():
    bad = FakeProvider(error=RuntimeError("down"))
    router = FakeRouter({"embed": [({"model": "m"}, bad)]})
    result = asyncio.run(classify(router, "embed", {"title": "x"}, [{"id": "C1", "title": "y"}]))
    assert result.verdict == "unclassified"
    assert "embedding call failed" in result.notes


# --- classify: threshold buckets -------------------------------------------


def _router_with_vectors(vectors):
    provider = FakeProvider(vectors=vectors)
    return FakeRouter({"embed": [({"model": "m"}, provider)]})


def test_classify_known_pattern_when_nearly_identical():
    # finding vector == corpus vector -> cosine similarity 1.0 >= HIGH_SIMILARITY
    router = _router_with_vectors([[1.0, 0.0], [1.0, 0.0]])
    corpus = [{"id": "C1", "title": "dup", "source": "solodit:1"}]
    result = asyncio.run(classify(router, "embed", {"title": "dup"}, corpus))
    assert result.verdict == "known-pattern"
    assert result.nearest[0]["id"] == "C1"


def test_classify_known_pattern_new_mechanism_in_the_middle_band():
    # orthogonal-ish but not fully dissimilar: cos(30deg) ~ 0.866, between MEDIUM and HIGH
    import math

    v1 = [1.0, 0.0]
    theta = math.radians(30)
    v2 = [math.cos(theta), math.sin(theta)]
    router = _router_with_vectors([v1, v2])
    result = asyncio.run(classify(router, "embed", {"title": "a"}, [{"id": "C1", "title": "b"}]))
    assert result.verdict == "known-pattern-new-mechanism"


def test_classify_no_corpus_match_when_dissimilar():
    router = _router_with_vectors([[1.0, 0.0], [0.0, 1.0]])  # orthogonal -> similarity 0.0
    result = asyncio.run(classify(router, "embed", {"title": "a"}, [{"id": "C1", "title": "b"}]))
    assert result.verdict == "no-corpus-match"


def test_classify_ranks_nearest_first_and_caps_at_five():
    vectors = [[1.0, 0.0]] + [[v, 1 - v] for v in (0.1, 0.9, 0.3, 0.95, 0.5, 0.2)]
    router = _router_with_vectors(vectors)
    corpus = [{"id": f"C{i}", "title": str(i)} for i in range(6)]
    result = asyncio.run(classify(router, "embed", {"title": "x"}, corpus))
    assert len(result.nearest) == 5
    sims = [n["similarity"] for n in result.nearest]
    assert sims == sorted(sims, reverse=True)
