"""Step 2: Router/Provider fallback, caching, and JSON extraction — no network."""

import asyncio
import textwrap
from types import SimpleNamespace

import pytest

from hound.llm import Provider, Router, cache_key, extract_json

FIXTURE_MODELS_YAML = textwrap.dedent(
    """
    providers:
      enabled_provider:
        base_url: http://example.invalid/v1
        key_env: TEST_KEY_PRESENT
        rpm: 6000
        concurrency: 2
        timeout: 5
      disabled_provider:
        base_url: http://example.invalid/v1
        key_env: TEST_KEY_MISSING
        rpm: 6000
        concurrency: 2
        timeout: 5
      local_provider:
        base_url: http://localhost:11434/v1
        local: true
        key_env: null
        rpm: 6000
        concurrency: 2
        timeout: 5

    roles:
      test_role:
        - {provider: disabled_provider, model: disabled-model}
        - {provider: enabled_provider, model: enabled-model}
      local_role:
        - {provider: local_provider, model: local-model}
        - {provider: enabled_provider, model: enabled-model}

    prices: {}
    budget: {monthly_usd: 20, reserve_usd: 0.5}
    """
)


@pytest.fixture
def models_yaml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TEST_KEY_PRESENT", "secret")
    monkeypatch.delenv("TEST_KEY_MISSING", raising=False)
    path = tmp_path / "models.yaml"
    path.write_text(FIXTURE_MODELS_YAML)
    return path


def test_fallback_order_drops_disabled_providers(models_yaml):
    router = Router(models_path=str(models_yaml))
    targets = router.targets("test_role")
    assert [t["provider"] for t, _ in targets] == ["enabled_provider"]


def test_local_only_filters_non_local_providers(models_yaml):
    router = Router(models_path=str(models_yaml), local_only=True)
    targets = router.targets("local_role")
    assert [t["provider"] for t, _ in targets] == ["local_provider"]


def test_targets_raises_when_nothing_is_enabled(models_yaml, monkeypatch):
    monkeypatch.delenv("TEST_KEY_PRESENT", raising=False)
    router = Router(models_path=str(models_yaml))
    with pytest.raises(RuntimeError):
        router.targets("test_role")


def test_cache_hit_skips_the_call(models_yaml, monkeypatch):
    router = Router(models_path=str(models_yaml))

    calls = {"n": 0}

    async def fake_complete(self, **kwargs):
        calls["n"] += 1
        raise RuntimeError("should not be called on a cache hit")

    monkeypatch.setattr(Provider, "complete", fake_complete)

    key = cache_key("enabled-model", "sys", "hello", 0.3, router.seed)
    (router.cache_dir / f"{key}.txt").write_text("cached response")

    result = asyncio.run(router.chat("test_role", "sys", "hello", temperature=0.3))

    assert result == "cached response"
    assert calls["n"] == 0


def test_extract_json_with_fences():
    text = '```json\n{"a": 1}\n```'
    assert extract_json(text) == {"a": 1}


def test_extract_json_with_think_tags():
    text = '<think>let me reason about this</think>\n{"a": 1}'
    assert extract_json(text) == {"a": 1}


def test_extract_json_with_surrounding_prose():
    text = 'Sure! Here is the JSON:\n{"a": 1}\nHope that helps.'
    assert extract_json(text) == {"a": 1}


def test_extract_json_returns_none_on_garbage():
    assert extract_json("no json here at all") is None


class FakeAPIError(Exception):
    def __init__(self, status_code, message):
        super().__init__(message)
        self.status_code = status_code


def _fake_response(content):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content))],
        usage=None,
    )


def test_400_mentioning_temperature_retries_once_without_it(models_yaml, monkeypatch):
    router = Router(models_path=str(models_yaml))
    calls = []

    async def fake_complete(self, *, model, messages, temperature, max_tokens, extra=None):
        calls.append(temperature)
        if temperature is not None:
            raise FakeAPIError(400, "Unsupported value: 'temperature' is not supported")
        return _fake_response("ok without temperature")

    monkeypatch.setattr(Provider, "complete", fake_complete)

    result = asyncio.run(router.chat("test_role", "sys", "hello", temperature=0.3))

    assert result == "ok without temperature"
    assert calls == [0.3, None]


def test_404_prints_model_not_found_warning(models_yaml, monkeypatch, capsys):
    router = Router(models_path=str(models_yaml))

    async def fake_complete(self, **kwargs):
        raise FakeAPIError(404, "no such model")

    monkeypatch.setattr(Provider, "complete", fake_complete)

    with pytest.raises(RuntimeError):
        asyncio.run(router.chat("test_role", "sys", "hello", temperature=0.3))

    out = capsys.readouterr().out
    assert "MODEL NOT FOUND: enabled_provider/enabled-model" in out
    assert "check the model id in models.yaml" in out
