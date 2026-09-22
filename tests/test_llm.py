"""Step 2: Router/Provider fallback, caching, and JSON extraction — no network."""

import asyncio
import json
import textwrap
from types import SimpleNamespace

import pytest

from hound.llm import (
    CallCeilingExceeded, OutOfCredits, Provider, Router, cache_key, extract_json, parse_cache_any_model,
)

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


def test_local_only_fails_fast_when_no_provider_is_local(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_KEY_PRESENT", "secret")
    path = tmp_path / "models.yaml"
    path.write_text(
        textwrap.dedent(
            """
            providers:
              enabled_provider:
                base_url: http://example.invalid/v1
                key_env: TEST_KEY_PRESENT
                rpm: 6000
                concurrency: 2
                timeout: 5
            roles:
              test_role:
                - {provider: enabled_provider, model: enabled-model}
            prices: {}
            """
        )
    )
    with pytest.raises(RuntimeError, match="no local provider configured"):
        Router(models_path=str(path), local_only=True)


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

    async def fake_complete(self, *, model, messages, temperature, max_tokens, extra=None, **kw):
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


def _resp(content, completion_tokens, finish_reason="stop"):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content), finish_reason=finish_reason)],
        usage=SimpleNamespace(prompt_tokens=10, completion_tokens=completion_tokens),
    )


def test_max_tokens_precedence_target_over_role_map_over_default(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TEST_KEY_PRESENT", "secret")
    path = tmp_path / "models.yaml"
    path.write_text(
        textwrap.dedent(
            """
            providers:
              p: {base_url: "http://example.invalid/v1", key_env: TEST_KEY_PRESENT, rpm: 6000, concurrency: 2, timeout: 5}
            max_tokens: {mapped_role: 777}
            roles:
              hunter: [{provider: p, model: m}]
              mapped_role: [{provider: p, model: m}]
              targeted_role: [{provider: p, model: m, max_tokens: 4321}]
              unknown_role: [{provider: p, model: m}]
            """
        )
    )
    router = Router(models_path=str(path), fresh=True)
    sent = {}

    async def fake_complete(self, *, model, messages, temperature, max_tokens, extra=None, **kw):
        sent["max_tokens"] = max_tokens
        return _resp("ok", 5)

    monkeypatch.setattr(Provider, "complete", fake_complete)

    for role, expected in [("hunter", 20000), ("mapped_role", 777), ("targeted_role", 4321), ("unknown_role", 2048)]:
        asyncio.run(router.chat(role, "s", f"u-{role}"))
        assert sent["max_tokens"] == expected, role

    asyncio.run(router.chat("hunter", "s", "explicit", max_tokens=9))
    assert sent["max_tokens"] == 9


def test_budget_spent_entirely_inside_think_is_a_reasoning_only_burn(models_yaml, monkeypatch, capsys):
    """The observed scorer failure: 60000/60000 completion tokens, all of it <think>, no answer.
    It must NOT be reported as ordinary truncation, because the remedy is the opposite — a
    bigger ceiling buys more reasoning, not more answer."""
    router = Router(models_path=str(models_yaml), fresh=True)

    async def fake_complete(self, *, model, messages, temperature, max_tokens, extra=None, **kw):
        # the shape actually observed: the provider carried reasoning on its own channel and
        # handed back an EMPTY content with finish_reason=length
        return _resp("", completion_tokens=max_tokens, finish_reason="length")

    monkeypatch.setattr(Provider, "complete", fake_complete)
    with pytest.raises(RuntimeError):
        asyncio.run(router.chat("test_role", "s", "u", max_tokens=100))

    out = capsys.readouterr().out
    assert "REASONING-ONLY BURN" in out
    assert "100/100 completion tokens" in out
    assert "Do not raise max_tokens" in out
    assert "returned an empty reply" not in out


def test_reply_cut_off_mid_reasoning_is_also_a_burn_not_an_answer(models_yaml, monkeypatch, capsys):
    """An unclosed <think> is what truncation mid-reasoning looks like. _THINK_RE only matches
    a CLOSED block, so without the guard the raw chain-of-thought would be returned as the
    model's answer."""
    router = Router(models_path=str(models_yaml), fresh=True)

    async def fake_complete(self, *, model, messages, temperature, max_tokens, extra=None, **kw):
        return _resp("<think>weighing the candidates " * 9, completion_tokens=max_tokens, finish_reason="length")

    monkeypatch.setattr(Provider, "complete", fake_complete)
    with pytest.raises(RuntimeError):
        asyncio.run(router.chat("test_role", "s", "u", max_tokens=100))

    out = capsys.readouterr().out
    assert "REASONING-ONLY BURN" in out
    assert "weighing the candidates" not in out  # reasoning never surfaces as an answer


def test_a_partially_written_answer_at_the_cap_is_ordinary_truncation(models_yaml, monkeypatch, capsys):
    """The other mode: the model DID start answering and got cut off. Distinct message, and the
    partial text is still returned to the caller."""
    router = Router(models_path=str(models_yaml), fresh=True)

    async def fake_complete(self, *, model, messages, temperature, max_tokens, extra=None, **kw):
        return _resp("<think>brief</think>{\"partial\": tru", completion_tokens=max_tokens, finish_reason="length")

    monkeypatch.setattr(Provider, "complete", fake_complete)
    text = asyncio.run(router.chat("test_role", "s", "u", max_tokens=100))

    out = capsys.readouterr().out
    assert "TRUNCATED BY max_tokens" in out
    assert "REASONING-ONLY BURN" not in out
    assert text == '{"partial": tru'  # partial answer handed back, just never cached


def test_empty_reply_well_under_the_cap_is_a_plain_empty_reply(models_yaml, monkeypatch, capsys):
    router = Router(models_path=str(models_yaml), fresh=True)

    async def fake_complete(self, *, model, messages, temperature, max_tokens, extra=None, **kw):
        return _resp("", completion_tokens=3, finish_reason="stop")

    monkeypatch.setattr(Provider, "complete", fake_complete)
    with pytest.raises(RuntimeError):
        asyncio.run(router.chat("test_role", "s", "u", max_tokens=100))

    out = capsys.readouterr().out
    assert "returned an empty reply" in out
    assert "TRUNCATED" not in out


def test_report_includes_per_call_token_detail(models_yaml, monkeypatch):
    router = Router(models_path=str(models_yaml), fresh=True)

    async def fake_complete(self, *, model, messages, temperature, max_tokens, extra=None, **kw):
        return _resp("hello", completion_tokens=42)

    monkeypatch.setattr(Provider, "complete", fake_complete)
    asyncio.run(router.chat("test_role", "s", "u"))

    call = router.report()["calls"][0]
    assert call["role"] == "test_role" and call["completion_tokens"] == 42 and call["max_tokens"] == 2048


def test_cache_salt_changes_the_key_but_unsalted_keys_are_unchanged():
    plain = cache_key("m", "s", "u", 0.0, 0)
    assert plain == cache_key("m", "s", "u", 0.0, 0, "")
    assert cache_key("m", "s", "u", 0.0, 0, "hash-of-file-v1") != plain
    assert cache_key("m", "s", "u", 0.0, 0, "hash-of-file-v1") != cache_key("m", "s", "u", 0.0, 0, "hash-of-file-v2")


def test_a_salted_call_never_serves_an_entry_cached_for_different_file_contents(models_yaml, monkeypatch):
    router = Router(models_path=str(models_yaml))
    calls = {"n": 0}

    async def fake_complete(self, *, model, messages, temperature, max_tokens, extra=None, **kw):
        calls["n"] += 1
        return _resp(f"verdict about version {calls['n']}", 5)

    monkeypatch.setattr(Provider, "complete", fake_complete)

    first = asyncio.run(router.chat("test_role", "s", "same prompt", cache_salt="file-v1"))
    again = asyncio.run(router.chat("test_role", "s", "same prompt", cache_salt="file-v1"))
    changed = asyncio.run(router.chat("test_role", "s", "same prompt", cache_salt="file-v2"))

    assert first == again  # same file contents -> cache hit
    assert changed != first  # file changed -> the old verdict is NOT served
    assert calls["n"] == 2


def test_a_reply_cut_off_at_max_tokens_is_returned_but_never_cached(models_yaml, monkeypatch, capsys):
    router = Router(models_path=str(models_yaml))

    async def fake_complete(self, *, model, messages, temperature, max_tokens, extra=None, **kw):
        return _resp('{"findings": [', completion_tokens=max_tokens, finish_reason="length")

    monkeypatch.setattr(Provider, "complete", fake_complete)
    text = asyncio.run(router.chat("test_role", "s", "u", max_tokens=50))

    assert text == '{"findings": ['
    assert list(router.cache_dir.glob("*.txt")) == []
    assert "TRUNCATED BY max_tokens" in capsys.readouterr().out


# --- cache_any_model ---------------------------------------------------------------------

CACHE_ANY_YAML = textwrap.dedent(
    """
    providers:
      primary: {base_url: "http://example.invalid/v1", key_env: TEST_KEY_PRESENT, rpm: 6000, concurrency: 2, timeout: 5}
    roles:
      hunter:  [{provider: primary, model: primary-model}, {provider: primary, model: fallback-model}]
      judge:   [{provider: primary, model: primary-model}, {provider: primary, model: fallback-model}]
    prices: {}
    """
)


def _cache_any_router(tmp_path, monkeypatch, **kw):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TEST_KEY_PRESENT", "secret")
    path = tmp_path / "models.yaml"
    path.write_text(CACHE_ANY_YAML)
    return Router(models_path=str(path), **kw)


def _seed_cache(router, prompt, reply, answered_by, provider="primary"):
    key = cache_key("*", "s", prompt, 0.3, 0)
    (router.cache_dir / f"{key}.txt").write_text(reply)
    if answered_by is not None:
        (router.cache_dir / f"{key}.meta.json").write_text(json.dumps({"model": answered_by, "provider": provider}))


def test_a_reply_from_another_configured_model_is_replayed_across_providers(tmp_path, monkeypatch):
    router = _cache_any_router(tmp_path, monkeypatch)
    calls = []

    async def fake_complete(self, *, model, messages, temperature, max_tokens, extra=None, **kw):
        calls.append(model)
        return _resp("reply", 5)

    monkeypatch.setattr(Provider, "complete", fake_complete)
    # a previous run's reply came from the FALLBACK model, which is still a configured target...
    _seed_cache(router, "prompt", "reply from the fallback", answered_by="fallback-model")
    # ...and this run tries the primary first, but still replays it rather than re-sampling
    assert asyncio.run(router.chat("hunter", "s", "prompt")) == "reply from the fallback"
    assert calls == []


def test_a_reply_from_a_model_no_longer_configured_for_the_role_is_not_replayed(tmp_path, monkeypatch, capsys):
    router = _cache_any_router(tmp_path, monkeypatch)
    calls = []

    async def fake_complete(self, *, model, messages, temperature, max_tokens, extra=None, **kw):
        calls.append(model)
        return _resp("fresh reply", 5)

    monkeypatch.setattr(Provider, "complete", fake_complete)
    _seed_cache(router, "prompt", "random free-router reply", answered_by="openrouter/free")

    assert asyncio.run(router.chat("hunter", "s", "prompt")) == "fresh reply"
    assert calls == ["primary-model"]
    assert "not a configured target for role 'hunter'" in capsys.readouterr().out

    # the stale entry was replaced, and now records who answered
    key = cache_key("*", "s", "prompt", 0.3, 0)
    assert (router.cache_dir / f"{key}.txt").read_text() == "fresh reply"
    assert json.loads((router.cache_dir / f"{key}.meta.json").read_text())["model"] == "primary-model"
    # and the next call replays the fresh one
    assert asyncio.run(router.chat("hunter", "s", "prompt")) == "fresh reply" and calls == ["primary-model"]


def test_a_model_agnostic_entry_with_no_recorded_model_cannot_be_verified_so_it_is_not_replayed(tmp_path, monkeypatch):
    router = _cache_any_router(tmp_path, monkeypatch)

    async def fake_complete(self, *, model, messages, temperature, max_tokens, extra=None, **kw):
        return _resp("fresh reply", 5)

    monkeypatch.setattr(Provider, "complete", fake_complete)
    _seed_cache(router, "prompt", "unverifiable", answered_by=None)
    assert asyncio.run(router.chat("hunter", "s", "prompt")) == "fresh reply"


def test_every_new_cache_entry_records_the_model_and_provider_that_answered(tmp_path, monkeypatch):
    router = _cache_any_router(tmp_path, monkeypatch)

    async def fake_complete(self, *, model, messages, temperature, max_tokens, extra=None, **kw):
        return _resp("reply", 5)

    monkeypatch.setattr(Provider, "complete", fake_complete)
    asyncio.run(router.chat("hunter", "s", "prompt"))
    meta = json.loads((router.cache_dir / f"{cache_key('*', 's', 'prompt', 0.3, 0)}.meta.json").read_text())
    assert meta == {"model": "primary-model", "provider": "primary"}


def test_judge_cache_stays_model_specific(tmp_path, monkeypatch):
    router = _cache_any_router(tmp_path, monkeypatch)
    calls = []

    async def fake_complete(self, *, model, messages, temperature, max_tokens, extra=None, **kw):
        calls.append(model)
        return _resp("fresh verdict", 5)

    monkeypatch.setattr(Provider, "complete", fake_complete)
    # a verdict cached for the FALLBACK model must not answer for the primary
    (router.cache_dir / f"{cache_key('fallback-model', 's', 'prompt', 0.3, 0)}.txt").write_text("old verdict")
    assert asyncio.run(router.chat("judge", "s", "prompt")) == "fresh verdict"
    assert calls == ["primary-model"]


def test_cache_any_model_none_restores_model_specific_hunter_keys(tmp_path, monkeypatch):
    router = _cache_any_router(tmp_path, monkeypatch, cache_any_model=parse_cache_any_model("none"))

    async def fake_complete(self, *, model, messages, temperature, max_tokens, extra=None, **kw):
        return _resp("fresh", 5)

    monkeypatch.setattr(Provider, "complete", fake_complete)
    (router.cache_dir / f"{cache_key('*', 's', 'prompt', 0.3, 0)}.txt").write_text("agnostic entry")
    assert asyncio.run(router.chat("hunter", "s", "prompt")) == "fresh"


def test_parse_cache_any_model():
    assert parse_cache_any_model(None) == {"mapper", "hunter", "poc"}
    assert parse_cache_any_model("none") == frozenset() == parse_cache_any_model("")
    assert parse_cache_any_model("hunter, judge") == {"hunter", "judge"}


# --- 402: hard abort, never a graceful fallback -----------------------------------------------


def test_a_402_raises_out_of_credits_instead_of_falling_back_to_the_next_target(models_yaml, monkeypatch):
    """The fallback chain exists so a scan survives a flaky provider. It must NOT quietly swap a
    paid model for a free one because the account can't pay — that produces a run whose numbers
    are not what they claim."""
    router = Router(models_path=str(models_yaml))
    tried = []

    async def fake_complete(self, *, model, messages, temperature, max_tokens, extra=None, **kw):
        tried.append(model)
        raise FakeAPIError(402, "This request requires more credits, or fewer max_tokens")

    monkeypatch.setattr(Provider, "complete", fake_complete)
    with pytest.raises(OutOfCredits) as excinfo:
        asyncio.run(router.chat("test_role", "s", "u"))

    assert tried == ["enabled-model"]  # stopped dead: no retry, no second target
    assert "402" in str(excinfo.value) or "credits" in str(excinfo.value)


def test_a_402_is_not_retried_with_backoff_like_a_429(models_yaml, monkeypatch, capsys):
    router = Router(models_path=str(models_yaml))
    calls = {"n": 0}

    async def fake_complete(self, *, model, messages, temperature, max_tokens, extra=None, **kw):
        calls["n"] += 1
        raise FakeAPIError(402, "insufficient credits")

    monkeypatch.setattr(Provider, "complete", fake_complete)
    with pytest.raises(OutOfCredits):
        asyncio.run(router.chat("test_role", "s", "u"))
    assert calls["n"] == 1
    assert "BACKOFF" not in capsys.readouterr().out


def test_other_payment_ish_errors_still_use_the_normal_fallback(models_yaml, monkeypatch):
    """Only 402 aborts; a 429 must still fall through the chain as before."""
    router = Router(models_path=str(models_yaml))
    calls = {"n": 0}

    async def fake_complete(self, *, model, messages, temperature, max_tokens, extra=None, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise FakeAPIError(429, "rate limited")
        return _resp("recovered", 5)

    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr(Provider, "complete", fake_complete)
    monkeypatch.setattr("hound.llm.asyncio.sleep", no_sleep)
    assert asyncio.run(router.chat("test_role", "s", "u")) == "recovered"
    assert calls["n"] == 2  # retried, unlike a 402


# --- the call ceiling must bound the HTTP attempt, never the queue wait ----------------------

SERIAL_YAML = textwrap.dedent(
    """
    providers:
      serial: {base_url: "http://example.invalid/v1", key_env: TEST_KEY_PRESENT, rpm: 100000, concurrency: 1, timeout: 30}
    roles:
      hunter: [{provider: serial, model: m}]
    prices: {}
    """
)


def _serial_router(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TEST_KEY_PRESENT", "secret")
    path = tmp_path / "models.yaml"
    path.write_text(SERIAL_YAML)
    return Router(models_path=str(path), fresh=True)


def test_queued_calls_on_a_serial_provider_are_not_killed_for_waiting_their_turn(tmp_path, monkeypatch):
    """REGRESSION GUARD. 14 lenses dispatched at once against concurrency:1 means 13 sit in the
    queue. Charging them for the wait killed 13 of 14 lenses on a real bench run, each having
    never sent a request. Aggregate runtime here (10 x 0.1s) far exceeds the 0.25s ceiling, and
    every call must still complete."""
    router = _serial_router(tmp_path, monkeypatch)
    n, per_call, ceiling = 10, 0.1, 0.25
    concurrent = {"now": 0, "max": 0}

    async def fake_complete(self, *, model, messages, temperature, max_tokens, extra=None, role="", on_slot=None):
        self._ensure_sync_primitives()
        async with self._semaphore:          # the real serialisation
            if on_slot is not None:
                on_slot()                     # budget starts HERE, not at task creation
            concurrent["now"] += 1
            concurrent["max"] = max(concurrent["max"], concurrent["now"])
            await asyncio.sleep(per_call)
            concurrent["now"] -= 1
        return _resp("ok", 5)

    monkeypatch.setattr(Provider, "complete", fake_complete)

    async def run_all():
        return await asyncio.gather(*(
            router.chat("hunter", "s", f"lens-{i}", ceiling=ceiling) for i in range(n)
        ))

    results = asyncio.run(run_all())

    assert results == ["ok"] * n          # ALL complete; none killed for queueing
    assert concurrent["max"] == 1         # the provider really was serial


def _fake_client(delay=0.0, hang=False):
    """Stands in for AsyncOpenAI so the REAL Provider.complete (timeout + queue logging) runs.

    `hang` waits on an Event that is never set, so a test that patches asyncio.sleep to skip
    backoff waits cannot accidentally un-hang it.
    """

    class FakeClient:
        class chat:
            class completions:
                @staticmethod
                async def create(**kwargs):
                    if hang:
                        await asyncio.Event().wait()
                    await asyncio.sleep(delay)
                    return _resp("ok", 5)

    return FakeClient()


def test_a_stalled_http_attempt_is_bounded_by_the_provider_timeout_not_the_ceiling(tmp_path, monkeypatch):
    """A call that hangs holding the slot is cut off by the per-attempt provider timeout
    (30s in this fixture, 0.1s here), which is what bounds a stall; the ceiling then stops
    the retries."""
    router = _serial_router(tmp_path, monkeypatch)
    provider = router.providers["serial"]
    provider.cfg["timeout"] = 0.1
    provider.client = _fake_client(hang=True)  # never returns

    async def no_sleep(_s):
        return None

    monkeypatch.setattr("hound.llm.asyncio.sleep", no_sleep)  # skip backoff waits
    with pytest.raises(RuntimeError) as excinfo:
        asyncio.run(router.chat("hunter", "s", "u", ceiling=5))

    # It terminated instead of hanging forever: the attempt was cut at the provider timeout,
    # then the ceiling stopped the retries.
    assert "budget exhausted" in str(excinfo.value) or "timeout" in str(excinfo.value).lower()


def test_the_ceiling_stops_further_retries_once_the_budget_is_spent(tmp_path, monkeypatch, capsys):
    router = _serial_router(tmp_path, monkeypatch)
    attempts = {"n": 0}

    async def fails_slowly(self, *, model, messages, temperature, max_tokens, extra=None, role="", on_slot=None):
        if on_slot is not None:
            on_slot()
        attempts["n"] += 1
        await asyncio.sleep(0.12)
        raise FakeAPIError(500, "server error")

    monkeypatch.setattr(Provider, "complete", fails_slowly)
    with pytest.raises(RuntimeError):
        asyncio.run(router.chat("hunter", "s", "u", ceiling=0.2))

    assert attempts["n"] < 3  # gave up early instead of burning all three retries
    assert "CALL CEILING" in capsys.readouterr().out


def test_a_queued_call_logs_that_it_is_waiting_rather_than_looking_hung(tmp_path, monkeypatch, capsys):
    """The ambiguity between "busy" and "hung" is what prompted the ceiling in the first place."""
    router = _serial_router(tmp_path, monkeypatch)
    router.providers["serial"].client = _fake_client(delay=0.05)

    async def run_three():
        return await asyncio.gather(*(router.chat("hunter", "s", f"u{i}") for i in range(3)))

    assert asyncio.run(run_three()) == ["ok"] * 3
    out = capsys.readouterr().out
    assert "queued:" in out and "waiting for a slot (concurrency 1)" in out
    assert "hunter" in out  # the role is named, so a slow lens is identifiable
