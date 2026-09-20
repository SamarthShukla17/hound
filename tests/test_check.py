"""Step 9: the check command — pings each role's first usable target only,
never falling through to a working second target that could mask a dead
first-choice endpoint."""

import argparse
import asyncio
import textwrap

from tests.mock_server import MockServer

from hound.llm import Router, _first_usable_target, check


def _models_yaml(base_url: str) -> str:
    return textwrap.dedent(
        f"""
        providers:
          mock:
            base_url: {base_url}
            key_env: null
            rpm: 6000
            concurrency: 8
            timeout: 5
          missing_key:
            base_url: https://example.invalid/v1
            key_env: SOME_MISSING_KEY_ENV_XYZ
            rpm: 60
            concurrency: 4
            timeout: 5
          dead:
            base_url: http://127.0.0.1:1/v1
            key_env: null
            rpm: 60
            concurrency: 4
            timeout: 2
          x402gw:
            type: x402
            base_url: https://placeholder.invalid/v1
            key_env: null
            rpm: 30
            concurrency: 2
            timeout: 5

        roles:
          mapper: [{{provider: mock, model: mock-model}}]
          hunter: [{{provider: missing_key, model: some-model}}]
          judge: [{{provider: dead, model: some-model}}]
          judge2: [{{provider: x402gw, model: some-model}}]
          poc: [{{provider: mock, model: mock-model}}]
          scorer: [{{provider: mock, model: mock-model}}]

        prices: {{}}
        budget: {{monthly_usd: 20, reserve_usd: 0.5}}
        """
    )


def _check_args(**overrides) -> argparse.Namespace:
    defaults = dict(models=None, local_only=False, paid=False, strict=False)
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def test_check_reports_a_live_target(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("SOME_MISSING_KEY_ENV_XYZ", raising=False)
    with MockServer() as mock:
        models_path = tmp_path / "models.yaml"
        models_path.write_text(_models_yaml(mock.base_url))
        asyncio.run(check(_check_args(models=str(models_path))))

    out = capsys.readouterr().out
    assert "mapper: mock/mock-model:" in out
    assert "poc: mock/mock-model:" in out


def test_check_names_the_missing_key_for_an_unusable_role(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("SOME_MISSING_KEY_ENV_XYZ", raising=False)
    with MockServer() as mock:
        models_path = tmp_path / "models.yaml"
        models_path.write_text(_models_yaml(mock.base_url))
        asyncio.run(check(_check_args(models=str(models_path))))

    out = capsys.readouterr().out
    assert "hunter: no usable target (missing: SOME_MISSING_KEY_ENV_XYZ)" in out


def test_check_reports_failure_for_a_dead_endpoint_and_exits_nonzero(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("SOME_MISSING_KEY_ENV_XYZ", raising=False)
    with MockServer() as mock:
        models_path = tmp_path / "models.yaml"
        models_path.write_text(_models_yaml(mock.base_url))
        exit_code = asyncio.run(check(_check_args(models=str(models_path))))

    out = capsys.readouterr().out
    assert "judge: dead/some-model: FAILED:" in out
    assert exit_code == 1


def test_first_usable_target_skips_x402_unless_paid(tmp_path):
    with MockServer() as mock:
        models_path = tmp_path / "models.yaml"
        models_path.write_text(_models_yaml(mock.base_url))
        router = Router(models_path=str(models_path))

        # Simulate a wallet + budget being configured (step 10 territory),
        # so this test exercises the --paid filter itself, independent of
        # whether that machinery exists yet.
        router.providers["x402gw"].enabled = True

        targets = router.roles["judge2"]
        assert _first_usable_target(router, targets, paid=False) is None

        found = _first_usable_target(router, targets, paid=True)
        assert found is not None
        assert found[0]["provider"] == "x402gw"


def test_check_skips_a_role_with_no_targets_without_failing(tmp_path, capsys):
    models_path = tmp_path / "models.yaml"
    models_path.write_text(
        "providers:\n  p: {base_url: 'http://127.0.0.1:1/v1', key_env: null, rpm: 60, concurrency: 1, timeout: 1}\n"
        "roles:\n  judge2: []\nprices: {}\n"
    )
    exit_code = asyncio.run(check(_check_args(models=str(models_path))))
    assert "judge2: no targets configured — skipped" in capsys.readouterr().out
    assert exit_code == 0


# --- strict preflight ------------------------------------------------------------------------
# Two distinct ways a role fails to reach its configured primary:
#   disabled primary (no key)  -> _first_usable_target skips it -> STRICT FAIL, would fall back
#   unreachable primary        -> it is "usable", the ping fails -> FAILED
# Both must fail the preflight, because both mean the run would not use the model it names.

STRICT_YAML = """
providers:
  live: {{base_url: {base}, key_env: null, rpm: 6000, concurrency: 4, timeout: 10}}
  needs_key: {{base_url: {base}, key_env: ABSENT_KEY_FOR_STRICT_TEST, rpm: 60, concurrency: 1, timeout: 10}}
  dead: {{base_url: "http://127.0.0.1:1/v1", key_env: null, rpm: 60, concurrency: 1, timeout: 2}}
roles:
  mapper: [{{provider: live, model: primary-model}}]
  hunter: [{{provider: needs_key, model: wanted-model}}, {{provider: live, model: fallback-model}}]
prices: {{}}
"""


def _strict_config(tmp_path, mock):
    path = tmp_path / "models.yaml"
    path.write_text(STRICT_YAML.format(base=mock.base_url))
    return path


def test_strict_fails_when_a_role_would_silently_fall_back_to_a_secondary(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ABSENT_KEY_FOR_STRICT_TEST", raising=False)
    with MockServer() as mock:
        exit_code = asyncio.run(check(_check_args(models=str(_strict_config(tmp_path, mock)), strict=True)))

    out = capsys.readouterr().out
    assert exit_code == 1
    assert "hunter: STRICT FAIL" in out
    assert "configured primary needs_key/wanted-model is unusable" in out
    assert "would fall back to live/fallback-model" in out
    assert "mapper: live/primary-model" in out  # the healthy role still reports normally


def test_without_strict_that_same_fallback_is_accepted(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ABSENT_KEY_FOR_STRICT_TEST", raising=False)
    with MockServer() as mock:
        exit_code = asyncio.run(check(_check_args(models=str(_strict_config(tmp_path, mock)), strict=False)))

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "STRICT FAIL" not in out
    assert "hunter: live/fallback-model" in out  # quietly used the fallback


def test_an_unreachable_primary_fails_the_preflight_too(tmp_path, capsys):
    with MockServer() as mock:
        path = tmp_path / "models.yaml"
        path.write_text(
            f"providers:\n  dead: {{base_url: 'http://127.0.0.1:1/v1', key_env: null, rpm: 60, concurrency: 1, timeout: 2}}\n"
            "roles:\n  hunter: [{provider: dead, model: m}]\nprices: {}\n"
        )
        assert asyncio.run(check(_check_args(models=str(path), strict=True))) == 1
    assert "FAILED" in capsys.readouterr().out


def test_strict_passes_when_every_role_resolves_to_its_primary(tmp_path, capsys):
    with MockServer() as mock:
        path = tmp_path / "models.yaml"
        path.write_text(
            f"providers:\n  live: {{base_url: {mock.base_url}, key_env: null, rpm: 6000, concurrency: 4, timeout: 10}}\n"
            "roles:\n  mapper: [{provider: live, model: m}]\n  hunter: [{provider: live, model: m}]\nprices: {}\n"
        )
        assert asyncio.run(check(_check_args(models=str(path), strict=True))) == 0
    assert "STRICT FAIL" not in capsys.readouterr().out
