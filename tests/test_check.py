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
    defaults = dict(models=None, local_only=False, paid=False)
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
