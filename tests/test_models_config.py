"""models.yaml sanity check: every role's fallback targets a defined provider."""

from pathlib import Path

import yaml

MODELS_YAML = Path(__file__).parent.parent / "models.yaml"


def load_models_config():
    return yaml.safe_load(MODELS_YAML.read_text())


def test_role_providers_exist():
    config = load_models_config()
    providers = set(config["providers"])

    for role, targets in config["roles"].items():
        assert targets, f"role {role!r} has no fallback targets"
        for target in targets:
            assert target["provider"] in providers, (
                f"role {role!r} targets unknown provider {target['provider']!r}"
            )
