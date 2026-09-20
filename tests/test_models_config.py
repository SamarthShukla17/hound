"""models.yaml sanity check: every role's fallback targets a defined provider."""

from pathlib import Path

import yaml

MODELS_YAML = Path(__file__).parent.parent / "models.yaml"

# judge2 may be empty on purpose: the pipeline skips it (single-judge, no dissent signal).
OPTIONAL_ROLES = {"judge2"}


def load_models_config():
    return yaml.safe_load(MODELS_YAML.read_text())


def test_role_providers_exist():
    config = load_models_config()
    providers = set(config["providers"])

    for role, targets in config["roles"].items():
        if role in OPTIONAL_ROLES:
            continue
        assert targets, f"role {role!r} has no fallback targets"
        for target in targets:
            assert target["provider"] in providers, (
                f"role {role!r} targets unknown provider {target['provider']!r}"
            )


def test_no_paid_target_is_active():
    config = load_models_config()
    active_models = {t["model"] for targets in config["roles"].values() for t in targets}
    assert active_models <= {"glm-4.7-flash", "openrouter/free"}


def test_role_max_tokens_are_positive_ints_for_known_roles():
    config = load_models_config()
    for role, value in config["max_tokens"].items():
        assert role in config["roles"]
        assert isinstance(value, int) and value > 0
