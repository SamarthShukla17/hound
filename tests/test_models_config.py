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


def test_only_the_intended_paid_model_is_active():
    config = load_models_config()
    active_models = {t["model"] for targets in config["roles"].values() for t in targets}
    # gpt-5.6-luna and grok-4.6 stay commented out. Two paid models are active: glm-4.7-flash
    # hunts (the only model measured to hunt productively) and glm-5.3-flash judges/scores.
    assert active_models <= {
        "glm-4.7-flash", "cohere/north-mini-code:free",
        "z-ai/glm-4.7-flash", "z-ai/glm-5.3-flash",
    }


def test_no_role_uses_a_random_model_router():
    """A random-router id (openrouter/free) picks a different model per call, so two runs with
    the same seed are not replicates. Every model must be pinned by name."""
    config = load_models_config()
    for role, targets in config["roles"].items():
        for t in targets:
            assert t["model"] != "openrouter/free", f"{role} uses the random free router"


def test_judge_and_scorer_are_glm_5_3_flash_then_zai_fallback():
    config = load_models_config()
    for role in ("judge", "scorer"):
        targets = config["roles"][role]
        assert [(t["provider"], t["model"]) for t in targets] == [
            ("openrouter", "z-ai/glm-5.3-flash"),
            ("zai", "glm-4.7-flash"),
        ]


def test_hunter_max_tokens_is_20000():
    assert load_models_config()["max_tokens"]["hunter"] == 20000


def test_role_max_tokens_are_positive_ints_for_known_roles():
    config = load_models_config()
    for role, value in config["max_tokens"].items():
        assert role in config["roles"]
        assert isinstance(value, int) and value > 0


def test_judges_have_the_large_reasoning_budget_but_the_scorer_no_longer_does():
    """Mandatory-reasoning models spend the completion budget thinking before emitting content,
    so the judges keep a large ceiling.

    The scorer's 60000 belonged to the OLD design, where one call graded every candidate against
    every ground-truth bug. Scoring is per-bug now — one bug, a ~3k prompt — so the huge ceiling
    stopped being headroom and became a hazard: twice a model spent all 60000 tokens reasoning
    and returned nothing, at 186s and $0.018 per silent failure."""
    caps = load_models_config()["max_tokens"]
    assert caps["judge"] == 24000 and caps["judge2"] == 24000
    assert caps["scorer"] == 8000
