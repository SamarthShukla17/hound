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
    # glm-4.7-flash hunts (the only model measured to hunt productively) and glm-5.3-flash
    # scores and diagnoses. gpt-5.6-luna is the JUDGE primary and grok-4.6 the judge2 (dissent)
    # model, both deliberate since 2026-09-24 (glm-5.3-flash as judge primary reconstructed
    # arguments the judge had already refuted). claude-sonnet-5 and o3 are SCORER FALLBACKS ONLY:
    # both accounts were out of credit, so they cost nothing today and take over automatically if
    # either is funded. Every entry is pinned by name.
    assert active_models <= {
        "glm-4.7-flash", "cohere/north-mini-code:free",
        "z-ai/glm-4.7-flash", "z-ai/glm-5.3-flash",
        "gpt-5.6-luna", "grok-4.6",
        "claude-sonnet-5", "o3",
    }


def test_the_paid_fallbacks_are_scorer_only_and_never_primary():
    """Grading is the role where an unreliable answer invalidates everything else, so it is the
    only role allowed a paid fallback -- and those must stay BELOW the primary, because an
    unfunded account would otherwise abort every run on its first call."""
    config = load_models_config()
    for role, targets in config["roles"].items():
        for position, t in enumerate(targets):
            if t["model"] in ("claude-sonnet-5", "o3"):
                assert role == "scorer", f"{role} must not use a paid frontier target"
                assert position > 0, f"{t['model']} must not be the scorer's primary"


def test_no_role_uses_a_random_model_router():
    """A random-router id (openrouter/free) picks a different model per call, so two runs with
    the same seed are not replicates. Every model must be pinned by name."""
    config = load_models_config()
    for role, targets in config["roles"].items():
        for t in targets:
            assert t["model"] != "openrouter/free", f"{role} uses the random free router"


def test_judge_is_luna_then_zai_then_glm_5_3_flash():
    """Judge order since 2026-09-24: PAID gpt-5.6-luna primary, FREE zai glm-4.7-flash first
    fallback, PAID openrouter glm-5.3-flash second fallback. glm-5.3-flash as primary produced
    verdicts that reconstructed arguments the judge had already refuted."""
    config = load_models_config()
    assert [(t["provider"], t["model"]) for t in config["roles"]["judge"]] == [
        ("openai", "gpt-5.6-luna"),
        ("zai", "glm-4.7-flash"),
        ("openrouter", "z-ai/glm-5.3-flash"),
    ]


def test_gpt_5_6_luna_is_judge_only():
    """luna is paid, so it is only allowed in the judge role (where the 2026-09-24 decision put
    it). Any other role using it is an unintended spend."""
    config = load_models_config()
    for role, targets in config["roles"].items():
        for t in targets:
            if t["model"] == "gpt-5.6-luna":
                assert role == "judge", f"{role} must not use the paid gpt-5.6-luna"


def test_the_scorer_offers_no_funded_alternative_grader():
    """scorer_fallback_error discards any run a second model helped grade, so a reachable
    fallback is a run-killer, not a safety net: on 2026-09-24 ONE stray call to zai threw away
    a run that had graded all 23 bugs with no failures. zai is therefore gone from this chain.
    anthropic/openai may stay listed only while they are unfunded -- they raise immediately, so
    they cost a fast failed hop and can never silently grade. Funding one is a deliberate
    decision to PROMOTE it to primary, not to leave it here."""
    targets = [(t["provider"], t["model"]) for t in load_models_config()["roles"]["scorer"]]
    assert targets[0] == ("openrouter", "z-ai/glm-5.3-flash")
    assert ("zai", "glm-4.7-flash") not in targets


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

    The scorer's ceiling is set from measurement, not intuition. Across 270 successful scorer
    calls: median 1264 completion tokens, p90 10359, max 36045 -- the ANSWER is short but
    mandatory reasoning gives it a very long tail. A cap of 8000 (guessed from the short answer)
    burned 14% of calls, and because any fallback use trips scorer_fallback_error, that aborted
    every scoring run. Keep it well above p99."""
    caps = load_models_config()["max_tokens"]
    assert caps["judge"] == 24000 and caps["judge2"] == 24000
    assert caps["scorer"] >= 32000, "below p99 (24847) the burn rate aborts whole scoring runs"


def test_diagnose_has_somewhere_to_fall_when_the_primary_burns_out():
    """A single-target diagnose role silently returned {} for 25 of 45 regions on 2026-09-22
    when glm-5.3-flash spent its whole budget reasoning. The fallbacks must be reasoning-OFF,
    because reasoning-on is the failure being fallen back FROM."""
    config = load_models_config()
    targets = config["roles"]["diagnose"]
    assert len(targets) >= 2, "diagnose must not be a single point of failure"

    for t in targets[1:]:
        extra = t.get("extra", {}).get("extra_body", {})
        reasoning_off = extra.get("reasoning", {}).get("enabled") is False
        thinking_off = extra.get("thinking", {}).get("type") == "disabled"
        assert reasoning_off or thinking_off, f"fallback {t['model']} still has reasoning on"


def test_diagnose_budget_fits_a_real_answer_without_funding_a_long_burn():
    """Measured real diagnosis answers: 2088-9028 completion tokens."""
    caps = load_models_config()["max_tokens"]
    assert 9028 < caps["diagnose"] <= 12000
