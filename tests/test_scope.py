"""Scope rules are a per-run input: profiles, injection into every agent, notes threading."""

import asyncio

import pytest

from hound.agents import hunter, judge, mapper, system
from hound.knowledge import KB, Lens
from hound.knowledge import load_kb
from hound.scope import (
    BOUNTY, BOUNTY_LADDER, BOUNTY_SCOPE, CONTEST, CONTEST_LADDER, CONTEST_SCOPE, Scope, as_scope, resolve_scope,
)
from pathlib import Path


@pytest.fixture
def kb():
    return KB(principles="1. PRINCIPLE-MARKER", lenses=[Lens(id="A3", kind="angle", title="t", body="b")])


class Recorder:
    def __init__(self, result):
        self.result, self.calls = result, []

    async def chat_json(self, role, system, user, *, temperature=0.3, max_tokens=None, cache_salt=""):
        self.calls.append({"role": role, "system": system, "user": user})
        return self.result


# --- the profiles -------------------------------------------------------------------


def test_contest_profile_has_no_blanket_privileged_only_exclusion():
    text = CONTEST.lower()
    for excluded_phrase in ("privileged-only", "privileged only", "admin misconfiguration", "centralization"):
        assert excluded_phrase not in text
    # it says the opposite: a privileged actor harming users IS in scope
    assert "privileged actor" in text and "is a valid finding" in text
    assert "never dismiss a finding merely because the caller is privileged" in text


def test_contest_profile_only_excludes_documented_trusted_behaviour_named_in_notes():
    assert "only if the scope notes name it as trusted" in CONTEST.lower()
    assert "rugging by design" in CONTEST.lower()


def test_bounty_profile_keeps_the_privileged_only_exclusions():
    text = BOUNTY.lower()
    assert "privileged-only paths are usually excluded" in text
    assert "admin misconfiguration are not findings" in text


def test_resolve_scope_defaults_to_contest_and_rejects_unknown_profiles():
    assert resolve_scope().name == "contest"
    assert resolve_scope("bounty").text == BOUNTY
    with pytest.raises(ValueError):
        resolve_scope("hackathon")


def test_as_scope_accepts_a_scope_bare_text_or_nothing():
    assert as_scope(BOUNTY_SCOPE) is BOUNTY_SCOPE
    assert as_scope(None) is CONTEST_SCOPE and as_scope("") is CONTEST_SCOPE
    inline = as_scope("my rules")
    assert isinstance(inline, Scope) and inline.text == "my rules" and inline.ladder == CONTEST_LADDER


def test_a_rules_file_overrides_the_profile_verbatim(tmp_path):
    readme = tmp_path / "README_scope.md"
    readme.write_text("Out of scope: the deployer key is trusted.\n")
    scope = resolve_scope("bounty", rules_file=readme)
    assert scope.name == "custom" and scope.source == str(readme)
    assert "the deployer key is trusted" in scope.text
    assert "privileged-only" not in scope.text.lower()  # the bounty rules text did NOT leak through
    assert scope.ladder == BOUNTY_LADDER  # ...but the ladder still follows --scope-profile


# --- injection --------------------------------------------------------------------------


def test_system_prompt_carries_the_scope_rules_and_no_longer_hardcodes_a_privileged_exclusion(kb):
    with_contest = system(kb, CONTEST_SCOPE)
    with_bounty = system(kb, BOUNTY_SCOPE)
    assert "SCOPE RULES (contest profile)" in with_contest and "SCOPE RULES (bounty profile)" not in with_contest
    assert "SCOPE RULES (bounty profile)" in with_bounty
    # the base prompt itself no longer contains a blanket privileged-only rule
    for prompt in (system(kb, "X"), with_contest):
        assert "privileged-only" not in prompt.lower() and "admin misconfiguration" not in prompt.lower()
    assert system(kb) == with_contest  # default is the contest profile


def test_hunters_and_judge_and_mapper_all_receive_the_run_scope_rules(kb):
    rules = "SCOPE RULES (custom)\nthe issuer is NOT trusted"
    lens = kb.lenses[0]
    r = Recorder({"findings": []})
    asyncio.run(hunter(r, kb, lens, "  1| x", scope=as_scope(rules)))
    r2 = Recorder({"verdict": "keep", "reason": "r"})
    asyncio.run(judge(r2, kb, "judge", {"title": "t", "location": "a.sol:1"}, "  1| x", scope=as_scope(rules)))
    r3 = Recorder({})
    asyncio.run(mapper(r3, kb, "  1| x", scope=as_scope(rules)))
    for rec in (r, r2, r3):
        assert "the issuer is NOT trusted" in rec.calls[0]["system"]


def test_the_judge_task_no_longer_hardcodes_that_the_attacker_must_be_unprivileged(kb):
    r = Recorder({"verdict": "keep", "reason": "r"})
    asyncio.run(judge(r, kb, "judge", {"title": "t", "location": "a.sol:1"}, "  1| x"))
    user = r.calls[0]["user"].lower()
    assert "attacker is unprivileged" not in user
    assert "privileged-only access" not in user
    assert "in scope under the scope rules above" in user


# --- notes reach hunters and the judge (previously only the mapper saw them) ------------


def test_scope_notes_reach_hunters_and_judge_after_the_code_and_map(kb):
    notes = "The s2Admin role is trusted."
    r = Recorder({"findings": []})
    asyncio.run(hunter(r, kb, kb.lenses[0], "  1| code", pmap="MAPTEXT", notes=notes))
    user = r.calls[0]["user"]
    assert user.startswith("  1| code")
    assert user.index("MAPTEXT") < user.index("SCOPE NOTES") < user.index("LENS A3")
    assert notes in user

    r2 = Recorder({"verdict": "keep", "reason": "r"})
    asyncio.run(judge(r2, kb, "judge", {"title": "t", "location": "a.sol:1"}, "  1| code", notes=notes))
    assert notes in r2.calls[0]["user"]


def test_no_notes_means_no_notes_block_so_prompts_and_cache_keys_are_unchanged(kb):
    r = Recorder({"findings": []})
    asyncio.run(hunter(r, kb, kb.lenses[0], "  1| code"))
    assert "SCOPE NOTES" not in r.calls[0]["user"]


# --- the scope-driven severity ladder and mapper invariant ------------------------------------


def test_the_contest_ladder_does_not_require_an_unprivileged_attacker():
    ladder = CONTEST_LADDER.lower()
    assert "unprivileged" not in ladder
    assert "by any actor, including a privileged one" in ladder
    assert "unless that behaviour is documented as intended trusted-admin power" in ladder
    assert "critical: direct theft, unbacked mint, or permanent freeze of user funds" in ladder


def test_the_bounty_ladder_keeps_the_unprivileged_requirement():
    assert "reachable by an unprivileged actor" in BOUNTY_LADDER


def test_the_whole_contest_system_prompt_never_asks_for_an_unprivileged_attacker():
    real_kb = load_kb(Path(__file__).parent.parent / "kb")
    assert "unprivileged" not in system(real_kb, CONTEST_SCOPE).lower()
    assert "reachable by an unprivileged actor" in system(real_kb, BOUNTY_SCOPE)


def test_the_ladder_is_taken_from_the_scope_not_a_constant(kb):
    assert CONTEST_LADDER in system(kb, CONTEST_SCOPE) and BOUNTY_LADDER not in system(kb, CONTEST_SCOPE)
    assert BOUNTY_LADDER in system(kb, BOUNTY_SCOPE) and CONTEST_LADDER not in system(kb, BOUNTY_SCOPE)


def test_the_mapper_invariant_wording_follows_the_scope(kb):
    for scope, expected, absent in [
        (CONTEST_SCOPE, "no permanent lock reachable by any actor", "no unprivileged permanent lock"),
        (BOUNTY_SCOPE, "no unprivileged permanent lock", "reachable by any actor"),
    ]:
        r = Recorder({})
        asyncio.run(mapper(r, kb, "  1| x", scope=scope))
        user = r.calls[0]["user"]
        assert expected in user and absent not in user
        # value conservation / no unbacked mint / authority integrity are in both
        for always in ("value conservation", "no unbacked mint", "authority integrity"):
            assert always in user
