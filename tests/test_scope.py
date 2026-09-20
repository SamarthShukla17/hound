"""Scope rules are a per-run input: profiles, injection into every agent, notes threading."""

import asyncio

import pytest

from hound.agents import hunter, judge, mapper, system
from hound.knowledge import KB, Lens
from hound.scope import BOUNTY, CONTEST, resolve_scope


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
    assert resolve_scope()["name"] == "contest"
    assert resolve_scope("bounty")["text"] == BOUNTY
    with pytest.raises(ValueError):
        resolve_scope("hackathon")


def test_a_rules_file_overrides_the_profile_verbatim(tmp_path):
    readme = tmp_path / "README_scope.md"
    readme.write_text("Out of scope: the deployer key is trusted.\n")
    scope = resolve_scope("bounty", rules_file=readme)
    assert scope["name"] == "custom" and scope["source"] == str(readme)
    assert "the deployer key is trusted" in scope["text"]
    assert "privileged-only" not in scope["text"].lower()  # the bounty profile did NOT leak through


# --- injection --------------------------------------------------------------------------


def test_system_prompt_carries_the_scope_rules_and_no_longer_hardcodes_a_privileged_exclusion(kb):
    with_contest = system(kb, CONTEST)
    with_bounty = system(kb, BOUNTY)
    assert "SCOPE RULES (contest profile)" in with_contest and "SCOPE RULES (bounty profile)" not in with_contest
    assert "SCOPE RULES (bounty profile)" in with_bounty
    # the base prompt itself no longer contains a blanket privileged-only rule
    base = system(kb, "X").lower()
    assert "privileged-only" not in base and "admin misconfiguration" not in base
    assert system(kb) == with_contest  # default is the contest profile


def test_hunters_and_judge_and_mapper_all_receive_the_run_scope_rules(kb):
    rules = "SCOPE RULES (custom)\nthe issuer is NOT trusted"
    lens = kb.lenses[0]
    r = Recorder({"findings": []})
    asyncio.run(hunter(r, kb, lens, "  1| x", scope_rules=rules))
    r2 = Recorder({"verdict": "keep", "reason": "r"})
    asyncio.run(judge(r2, kb, "judge", {"title": "t", "location": "a.sol:1"}, "  1| x", scope_rules=rules))
    r3 = Recorder({})
    asyncio.run(mapper(r3, kb, "  1| x", scope_rules=rules))
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
