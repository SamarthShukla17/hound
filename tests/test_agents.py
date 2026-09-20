"""Step 6: agent prompt builders — monkeypatched Router, no network."""

import asyncio

import pytest

from hound.agents import hunter, judge, mapper, poc, system
from hound.knowledge import KB, Lens
from hound.schema import Verdict


@pytest.fixture
def kb():
    return KB(
        principles="1. FALSIFICATION-FIRST-MARKER: for every candidate, find the cheapest disproof.",
        lenses=[
            Lens(
                id="A5",
                kind="angle",
                title="The permanent-lock lens",
                body="Stand here: assume you don't want to steal, you want to trap funds forever.",
            )
        ],
    )


class FakeRouter:
    def __init__(self, *, chat_json_result=None, chat_json_error=None, chat_result=None, chat_error=None):
        self.chat_json_result = chat_json_result
        self.chat_json_error = chat_json_error
        self.chat_result = chat_result
        self.chat_error = chat_error
        self.calls = []

    async def chat_json(self, role, system, user, *, temperature=0.3, max_tokens=2048):
        self.calls.append({"role": role, "system": system, "user": user, "temperature": temperature})
        if self.chat_json_error is not None:
            raise self.chat_json_error
        return self.chat_json_result

    async def chat(self, role, system, user, *, temperature=0.3, max_tokens=2048):
        self.calls.append({"role": role, "system": system, "user": user, "temperature": temperature})
        if self.chat_error is not None:
            raise self.chat_error
        return self.chat_result


# --- system() ----------------------------------------------------------


def test_system_contains_impact_ladder_and_principles(kb):
    text = system(kb)
    assert "IMPACT LADDER" in text
    assert "critical:" in text
    assert "FALSIFICATION-FIRST-MARKER" in text


# --- mapper --------------------------------------------------------------


def test_mapper_returns_map_on_success(kb):
    r = FakeRouter(chat_json_result={"summary": "a vault", "invariants": []})
    result = asyncio.run(mapper(r, kb, "  1| contract Vault {}"))
    assert result == {"summary": "a vault", "invariants": []}


def test_mapper_returns_empty_dict_on_malformed_json(kb):
    r = FakeRouter(chat_json_error=ValueError("chat_json: could not extract JSON"))
    result = asyncio.run(mapper(r, kb, "  1| contract Vault {}"))
    assert result == {}


def test_mapper_prompt_starts_with_code(kb):
    r = FakeRouter(chat_json_result={})
    code = "  1| contract Vault {}\n  2| }"
    asyncio.run(mapper(r, kb, code))
    assert r.calls[0]["user"].startswith(code)


# --- hunter --------------------------------------------------------------


def test_hunter_keeps_only_valid_non_low_findings(kb):
    lens = kb.lenses[0]
    r = FakeRouter(
        chat_json_result={
            "findings": [
                {
                    "title": "Permanent lock via unclosed exists flag",
                    "severity": "high",
                    "bug_class": "lock",
                    "location": "Vault.sol:10",
                    "root_cause": "flag never cleared",
                    "impact": "funds stuck forever",
                    "exploit_steps": ["set flag", "never clear it"],
                    "falsification": "check if flag is ever reset",
                    "confidence": 0.7,
                },
                {"title": "malformed, missing required fields"},
                {
                    "title": "Cosmetic issue",
                    "severity": "low",
                    "location": "Vault.sol:1",
                    "root_cause": "x",
                    "impact": "x",
                    "exploit_steps": [],
                },
            ]
        }
    )
    result = asyncio.run(hunter(r, kb, lens, "  1| contract Vault {}"))
    assert len(result) == 1
    assert result[0]["title"] == "Permanent lock via unclosed exists flag"
    assert result[0]["lenses"] == ["A5"]
    assert result[0]["votes"] == 1


def test_hunter_returns_empty_list_on_model_failure(kb):
    lens = kb.lenses[0]
    r = FakeRouter(chat_json_error=RuntimeError("all targets failed"))
    result = asyncio.run(hunter(r, kb, lens, "  1| contract Vault {}"))
    assert result == []


def test_hunter_prompt_starts_with_code_and_mentions_only_its_lens(kb):
    lens = kb.lenses[0]
    r = FakeRouter(chat_json_result={"findings": []})
    code = "  1| contract Vault {}\n  2| }"
    asyncio.run(hunter(r, kb, lens, code, already=["a prior finding title"]))
    user = r.calls[0]["user"]
    assert user.startswith(code)
    assert "LENS A5" in user
    assert "a prior finding title" in user


# --- judge -----------------------------------------------------------------


def test_judge_returns_validated_verdict(kb):
    r = FakeRouter(chat_json_result={"verdict": "keep", "reason": "no guard found", "severity": "high"})
    cand = {"title": "x", "location": "Vault.sol:1"}
    result = asyncio.run(judge(r, kb, "judge", cand, "  1| contract Vault {}"))
    assert isinstance(result, Verdict)
    assert result.verdict == "keep"


def test_judge_call_that_raises_returns_needs_poc(kb):
    r = FakeRouter(chat_json_error=RuntimeError("all targets failed"))
    cand = {"title": "x", "location": "Vault.sol:1"}
    result = asyncio.run(judge(r, kb, "judge", cand, "  1| contract Vault {}"))
    assert result.verdict == "needs_poc"
    assert "all targets failed" in result.reason


def test_judge_uses_the_role_parameter_to_pick_the_model(kb):
    r = FakeRouter(chat_json_result={"verdict": "kill", "reason": "acknowledged issue"})
    cand = {"title": "x", "location": "Vault.sol:1"}
    asyncio.run(judge(r, kb, "judge2", cand, "  1| contract Vault {}"))
    assert r.calls[0]["role"] == "judge2"


def test_judge_prompt_starts_with_code(kb):
    r = FakeRouter(chat_json_result={"verdict": "kill", "reason": "x"})
    code = "  1| contract Vault {}\n  2| }"
    asyncio.run(judge(r, kb, "judge", {"title": "x", "location": "Vault.sol:1"}, code))
    assert r.calls[0]["user"].startswith(code)


# --- poc ---------------------------------------------------------------


def test_poc_returns_code_on_success(kb):
    r = FakeRouter(chat_result="function test_exploit() public {}")
    result = asyncio.run(poc(r, kb, {"title": "x"}, "  1| contract Vault {}"))
    assert result == "function test_exploit() public {}"


def test_poc_returns_a_commented_stub_on_failure(kb):
    r = FakeRouter(chat_error=RuntimeError("all targets failed"))
    result = asyncio.run(poc(r, kb, {"title": "x"}, "  1| contract Vault {}"))
    assert result.startswith("//")


def test_poc_prompt_starts_with_code(kb):
    r = FakeRouter(chat_result="ok")
    code = "  1| contract Vault {}\n  2| }"
    asyncio.run(poc(r, kb, {"title": "x"}, code, refs="// some skeleton"))
    assert r.calls[0]["user"].startswith(code)


def test_poc_prompt_demands_a_self_contained_compilable_file(kb):
    r = FakeRouter(chat_result="ok")
    asyncio.run(poc(r, kb, {"title": "x"}, "  1| contract Vault {}"))
    user = r.calls[0]["user"]
    assert "self-contained and compilable" in user
    assert "define it in full in this file" in user
    assert "fallback/receive" in user
    assert "Nothing that does not compile is a PoC" in user
