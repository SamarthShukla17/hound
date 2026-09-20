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
    def __init__(
        self, *, chat_json_result=None, chat_json_results=None, chat_json_error=None, chat_result=None, chat_error=None
    ):
        self.chat_json_results = list(chat_json_results) if chat_json_results is not None else None
        self.chat_json_result = chat_json_result
        self.chat_json_error = chat_json_error
        self.chat_result = chat_result
        self.chat_error = chat_error
        self.calls = []

    async def chat_json(self, role, system, user, *, temperature=0.3, max_tokens=2048, cache_salt=""):
        self.calls.append({"role": role, "system": system, "user": user, "temperature": temperature, "salt": cache_salt})
        if self.chat_json_error is not None:
            raise self.chat_json_error
        if self.chat_json_results is not None:
            return self.chat_json_results.pop(0)
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


# --- judge: malformed payloads seen in the live bench run --------------------

CAND = {"title": "x", "location": "Vault.sol:1"}
CODE = "  1| contract Vault {}"
# The string "null" for severity and null for killed_by, with a valid verdict/reason.
SEVERITY_NULL_STRING = {"verdict": "keep", "reason": "no guard found", "severity": "null", "killed_by": None}
# The model answered with an unrelated shape: no verdict, no reason.
MISSING_VERDICT = {"auditor": "Senior Smart-contract auditor", "evidence": []}


def test_judge_accepts_severity_null_string_and_null_killed_by_without_a_repair_call(kb):
    r = FakeRouter(chat_json_result=SEVERITY_NULL_STRING)
    result = asyncio.run(judge(r, kb, "judge", CAND, CODE))
    assert result.verdict == "keep"
    assert result.severity is None
    assert result.killed_by == ""
    assert len(r.calls) == 1


def test_judge_missing_verdict_triggers_exactly_one_repair_call_and_uses_it(kb):
    good = {"verdict": "kill", "reason": "guarded by onlyOwner at line 5", "severity": None, "killed_by": "onlyOwner"}
    r = FakeRouter(chat_json_results=[MISSING_VERDICT, good])
    result = asyncio.run(judge(r, kb, "judge", CAND, CODE))
    assert result.verdict == "kill"
    assert len(r.calls) == 2
    repair_prompt = r.calls[1]["user"]
    assert repair_prompt.startswith(CODE)  # the ordering rule still holds on the repair call
    assert "REPAIR" in repair_prompt and "auditor" in repair_prompt


def test_judge_missing_verdict_and_a_bad_repair_falls_back_to_needs_poc_after_one_repair(kb):
    r = FakeRouter(chat_json_results=[MISSING_VERDICT, MISSING_VERDICT, MISSING_VERDICT])
    result = asyncio.run(judge(r, kb, "judge", CAND, CODE))
    assert result.verdict == "needs_poc"
    assert len(r.calls) == 2  # original + ONE repair, never a loop


def test_judge_call_that_raises_is_not_repaired_it_is_needs_poc(kb):
    r = FakeRouter(chat_json_error=RuntimeError("all targets failed"))
    result = asyncio.run(judge(r, kb, "judge", CAND, CODE))
    assert result.verdict == "needs_poc"
    assert len(r.calls) == 1


def test_judge_forwards_the_cache_salt_including_on_the_repair_call(kb):
    good = {"verdict": "kill", "reason": "guarded", "severity": None, "killed_by": "x"}
    r = FakeRouter(chat_json_results=[MISSING_VERDICT, good])
    asyncio.run(judge(r, kb, "judge", CAND, CODE, cache_salt="abc123"))
    assert [c["salt"] for c in r.calls] == ["abc123", "abc123"]


def test_no_salt_is_sent_when_none_is_given(kb):
    r = FakeRouter(chat_json_result={"verdict": "kill", "reason": "x"})
    asyncio.run(judge(r, kb, "judge", CAND, CODE))
    assert r.calls[0]["salt"] == ""
