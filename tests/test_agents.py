"""Step 6: agent prompt builders — monkeypatched Router, no network."""

import asyncio
import json

import pytest

from hound.agents import _invariant_checklist, diagnose, hunter, judge, mapper, poc, system
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
                    "observation": "o", "invariant": "inv", "violation": "v",
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
                    "observation": "o", "invariant": "inv", "violation": "v",
                    "root_cause": "x",
                    "impact": "x",
                    "exploit_steps": [],
                },
            ]
        }
    )
    result = asyncio.run(hunter(r, kb, lens, "  1| contract Vault {}"))
    assert result.ok and len(result.findings) == 1
    assert result.findings[0]["title"] == "Permanent lock via unclosed exists flag"
    assert result.findings[0]["lenses"] == ["A5"]
    assert result.findings[0]["votes"] == 1


def test_hunter_reports_failure_distinctly_from_finding_nothing(kb):
    """A lens that failed and a lens that legitimately found nothing both yield no
    candidates, but only the second is a clean negative."""
    lens = kb.lenses[0]

    failed = asyncio.run(hunter(FakeRouter(chat_json_error=RuntimeError("all targets failed")), kb, lens, "  1| x"))
    assert failed.findings == [] and failed.ok is False
    assert "all targets failed" in failed.error

    clean = asyncio.run(hunter(FakeRouter(chat_json_result={"findings": []}), kb, lens, "  1| x"))
    assert clean.findings == [] and clean.ok is True and clean.error == ""


def test_a_reply_without_a_findings_list_is_a_failure_not_a_clean_negative(kb):
    r = FakeRouter(chat_json_result={"unexpected": "shape"})
    result = asyncio.run(hunter(r, kb, kb.lenses[0], "  1| x"))
    assert result.ok is False and "no findings list" in result.error


def test_a_lens_whose_call_hits_the_routers_ceiling_is_recorded_as_failed(kb):
    """The ceiling itself lives in the router (it must start at slot acquisition, not task
    creation). The hunter's job is only to report the resulting failure as a failure, so the
    lens is never mistaken for a clean negative."""
    from hound.llm import CallCeilingExceeded

    class CeilingRouter:
        async def chat_json(self, *a, **kw):
            raise RuntimeError(f"all targets failed for role 'hunter': {CallCeilingExceeded('300s budget exhausted')}")

    result = asyncio.run(hunter(CeilingRouter(), kb, kb.lenses[0], "  1| x"))
    assert result.ok is False and result.findings == []
    assert "budget exhausted" in result.error


def test_hunter_no_longer_wraps_its_own_call_in_a_wall_clock_timeout(kb):
    """Regression guard: wrapping the whole coroutine charged a lens for QUEUE time and killed
    13 of 14 lenses on a concurrency:1 provider for waiting their turn."""
    import inspect

    from hound import agents

    src = inspect.getsource(agents.hunter)
    assert "wait_for" not in src
    assert "ceiling" not in inspect.signature(agents.hunter).parameters


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
    good = {"verdict": "kill", "reason": "guarded by onlyOwner at line 5", "severity": None,
            "killed_by": "onlyOwner", "disproof_location": "Vault.sol:5"}
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
    good = {"verdict": "kill", "reason": "guarded", "severity": None, "killed_by": "x",
            "disproof_location": "Vault.sol:5"}
    r = FakeRouter(chat_json_results=[MISSING_VERDICT, good])
    asyncio.run(judge(r, kb, "judge", CAND, CODE, cache_salt="abc123"))
    assert [c["salt"] for c in r.calls] == ["abc123", "abc123"]


def test_no_salt_is_sent_when_none_is_given(kb):
    r = FakeRouter(chat_json_result={"verdict": "kill", "reason": "x"})
    asyncio.run(judge(r, kb, "judge", CAND, CODE))
    assert r.calls[0]["salt"] == ""


# --- 402 propagates through every agent's graceful catch-all ----------------------------------


class CreditlessRouter:
    async def chat_json(self, role, system, user, **kw):
        from hound.llm import OutOfCredits

        raise OutOfCredits("openrouter/z-ai/glm-5.3-flash for role 'judge': 402")

    chat = chat_json


@pytest.mark.parametrize("agent_call", [
    lambda kb: mapper(CreditlessRouter(), kb, "  1| x"),
    lambda kb: hunter(CreditlessRouter(), kb, kb.lenses[0], "  1| x"),
    lambda kb: judge(CreditlessRouter(), kb, "judge", {"title": "t", "location": "a.sol:1"}, "  1| x"),
    lambda kb: poc(CreditlessRouter(), kb, {"title": "t"}, "  1| x"),
], ids=["mapper", "hunter", "judge", "poc"])
def test_out_of_credits_is_not_swallowed_by_graceful_degradation(kb, agent_call):
    """Every agent degrades gracefully on a model failure — except this one. A judge that
    returns needs_poc on 402 turns an unpayable run into 23 fake 'needs_poc' verdicts."""
    from hound.llm import OutOfCredits

    with pytest.raises(OutOfCredits):
        asyncio.run(agent_call(kb))


def test_a_kill_without_a_disproof_citation_gets_one_repair_then_becomes_needs_poc(kb):
    """A model that kills a finding but can't say where the disproof lives must not delete
    evidence on that basis."""
    uncited_kill = {"verdict": "kill", "reason": "there is surely a guard somewhere", "killed_by": "a guard"}
    r = FakeRouter(chat_json_results=[uncited_kill, uncited_kill])
    result = asyncio.run(judge(r, kb, "judge", CAND, CODE))
    assert result.verdict == "needs_poc"
    assert len(r.calls) == 2  # one repair, not a loop


class Recorder:
    def __init__(self, result):
        self.result, self.calls = result, []

    async def chat_json(self, role, system, user, *, temperature=0.3, max_tokens=None, cache_salt=""):
        self.calls.append({"role": role, "system": system, "user": user})
        return self.result


# --- diagnose: read the region cold ------------------------------------------------------------

CAND_WITH_STORY = {
    "id": "F001", "title": "Attacker drains the vault via missing ownership check",
    "location": "src/Vault.sol:12-14",
    "root_cause": "transferVesting does not verify the caller owns the tokens",
    "impact": "an attacker steals every beneficiary's allocation",
}


def test_diagnose_is_never_shown_the_locating_passs_story(kb):
    """The measured failure is a hunter reaching the right lines and inventing the defect.
    Handing the diagnoser that invention would just launder it."""
    r = Recorder({"defect_found": True, "observation": "o", "invariant": "i", "violation": "v", "impact": "im"})
    asyncio.run(diagnose(r, kb, "  12| code here", CAND_WITH_STORY["location"]))

    prompt = r.calls[0]["user"]
    assert "src/Vault.sol:12-14" in prompt          # the location IS given
    assert "  12| code here" in prompt               # so is the code
    for leaked in ("drains the vault", "missing ownership check", "does not verify the caller owns",
                   "steals every beneficiary"):
        assert leaked not in prompt


def test_diagnose_prompt_permits_finding_nothing_and_a_different_defect(kb):
    r = Recorder({"defect_found": False, "observation": "the guard is present"})
    asyncio.run(diagnose(r, kb, "  1| x", "V.sol:1"))
    prompt = r.calls[0]["user"]
    assert "nothing is wrong here" in prompt.lower()
    assert "may be a different defect" in prompt.lower()
    assert "defect_found" in prompt


def test_diagnose_orders_mechanism_before_impact(kb):
    r = Recorder({"defect_found": True})
    asyncio.run(diagnose(r, kb, "  1| x", "V.sol:1"))
    p = r.calls[0]["user"]
    # the numbered instruction list, not the first mention of each word in prose
    assert p.index("1. observation") < p.index("2. invariant") < p.index("3. violation") < p.index("4. impact")
    assert "do not write a later one before an earlier one" in p


def test_diagnose_uses_its_own_role_and_returns_empty_on_failure(kb):
    r = Recorder({"defect_found": True})
    asyncio.run(diagnose(r, kb, "  1| x", "V.sol:1"))
    assert r.calls[0]["role"] == "diagnose"

    class Broken:
        async def chat_json(self, *a, **k):
            raise RuntimeError("all targets failed")

    assert asyncio.run(diagnose(Broken(), kb, "  1| x", "V.sol:1")) == {}


# --- invariant-check diagnose framing -------------------------------------------------------


REAL_MAP = {"map": {"invariants": [
    {"id": "I3", "statement": "A user cannot claim more tokens than are available."},
    {"id": "I4", "statement": "A user cannot transfer more vested tokens than they hold (total - claimed)."},
]}}


def test_checklist_extracts_invariants_from_a_nested_map_dict():
    block = _invariant_checklist(REAL_MAP)
    assert "INVARIANTS TO CHECK" in block
    assert "I3: A user cannot claim more tokens" in block
    assert "I4: A user cannot transfer more vested" in block


def test_checklist_accepts_a_json_string_and_a_flat_map():
    assert "I4:" in _invariant_checklist(json.dumps(REAL_MAP))
    assert "I4:" in _invariant_checklist(REAL_MAP["map"])  # not nested under "map"


def test_checklist_is_empty_when_there_is_nothing_to_check():
    """An empty checklist must render "" so diagnose() can fall back rather than ask the model
    to check an empty list."""
    assert _invariant_checklist(None) == ""
    assert _invariant_checklist({"map": {"invariants": []}}) == ""
    assert _invariant_checklist("pre-formatted map text, not JSON") == ""
    assert _invariant_checklist({"map": {"invariants": [{"id": "I1"}]}}) == ""  # no statement


def _capture_prompt(monkeypatch):
    seen = {}

    class R:
        async def chat_json(self, role, sys_prompt, user, **kw):
            seen["user"] = user
            return {"defect_found": False}

    return R(), seen


def test_invariant_mode_puts_the_checklist_in_the_prompt(kb):
    r, seen = _capture_prompt(None)
    asyncio.run(diagnose(r, kb, "code", "V.sol:1-9", pmap=REAL_MAP, mode="invariant"))
    assert "INVARIANTS TO CHECK" in seen["user"]
    assert "ONE AT A TIME" in seen["user"]


def test_invariant_mode_warns_that_an_invariant_may_restate_the_bug(kb):
    """I4 in the real SecondSwap map was copied from the buggy check itself. Without this
    warning, checking against it confirms the defect is correct behaviour."""
    r, seen = _capture_prompt(None)
    asyncio.run(diagnose(r, kb, "code", "V.sol:1-9", pmap=REAL_MAP, mode="invariant"))
    assert "mis_stated" in seen["user"]
    assert "uncovered_property" in seen["user"]


def test_invariant_mode_falls_back_to_open_when_the_map_has_no_invariants(kb):
    r, seen = _capture_prompt(None)
    asyncio.run(diagnose(r, kb, "code", "V.sol:1-9", pmap={"map": {"invariants": []}}, mode="invariant"))
    assert "INVARIANTS TO CHECK" not in seen["user"]
    assert "state what, if anything, ACTUALLY violates" in seen["user"]


def test_open_mode_is_unchanged_and_is_the_default(kb):
    r, seen = _capture_prompt(None)
    asyncio.run(diagnose(r, kb, "code", "V.sol:1-9", pmap=REAL_MAP))
    assert "INVARIANTS TO CHECK" not in seen["user"]
