"""Threaded stdlib HTTP mock of an OpenAI-compatible chat endpoint, for the
step 7/8 integration tests. No real network, no extra dependencies.

Dispatches on the last user message's content: "TASK: MAP" -> a small map,
"TASK: HUNT" -> three canned findings (one valid against FIXTURE_LOCATION,
one citing a path that doesn't exist, one malformed), "TASK: FALSIFY" -> a
keep verdict, "TASK: SCORE" -> a fixed 3-EXACT/2-PARTIAL/5-MISS scoring
payload, anything else -> PoC code. Every reply is wrapped in
<think>...</think> (and, for the JSON tasks, ```json fences too) so the
router's stripping and JSON extraction are exercised for real, not skipped.
Every parsed request body is also recorded, so tests can inspect exactly
what was sent (e.g. which findings were included in a scoring request).
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# test_pipeline.py's fixture repo must contain a real file at this location
# with a real line 12-14, so the "valid" hunter finding below resolves.
FIXTURE_LOCATION = "src/Vault.sol:12-14"

MAP_REPLY = {
    "summary": "A minimal vault contract.",
    "actors": ["depositor"],
    "entry_points": [{"loc": "src/Vault.sol:7", "who": "anyone", "moves_value": True}],
    "state_machine": [],
    "subsystems": [],
    "trust_edges": [],
    "invariants": [
        {"id": "I1", "statement": "balances never exceed the contract's own balance", "threatened_by": []}
    ],
}

HUNT_REPLY = {
    "findings": [
        {
            "title": "Reentrancy in withdraw",
            "severity": "high",
            "bug_class": "reentrancy",
            "location": FIXTURE_LOCATION,
            "observation": "line 14 sends ETH via call{value:} and line 15 then decrements balances[msg.sender]",
            "invariant": "a caller's recorded balance must fall before control leaves the contract",
            "violation": "a receiver that re-enters withdraw at line 13 sees the pre-decrement balance",
            "root_cause": "balance is decremented after the external call completes",
            "impact": "an attacker can drain the vault via a reentrant call",
            "exploit_steps": ["deposit", "call withdraw from a malicious receiver", "reenter withdraw"],
            "falsification": "check whether balances[msg.sender] is zeroed before the external call",
            "confidence": 0.8,
        },
        {
            "title": "Bug in a file that does not exist",
            "severity": "high",
            "bug_class": "hallucination",
            "location": "NoSuchFile.sol:5",
            "observation": "fabricated",
            "invariant": "fabricated",
            "violation": "fabricated",
            "root_cause": "fabricated",
            "impact": "fabricated",
            "exploit_steps": ["fabricated"],
            "falsification": "fabricated",
            "confidence": 0.9,
        },
        {
            "title": "Malformed entry missing required fields",
        },
    ]
}

DIAGNOSE_REPLY = {
    "defect_found": True,
    "title": "Re-entrancy window in withdraw",
    "severity": "high",
    "bug_class": "reentrancy",
    "observation": "line 14 transfers ETH before line 15 updates balances",
    "invariant": "the caller's balance must fall before control leaves the contract",
    "violation": "a receiver re-entering withdraw at line 13 reads the stale balance",
    "impact": "the vault pays out more than the caller deposited",
    "exploit_steps": ["deposit", "re-enter from the receiver"],
    "falsification": "check whether balances are written before the call",
    "confidence": 0.7,
}

FALSIFY_REPLY = {
    "verdict": "keep",
    "reason": "no guard or modifier protects this path",
    "severity": "high",
    "killed_by": "",
}

# 3 EXACT + 2 PARTIAL + 5 MISS -> weighted recall (3 + 0.5*2) / 10 = 40%.
SCORE_REPLY = {
    "scores": [
        {"gt_id": "GT1", "verdict": "EXACT", "finding_id": "F001", "why": "same root cause, same fix"},
        {"gt_id": "GT2", "verdict": "EXACT", "finding_id": "F002", "why": "same root cause, same fix"},
        {"gt_id": "GT3", "verdict": "EXACT", "finding_id": "F003", "why": "same root cause, same fix"},
        {"gt_id": "GT4", "verdict": "PARTIAL", "finding_id": "F004", "why": "same root cause, narrower fix"},
        {"gt_id": "GT5", "verdict": "PARTIAL", "finding_id": "F005", "why": "severity off by two levels"},
        {"gt_id": "GT6", "verdict": "MISS", "finding_id": None, "why": "different root cause"},
        {"gt_id": "GT7", "verdict": "MISS", "finding_id": None, "why": "different root cause"},
        {"gt_id": "GT8", "verdict": "MISS", "finding_id": None, "why": "different root cause"},
        {"gt_id": "GT9", "verdict": "MISS", "finding_id": None, "why": "different root cause"},
        {"gt_id": "GT10", "verdict": "MISS", "finding_id": None, "why": "different root cause"},
    ],
    "off_catalog": [{"finding_id": "F999", "note": "real-looking but outside the answer key"}],
}

POC_REPLY = (
    "function test_reentrancy() public {\n"
    "    // ASSUME: the attacker contract's receive() reenters withdraw\n"
    "    vm.prank(attacker);\n"
    "    vault.withdraw(1 ether);\n"
    "    assertEq(address(vault).balance, 0);\n"
    "}\n"
)


def _wrap(payload_text: str, as_json: bool) -> str:
    body = f"```json\n{payload_text}\n```" if as_json else payload_text
    return f"<think>reasoning about the task privately</think>\n{body}"


class _MockHandler(BaseHTTPRequestHandler):
    server_version = "HoundMock/1.0"

    def log_message(self, fmt, *args):  # silence stdlib's default request logging
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b"{}"
        request = json.loads(body or b"{}")
        self.server.request_count += 1
        self.server.requests.append(request)

        user_content = ""
        for message in reversed(request.get("messages", [])):
            if message.get("role") == "user":
                user_content = message.get("content", "")
                break

        if "TASK: MAP" in user_content:
            content = _wrap(json.dumps(MAP_REPLY), as_json=True)
        elif "TASK: HUNT" in user_content:
            content = _wrap(json.dumps(HUNT_REPLY), as_json=True)
        elif "TASK: DIAGNOSE" in user_content:
            content = _wrap(json.dumps(DIAGNOSE_REPLY), as_json=True)
        elif "TASK: FALSIFY" in user_content:
            content = _wrap(json.dumps(FALSIFY_REPLY), as_json=True)
        elif "TASK: SCORE" in user_content:
            content = _wrap(json.dumps(SCORE_REPLY), as_json=True)
        else:
            content = _wrap(POC_REPLY, as_json=False)

        response = {
            "id": "mock-completion",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": request.get("model", "mock-model"),
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}
            ],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
        }
        payload = json.dumps(response).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class MockServer:
    """Usage: with MockServer() as mock: ... mock.base_url, mock.request_count"""

    def __init__(self):
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _MockHandler)
        self._httpd.request_count = 0
        self._httpd.requests = []
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1"

    @property
    def request_count(self) -> int:
        return self._httpd.request_count

    @property
    def requests(self) -> list:
        return self._httpd.requests

    def start(self) -> "MockServer":
        self._thread.start()
        return self

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()

    def __enter__(self) -> "MockServer":
        return self.start()

    def __exit__(self, *exc_info):
        self.stop()
