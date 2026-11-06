"""Run manifest: persists what hound/llm.py's Router already computes (`report()`: per-model
usage, cost, call_log) plus this invocation's own command/args/ceiling/breach state, so a
bloodhound command's spend is on disk, not only printed and lost once the terminal scrolls.

Not a replay/resume system and not a new findings state machine - both would duplicate what
runs.py's findings.json (and hound's own scan) already do. This is cost and provenance only,
written once per invocation.
"""

import json
from pathlib import Path


def build(command: str, args: dict, router, governor=None) -> dict:
    manifest = {"command": command, "args": args, "cost_report": router.report() if router is not None else None}
    if governor is not None:
        manifest["max_cost_usd"] = governor.max_cost_usd
        manifest["breached"] = governor.breached
    return manifest


def write(path, command: str, args: dict, router, governor=None) -> None:
    Path(path).write_text(json.dumps(build(command, args, router, governor), indent=2, sort_keys=True, default=str))
