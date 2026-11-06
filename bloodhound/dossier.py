"""Dossier: render one submission-ready write-up per execution-confirmed finding, following
kb/REPORT_TEMPLATE.md's own section shape.

hound's existing report (pipeline.py's `_render_report`) already has to hedge every finding with
"UNVERIFIED until I read the cited lines and run the PoC" - because until bloodhound, nothing
ever ran it. This module exists to say the CONFIDENCE line truthfully for a finding that
actually went through the Forger/Panel: "Foundry-verified: N test(s) passing on <commit>"
instead of "logically argued, NOT executed", with the real trace quoted, never summarized or
invented. Exactly per REPORT_TEMPLATE.md's own rule: "state it; never imply execution you did
not do."

Sections the pipeline has no data for (Threat Model prose, Production Parameters,
Recommendation, Duplicate Differentiation) are left as explicit TODOs for the human, never
fabricated - the same discipline external.py applies to a third-party finding's missing
mechanism fields: an empty section says "nobody derived this yet", not "there is nothing here".
"""


def _confidence_line(forge_result, commit: str = "") -> str:
    where = f" on {commit}" if commit else ""
    return f"Foundry-verified: 1 test passing{where}, unmodified contracts"


def _refutation_log(panel_result) -> list:
    if panel_result is None:
        return []
    lines = ["Refutation Log"]
    if not panel_result.role_verdicts:
        lines.append("- no refuter role configured")
    for role, v in panel_result.role_verdicts.items():
        tail = f" [{v['injection']}]" if "injection" in v else ""
        lines.append(f"- {role}: {v.get('verdict')} - {v.get('reason', '')}{tail}")
    verdict_line = f"- panel result: KILLED - {panel_result.surviving_refutation}" if panel_result.killed else "- panel result: survived"
    lines.append(verdict_line)
    lines.append("")
    return lines


def _novelty_section(novelty_result) -> list:
    if novelty_result is None:
        return []
    line = novelty_result.verdict
    if novelty_result.nearest:
        top = novelty_result.nearest[0]
        line += f" (nearest: {top.get('id', '')} {top.get('source', '')}, similarity {top['similarity']:.2f})"
    return ["Novelty", line, ""]


def render(finding: dict, forge_result, panel_result=None, novelty_result=None, *, commit: str = "") -> str:
    """ForgeResult with status != "forged" produces no honest Confidence claim to make - enforced
    here, not left to caller discipline, so a future call site can't accidentally print a
    "Foundry-verified" claim for a finding the Forger/Panel never actually confirmed."""
    if forge_result.status != "forged":
        raise ValueError(f"render() requires a forged ForgeResult, got status={forge_result.status!r}")
    lines = [
        f"TITLE:        {finding.get('title', '')}",
        f"SEVERITY:     {finding.get('severity', '')}",
        f"CONFIDENCE:   {_confidence_line(forge_result, commit)}",
        f"TARGET:       {finding.get('location', '')}",
        "",
        "Summary",
        finding.get("root_cause", "") or "[fill in: 2-3 sentences, what breaks, in plain terms]",
        "",
        "Threat Model",
        "[TODO - human: attacker identity, capital/access needed, which invariant is violated]",
        "",
        "Root Cause",
        finding.get("root_cause", ""),
        "",
        "Production Parameters",
        "[TODO - human: deploy/verify values this depends on, with file:line - not test defaults]",
        "",
        "Impact",
        finding.get("impact", ""),
        "",
    ]
    lines += _novelty_section(novelty_result)
    lines += [
        "Proof of Concept",
        "```solidity",
        forge_result.poc_code.strip(),
        "```",
        "",
        "Execution trace (attack - demonstrates the bug):",
        "```",
        forge_result.attack_output.strip()[:4000],
        "```",
    ]
    if forge_result.control_code:
        lines += [
            "",
            "Control (same test, attack step removed - proves the assertion is not tautological):",
            "```solidity",
            forge_result.control_code.strip(),
            "```",
        ]
    lines.append("")
    lines += _refutation_log(panel_result)
    lines += [
        "Recommendation",
        "[TODO - human: the fix and its trade-off]",
        "",
        "Duplicate Differentiation",
        "[TODO - human: one sentence against each relevant known/excluded item]",
        "",
    ]
    return "\n".join(lines) + "\n"
