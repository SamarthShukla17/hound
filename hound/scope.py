"""Scope rules are a per-run input, not a constant.

Contests and bounty programs draw the line differently. A bounty usually excludes
anything needing a privileged actor; a contest grades what the code allows, so a
privileged actor causing loss to users IS a valid finding. Hardcoding either one
silently kills real bugs on the other kind of target, so the active rules are
resolved per run, injected into the shared system prompt for the mapper, hunters,
judge and PoC agent, and recorded in findings.json.
"""

from pathlib import Path

CONTEST = """SCOPE RULES (contest profile)
- A privileged actor (issuer, admin, owner, manager, deployer) causing loss, lock, theft or unfair outcomes for users IS a valid finding. Contests grade what the code allows, not who is trusted: never dismiss a finding merely because the caller is privileged or the path is role-gated.
- Exclude only: (a) the admin rugging by design, and (b) behaviour the SCOPE NOTES document as trusted-admin behaviour. A role is trusted ONLY if the SCOPE NOTES name it as trusted; with no such note, no role is trusted.
- A finding still needs a concrete harm to users or the protocol, a real root-cause defect, and a citation."""

BOUNTY = """SCOPE RULES (bounty profile)
- Privileged-only paths are usually excluded: a finding that needs an admin, owner or other privileged role to act is not a finding unless an unprivileged actor can trigger it.
- Centralization/admin-trust and admin misconfiguration are not findings."""

PROFILES = {"contest": CONTEST, "bounty": BOUNTY}
DEFAULT_PROFILE = "contest"


def resolve_scope(profile: str = DEFAULT_PROFILE, rules_file=None) -> dict:
    """{"name", "source", "text"} for the run. A rules file (the target's actual README
    scope text) overrides the built-in profile entirely."""
    if rules_file:
        body = Path(rules_file).read_text().strip()
        return {
            "name": "custom",
            "source": str(rules_file),
            "text": f"SCOPE RULES (from {Path(rules_file).name}, verbatim)\n{body}",
        }
    if profile not in PROFILES:
        raise ValueError(f"unknown scope profile {profile!r} (expected one of {', '.join(PROFILES)})")
    return {"name": profile, "source": "builtin", "text": PROFILES[profile]}
