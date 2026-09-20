"""Scope is a per-run input, not a constant.

Contests and bounty programs draw the line differently. A bounty usually excludes anything
needing a privileged actor; a contest grades what the code allows, so a privileged actor
causing loss to users IS a valid finding. Hardcoding either silently kills real bugs on the
other kind of target. Three pieces of prompt wording depend on it, so a Scope carries all of
them: the SCOPE RULES text, the severity ladder (does "critical" require an unprivileged
attacker?), and the mapper's permanent-lock invariant. A Scope is injected into the mapper,
hunters, judge and PoC agent, and recorded in findings.json.
"""

from dataclasses import asdict, dataclass, replace
from pathlib import Path

CONTEST = """SCOPE RULES (contest profile)
- A privileged actor (issuer, admin, owner, manager, deployer) causing loss, lock, theft or unfair outcomes for users IS a valid finding. Contests grade what the code allows, not who is trusted: never dismiss a finding merely because the caller is privileged or the path is role-gated.
- Exclude only: (a) the admin rugging by design, and (b) behaviour the SCOPE NOTES document as trusted-admin behaviour. A role is trusted ONLY if the SCOPE NOTES name it as trusted; with no such note, no role is trusted.
- A finding still needs a concrete harm to users or the protocol, a real root-cause defect, and a citation."""

BOUNTY = """SCOPE RULES (bounty profile)
- Privileged-only paths are usually excluded: a finding that needs an admin, owner or other privileged role to act is not a finding unless an unprivileged actor can trigger it.
- Centralization/admin-trust and admin misconfiguration are not findings."""

CONTEST_LADDER = """IMPACT LADDER
- critical: direct theft, unbacked mint, or permanent freeze of user funds — by ANY actor, including a privileged one, unless that behaviour is documented as intended trusted-admin power in the SCOPE NOTES.
- high: fund loss or permanent lock under a reachable condition; a broken core invariant; privilege escalation; a privileged actor taking, locking or misallocating funds users are owed.
- medium: bounded value leakage, mis-accounting, or griefing/DoS of a core function.
Explicitly ignore: style, gas, events, naming."""

BOUNTY_LADDER = """IMPACT LADDER
- critical: direct theft, unbacked mint, or permanent freeze reachable by an unprivileged actor.
- high: fund loss or permanent lock under a reachable condition; a broken core invariant; privilege escalation.
- medium: bounded value leakage, mis-accounting, or griefing/DoS of a core function.
Explicitly ignore: style, gas, events, naming. (What counts as in scope for privileged actors is set by the SCOPE RULES below.)"""


@dataclass(frozen=True)
class Scope:
    name: str
    source: str
    text: str  # the SCOPE RULES block
    ladder: str  # the IMPACT LADDER block
    lock_invariant: str  # how the mapper words the permanent-lock invariant

    def as_dict(self) -> dict:
        return asdict(self)


CONTEST_SCOPE = Scope("contest", "builtin", CONTEST, CONTEST_LADDER, "no permanent lock reachable by any actor")
BOUNTY_SCOPE = Scope("bounty", "builtin", BOUNTY, BOUNTY_LADDER, "no unprivileged permanent lock")
PROFILES = {"contest": CONTEST_SCOPE, "bounty": BOUNTY_SCOPE}
DEFAULT_PROFILE = "contest"


def resolve_scope(profile: str = DEFAULT_PROFILE, rules_file=None) -> Scope:
    """The run's Scope. A rules file (the target's actual README scope text) replaces the
    SCOPE RULES text; the severity ladder and lock invariant still follow `profile`."""
    if profile not in PROFILES:
        raise ValueError(f"unknown scope profile {profile!r} (expected one of {', '.join(PROFILES)})")
    base = PROFILES[profile]
    if not rules_file:
        return base
    body = Path(rules_file).read_text().strip()
    return replace(
        base, name="custom", source=str(rules_file),
        text=f"SCOPE RULES (from {Path(rules_file).name}, verbatim)\n{body}",
    )


def as_scope(value) -> Scope:
    """Accept a Scope, a bare rules-text string (contest ladder), or None/"" (contest)."""
    if isinstance(value, Scope):
        return value
    if not value:
        return CONTEST_SCOPE
    return replace(CONTEST_SCOPE, name="custom", source="inline", text=value)
