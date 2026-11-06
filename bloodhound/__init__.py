"""Bloodhound: execution-gated verification layer for hound's candidates.

Hound's hunter/judge/judge2 stages produce an LLM *opinion* that a finding is real. Bloodhound
never adds another opinion on top — it tries to kill the opinion with a compiled, executed test.
A finding only earns "forged" by surviving forge build/test twice: once with the attack present
(must demonstrate the bug) and once with the attack removed (must NOT demonstrate it). An LLM can
be argued into or out of a verdict; a passing/failing forge run cannot.
"""

__version__ = "0.1.0"
