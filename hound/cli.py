"""Command-line interface.

Remaining subcommands are stubbed here and get real bodies in later steps:
budget (10), coach (11), run-pocs (12).
"""

import argparse
import asyncio
from pathlib import Path

from dotenv import load_dotenv


def _not_implemented(name: str):
    def handler(args: argparse.Namespace) -> int:
        print(f"'{name}' is not implemented yet (scaffolded in step 1).")
        return 1

    return handler


def _cmd_scan(args: argparse.Namespace) -> int:
    from .pipeline import scan  # deferred: keeps --help fast for every other subcommand

    return asyncio.run(scan(args))


def _cmd_rejudge(args: argparse.Namespace) -> int:
    from .pipeline import rejudge

    return asyncio.run(rejudge(args))


def _cmd_score(args: argparse.Namespace) -> int:
    from .score import score

    return asyncio.run(score(args))


def _cmd_union(args: argparse.Namespace) -> int:
    from .score import print_union, union_scores

    try:
        print_union(union_scores(args.run_dirs))
    except (OSError, KeyError, ValueError) as exc:
        print(f"union: {exc}")
        return 1
    return 0


def _cmd_kill(args: argparse.Namespace) -> int:
    from .corpus import kill_finding

    try:
        entry = kill_finding(args.run_dir, args.finding_id, args.reason)
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc))
        return 1
    print(f"appended to corpus: {entry['title']} @ {entry['location']}")
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    from .llm import check

    return asyncio.run(check(args))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hound", description=__doc__)
    parser.add_argument("--models", default="models.yaml", help="path to models.yaml")
    parser.add_argument(
        "--local-only", action="store_true", help="only use local (Ollama) providers"
    )
    parser.add_argument(
        "--cache-any-model", dest="cache_any_model", default=None, metavar="ROLES",
        help='roles whose cache key ignores the model id, comma-separated (default: mapper,hunter,poc; '
             '"none" disables). judge/scorer stay model-specific unless listed.',
    )

    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="audit a target codebase")
    scan.add_argument("target", help="path to the target codebase")
    scan.add_argument("--kb", default="kb", help="path to the kb/ directory (default: kb)")
    scan.add_argument("--scope", default=None, help="scope file: one glob per line, # comments ignored")
    scan.add_argument("--known", default=None, help="known/acknowledged issues file")
    scan.add_argument("--notes", default=None, help="scope notes file (exclusions, trusted roles, token assumptions)")
    scan.add_argument("--lenses", default="all", help='"all" | kinds "A,P" | ids "A1,P4" (default: all)')
    scan.add_argument("--passes", type=int, default=2)
    scan.add_argument("--budget", type=int, default=240_000, help="chars per chunk (default: 240000)")
    scan.add_argument("--judge-budget", dest="judge_budget", type=int, default=120_000)
    scan.add_argument("--map-cap", dest="map_cap", type=int, default=12_000)
    scan.add_argument("--max-judge", dest="max_judge", type=int, default=40)
    scan.add_argument("--temp", type=float, default=0.3)
    scan.add_argument("--seed", type=int, default=0)
    scan.add_argument("--fresh", action="store_true", help="bypass the disk cache on read")
    scan.add_argument("--no-judge2", dest="no_judge2", action="store_true")
    scan.add_argument(
        "--judge-mode", dest="judge_mode", choices=["advisory", "gate"], default="advisory",
        help="advisory (default): the judge annotates, nothing is removed; gate: judge kills are removed from the scored set",
    )
    scan.add_argument(
        "--scope-profile", dest="scope_profile", choices=["contest", "bounty"], default="contest",
        help="contest (default): a privileged actor harming users IS a finding; bounty: privileged-only paths are excluded",
    )
    scan.add_argument(
        "--scope-rules", dest="scope_rules", default=None, metavar="FILE",
        help="the target's actual README scope text; overrides --scope-profile",
    )
    scan.add_argument("--dry-run", dest="dry_run", action="store_true")
    scan.add_argument("--out", default="runs", help="output directory (default: runs)")
    scan.set_defaults(handler=_cmd_scan)

    rejudge = sub.add_parser(
        "rejudge", help="re-run only the judge stage on a finished run (no re-hunt); writes a new run dir"
    )
    rejudge.add_argument("run_dir")
    rejudge.add_argument("--kb", default="kb")
    rejudge.add_argument("--known", default=None)
    rejudge.add_argument("--notes", default=None, help="scope notes file; name trusted roles here (contest profile)")
    rejudge.add_argument("--scope-profile", dest="scope_profile", choices=["contest", "bounty"], default="contest")
    rejudge.add_argument("--scope-rules", dest="scope_rules", default=None, metavar="FILE")
    rejudge.add_argument("--judge-mode", dest="judge_mode", choices=["advisory", "gate"], default="advisory")
    rejudge.add_argument("--judge-budget", dest="judge_budget", type=int, default=120_000)
    rejudge.add_argument("--map-cap", dest="map_cap", type=int, default=12_000)
    rejudge.add_argument("--max-judge", dest="max_judge", type=int, default=40)
    rejudge.add_argument("--no-judge2", dest="no_judge2", action="store_true")
    rejudge.add_argument("--fresh", action="store_true", help="bypass the disk cache on read")
    rejudge.add_argument("--out", default="runs")
    rejudge.set_defaults(handler=_cmd_rejudge)

    score = sub.add_parser("score", help="score a run against a ground-truth file")
    score.add_argument("run_dir")
    score.add_argument("truth")
    score.add_argument("--include-killed", dest="include_killed", action="store_true",
                       help="score every finding, including those removed by deterministic gates")
    score.add_argument("--as-gate", dest="as_gate", action="store_true",
                       help="score only what a judge gate would have kept (drop every judge kill)")
    score.set_defaults(handler=_cmd_score)

    union = sub.add_parser("union", help="union several scored runs (e.g. seeds): a bug counts if ANY run found it")
    union.add_argument("run_dirs", nargs="+", help="run dirs that each contain a score.json")
    union.set_defaults(handler=_cmd_union)

    kill = sub.add_parser("kill", help="confirm a finding as a false positive")
    kill.add_argument("run_dir")
    kill.add_argument("finding_id")
    kill.add_argument("reason")
    kill.set_defaults(handler=_cmd_kill)

    check = sub.add_parser("check", help="ping each role's first fallback target")
    check.add_argument("--paid", action="store_true", help="also probe x402 providers (spends real money)")
    check.set_defaults(handler=_cmd_check)

    coach = sub.add_parser("coach", help="ask guided questions about a target, no verdicts")
    coach.set_defaults(handler=_not_implemented("coach"))

    run_pocs = sub.add_parser("run-pocs", help="execute PoC scaffolds from a run")
    run_pocs.set_defaults(handler=_not_implemented("run-pocs"))

    budget = sub.add_parser("budget", help="show x402 monthly spend")
    budget.set_defaults(handler=_not_implemented("budget"))

    return parser


def main() -> None:
    # Anchored to the project root, not the cwd, so keys load from any directory.
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    parser = build_parser()
    args = parser.parse_args()

    if not getattr(args, "command", None):
        parser.print_help()
        raise SystemExit(0)

    raise SystemExit(args.handler(args))


if __name__ == "__main__":
    main()
