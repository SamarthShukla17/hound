"""Command-line interface.

Subcommands are stubbed here now and get real bodies in later steps:
scan (7), score/kill (8), check (9), budget (10), coach (11), run-pocs (12).
"""

import argparse


def _not_implemented(name: str):
    def handler(args: argparse.Namespace) -> int:
        print(f"'{name}' is not implemented yet (scaffolded in step 1).")
        return 1

    return handler


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hound", description=__doc__)
    parser.add_argument("--models", default="models.yaml", help="path to models.yaml")
    parser.add_argument(
        "--local-only", action="store_true", help="only use local (Ollama) providers"
    )

    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="audit a target codebase")
    scan.set_defaults(handler=_not_implemented("scan"))

    score = sub.add_parser("score", help="score a run against a ground-truth file")
    score.set_defaults(handler=_not_implemented("score"))

    kill = sub.add_parser("kill", help="confirm a finding as a false positive")
    kill.set_defaults(handler=_not_implemented("kill"))

    check = sub.add_parser("check", help="ping each role's first fallback target")
    check.set_defaults(handler=_not_implemented("check"))

    coach = sub.add_parser("coach", help="ask guided questions about a target, no verdicts")
    coach.set_defaults(handler=_not_implemented("coach"))

    run_pocs = sub.add_parser("run-pocs", help="execute PoC scaffolds from a run")
    run_pocs.set_defaults(handler=_not_implemented("run-pocs"))

    budget = sub.add_parser("budget", help="show x402 monthly spend")
    budget.set_defaults(handler=_not_implemented("budget"))

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not getattr(args, "command", None):
        parser.print_help()
        raise SystemExit(0)

    raise SystemExit(args.handler(args))


if __name__ == "__main__":
    main()
