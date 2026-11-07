"""Command line: check one password (never as an argument), audit a password-manager export."""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from . import __version__
from .audit import AuditError, audit, read_rows
from .estimate import analyse, crack_times, feedback, load_wordlist
from .hibp import DEFAULT_URL, BreachError, Checker, PwnedFile, RangeClient
from .report import SCORE_NAMES, to_json, to_markdown, to_text


def _checker(args: argparse.Namespace) -> Checker | None:
    if args.hibp_file:
        return PwnedFile(args.hibp_file)
    if args.hibp:
        return RangeClient(args.hibp_url)
    return None


def _read_password() -> str:
    if sys.stdin.isatty():
        return getpass.getpass("Password (not shown, not stored): ")
    return sys.stdin.readline().rstrip("\r\n")


def cmd_check(args: argparse.Namespace) -> int:
    if args.wordlist:
        load_wordlist(args.wordlist)
    password = _read_password()
    if not password:
        print("pwaudit: empty password", file=sys.stderr)
        return 2
    result = analyse(password, args.context)
    tips = feedback(result, password)
    breached: int | None = None
    checker = _checker(args)
    breach_error = ""
    if checker is not None:
        try:
            breached = checker.count(password)
        except BreachError as error:
            breach_error = str(error)
        finally:
            if isinstance(checker, PwnedFile):
                checker.close()
    ok = (
        result.score >= args.min_score
        and len(password) >= args.min_length
        and not breached
        and not breach_error
    )
    if args.json:
        print(
            json.dumps(
                {
                    "score": result.score,
                    "rating": SCORE_NAMES[result.score],
                    "guesses_log10": round(result.bits * 0.30103, 1),
                    "bits": round(result.bits, 1),
                    "length": len(password),
                    "breach_count": breached,
                    "breach_check_error": breach_error or None,
                    "crack_times": dict(crack_times(result.guesses)),
                    "advice": tips,
                    "ok": ok,
                },
                indent=1,
            )
        )
    else:
        print(
            f"Rating:  {SCORE_NAMES[result.score]} ({result.score}/4), about 2^{result.bits:.0f} guesses, {len(password)} characters"
        )
        if breached:
            print(f"Breach:  FOUND {breached:,} times in known breaches. Do not use it anywhere.")
        elif breach_error:
            print(f"Breach:  could not check ({breach_error}). This is NOT a clean result.")
        elif breached == 0:
            print("Breach:  not found in the data set")
        else:
            print("Breach:  not checked (add --hibp or --hibp-file)")
        print("Time to crack, on average:")
        for label, time in crack_times(result.guesses):
            print(f"  {time:>12}  {label}")
        for tip in tips:
            print(f"- {tip}")
    return 3 if args.exit_code and not ok else (1 if breach_error else 0)


def cmd_audit(args: argparse.Namespace) -> int:
    if args.wordlist:
        load_wordlist(args.wordlist)
    checker = _checker(args)
    try:
        report = audit(read_rows(args.file), checker, args.min_score, args.min_length)
    finally:
        if isinstance(checker, PwnedFile):
            checker.close()
    render = {"text": to_text, "md": to_markdown, "json": to_json}[args.format]
    print(render(report), end="")
    if report.breach_errors and not report.checked_breaches:
        return 1
    return 3 if args.exit_code and report.problems else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwaudit",
        description="Password strength, reuse and breach checks. Passwords are never taken as "
        "arguments and never printed.",
    )
    parser.add_argument("--version", action="version", version=f"pwaudit {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--hibp",
            action="store_true",
            help="check Have I Been Pwned (online, sends only 5 hex characters of the SHA-1)",
        )
        p.add_argument(
            "--hibp-file",
            metavar="FILE",
            help="check a downloaded 'ordered by hash' Pwned Passwords file (offline)",
        )
        p.add_argument("--hibp-url", default=DEFAULT_URL, help=argparse.SUPPRESS)
        p.add_argument(
            "--wordlist",
            metavar="FILE",
            help="extra dictionary, most common first (for example a leaked-password list)",
        )
        p.add_argument(
            "--min-score",
            type=int,
            default=2,
            choices=range(5),
            metavar="0-4",
            help="below this is weak (default 2)",
        )
        p.add_argument("--min-length", type=int, default=12, help="default 12")
        p.add_argument("--exit-code", action="store_true", help="exit 3 when there is a problem")

    p = sub.add_parser("check", help="check one password, read from the keyboard or from stdin")
    common(p)
    p.add_argument(
        "--context",
        action="append",
        default=[],
        metavar="WORD",
        help="a user name or site name the password must not contain (repeatable)",
    )
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("audit", help="audit a password-manager CSV export")
    common(p)
    p.add_argument("file")
    p.add_argument("--format", choices=["text", "md", "json"], default="text")
    p.set_defaults(func=cmd_audit)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (AuditError, BreachError) as error:
        print(f"pwaudit: {error}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
