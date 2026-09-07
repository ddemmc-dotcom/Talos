#!/usr/bin/env python3
"""Standalone runner: HTTP login brute-forcer (Basic auth or HTML form).

Shares the exact engine and report renderer used by the menu and the UI.
Use it ONLY against systems you are authorised to test:

    python3 scripts/http_bruteforce.py https://example.com/login --user admin \\
        --passwords-file wordlists/pass.txt
    python3 scripts/http_bruteforce.py http://host/login --mode form \\
        --user admin --users-file users.txt --passwords-file pass.txt \\
        --success-marker "Welcome," --fail-marker "Invalid"

Exit codes: 0 = at least one credential found, 1 = none found,
2 = the run itself failed.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="http_bruteforce.py",
        description="Wordlist credential testing against HTTP Basic auth or login forms.",
    )
    parser.add_argument("url", help="login URL (https://... added automatically if omitted)")
    parser.add_argument("--mode", choices=("basic", "form"), default="basic")
    user = parser.add_mutually_exclusive_group(required=True)
    user.add_argument("--user", dest="single_user", help="one username to test")
    user.add_argument("--users-file", help="file with one username per line")
    creds = parser.add_mutually_exclusive_group()
    creds.add_argument("--passwords-file", help="file with one password per line")
    creds.add_argument(
        "--passwords", default="", help="inline comma-separated password list"
    )
    parser.add_argument("--delay", type=float, default=0.1, help="seconds between attempts")
    parser.add_argument("--timeout", type=float, default=8.0, help="per-request timeout")
    parser.add_argument(
        "--no-stop", action="store_true",
        help="keep testing after the first valid credential is found",
    )
    parser.add_argument("--user-field", default="username", help="form username field name")
    parser.add_argument("--pass-field", default="password", help="form password field name")
    parser.add_argument("--success-marker", default="", help="text only present after a good login")
    parser.add_argument("--fail-marker", default="", help="text present when a login fails")
    return parser


def main(argv=None) -> int:
    from src.core import report
    from src.modules.attack import HttpBruteforceModule

    args = build_parser().parse_args(argv)
    options: dict = {
        "url": args.url,
        "mode": args.mode,
        "delay": args.delay,
        "timeout": args.timeout,
        "stop_on_found": not args.no_stop,
    }
    if args.users_file:
        options["users_file"] = args.users_file
    else:
        options["user"] = args.single_user
    if args.passwords_file:
        options["passwords_file"] = args.passwords_file
    elif args.passwords:
        options["passwords"] = [p.strip() for p in args.passwords.split(",") if p.strip()]
    if args.mode == "form":
        options.update(
            {
                "user_field": args.user_field,
                "pass_field": args.pass_field,
                "success_marker": args.success_marker,
                "fail_marker": args.fail_marker,
            }
        )
    try:
        HttpBruteforceModule.validate_environment()
    except Exception as exc:
        print(f"[x] {exc}", file=sys.stderr)
        return 2

    from src.core import progress

    started = time.perf_counter()
    instance = HttpBruteforceModule()
    instance.set_progress_sink(progress.cli_sink)
    result = instance.run({"options": options})
    progress.clear_cli_line()
    elapsed = time.perf_counter() - started
    report.print_result(result)
    print(f"  elapsed: {elapsed:.2f}s   status: {result.status.value}")

    if not result.ok:
        return 2
    found = len((result.data or {}).get("found") or [])
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())
