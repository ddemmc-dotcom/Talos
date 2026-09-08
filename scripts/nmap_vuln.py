#!/usr/bin/env python3
"""Standalone runner: Nmap NSE vulnerability scan (--script vuln).

Shares the exact engine and report renderer used by the menu and the UI:

    python3 scripts/nmap_vuln.py scanme.nmap.org
    python3 scripts/nmap_vuln.py 192.168.1.0/24 --ports 445,139 --scripts vuln,safe --timeout 900

Exit codes: 0 = scan completed, 1 = the scan failed or was unavailable.
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
        prog="nmap_vuln.py",
        description="Nmap vulnerability scan using the NSE vuln script family.",
    )
    parser.add_argument("target", help="host, IP or CIDR range to scan")
    parser.add_argument("--ports", default="", help="comma separated port list (optional)")
    parser.add_argument(
        "--scripts",
        default="vuln",
        help="NSE script(s) to run (default: vuln)",
    )
    parser.add_argument("--timeout", type=float, default=600.0, help="scan timeout in seconds")
    parser.add_argument(
        "--extra", action="append", default=[], metavar="ARG",
        help="extra nmap argument, e.g. --extra -sV (repeatable)",
    )
    return parser


def main(argv=None) -> int:
    from src.core import report
    from src.modules.attack import NmapVulnModule

    args = build_parser().parse_args(argv)
    context = {
        "target": args.target,
        "options": {
            "nse_scripts": args.scripts,
            "extra_args": args.extra,
            "timeout": args.timeout,
        },
    }
    if args.ports:
        context["ports"] = args.ports
    try:
        NmapVulnModule.validate_environment()
    except Exception as exc:
        print(f"[x] {exc}", file=sys.stderr)
        return 1
    from src.core import progress

    started = time.perf_counter()
    instance = NmapVulnModule()
    instance.set_progress_sink(progress.cli_sink)
    result = instance.run(context)
    progress.clear_cli_line()
    elapsed = time.perf_counter() - started
    report.print_result(result)
    print(f"  elapsed: {elapsed:.2f}s   status: {result.status.value}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
