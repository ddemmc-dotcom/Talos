#!/usr/bin/env python3
"""Standalone runner: read-only automated vulnerability audit.

Shares the exact engine and report renderer used by the menu and the UI:

    python3 scripts/auto_audit.py 10.0.0.5
    python3 scripts/auto_audit.py 192.168.1.0/24 --ports 22,80,443 --os-detect

The audit runs ``nmap -sV`` (+ optional ``-O``) and cross-references the
banners against built-in knowledge bases for outdated services, default
configurations and weak-auth surfaces.  It is strictly read-only: it never
exploits, brute-forces or modifies the target, and every finding is a
candidate that must be verified manually.

Exit codes: 0 = audit completed, 1 = the audit failed or was unavailable.
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
        prog="auto_audit.py",
        description="Read-only automated vulnerability audit (reports candidates, never attacks).",
    )
    parser.add_argument("target", help="host, IP or CIDR range to audit")
    parser.add_argument("--ports", default="", help="comma separated port list (optional)")
    parser.add_argument(
        "--os-detect",
        action="store_true",
        help="include OS fingerprinting (-O; usually needs root)",
    )
    parser.add_argument(
        "--scripts",
        default="ssh-auth-methods,ftp-anon,http-default-accounts",
        help="read-only NSE scripts; pass '' to disable (default: weak-auth checks)",
    )
    parser.add_argument("--timeout", type=float, default=600.0, help="scan timeout in seconds")
    return parser


def main(argv=None) -> int:
    from src.core import report
    from src.modules.auto_audit import AutoAuditModule, can_run_os_detection

    args = build_parser().parse_args(argv)
    if args.os_detect and not can_run_os_detection():
        print(
            "[w] --os-detect needs root privileges; OS fingerprinting will be "
            "skipped (the scan continues).",
            file=sys.stderr,
        )
    context = {
        "target": args.target,
        "options": {
            "os_detect": args.os_detect,
            "nse_scripts": args.scripts,
            "timeout": args.timeout,
        },
    }
    if args.ports:
        context["ports"] = args.ports
    try:
        AutoAuditModule.validate_environment()
    except Exception as exc:
        print(f"[x] {exc}", file=sys.stderr)
        return 1
    from src.core import progress

    started = time.perf_counter()
    instance = AutoAuditModule()
    instance.set_progress_sink(progress.cli_sink)
    result = instance.run(context)
    progress.clear_cli_line()
    elapsed = time.perf_counter() - started
    report.print_result(result)
    print(f"  elapsed: {elapsed:.2f}s   status: {result.status.value}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())