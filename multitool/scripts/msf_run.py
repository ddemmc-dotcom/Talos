#!/usr/bin/env python3
"""Standalone runner: execute a Metasploit module through msfrpcd.

Shares the exact engine and report renderer used by the menu and the UI.
Needs a running RPC daemon and credentials:

    msfrpcd -P <password> -a 127.0.0.1 -p 55553
    export MSF_RPC_PASSWORD=<password>

    python3 scripts/msf_run.py scanner/portscan/tcp --target 10.0.0.5 --option THREADS=10
    python3 scripts/msf_run.py exploit/multi/handler --type exploit \\
        --payload linux/x64/meterpreter/reverse_tcp --option LHOST=10.0.0.1

Exit codes: 0 = module ran, 1 = the run failed or the daemon was unreachable.
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
        prog="msf_run.py",
        description="Run a Metasploit module (auxiliary/exploit/post) via the RPC daemon.",
    )
    parser.add_argument("module", help="module path, e.g. scanner/portscan/tcp")
    parser.add_argument("--type", dest="module_type", default="auxiliary",
                        help="auxiliary / exploit / post (default: auxiliary)")
    parser.add_argument("--target", default="", help="target host/IP (wired into RHOSTS)")
    parser.add_argument("--payload", default="", help="payload for exploits (optional)")
    parser.add_argument(
        "--option", action="append", default=[], metavar="KEY=VALUE",
        help="datastore option, repeatable, e.g. --option THREADS=10",
    )
    return parser


def main(argv=None) -> int:
    from src.core import report
    from src.modules.metasploit_wrapper import MetasploitModule

    args = build_parser().parse_args(argv)
    datastore: dict = {}
    for token in args.option:
        if "=" not in token:
            print(f"[x] option {token!r} is not KEY=VALUE", file=sys.stderr)
            return 1
        key, _, value = token.partition("=")
        datastore[key.strip()] = value.strip()

    context = {
        "options": {
            "msf_type": args.module_type,
            "msf_module": args.module,
            "msf_options": datastore,
        }
    }
    if args.payload:
        context["options"]["payload"] = args.payload
    if args.target:
        context["target"] = args.target

    try:
        MetasploitModule.validate_environment()
    except Exception as exc:
        print(f"[x] {exc}", file=sys.stderr)
        return 1

    from src.core import progress

    started = time.perf_counter()
    instance = MetasploitModule()
    instance.set_progress_sink(progress.cli_sink)
    result = instance.run(context)
    progress.clear_cli_line()
    elapsed = time.perf_counter() - started
    report.print_result(result)
    print(f"  elapsed: {elapsed:.2f}s   status: {result.status.value}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
