#!/usr/bin/env python3
"""Easy-to-use terminal UI for the multi-tool framework.

On the first run this launcher detects missing dependencies from
``requirements.txt`` and — with a single ``Y`` — installs them automatically
(``pip install`` into the current interpreter). After that it starts the
keyboard-driven Textual UI, which wraps the same orchestrator as the CLI:

    python3 ui.py              # auto-install missing deps on first run, then start
    python3 ui.py --yes        # never prompt; install anything missing
    python3 ui.py --no-install # skip installs; launch anyway if core deps exist
    python3 ui.py --check-deps # only report what is missing, then exit

Core deps (textual, pydantic) are required to start the UI; optional deps
such as pymetasploit3 degrade gracefully (they surface in the readiness
report as MISSING until installed / a daemon is running).

Inside the UI: select a module with the arrow keys, type your target/ports
and KEY=VALUE options, then press ENTER in an input or Ctrl+S to run.
There are no buttons and no tabs — everything is keyboard-driven.
"""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

# NOTE: bootstrap is stdlib-only, so it can run before pydantic/textual exist.
from src.bootstrap import ensure_requirements


def _banner() -> None:
    print("=" * 64)
    print("  multi-tool UI — modules (nmap, vuln scan, brute-force, Metasploit)")
    print("  Logs: logs/toolkit.log    Audit trail: logs/audit.jsonl")
    print("=" * 64)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ui.py",
        description="Terminal UI for the multi-tool framework "
        "(auto-installs missing dependencies on first run).",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Auto-install missing dependencies without prompting.",
    )
    parser.add_argument(
        "--no-install",
        action="store_true",
        help="Never install anything; launch anyway when core deps exist.",
    )
    parser.add_argument(
        "--check-deps",
        action="store_true",
        help="Report missing dependencies and exit without installing.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    _banner()
    ok, still_missing, _installed = ensure_requirements(
        assume_yes=args.yes,
        skip_install=args.no_install,
        check_only=args.check_deps,
    )
    if args.check_deps:
        return 0 if ok else 1
    if not ok:
        print(
            "\n[ui] core dependencies are missing and were not installed. "
            "Run:  python3 ui.py --yes",
            file=sys.stderr,
        )
        return 1
    if still_missing:
        print(
            "\n[ui] note: optional dependencies still missing "
            f"({', '.join(still_missing)}).\n"
            "    They will show up as MISSING in the readiness report; "
            "install with 'python3 ui.py --yes' whenever you want them.\n"
        )

    # Imported only now: bootstrap guarantees pydantic + textual are present.
    try:
        from src.tui.app import ToolkitTuiApp
    except ImportError as exc:  # pragma: no cover - defensive
        print(f"[ui] could not start the UI: {exc}", file=sys.stderr)
        return 1

    print("[ui] starting terminal UI — keyboard-driven; press 'q' to quit.\n")
    ToolkitTuiApp().run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
