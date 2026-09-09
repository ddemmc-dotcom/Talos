#!/usr/bin/env python3
"""Standalone runner: local data scraper (browser diagnostics & event logger).

Shares the exact engine used by the menu and the UI.  Serves a consent-based
diagnostics page on localhost and streams every request — browser environment,
LAN IPs, connectivity probes, UI events, form data — to this terminal and the
framework log.  The server keeps running until this window is closed (or
Ctrl+C is pressed), which is what makes it easy to port-forward:

    python3 scripts/data_scraper.py --port 8080 --redirect https://example.com
    python3 scripts/data_scraper.py --qrcode --ngrok -v
    python3 scripts/data_scraper.py --duration 30   # auto-stop after 30s

Exit codes: 0 = the session ran (with or without collected data),
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
        prog="data_scraper.py",
        description=(
            "Serves a consent-based browser diagnostics page on localhost and "
            "streams every request — browser environment, LAN IPs, connectivity "
            "probes, UI events and form data — into this terminal and the "
            "framework log. Run until this window is closed or Ctrl+C is pressed."
        ),
        epilog="Authorised use only — the page collects data from whoever opens it.",
    )
    parser.add_argument(
        "-p", "--port", type=int, default=8080,
        help="localhost port to bind the HTTP server (default: 8080)",
    )
    parser.add_argument(
        "--redirect", default="https://www.google.com",
        help="where to redirect the browser after collection (empty = no redirect)",
    )
    parser.add_argument(
        "--qrcode", action="store_true",
        help="print an ASCII QR code of the localhost URL in the console",
    )
    parser.add_argument(
        "--ngrok", action="store_true",
        help="expose the server publicly via ngrok when the binary is installed",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="increase framework logging verbosity (pass-through)",
    )
    parser.add_argument(
        "--duration", type=float, default=0.0,
        help="auto-stop after N seconds (default 0 = run until the window closes / Ctrl+C)",
    )
    return parser


def main(argv=None) -> int:
    from src.core import progress
    from src.core import report
    from src.modules.data_scraper import DataScraperModule

    args = build_parser().parse_args(argv)
    options = {
        "port": args.port,
        "redirect": args.redirect,
        "qrcode": args.qrcode,
        "ngrok": args.ngrok,
        "verbose": args.verbose,
        "duration": args.duration,
    }
    instance = DataScraperModule()
    instance.set_progress_sink(progress.cli_sink)
    instance.set_banner_callback(lambda lines: [print(line) for line in lines])
    # The server lives in this terminal: every connection streams to stdout.
    instance.set_stdout_stream(True)

    started = time.perf_counter()
    try:
        result = instance.run({"options": options})
    except KeyboardInterrupt:  # belt-and-braces; run() handles it internally
        instance.stop()
        print("\n[x] Interrupted — data scraper stopped.", file=sys.stderr)
        return 130
    progress.clear_cli_line()
    report.print_result(result)
    print(f"  elapsed: {time.perf_counter() - started:.2f}s   status: {result.status.value}")
    return 0 if result.ok else 2


if __name__ == "__main__":
    sys.exit(main())