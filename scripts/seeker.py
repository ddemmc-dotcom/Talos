#!/usr/bin/env python3
"""Standalone runner for the Talos Seeker module.

Example:
    python3 scripts/seeker.py --template NearYou --port 8080
    python3 scripts/seeker.py --template Telegram --tunnel
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def build_parser() -> argparse.ArgumentParser:
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_seeker_path = os.path.normpath(
        os.path.join(project_root, "external_tools", "seeker", "seeker.py")
    )

    parser = argparse.ArgumentParser(
        prog="seeker.py",
        description="Launch the Talos Seeker social-engineering page generator.",
    )
    parser.add_argument("--template", default=os.environ.get("SEEKER_DEFAULT_TEMPLATE", "NearYou"), help="Seeker template to launch (NearYou, WhatsApp, Telegram, Zoom, Google Drive, Google reCAPTCHA)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("SEEKER_DEFAULT_PORT", "8080")), help="local port to bind the Seeker page to")
    parser.add_argument("--tunnel", action="store_true", help="attempt to expose the page through ngrok")
    parser.add_argument("--timeout", type=float, default=float(os.environ.get("SEEKER_TIMEOUT", "60")), help="seconds to wait for the generated link to appear")
    parser.add_argument("--path", default=os.environ.get("SEEKER_PATH", default_seeker_path), help="custom Seeker script path")
    parser.add_argument("--terminal-child", action="store_true", help=argparse.SUPPRESS)
    return parser


def _run_terminal_child(args) -> int:
    """Run the upstream process once and render its output for the operator."""
    from src.modules.seeker import _template_index

    seeker_path = os.path.abspath(args.path)
    command = [
        sys.executable,
        seeker_path,
        "-t",
        str(_template_index(args.template)),
        "-p",
        str(args.port),
    ]
    print("", flush=True)
    print("=" * 60, flush=True)
    print("  TALOS / SEEKER HOSTING CONSOLE", flush=True)
    print("=" * 60, flush=True)
    print(f"  template : {args.template}", flush=True)
    print(f"  port     : {args.port}", flush=True)
    print(f"  local    : http://127.0.0.1:{args.port}", flush=True)
    print("  mode     : background subprocess; output translated by Talos", flush=True)
    print("  status   : starting", flush=True)
    print("-" * 60, flush=True)

    process = subprocess.Popen(
        command,
        cwd=os.path.dirname(seeker_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    ansi = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
    try:
        for raw_line in process.stdout or ():
            line = ansi.sub("", raw_line).rstrip()
            if not line:
                continue
            if "Starting PHP Server" in line:
                label = "[SERVER]"
            elif "Waiting for Client" in line:
                label = "[WAIT]  "
            elif "Exception" in line or "Unable" in line or "failed" in line.lower():
                label = "[ERROR] "
            else:
                label = "[SEEKER]"
            print(f"{label} {line}", flush=True)
    finally:
        return_code = process.wait()

    print("-" * 60, flush=True)
    print(f"  status   : {'stopped' if return_code == 0 else 'failed'} ({return_code})", flush=True)
    return return_code


def main(argv=None) -> int:
    from src.core import progress, report
    from src.modules.seeker import SeekerModule

    args = build_parser().parse_args(argv)
    if args.terminal_child:
        return _run_terminal_child(args)

    context = {
        "options": {
            "template": args.template,
            "port": args.port,
            "tunnel": args.tunnel,
            "timeout": args.timeout,
        }
    }

    if args.path:
        os.environ["SEEKER_PATH"] = args.path

    try:
        SeekerModule.validate_environment()
    except Exception as exc:
        print(f"[x] {exc}", file=sys.stderr)
        return 1

    started = time.perf_counter()
    instance = SeekerModule()
    instance.set_progress_sink(progress.cli_sink)
    result = instance.run(context)
    progress.clear_cli_line()
    elapsed = time.perf_counter() - started
    report.print_result(result)
    print(f"  elapsed: {elapsed:.2f}s   status: {result.status.value}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
