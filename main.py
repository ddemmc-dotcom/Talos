#!/usr/bin/env python3
"""TALOS — a menu-driven, professional multi-tool.

Entry point responsibilities:
1. ``check_dependencies()`` — verify the libraries the menu needs are
   importable and auto-install any that are missing via ``pip``;
2. create one persistent :class:`~src.core.context.Session`;
3. start the menu state machine (``MAIN_MENU -> CATEGORY_VIEW ->
   MODULE_EXECUTION -> SHOW_RESULTS -> MAIN_MENU``);
4. catch ``KeyboardInterrupt`` and end with a clean, professional message.

Run it with:  python main.py
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from typing import List, Tuple

#: (pip distribution, python import name)
#:
#: ``pydantic`` is the only *hard* dependency here: it is imported at module
#: load time through  menu -> logging_utils -> models.tool_result. The rest
#: are imported lazily inside the modules themselves, but pre-installing them
#: keeps every menu entry working on the first run.
REQUIRED_PACKAGES: List[Tuple[str, str]] = [
    ("pydantic", "pydantic"),
    ("requests", "requests"),
    ("dnspython", "dns"),
    ("cryptography", "cryptography"),
    ("colorama", "colorama"),
]


def _importable(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, ValueError, ModuleNotFoundError):
        return False


def check_dependencies() -> List[str]:
    """Auto-install any missing declared libraries; return what is still out.

    Never raises: the tool keeps running with degraded modules if an install
    fails (e.g. on a locked-down or PEP 668 managed interpreter).
    """
    missing = [dist for dist, module in REQUIRED_PACKAGES if not _importable(module)]
    for dist in missing:
        print(f"[WARN] Library '{dist}' is not installed. Installing via pip...")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", dist],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=300,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            print(f"[WARN] Automatic install of '{dist}' failed: {exc}")
            continue
        if result.returncode != 0:
            tail = "\n".join((result.stdout or "").strip().splitlines()[-4:])
            print(f"[WARN] Automatic install of '{dist}' reported an error.\n{tail}")
    still_missing = [dist for dist, module in REQUIRED_PACKAGES if not _importable(module)]
    if still_missing:
        print(
            f"[WARN] Still missing: {', '.join(still_missing)}. "
            "Affected modules will report a clean error when used."
        )
    return still_missing


def main() -> int:
    still_missing = check_dependencies()
    print()

    # The menu imports pydantic (via models.tool_result) at import time, so a
    # still-missing pydantic is fatal here; everything else degrades cleanly
    # inside the guarded module runner.
    if "pydantic" in still_missing:
        print(
            "[FATAL] pydantic could not be installed/imported and the menu "
            "cannot start without it. Install it manually with:\n"
            f"    {sys.executable} -m pip install pydantic"
        )
        return 1

    try:
        from src.core.context import Session
        from src.core.menu import run as run_menu
    except ImportError as exc:
        print(f"[FATAL] could not load the menu: {exc}")
        return 1

    session = Session(name="talos")
    try:
        run_menu(session)
    except KeyboardInterrupt:
        print()
        print("[INFO] Session terminated cleanly.")
        return 0
    print("[INFO] Session terminated cleanly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
