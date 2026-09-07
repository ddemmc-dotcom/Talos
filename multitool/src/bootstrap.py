"""First-run dependency bootstrap (stdlib only — no third-party imports).

``ui.py`` runs this module *before* importing anything that needs pydantic or
textual, so a fresh checkout can install its own dependencies automatically.

Pipeline
--------
1. Parse ``requirements.txt`` into ``(distribution, import_name, pip_spec)``.
2. Detect which distributions are missing via ``importlib.util.find_spec()``.
3. Unless skipped, offer to ``pip install`` the missing ones (streaming pip
   output to the console) and re-check afterwards.

Only a small set of *core* packages (``textual``, ``pydantic``) is required
for the UI to launch; every other dependency degrades gracefully through the
module ``validate_environment()`` machinery (e.g. Metasploit needs a running
``msfrpcd`` anyway).
"""
from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

PROJECT_ROOT: Path = Path(__file__).resolve().parents[1]
REQUIREMENTS_FILE: Path = PROJECT_ROOT / "requirements.txt"

#: Core packages without which the UI cannot even import/start.
CORE_IMPORTS = frozenset({"textual", "pydantic"})

#: pip distribution name -> python module used for presence detection.
_DIST_TO_IMPORT: Dict[str, str] = {
    "python-dotenv": "dotenv",
    "pymetasploit3": "pymetasploit3",
    "pydantic": "pydantic",
    "textual": "textual",
    "dnspython": "dns",
    "requests": "requests",
    "cryptography": "cryptography",
    "colorama": "colorama",
}

Requirement = Tuple[str, str, str]  # (distribution, import_name, pip_spec)


def parse_requirements(path: Optional[Path] = None) -> List[Requirement]:
    """Parse requirements.txt into (dist, import_name, pip_spec) tuples."""
    path = path or REQUIREMENTS_FILE
    entries: List[Requirement] = []
    if not path.exists():
        return entries
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        # Distribution name = leading package token, minus any version
        # constraint / extra marker (e.g. 'pydantic>=2.0' -> 'pydantic').
        name_match = re.match(r"^[A-Za-z0-9._-]+", line)
        if not name_match:
            continue
        dist = name_match.group(0)
        entries.append((dist, _DIST_TO_IMPORT.get(dist, dist), line))
    return entries


def _is_importable(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, ValueError, ModuleNotFoundError):
        return False


def missing_dependencies(
    entries: Optional[List[Requirement]] = None,
) -> List[Requirement]:
    """Return the requirement tuples whose import modules are absent."""
    entries = entries if entries is not None else parse_requirements()
    return [entry for entry in entries if not _is_importable(entry[1])]


def _pip_install(pip_specs: List[str]) -> bool:
    """Install the given pip specs into the current interpreter."""
    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        *pip_specs,
    ]
    print(f"\n$ {' '.join(command)}")
    try:
        result = subprocess.run(command, cwd=str(PROJECT_ROOT))
    except OSError as exc:
        print(f"[bootstrap] failed to run pip: {exc}", file=sys.stderr)
        return False
    return result.returncode == 0


def ensure_requirements(
    *,
    assume_yes: bool = False,
    skip_install: bool = False,
    check_only: bool = False,
) -> Tuple[bool, List[str], List[str]]:
    """Make sure declared dependencies are available.

    Returns ``(all_ok, still_missing, installed)`` — never raises. When
    ``check_only`` is set nothing is installed and no prompt is shown.
    """
    entries = parse_requirements()
    missing = missing_dependencies(entries)
    installed: List[str] = []

    if not missing:
        if not check_only:
            print(
                f"[bootstrap] all {len(entries)} declared dependencies are installed."
            )
        return True, [], []

    print(
        f"[bootstrap] {len(missing)} declared dependenc{'y' if len(missing) == 1 else 'ies'} "
        f"not found on first run:"
    )
    for dist, _import_name, spec in missing:
        marker = " [required for UI]" if _import_name in CORE_IMPORTS else ""
        print(f"    - {spec}{marker}")

    missing_names = [entry[1] for entry in missing]
    if check_only or skip_install:
        if check_only:
            print(
                "[bootstrap] check-only mode: nothing was installed. "
                "Run 'python3 ui.py' to auto-install."
            )
        else:
            print(
                "[bootstrap] install skipped (--no-install). "
                "Run 'python3 ui.py --yes' or "
                f"'{sys.executable} -m pip install -r requirements.txt'."
            )
        core_missing = [
            name for name in missing_names if name in CORE_IMPORTS
        ]
        return not core_missing, missing_names, installed

    do_install = assume_yes
    if not do_install:
        try:
            answer = input("Auto-install the missing dependencies now? [Y/n] ").strip().lower()
        except EOFError:  # non-interactive context: default to yes
            answer = "y"
        do_install = answer in ("", "y", "yes")

    if not do_install:
        print("[bootstrap] install declined.")
        core_missing = [name for name in missing_names if name in CORE_IMPORTS]
        return not core_missing, missing_names, installed

    pip_specs = [entry[2] for entry in missing]
    if not _pip_install(pip_specs):
        print("[bootstrap] pip install reported an error.", file=sys.stderr)
    installed = [entry[1] for entry in missing]

    still_missing = missing_dependencies(entries)
    still_names = [entry[1] for entry in still_missing]
    if not still_names:
        print("[bootstrap] all dependencies are now available.")
        return True, [], installed

    print(
        f"[bootstrap] {len(still_names)} dependenc{'y' if len(still_names) == 1 else 'ies'} "
        f"still missing: {', '.join(still_names)}",
        file=sys.stderr,
    )
    core_still_missing = [name for name in still_names if name in CORE_IMPORTS]
    return not core_still_missing, still_names, installed


if __name__ == "__main__":  # manual smoke test
    ok, missing, installed = ensure_requirements(check_only=True)
    print(f"ok={ok} missing={missing} installed={installed}")
