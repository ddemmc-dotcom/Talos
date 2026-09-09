"""TALOS menu engine — one clean, flat module list.

All modules live in **one numbered list** (no categories, no sub-menus)
and each number runs its module immediately::

    MAIN_MENU -> MODULE_EXECUTION -> SHOW_RESULTS -> MAIN_MENU

Reconnaissance, OSINT, utilities and the attacking modules (Nmap
vulnerability scan, Metasploit runner, HTTP login brute-forcer) sit side
by side; every entry is just a number, a title and an action.

Every module call runs inside a guarded wrapper — unexpected exceptions are
logged with a full traceback to ``logs/error.log`` (timestamped) while the
user only ever sees a short, professional ``[x] ...`` line.

The chrome is colourful by default but is disabled automatically when
stdout is not a TTY or when the ``NO_COLOR`` environment variable is set,
so logs and pipes stay clean.
"""
from __future__ import annotations

import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from src.core import formatting as fmt
from src.core import progress
from src.core.context import Session
from src.logging_utils import get_logger

# ---------------------------------------------------------------------------
# logging (traceback audit)
# ---------------------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
LOG_DIR: Path = PROJECT_ROOT / "logs"
ERROR_LOG: Path = LOG_DIR / "error.log"
MENU_LOGGER = get_logger("talos.menu")


def _log_traceback(module_label: str, exc: BaseException) -> None:
    """Append a timestamped full traceback to logs/error.log."""
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        body = "".join(
            traceback.format_exception(type(exc), exc, exc.__traceback__)
        )
        with open(ERROR_LOG, "a", encoding="utf-8") as handle:
            handle.write(f"\n[{stamp}] module={module_label}\n{body}")
    except OSError:  # pragma: no cover - logging must never crash the tool
        pass


# ---------------------------------------------------------------------------
# banner
# ---------------------------------------------------------------------------
_BANNER_ART = [
    r" ████████╗ █████╗ ██╗      ██████╗ ███████╗",
    r" ╚══██╔══╝██╔══██╗██║     ██╔═══██╗██╔════╝",
    r"    ██║   ███████║██║     ██║   ██║███████╗",
    r"    ██║   ██╔══██║██║     ██║   ██║╚════██║",
    r"    ██║   ██║  ██║███████╗╚██████╔╝███████║",
    r"    ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝",
]
_BANNER_GRADIENT = [fmt._CYAN, fmt._MAGENTA, fmt._YELLOW, fmt._GREEN, fmt._MAGENTA, fmt._CYAN]


def _print_banner() -> None:
    """Big colourful block-letter banner with a double-line frame."""
    if not fmt._USE_COLOR:
        for line in _BANNER_ART:
            print(line)
        print("=" * 64)
        return
    frame = fmt._BOLD + fmt._CYAN + "╔" + "═" * 66 + "╗" + fmt._RESET
    print(frame)
    for index, art_line in enumerate(_BANNER_ART):
        color = _BANNER_GRADIENT[index % len(_BANNER_GRADIENT)]
        print(f"{fmt._BOLD}{color}║{fmt._RESET}  {fmt._BOLD}{color}{art_line}{fmt._RESET}  {fmt._BOLD}{color}║{fmt._RESET}")
    underline = fmt._BOLD + fmt._YELLOW + "─" * 66 + fmt._RESET
    print(f"{fmt._BOLD}{fmt._CYAN}║{fmt._RESET}{underline}{fmt._BOLD}{fmt._CYAN}║{fmt._RESET}")
    tagline = (
        fmt._BOLD + fmt._WHITE + "multi-tool" + fmt._RESET
        + "  ·  " + fmt._CYAN + "reconnaissance" + fmt._RESET
        + "  ·  " + fmt._MAGENTA + "osint" + fmt._RESET
        + "  ·  " + fmt._YELLOW + "utilities" + fmt._RESET
        + "  ·  " + fmt._RED + "attack" + fmt._RESET
    )
    print(f"{fmt._BOLD}{fmt._CYAN}║{fmt._RESET}  {tagline}{fmt._BOLD}{fmt._CYAN}║{fmt._RESET}")
    print(f"{fmt._BOLD}{fmt._CYAN}╚" + "═" * 66 + "╝{fmt._RESET}")


def _session_line(session: Session) -> None:
    print(
        fmt.dim(
            "session: {name}   target ip: {ip}   target domain: {dom}   "
            "results: {n}".format(
                name=session.name,
                ip=session.target_ip or "-",
                dom=session.target_domain or "-",
                n=len(session.scan_results),
            )
        )
    )


def _module_header(number: int, title: str) -> None:
    fmt.print_box(
        [fmt.white(f"MODULE {number:02d}", bold=True), fmt.cyan(title)],
        accent=fmt._MAGENTA,
        bold=True,
    )


def _progress_header(title: str) -> None:
    """One-line banner shown while a module is executing."""
    print(f"  {fmt.paint('▶', fmt._CYAN, bold=True)}  {fmt.white(title, bold=True)}  {fmt.dim('(running — logs below)')}")


# ---------------------------------------------------------------------------
# input helpers
# ---------------------------------------------------------------------------
class _ExitRequested(Exception):
    """Raised internally when the user (or stdin EOF) asks to quit."""


def _read(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        raise _ExitRequested() from None


# ---------------------------------------------------------------------------
# the single module list (flat — no categories, sequential numbers)
# ---------------------------------------------------------------------------
def _build_modules() -> List[Dict[str, Any]]:
    """One flat, ordered list of every module in the tool (01..N)."""
    from src.modules import network_scan as network
    from src.modules import osint_scan as osint
    from src.modules import utilities as utils
    from src.modules import network_extra as net_extra
    from src.modules import osint_extra as osint_extra
    from src.modules import utilities_extra as utils_extra
    from src.modules import security as security_mod
    from src.modules import attack as attack_mod
    from src.modules import data_scraper as data_scraper_mod

    # (title, function) — the order below is the number you type.
    specs: List[tuple] = [
        # ---- network ----
        ("Show My IP", network.show_my_ip),
        ("IP Scanner (Ping Sweep)", network.ip_scanner),
        ("IP Pinger (RTT / TTL)", network.ip_pinger),
        ("IP Port Scanner", network.port_scanner),
        ("Port Banner Grabber", net_extra.banner_grabber),
        ("SSL/TLS Certificate Checker", net_extra.ssl_checker),
        ("HTTP Security Headers", net_extra.http_headers),
        ("Website Info Scanner", network.website_info),
        ("DNS Lookup", network.dns_lookup),
        ("Traceroute", network.traceroute),
        ("IP Geolocation Lookup", net_extra.ip_geolocation),
        # ---- osint ----
        ("Username Tracker", osint.username_tracker),
        ("Subdomain Finder (wordlist)", osint.subdomain_finder),
        ("Email / Contact Finder", osint.email_finder),
        ("Phone Number Lookup", osint.phone_lookup),
        ("Metadata Extractor", osint.metadata_extractor),
        ("HTTP Method Tester", security_mod.http_method_tester),
        ("VHOST Scanner", security_mod.vhost_scanner),
        ("Web Directory Bruteforcer", security_mod.web_directory_bruteforcer),
        ("Whois Lookup (RDAP)", osint.whois_lookup),
        ("Certificate Transparency Lookup", osint.ct_lookup),
        ("Reverse DNS Lookup", osint_extra.reverse_dns),
        ("Wayback Machine Lookup", osint_extra.wayback_lookup),
        ("Email Header Analyzer", osint_extra.email_header_analyzer),
        # ---- utilities ----
        ("WAF Detection", security_mod.waf_detection),
        ("DNS Zone Transfer Check", osint_extra.dns_zone_transfer),
        ("Open Port Finder (fast)", osint_extra.open_port_finder),
        ("Password Generator", utils.password_generator),
        ("Hash Generator", utils.hash_generator),
        ("Session / Target Manager", utils.manage_session),
        ("JWT Token Analyzer", security_mod.jwt_token_analyzer),
        ("HTTP/2 & Deprecated TLS Checker", security_mod.http2_tls_checker),
        ("Leaked Credential Checker", security_mod.leaked_credential_checker),
        ("Timestamp Converter", utils_extra.timestamp_converter),
        ("Subdomain Takeover Checker", security_mod.subdomain_takeover_checker),
        # ---- attack ----
        ("HTTP Login Brute-Forcer", attack_mod.menu_http_bruteforce),
        ("Nmap Vulnerability Scan", attack_mod.menu_nmap_vuln),
        ("Auto Vulnerability Audit", attack_mod.menu_auto_audit),
        ("Metasploit Module Runner", attack_mod.menu_metasploit),
        ("Data Scraper", data_scraper_mod.menu_data_scraper),
    ]
    modules: List[Dict[str, Any]] = []
    for index, (title, func) in enumerate(specs, start=1):
        modules.append({"number": index, "title": title, "func": func})
    return modules


# ---------------------------------------------------------------------------
# guarded execution
# ---------------------------------------------------------------------------
def _short_reason(exc: BaseException) -> str:
    message = str(exc).strip().replace("\n", " ")
    if message:
        return message[:180]
    return type(exc).__name__


def execute_module(session: Session, module: Dict[str, Any]) -> None:
    """Run a module under the zero-crash guard, then pause on results."""
    number = int(module["number"])
    title = str(module["title"])
    _module_header(number, title)
    _progress_header(f"[{number:02d}] {title}")
    started = time.monotonic()
    before_keys = set(session.scan_results)
    try:
        module["func"](session)
    except KeyboardInterrupt:
        print(fmt.red("[x] Module interrupted by the user; returning to the menu."))
    except Exception as exc:
        _log_traceback(f"{number:02d} {title}", exc)
        print(fmt.red(f"[x] Failed to execute module: {_short_reason(exc)}"))
    elapsed = time.monotonic() - started
    after_keys = set(session.scan_results)
    MENU_LOGGER.info(
        "module=%02d title=%s elapsed_ms=%.3f result_keys_added=%s total_result_sets=%d",
        number,
        title,
        elapsed * 1000.0,
        sorted(after_keys - before_keys),
        len(after_keys),
    )
    progress.clear_cli_line()
    print(progress.bar_text(1.0))
    print(fmt.tag_ok(f"module {number:02d} completed in {elapsed:.2f}s"))
    print()
    try:
        _read(fmt.dim("Press [ENTER] to return to the menu "))
    except _ExitRequested:
        raise


# ---------------------------------------------------------------------------
# rendering the single list
# ---------------------------------------------------------------------------
def _view_module_list(modules: List[Dict[str, Any]]) -> None:
    """Print every module as a full-width three-column picker grid.

    The columns split the ordered module list column-major (top→bottom in
    column one, then column two, ...) so 39 modules render as 13/13/13 and
    the whole menu covers the screen instead of scrolling one long column.
    """
    available = fmt.terminal_width()
    col_width = fmt.fit_width(available, cells=3)
    # Build cells "[NN] Title" truncated to the column width (numbers always
    # visible in full — that is what the user types).
    cells: List[str] = []
    for module in modules:
        number = fmt.green(f"[{int(module['number']):02d}]", bold=True)
        title = str(module["title"])
        # Width budget inside the cell after the number prefix.
        budget = max(4, col_width - 6)
        shown = title if len(title) <= budget else title[: max(1, budget - 1)] + "…"
        cells.append(f"{number} {fmt.white(shown, bold=True)}")

    columns = fmt.column_split(cells, 3)
    rows: List[List[str]] = []
    for row_index in range(max(len(col) for col in columns)):
        row: List[str] = []
        for col in columns:
            if row_index < len(col):
                row.append(col[row_index])
        rows.append(row)

    print()
    title_box = fmt.box([fmt.white("MODULES — ALL", bold=True)], accent=fmt._CYAN, bold=True)
    for line in title_box:
        print(line)
    print()
    for line in fmt.render_columns(rows, gap=2, min_width=col_width):
        print(line)
    print()
    hint = f"type a number (01–{len(modules):02d}) to run it   ·   [E]xit"
    print(fmt.white(hint, bold=True))
    print(fmt.dim("modules run with a live progress bar + step log"))


# ---------------------------------------------------------------------------
# the engine
# ---------------------------------------------------------------------------
def run(session: Session) -> None:
    """Start the menu state machine (blocks until the user exits)."""
    fmt.init_color()
    modules = _build_modules()

    while True:
        try:
            # ------------- MAIN_MENU (single flat list) -------------
            _print_banner()
            _session_line(session)
            _view_module_list(modules)

            choice = _read(fmt.cyan("talos > ", bold=True)).lower()

            if choice in ("e", "exit", "quit", "q"):
                break

            number = _parse_number(choice)
            module = _find_module(modules, number)
            if module is None:
                print(fmt.red(f"[x] Unknown module '{choice}'. Choose a number from the list."))
                print()
                continue

            # ---- MODULE_EXECUTION -> SHOW_RESULTS -> MAIN_MENU ----
            execute_module(session, module)
        except _ExitRequested:
            print(fmt.dim("\nInput stream closed — exiting cleanly."))
            return
        except KeyboardInterrupt:
            print(fmt.red("\n[x] Interrupted; press [E] to exit cleanly."))
            continue


def _parse_number(choice: str) -> Optional[int]:
    digits = choice.strip()
    if digits.isdigit() and 0 < int(digits) <= 999:
        return int(digits)
    return None


def _find_module(modules: List[Dict[str, Any]], number: Optional[int]) -> Optional[Dict[str, Any]]:
    if number is None:
        return None
    for module in modules:
        if int(module["number"]) == number:
            return module
    return None
