#!/usr/bin/env python3
"""TALOS self-test — exercises every module and reports PASS/FAIL/SKIP.

Two layers are verified:

1. **Engine modules** (the orchestrator's ``BaseModule`` classes — nmap,
   nmap_vuln, http_bruteforce, metasploit) run for real:
   * ``nmap`` / ``nmap_vuln``  — quick scans against 127.0.0.1
   * ``http_bruteforce``       — Basic-auth AND form-login attacks against a
     local mock HTTP server (no external network needed)
   * ``metasploit``            — expected to degrade gracefully to a
     ``ToolResult`` when no ``msfrpcd`` daemon is running
   Every engine is also exercised through the **Orchestrator** (the exact
   path the TUI and scripts use), so context validation + auditing are
   covered too.

2. **CLI menu modules** (the 40 functions behind the numbered menu) are each
   driven with a scripted answer stream (real targets for scanners/finders,
   meaningful inputs for the utilities) while stdout is captured. A module
   PASSes when it completes without an uncaught exception; network hiccups
   that the module handles gracefully still PASS (that is correct behaviour).

Exit codes: 0 = no failures, 1 = at least one module FAILed, 2 = usage error.
Modules whose backing binary/service is absent are reported SKIP, never FAIL.

    python3 scripts/self_test.py          # full run (needs network for menu tier)
    python3 scripts/self_test.py --no-net # skip internet-only menu modules
"""
from __future__ import annotations

import builtins
import contextlib
import io
import os
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.core.table import print_table  # noqa: E402
from src.models.tool_result import ToolResult  # noqa: E402

_RESULTS: List[Tuple[str, str, str]] = []  # (layer, name, verdict)
_FAILURES: List[Tuple[str, str, str]] = []  # (name, verdict, reason)


def _record(layer: str, name: str, verdict: str, reason: str = "") -> None:
    _RESULTS.append((layer, name, verdict))
    if verdict == "FAIL":
        _FAILURES.append((name, verdict, reason))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
class _AnswerFeeder:
    """Drop-in ``input()`` replacement: answers in order, then EOFError."""

    def __init__(self, answers: List[str]) -> None:
        self._queue: List[str] = list(answers)

    def __call__(self, prompt: str = "") -> str:
        sys.stdout.write(prompt)
        sys.stdout.flush()
        if self._queue:
            return self._queue.pop(0)
        raise EOFError


@contextlib.contextmanager
def _patched_input(answers: List[str]):
    original = builtins.input
    builtins.input = _AnswerFeeder(answers)
    try:
        yield
    finally:
        builtins.input = original


def _run_menu_function(
    func: Callable,
    answers: List[str],
    *,
    timeout: float = 45.0,
) -> Tuple[bool, str]:
    """Run one menu module with scripted stdin; capture all output."""
    from src.core.context import Session

    out = io.StringIO()
    result_holder: Dict[str, Any] = {}
    error_holder: Dict[str, Any] = {}

    def worker() -> None:
        try:
            with _patched_input(answers):
                with contextlib.redirect_stdout(out):
                    func(Session(name="selftest"))
            result_holder["ok"] = True
        except BaseException as exc:  # noqa: BLE001 - a crash is a FAIL
            error_holder["exc"] = exc
            result_holder["ok"] = False

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        return False, "timed out after %.0fs" % timeout
    if not result_holder.get("ok"):
        exc = error_holder.get("exc")
        return False, f"{type(exc).__name__}: {exc}" if exc else "module raised"
    return True, ""


# ---------------------------------------------------------------------------
# tier 1: engines (real runs)
# ---------------------------------------------------------------------------
def _run_engine_tests() -> None:
    from src.orchestrator import Orchestrator
    from src.errors.registry import ToolError

    orch = Orchestrator(discover=True)

    # --- nmap on localhost (fast, no external net) ---
    if "nmap" in orch.modules:
        try:
            result: ToolResult = orch.execute(
                "nmap", target="127.0.0.1", ports="22,80", options={"timeout": 60}
            )
            ok = isinstance(result, ToolResult) and result.ok
            _record(
                "engine",
                "nmap (localhost, via orchestrator)",
                "PASS" if ok else "FAIL",
                "" if ok else f"status={result.status.value}",
            )
        except Exception as exc:  # noqa: BLE001
            _record("engine", "nmap (localhost, via orchestrator)", "FAIL", str(exc))
    else:
        _record("engine", "nmap", "SKIP", "module not discovered")

    # --- nmap_vuln (script=version, still fast) ---
    if "nmap_vuln" in orch.modules:
        try:
            result = orch.execute(
                "nmap_vuln",
                target="127.0.0.1",
                ports="22",
                options={"nse_scripts": "http-title", "timeout": 90},
            )
            ok = isinstance(result, ToolResult) and result.ok
            _record(
                "engine",
                "nmap_vuln (localhost, --script http-title)",
                "PASS" if ok else "FAIL",
                "" if ok else f"status={result.status.value}",
            )
        except Exception as exc:  # noqa: BLE001
            _record("engine", "nmap_vuln", "FAIL", str(exc))
    else:
        _record("engine", "nmap_vuln", "SKIP", "module not discovered")

    # --- auto_audit: read-only audit on localhost (fast, no NSE) ---
    if "auto_audit" in orch.modules:
        try:
            result = orch.execute(
                "auto_audit",
                target="127.0.0.1",
                ports="22,80",
                options={"os_detect": False, "nse_scripts": "", "timeout": 90},
            )
            ok = (
                isinstance(result, ToolResult)
                and result.ok
                and isinstance((result.data or {}).get("findings"), list)
                and isinstance((result.data or {}).get("summary"), dict)
            )
            _record(
                "engine",
                "auto_audit (localhost, via orchestrator)",
                "PASS" if ok else "FAIL",
                "" if ok else f"status={result.status.value}",
            )
        except Exception as exc:  # noqa: BLE001
            _record("engine", "auto_audit (localhost, via orchestrator)", "FAIL", str(exc))
    else:
        _record("engine", "auto_audit", "SKIP", "module not discovered")

    # --- http_bruteforce: local mock servers (Basic + form) ---
    for mode, answers_extra in (
        ("basic", {"user": "admin", "passwords": ["letmein", "wrong"]}),
        ("form", {"user": "admin", "passwords": ["wrong", "letmein"],
                  "user_field": "username", "pass_field": "password"}),
    ):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import base64
        import threading as _t

        class _Handler(BaseHTTPRequestHandler):
            def _check(self) -> bool:
                if mode == "basic":
                    expected = "Basic " + base64.b64encode(b"admin:letmein").decode()
                    return self.headers.get("Authorization") == expected
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode("utf-8", "replace")
                return "username=admin" in body and "password=letmein" in body

            def do_GET(self):  # noqa: N802
                if mode == "form-page-change":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"<form><input name='username'><input name='password'></form>")
                    return
                if self._check():
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"welcome back")
                else:
                    self.send_response(401)
                    self.end_headers()

            def do_POST(self):  # noqa: N802
                if mode == "form-page-change":
                    length = int(self.headers.get("Content-Length", 0))
                    body = self.rfile.read(length).decode("utf-8", "replace")
                    self.send_response(200)
                    self.end_headers()
                    if "password=letmein" in body:
                        self.wfile.write(b"<h1>Dashboard</h1><p>Welcome authenticated user</p>")
                    else:
                        self.wfile.write(b"<form><input name='username'><input name='password'></form>")
                    return
                if self._check():
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"welcome back")
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"invalid login")

            def log_message(self, *args: Any) -> None:  # silence
                pass

        server = HTTPServer(("127.0.0.1", 0), _Handler)
        _t.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{server.server_port}/login"
        options: Dict[str, Any] = {
            "url": url,
            "mode": mode,
            "delay": 0.0,
            "timeout": 5,
            "stop_on_found": True,
            "user": "admin",
        }
        options.update({k: v for k, v in answers_extra.items() if k != "user"})
        if mode == "form":
            options["success_marker"] = "welcome back"
            options["fail_marker"] = "invalid login"
        try:
            result = orch.execute("http_bruteforce", options=options)
            found = len((result.data or {}).get("found") or []) if result.ok else 0
            ok = isinstance(result, ToolResult) and result.ok and found == 1
            _record(
                "engine",
                f"http_bruteforce {mode} (mock server)",
                "PASS" if ok else "FAIL",
                "" if ok else f"status={result.status.value}, found={found}",
            )
        except Exception as exc:  # noqa: BLE001
            _record("engine", f"http_bruteforce {mode}", "FAIL", str(exc))
        finally:
            server.shutdown()

    # Regression: both wrong and correct form submissions return HTTP 200;
    # only the successful response changes the page.
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class _PageChangeHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<form><input name='username'><input name='password'></form>")

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", "replace")
            self.send_response(200)
            self.end_headers()
            if "password=letmein" in body:
                self.wfile.write(b"<h1>Dashboard</h1><p>Welcome authenticated user</p>")
            else:
                self.wfile.write(b"<h1>Login failed</h1><p>Try again</p>")

        def log_message(self, *args: Any) -> None:  # silence
            pass

    server = HTTPServer(("127.0.0.1", 0), _PageChangeHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        result = orch.execute(
            "http_bruteforce",
            options={
                "url": f"http://127.0.0.1:{server.server_port}/login",
                "mode": "form",
                "delay": 0.0,
                "timeout": 5,
                "stop_on_found": True,
                "user": "admin",
                "passwords": ["wrong", "also-wrong", "letmein"],
            },
        )
        found = (result.data or {}).get("found") or []
        ok = (
            isinstance(result, ToolResult)
            and result.ok
            and (result.data or {}).get("attempts") == 3
            and len(found) == 1
            and found[0].get("password") == "letmein"
            and found[0].get("confidence") == "candidate"
        )
        _record(
            "engine",
            "http_bruteforce form (page-change detection)",
            "PASS" if ok else "FAIL",
            "" if ok else f"status={result.status.value}, found={found}",
        )
    except Exception as exc:  # noqa: BLE001
        _record("engine", "http_bruteforce form (page-change detection)", "FAIL", str(exc))
    finally:
        server.shutdown()

    # --- metasploit: graceful degradation when no daemon is present ---
    if "metasploit" in orch.modules:
        try:
            result = orch.execute(
                "metasploit", options={"msf_type": "auxiliary", "msf_module": "scanner/portscan/tcp"}
            )
            if not isinstance(result, ToolResult):
                _record("engine", "metasploit (no daemon)", "FAIL", "no ToolResult")
            elif result.ok:
                _record("engine", "metasploit (no daemon)", "PASS",
                        "daemon unexpectedly reachable — module ran")
            else:
                _record("engine", "metasploit (no daemon)", "PASS",
                        "degraded cleanly → " + result.status.value)
        except Exception as exc:  # noqa: BLE001
            _record("engine", "metasploit (no daemon)", "FAIL", str(exc))
    else:
        _record("engine", "metasploit", "SKIP", "module not discovered")


# ---------------------------------------------------------------------------
# tier 2: CLI menu modules (40)
# ---------------------------------------------------------------------------
# Answers are keyed by exact menu title. Modules absent from this map get an
# empty stream (EOF) which they must handle gracefully — a clean "no target /
# aborted" exit still PASSes as long as nothing crashes.
_MENU_ANSWERS: Dict[str, List[str]] = {
    "Show My IP": [],
    "IP Scanner (Ping Sweep)": ["127.0.0.1"],
    "IP Pinger (RTT / TTL)": ["127.0.0.1"],
    "IP Port Scanner": ["127.0.0.1", "22,80"],
    "Port Banner Grabber": ["127.0.0.1", "22"],
    "SSL/TLS Certificate Checker": ["example.com", "443"],
    "HTTP Security Headers": ["https://example.com"],
    "Website Info Scanner": ["example.com"],
    "DNS Lookup": ["example.com"],
    "Traceroute": ["127.0.0.1"],
    "IP Geolocation Lookup": ["8.8.8.8"],
    "Ping Flood Test (safe)": ["127.0.0.1", "5"],
    "Username Tracker": ["talos_selftest_user_404"],
    "Subdomain Finder (wordlist)": ["example.com", ""],
    "Email / Contact Finder": ["https://example.com"],
    "Phone Number Lookup": ["+15551234567"],
    "Metadata Extractor": ["https://example.com"],
    "HTTP Method Tester": ["https://example.com"],
    "VHOST Scanner": ["example.com", "www,admin,dev"],
    "Web Directory Bruteforcer": ["https://example.com", "robots.txt,sitemap.xml,admin"],
    "Whois Lookup (RDAP)": ["example.com"],
    "Certificate Transparency Lookup": ["example.com"],
    "Reverse DNS Lookup": ["8.8.8.8"],
    "Wayback Machine Lookup": ["https://example.com"],
    "Email Header Analyzer": [],  # EOF ends the paste loop cleanly
    "DNS Zone Transfer Check": ["example.com"],
    "Open Port Finder (fast)": ["127.0.0.1", "22,80"],
    "Password Generator": ["16"],
    "Hash Generator": ["hello", "sha256"],
    "WAF Detection": ["https://example.com"],
    "JWT Token Analyzer": ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJleHAiOjE3MDAwMDAwMDB9.c2lnbmF0dXJl"],
    "HTTP/2 & Deprecated TLS Checker": ["example.com", "443"],
    "Leaked Credential Checker": ["selftest@example.com"],
    "Timestamp Converter": ["ts2date", "1700000000"],
    "Subdomain Takeover Checker": ["www.example.com,does-not-exist.example.com"],
    "Session / Target Manager": ["4", "e"],
    # Attacking modules are menu *wrappers* around the engines already tested
    # above; feed EOF so they abort cleanly without launching real attacks.
    "HTTP Login Brute-Forcer": [],
    "Nmap Vulnerability Scan": [],
    "Auto Vulnerability Audit": ["127.0.0.1", "22,80", "n", "", "60"],
    "Metasploit Module Runner": [],
    # Interactive: the wrapper spawns a hosting terminal only in a real
    # TTY session; under the scripted run it prints the manual command
    # instead, so the answers just cover the configuration prompts.
    "Data Scraper": ["8123", "https://example.com", "n", "n", "n"],
}

#: internet-dependent titles that get skipped under --no-net
_NET_ONLY_TITLES = {
    "Show My IP", "SSL/TLS Certificate Checker", "HTTP Security Headers",
    "Website Info Scanner", "DNS Lookup", "IP Geolocation Lookup",
    "Username Tracker", "Subdomain Finder (wordlist)", "Email / Contact Finder",
    "Phone Number Lookup", "Metadata Extractor", "Whois Lookup (RDAP)",
    "Certificate Transparency Lookup", "Reverse DNS Lookup",
    "Wayback Machine Lookup", "HTTP Method Tester", "VHOST Scanner",
    "Web Directory Bruteforcer", "WAF Detection", "HTTP/2 & Deprecated TLS Checker",
    "DNS Zone Transfer Check", "Subdomain Takeover Checker",
}


def _run_menu_module_tests(no_net: bool) -> None:
    from src.core.menu import _build_modules

    modules = _build_modules()
    if not modules:
        _record("menu", "catalog", "FAIL", "no modules discovered")
        return
    _record("menu", "catalog", "PASS", f"{len(modules)} module(s) registered")
    for module in modules:
        title = str(module["title"])
        func = module["func"]
        answers = _MENU_ANSWERS.get(title, [])
        if no_net and title in _NET_ONLY_TITLES:
            _record("menu", f"{int(module['number']):02d} {title}", "SKIP", "needs network (--no-net)")
            continue
        ok, reason = _run_menu_function(func, answers)
        _record("menu", f"{int(module['number']):02d} {title}", "PASS" if ok else "FAIL", reason)


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------
def _print_report() -> int:
    print()
    print("=" * 78)
    print("  TALOS self-test report")
    print("=" * 78)
    counts: Dict[str, int] = {"PASS": 0, "FAIL": 0, "SKIP": 0}
    for _layer, _name, verdict in _RESULTS:
        counts[verdict] = counts.get(verdict, 0) + 1
    rows: List[Tuple[str, str, str]] = []
    for layer, name, verdict in _RESULTS:
        rows.append((layer, name, verdict))
    print_table(["layer", "module", "verdict"], rows)
    print()
    print_table(
        ["summary", "count"],
        [("PASS", counts["PASS"]), ("FAIL", counts["FAIL"]), ("SKIP", counts["SKIP"]),
         ("total", len(_RESULTS))],
    )
    if _FAILURES:
        print()
        print("  failures:")
        for name, _verdict, reason in _FAILURES:
            print(f"    [x] {name}: {reason}")
    print()
    return 1 if _FAILURES else 0


def main(argv: Optional[List[str]] = None) -> int:
    no_net = "--no-net" in (argv or sys.argv[1:])
    started = time.perf_counter()
    _run_engine_tests()
    _run_menu_module_tests(no_net)
    elapsed = time.perf_counter() - started
    print(f"\n  self-test finished in {elapsed:.1f}s")
    return _print_report()


if __name__ == "__main__":
    sys.exit(main())
