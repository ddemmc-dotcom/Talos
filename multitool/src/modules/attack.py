"""TALOS — ATTACK MODULES (36-38).

Two new engine modules plus menu wrappers that share one engine with the
terminal UI and the standalone ``scripts/`` runners:

* ``nmap_vuln``       — Nmap vulnerability scan using the NSE ``vuln``
  script family (and any other NSE script the user picks).
* ``http_bruteforce`` — credential testing against HTTP Basic auth or an
  HTML login form, driven by username/password wordlists, rate-limited and
  capped so it stays a controlled, authorised assessment tool.
* ``metasploit``      — already provided by ``src.modules.metasploit_wrapper``;
  the ``menu_metasploit`` wrapper below makes it reachable from the CLI menu.

Every module returns a structured :class:`ToolResult` (rendered into the
detailed report by :mod:`src.core.report`) and never prints from the engine
classes, so the same code powers the menu, the TUI and the scripts.
"""
from __future__ import annotations

import html
import difflib
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from src.core import formatting as fmt
from src.core import progress
from src.core import report
from src.core.context import Session
from src.errors.registry import ErrorCategory, ToolError
from src.models.tool_result import ToolResult
from src.modules.metasploit_wrapper import MetasploitModule
from src.modules.nmap_wrapper import NmapModule
from src.orchestrator import BaseModule

_USER_AGENT = (
    "Mozilla/5.0 (compatible; TALOS/3.0; +https://example.invalid/talos)"
)

#: Small, honest built-in fallback list — only used when the user runs the
#: brute-forcer without pointing it at a wordlist file.
DEFAULT_WEAK_PASSWORDS: List[str] = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball",
    "abc123", "football", "monkey", "letmein", "shadow", "master",
    "666666", "qwertyuiop", "123321", "mustang", "1234567890", "admin",
]

_MAX_ATTEMPTS = 5000
_MAX_WORDLIST_LINES = 200_000


# ---------------------------------------------------------------------------
# helpers shared by the engine + wrappers
# ---------------------------------------------------------------------------
def _import_requests():
    try:
        import requests  # noqa: PLC0415
    except ImportError as exc:
        raise ToolError(
            "the 'requests' library is not installed. Run: "
            f"{sys.executable} -m pip install requests",
            category=ErrorCategory.MISSING,
            module="http_bruteforce",
        ) from exc
    return requests


def _read_list_option(value: Any) -> Optional[List[str]]:
    """Normalise a users/passwords option to a list of non-empty strings."""
    if value is None:
        return None
    if isinstance(value, str):
        parts = [part.strip() for part in value.splitlines()]
        return [part for part in parts if part]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return None


def _load_lines(path: str, limit: int = _MAX_WORDLIST_LINES) -> List[str]:
    """Read one word/phrase per line from ``path`` (deduplicated)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines = [ln.strip() for ln in handle if ln.strip()]
    except OSError as exc:
        raise ToolError(
            f"could not read wordlist file {path!r}: {exc}",
            category=ErrorCategory.PARSE,
            module="http_bruteforce",
        ) from exc
    if len(lines) > limit:
        lines = lines[:limit]
    seen = set()
    unique: List[str] = []
    for line in lines:
        if line not in seen:
            seen.add(line)
            unique.append(line)
    return unique


def _seconds_since(start: float) -> float:
    return time.perf_counter() - start


def _extract_hidden_fields(page: str, skip: set) -> Dict[str, str]:
    """Pull CSRF/anti-forgery tokens out of a login form's hidden inputs.

    Real-world login forms (Django, Laravel, Rails, ASP.NET, Express-CSRF,
    ...) reject POSTs that lack the hidden token they rendered into the
    form. A brute-forcer that never fetches the form will get a 100 %
    failure rate on those sites; fetching the page once and replaying its
    hidden fields is what hydra/patator-style tools do.
    """
    found: Dict[str, str] = {}
    for tag in re.findall(r"<input\b[^>]*>", page, re.IGNORECASE):
        attrs = {k.lower(): v for k, v in re.findall(
            r'([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]*)',
            tag,
        )}
        field_type = (attrs.get("type", "text") or "").strip("\"'")
        if field_type.lower() != "hidden":
            continue
        name = (attrs.get("name") or "").strip("\"'")
        if not name or name in skip:
            continue
        value = (attrs.get("value") or "").strip("\"'")
        found[name] = html.unescape(value)
    return found


def _form_action(page: str) -> str:
    """The ``action`` of the first <form> in the page ('' when absent)."""
    for tag in re.findall(r"<form\b[^>]*>", page, re.IGNORECASE):
        m = re.search(r"action\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]*)", tag, re.IGNORECASE)
        if m:
            action = m.group(1).strip("\"'")
            if action and action not in ("#", "javascript:void(0)"):
                return html.unescape(action)
        return ""  # <form> without an action posts to the current URL
    return ""


def _same_page(a: str, b: str) -> bool:
    """Do two URLs point at the same path (ignoring query strings) ?"""
    pa, pb = urlparse(a), urlparse(b)
    return (pa.netloc, pa.path.rstrip("/")) == (pb.netloc, pb.path.rstrip("/"))


# ===========================================================================
# 37 — Nmap vulnerability scan (NSE --script)
# ===========================================================================
class NmapVulnModule(NmapModule):
    """Nmap scan with the NSE vulnerability script family enabled."""

    NAME = "nmap_vuln"
    DESCRIPTION = (
        "Nmap vulnerability scan (NSE --script vuln) — detects known "
        "vulnerabilities on reachable services"
    )

    def run(self, context: Dict[str, Any]) -> ToolResult:
        options = dict(context.get("options") or {})
        scripts = str(options.get("nse_scripts") or "vuln")
        extra_args = [str(a) for a in (options.get("extra_args") or [])]
        merged = ["--script", scripts, *extra_args]
        enriched = dict(context)
        enriched["options"] = {**options, "extra_args": merged}
        result = super().run(enriched)
        if result.ok and isinstance(result.data, dict):
            hosts = result.data.get("hosts") or []
            script_hits = 0
            vulnerability_candidates = 0
            for host in hosts:
                host_scripts = host.get("host_scripts") or []
                script_hits += len(host_scripts)
                vulnerability_candidates += sum(
                    _looks_vulnerable_script(item) for item in host_scripts
                )
                for port in host.get("ports") or []:
                    scripts_on_port = port.get("scripts") or []
                    script_hits += len(scripts_on_port)
                    vulnerability_candidates += sum(
                        _looks_vulnerable_script(item) for item in scripts_on_port
                    )
            result = result.model_copy(
                update={"data": {
                    **result.data,
                    "scripts": str(scripts),
                    "script_hits": script_hits,
                    "vulnerability_candidates": vulnerability_candidates,
                    "finding_quality": "candidate" if vulnerability_candidates else "informational",
                }}
            )
        return result


def _looks_vulnerable_script(script: Dict[str, Any]) -> bool:
    """Recognize explicit NSE vulnerability language, not arbitrary output."""
    text = str(script.get("output", "")).lower()
    if re.search(r"\b(?:not|no)\s+(?:known\s+)?vulnerable\b|state:\s*not\s+vulnerable|not affected", text):
        return False
    return bool(re.search(r"\b(vulnerable|state:\s*vulnerable|cve-\d{4}-\d+|vuln)\b", text))


# ===========================================================================
# 36 — HTTP login brute-forcer (Basic auth / HTML form)
# ===========================================================================
class HttpBruteforceModule(BaseModule):
    """Credential testing against HTTP Basic auth or an HTML login form.

    Reads ``context``:

    * ``target`` / ``options.url``   — the login URL (required)
    * ``options.mode``               — ``basic`` (default) or ``form``
    * ``options.user``               — single username, or
    * ``options.users``              — inline list, or
    * ``options.users_file``         — path, one username per line
    * ``options.passwords_file``     — path, one password per line
      (when omitted a small built-in weak-password list is used)
    * ``options.passwords``          — inline list of passwords
    * ``options.delay``              — seconds to sleep between attempts (default 0.05)
    * ``options.timeout``            — per-request timeout (default 8)
    * ``options.stop_on_found``      — stop at the first confirmed hit (default true)
    * form only:
    * ``options.user_field``         — name of the username form field (default ``username``)
    * ``options.pass_field``         — name of the password form field (default ``password``)
    * ``options.extra_fields``       — extra KEY=VALUE pairs submitted with the form
    * ``options.success_marker``     — text that only appears after a successful login
    * ``options.fail_marker``        — text that marks a failed login attempt

    The run is strictly rate-limited, sequential, capped at
    ``_MAX_ATTEMPTS`` and — for ``form`` mode without markers — reports hits
    as *possible* rather than claiming a confirmed login.
    """

    NAME = "http_bruteforce"
    DESCRIPTION = (
        "HTTP login brute-forcer — wordlist credential testing against "
        "Basic auth or HTML login forms (rate-limited)"
    )

    # ------------------------------------------------------------------
    @classmethod
    def validate_environment(cls) -> None:
        _import_requests()

    # ------------------------------------------------------------------
    def run(self, context: Dict[str, Any]) -> ToolResult:
        start = time.perf_counter()
        try:
            return self._run_inner(context, start)
        except ToolError as exc:
            return ToolResult.from_tool_error(
                self.NAME, exc, duration_ms=_seconds_since(start) * 1000.0
            )
        except Exception as exc:  # defensive — never crash the orchestrator
            return ToolResult.failed(
                self.NAME,
                f"unexpected brute-force failure: {exc!r}",
                category=ErrorCategory.RESOURCE,
                duration_ms=_seconds_since(start) * 1000.0,
            )

    # ------------------------------------------------------------------
    def _run_inner(self, context: Dict[str, Any], start: float) -> ToolResult:
        options = dict(context.get("options") or {})
        # An explicit options.url wins over the shared context target (a
        # previous scan may have left target=host in the orchestrator context).
        url = str(options.get("url") or context.get("target") or "").strip()
        if not url:
            raise ToolError(
                "a login URL is required (set the target or options.url)",
                category=ErrorCategory.PARSE,
                module=self.NAME,
            )
        if "://" not in url:
            url = f"https://{url}"
        mode = str(options.get("mode") or "basic").strip().lower()
        if mode not in ("basic", "form"):
            raise ToolError(
                f"mode must be 'basic' or 'form', got {mode!r}",
                category=ErrorCategory.PARSE,
                module=self.NAME,
            )

        # ---- credential sources --------------------------------------
        users: Optional[List[str]] = None
        users_file = options.get("users_file")
        if users_file:
            users = _load_lines(str(users_file))
        if users is None:
            users = _read_list_option(options.get("user") or options.get("users"))
        if not users:
            raise ToolError(
                "no usernames given — set options.user / options.users or "
                "options.users_file",
                category=ErrorCategory.PARSE,
                module=self.NAME,
            )

        passwords_file = options.get("passwords_file")
        if passwords_file:
            passwords = _load_lines(str(passwords_file))
            wordlist_label = f"file: {passwords_file}"
        else:
            passwords = _read_list_option(options.get("passwords"))
            if passwords:
                wordlist_label = f"inline list ({len(passwords)} entries)"
            else:
                wordlist_label = "built-in default weak-password list"
        if not passwords:
            passwords = list(DEFAULT_WEAK_PASSWORDS)
        passwords = [p for p in passwords if p]

        try:
            delay = max(0.0, float(options.get("delay") or 0.05))
        except (TypeError, ValueError):
            delay = 0.05
        try:
            timeout = max(1.0, float(options.get("timeout") or 8.0))
        except (TypeError, ValueError):
            timeout = 8.0
        stop_on_found = _as_bool(options.get("stop_on_found", True))

        found: List[Dict[str, str]] = []
        attempts = 0
        errors = 0
        total = min(len(users) * len(passwords), _MAX_ATTEMPTS)
        self.report_progress(
            f"credential testing against {url} ({mode} mode) — "
            f"{len(users)} user(s) × {len(passwords)} password(s)",
            0.0,
        )

        if mode == "basic":
            result = self._brute_basic(
                url, users, passwords, delay, timeout, stop_on_found, found
            )
        else:
            result = self._brute_form(url, users, passwords, options, delay, timeout,
                                      stop_on_found, found)
        attempts, errors = result

        data: Dict[str, Any] = {
            "url": url,
            "mode": mode,
            "users": ", ".join(users[:6]) + (" …" if len(users) > 6 else ""),
            "user_count": len(users),
            "wordlist": wordlist_label,
            "password_count": len(passwords),
            "attempts": attempts,
            "found": found,
            "errors": errors,
        }
        if "built-in" in wordlist_label:
            data["note"] = "no wordlist file supplied — used the small built-in fallback list"
        if errors:
            data["note"] = " ".join(
                filter(None, [data.get("note"), f"{errors} request(s) failed (network/HTTP error)."])
            )
        if mode == "form" and not (options.get("success_marker") or options.get("fail_marker")):
            data["note"] = " ".join(
                filter(
                    None,
                    [data.get("note"),
                     "no success/fail markers configured — form hits are reported as 'possible', verify manually"],
                )
            )
        return ToolResult.success(
            self.NAME, data=data, duration_ms=_seconds_since(start) * 1000.0
        )

    # ------------------------------------------------------------------
    def _brute_basic(
        self,
        url: str,
        users: List[str],
        passwords: List[str],
        delay: float,
        timeout: float,
        stop_on_found: bool,
        found: List[Dict[str, str]],
    ) -> Tuple[int, int]:
        requests = _import_requests()
        attempts = 0
        errors = 0
        total = max(1, min(len(users) * len(passwords), _MAX_ATTEMPTS))
        session = requests.Session()
        session.headers.update({"User-Agent": _USER_AGENT})
        for user in users:
            for password in passwords:
                if attempts >= _MAX_ATTEMPTS:
                    return attempts, errors
                attempts += 1
                self._emit_brute_progress(user, password, attempts, total)
                try:
                    response = session.get(
                        url, auth=(user, password), timeout=timeout, allow_redirects=True
                    )
                except requests.exceptions.RequestException:
                    errors += 1
                    if delay:
                        time.sleep(delay)
                    continue
                code = response.status_code
                if code == 401:
                    pass  # wrong credentials — keep going
                elif 200 <= code < 400:
                    found.append(
                        {
                            "username": user,
                            "password": password,
                            "confidence": "candidate",
                            "detail": f"candidate — HTTP {code} (Basic auth did not return 401; verify with an authenticated resource)",
                        }
                    )
                    self.report_progress(
                        f"candidate: {user}:{password} returned HTTP {code}; verify access", 1.0
                    )
                    # Basic auth without an authenticated-resource check is
                    # only a candidate; never stop on an unverified result.
                else:
                    errors += 1
                if delay:
                    time.sleep(delay)
        return attempts, errors

    def _brute_form(
        self,
        url: str,
        users: List[str],
        passwords: List[str],
        options: Dict[str, Any],
        delay: float,
        timeout: float,
        stop_on_found: bool,
        found: List[Dict[str, str]],
    ) -> Tuple[int, int]:
        requests = _import_requests()
        user_field = str(options.get("user_field") or "username")
        pass_field = str(options.get("pass_field") or "password")
        success_marker = str(options.get("success_marker") or "")
        fail_marker = str(options.get("fail_marker") or "")
        extra_fields: Dict[str, str] = {}
        for token in (options.get("extra_fields") or "").split(","):
            token = token.strip()
            if "=" in token:
                key, _, value = token.partition("=")
                extra_fields[key.strip()] = value.strip()
        attempts = 0
        errors = 0
        total = max(1, min(len(users) * len(passwords), _MAX_ATTEMPTS))
        session = requests.Session()
        session.headers.update({"User-Agent": _USER_AGENT})
        post_url = url
        failure_body: Optional[str] = None

        # ---- preflight: fetch the login page once, like a real browser ----
        # This captures session cookies, the hidden CSRF/anti-forgery token
        # (many frameworks reject POSTs without it) and the real form
        # ``action`` when it differs from the page URL.
        login_text = ""
        try:
            page = session.get(url, timeout=timeout, allow_redirects=True)
            if page.status_code == 200 and page.url:
                post_url = page.url  # follow any redirect the form lives at
                login_text = page.text or ""
                hidden = _extract_hidden_fields(login_text, skip={user_field, pass_field})
                for key, value in hidden.items():
                    extra_fields.setdefault(key, value)
                action = _form_action(login_text)
                if action:
                    post_url = urljoin(post_url, action)
        except requests.exceptions.RequestException:
            pass  # preflight is best-effort; attempts still run

        for user in users:
            for password in passwords:
                if attempts >= _MAX_ATTEMPTS:
                    return attempts, errors
                attempts += 1
                self._emit_brute_progress(user, password, attempts, total)
                payload: Dict[str, str] = {
                    user_field: user,
                    pass_field: password,
                    **extra_fields,
                }
                try:
                    response = session.post(post_url, data=payload, timeout=timeout,
                                            allow_redirects=True)
                except requests.exceptions.RequestException:
                    errors += 1
                    if delay:
                        time.sleep(delay)
                    continue
                body = response.text or ""
                page_changed, change_ratio = _page_changed(body, login_text, pass_field)
                failure_page_changed = page_changed
                if not success_marker and not fail_marker:
                    if failure_body is None:
                        # The first markerless response establishes the
                        # application's ordinary failed-login page. A 200
                        # response is never a finding by itself.
                        failure_body = body
                        failure_page_changed = False
                    else:
                        failure_page_changed = page_changed and _page_similarity(failure_body, body) < 0.85
                # Redirects and HTTP 200 responses are not enough: failed
                # login handlers commonly use both. Require a page change
                # from both the login page and the ordinary failure page.
                redirected = not _same_page(post_url, response.url or post_url)
                if fail_marker and fail_marker in body:
                    pass  # explicit failure — keep going
                elif success_marker and success_marker in body:
                    found.append(
                        {
                            "username": user,
                            "password": password,
                            "confidence": "confirmed",
                            "detail": "success marker matched on the response page",
                        }
                    )
                    self.report_progress(
                        f"hit! {user}:{password} — success marker matched", 1.0
                    )
                    if stop_on_found:
                        return attempts, errors
                elif success_marker:
                    pass  # marker configured but not present -> failed attempt
                elif fail_marker:
                    pass  # fail marker configured but absent -> inconclusive
                elif redirected and failure_page_changed:
                    found.append(
                        {
                            "username": user,
                            "password": password,
                            "confidence": "candidate",
                            "detail": (f"candidate — redirected to {response.url} and response page changed "
                                       f"(similarity {change_ratio:.0%}; verify authenticated access)"),
                        }
                    )
                    self.report_progress(
                        f"candidate: {user}:{password} (redirect + page change)", 1.0
                    )
                elif response.ok and failure_page_changed:
                    found.append(
                        {
                            "username": user,
                            "password": password,
                            "confidence": "candidate",
                            "detail": (f"candidate — HTTP {response.status_code} response page changed "
                                       f"(similarity {change_ratio:.0%}; verify authenticated access)"),
                        }
                    )
                    self.report_progress(
                        f"candidate: {user}:{password} (page changed)", 1.0
                    )
                elif response.ok:
                    # An unchanged HTTP 200 login page is a failed attempt.
                    pass
                else:
                    errors += 1
                if delay:
                    time.sleep(delay)
        return attempts, errors


    def _emit_brute_progress(
        self, user: str, password: str, attempts: int, total: int
    ) -> None:
        """Report brute-force progress, throttling messages to ~2 % steps."""
        fraction = min(1.0, attempts / total)
        last = getattr(self, "_last_brute_frac", -1.0)
        if fraction - last >= 0.02 or fraction >= 1.0:
            self._last_brute_frac = fraction
            self.report_progress(
                f"trying {user}:{password} ({attempts}/{total})", fraction
            )
        else:
            self.report_progress(None, fraction)


def _looks_like_same_form(body: str, login_text: str, pass_field: str) -> bool:
    """Is ``body`` the same login form page (i.e. the login failed) ?

    Without success/fail markers the strongest available signal is page
    identity: a failed attempt re-renders the identical login form (it still
    contains the password field and is about the same length), while a real
    post-login page looks different.
    """
    if not login_text or not body:
        return False
    if pass_field not in body:
        return False
    size_delta = abs(len(body) - len(login_text))
    return size_delta < max(200, int(len(login_text) * 0.2))


def _page_changed(body: str, login_text: str, pass_field: str) -> Tuple[bool, float]:
    """Require a material response-page change before reporting a candidate."""
    if not body or not login_text:
        return False, 1.0
    if _looks_like_same_form(body, login_text, pass_field):
        return False, 1.0
    similarity = _page_similarity(login_text, body)
    # A changed error page can still be HTTP 200. Require the login password
    # field to disappear before treating a markerless response as a candidate.
    return pass_field not in body and similarity < 0.95, similarity


def _page_similarity(first: str, second: str) -> float:
    """Compare page text after removing formatting-only differences."""
    first_normalized = re.sub(r"\s+", " ", first).strip().lower()
    second_normalized = re.sub(r"\s+", " ", second).strip().lower()
    return difflib.SequenceMatcher(
        None, first_normalized, second_normalized, autojunk=False
    ).ratio()


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in ("1", "true", "yes", "on", "y")


# ===========================================================================
# CLI menu wrappers (prompt-driven, render the shared report)
# ===========================================================================
def _ask(prompt: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    try:
        return input(f"  {prompt}{suffix}: ").strip() or (default or "")
    except EOFError:
        return default or ""


def _run_and_report(session: Session, module, context: Dict[str, Any]) -> None:
    """Validate, run an engine module and print its shared report."""
    try:
        module.validate_environment()
    except ToolError as exc:
        print(fmt.tag_error(str(exc)))
        print(fmt.tag_warn(f"module unavailable ({exc.category_name}). Nothing was run."))
        return
    started = time.perf_counter()
    instance = module()
    instance.set_progress_sink(progress.cli_sink)
    result = instance.run(context)
    progress.clear_cli_line()
    elapsed = time.perf_counter() - started
    report.print_result(result)
    print(fmt.dim(f"  elapsed: {elapsed:.2f}s   status: {result.status.value}"))
    if result.ok:
        data = result.data or {}
        session.set_result(module.NAME, data)
        print(fmt.tag_ok(f"Result stored in the session as '{module.NAME}'."))
    print()


def menu_nmap_vuln(session: Session) -> None:
    """CLI wrapper — Nmap NSE vulnerability scan (module 37)."""
    print("  Runs nmap with the NSE 'vuln' script family against a target.")
    print("  Requires the nmap binary. Slow scans need a longer timeout.")
    print()
    target = _ask("Target (host / IP / CIDR)", session.target_ip or session.target_domain or "")
    if not target:
        print(fmt.tag_error("No target given; aborting the scan."))
        return
    ports = _ask("Ports (comma separated, optional)", "")
    scripts = _ask("NSE scripts (default: vuln)", "vuln")
    try:
        timeout = float(_ask("Timeout in seconds", "600"))
    except ValueError:
        timeout = 600.0
    options: Dict[str, Any] = {
        "nse_scripts": scripts,
        "extra_args": [],
        "timeout": timeout,
    }
    context: Dict[str, Any] = {"target": target, "options": options}
    if ports:
        context["ports"] = ports
    if not _looks_like_url(target) and _is_single_token(target):
        session.target_ip = target
    _run_and_report(session, NmapVulnModule, context)


def menu_http_bruteforce(session: Session) -> None:
    """CLI wrapper — HTTP login brute-forcer (module 36)."""
    print("  Wordlist credential testing against an HTTP login.")
    print("  Basic auth: accurate. Form login: needs success/fail markers")
    print("  to confirm a hit (otherwise reported as 'possible').")
    print("  Use it ONLY on systems you are authorised to test.")
    print()
    default_url = ""
    if session.target_domain:
        default_url = f"https://{session.target_domain}"
    url = _ask("Login URL", default_url)
    if not url:
        print(fmt.tag_error("No login URL given; aborting."))
        return
    mode = _ask("Mode (basic / form)", "basic").strip().lower()
    if mode not in ("basic", "form"):
        print(fmt.tag_error("Mode must be 'basic' or 'form'."))
        return
    users = _ask("Username (or path to a username list file)", "")
    if not users:
        print(fmt.tag_error("A username or username list is required."))
        return
    passwords_file = _ask("Password wordlist file (empty = small built-in list)", "")
    if os_path_exists(passwords_file) is False and passwords_file:
        print(fmt.tag_warn(f"Cannot read wordlist {passwords_file!r}; using the built-in list."))
        passwords_file = ""
    if mode == "form":
        success_marker = _ask("Success marker (text only on the post-login page, optional)", "")
        fail_marker = _ask("Fail marker (text on the login-failed page, optional)", "")
    else:
        success_marker = fail_marker = ""
    try:
        delay = float(_ask("Delay between attempts in seconds (0 = none)", "0.1"))
    except ValueError:
        delay = 0.1
    options: Dict[str, Any] = {
        "url": url,
        "mode": mode,
        "delay": delay,
        "timeout": 8.0,
        "stop_on_found": True,
    }
    if "\n" in users or os_path_exists(users):
        options["users_file"] = users
    else:
        options["user"] = users
    if passwords_file:
        options["passwords_file"] = passwords_file
    if success_marker:
        options["success_marker"] = success_marker
    if fail_marker:
        options["fail_marker"] = fail_marker
    print()
    _run_and_report(session, HttpBruteforceModule, {"options": options})


def menu_metasploit(session: Session) -> None:
    """CLI wrapper — run a Metasploit module through msfrpcd (module 38)."""
    print("  Executes a Metasploit module via the RPC daemon (msfrpcd).")
    print("  Start it first, e.g.:  msfrpcd -P <password> -a 127.0.0.1 -p 55553")
    print()
    target = _ask("Target (optional — wired into RHOSTS)", session.target_ip or "")
    module_type = _ask("Module type (auxiliary / exploit / post)", "auxiliary").strip().lower()
    module_name = _ask("Module path (e.g. scanner/portscan/tcp)", "")
    if not module_name:
        print(fmt.tag_error("A Metasploit module path is required."))
        return
    payload = _ask("Payload (optional)", "")
    raw_options = _ask("Datastore options (KEY=VALUE, comma separated, optional)", "")
    datastore: Dict[str, str] = {}
    for token in raw_options.split(","):
        token = token.strip()
        if "=" in token:
            key, _, value = token.partition("=")
            datastore[key.strip()] = value.strip()
    options: Dict[str, Any] = {
        "msf_type": module_type,
        "msf_module": module_name,
        "msf_options": datastore,
    }
    if payload:
        options["payload"] = payload
    context: Dict[str, Any] = {"options": options}
    if target:
        context["target"] = target
    print()
    _run_and_report(session, MetasploitModule, context)


def os_path_exists(path: str) -> bool:
    return os.path.isfile(path)


def _looks_like_url(target: str) -> bool:
    return "://" in target


def _is_single_token(target: str) -> bool:
    return bool(target) and " " not in target
