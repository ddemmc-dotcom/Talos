"""Metasploit RPC integration module (via ``pymetasploit3`` -> ``msfrpcd``).

Hardening rules implemented here:

* **Ping check** — every attempt calls ``client.call("core.version")`` before
  ``client.modules.execute(...)``, so dead daemons are detected early.
* **Retry with exponential backoff** — ``ConnectionRefusedError`` and
  ``xmlrpc.client.ProtocolError`` (plus socket timeouts) trigger up to **2**
  retries with backoff (1s, 2s). When they are exhausted the module returns a
  ``ToolResult`` with ``status="UNAVAILABLE"`` instead of raising.
* **Auth failures** are caught and mapped to ``ERROR`` / ``AUTH``.
* All RPC connectivity is configured through environment variables
  (``MSF_RPC_HOST`` / ``MSF_RPC_PORT`` / ``MSF_RPC_PASSWORD`` /
  ``MSF_RPC_SSL``), which may live in a ``.env`` file loaded by
  ``python-dotenv``.
"""
from __future__ import annotations

import os
import socket
import time
import xmlrpc.client
from typing import Any, Dict, Optional, Tuple, Type

from src.errors.registry import ErrorCategory, ToolError
from src.logging_utils import get_logger
from src.models.tool_result import ResultStatus, ToolResult
from src.orchestrator import BaseModule

_MAX_RETRIES = 2
_BACKOFF_BASE_SECONDS = 1.0
_SOCKET_PROBE_TIMEOUT = 2.0
_RPC_CALL_TIMEOUT = 30.0

_ENV_HOST = "MSF_RPC_HOST"
_ENV_PORT = "MSF_RPC_PORT"
_ENV_PASSWORD = "MSF_RPC_PASSWORD"
_ENV_SSL = "MSF_RPC_SSL"


class MetasploitModule(BaseModule):
    """Run auxiliary/exploit/post modules through the Metasploit RPC API."""

    NAME = "metasploit"
    DESCRIPTION = "Auxiliary/exploit execution via the Metasploit RPC daemon (msfrpcd)"

    # ------------------------------------------------------------------
    # environment
    # ------------------------------------------------------------------
    @classmethod
    def validate_environment(cls) -> None:
        """Raise ToolError(MISSING) if the RPC prerequisites are not met."""
        cls._load_msf_libs()
        host = os.environ.get(_ENV_HOST, "127.0.0.1").strip() or "127.0.0.1"
        port = int(os.environ.get(_ENV_PORT, "55553"))
        if not (os.environ.get(_ENV_PASSWORD) or "").strip():
            raise ToolError(
                f"{_ENV_PASSWORD} is not set. Start the RPC daemon with "
                "'msfrpcd -P <password> -a 127.0.0.1 -p 55553' and export "
                f"{_ENV_PASSWORD}=<password> (or put it in a .env file).",
                category=ErrorCategory.MISSING,
                module=cls.NAME,
            )
        # Probe the RPC socket without sending any RPC traffic.
        try:
            with socket.create_connection((host, port), timeout=_SOCKET_PROBE_TIMEOUT):
                pass
        except OSError as exc:
            raise ToolError(
                f"Metasploit RPC daemon unreachable at {host}:{port} ({exc}). "
                "Start it with: msfrpcd -P <password> -a 127.0.0.1 -p 55553",
                category=ErrorCategory.MISSING,
                module=cls.NAME,
            ) from exc

    # ------------------------------------------------------------------
    # execution
    # ------------------------------------------------------------------
    def run(self, context: Dict[str, Any]) -> ToolResult:
        start = time.perf_counter()
        self._maybe_load_dotenv()

        target = context.get("target")
        ports = context.get("ports")
        options = dict(context.get("options") or {})

        module_type = str(options.get("msf_type") or "auxiliary")
        module_name = str(options.get("msf_module") or "").strip()
        user_options = dict(options.get("msf_options") or {})
        payload = options.get("payload")

        if not module_name:
            return ToolResult.failed(
                self.NAME,
                "metasploit run requires options['msf_module'] (e.g. "
                "scanner/portscan/tcp) and options['msf_type']",
                category=ErrorCategory.PARSE,
                duration_ms=_elapsed_ms(start),
            )

        try:
            host, port, ssl, password = self._rpc_config()
        except ToolError as exc:
            return ToolResult.from_tool_error(
                self.NAME, exc, duration_ms=_elapsed_ms(start)
            )

        datastore: Dict[str, Any] = {str(k): str(v) for k, v in user_options.items()}
        # Sensible auto-wiring — explicit user options always win.
        if "RHOSTS" not in datastore and target:
            datastore["RHOSTS"] = str(target)
        if "PORTS" not in datastore and ports and "portscan" in module_name.lower():
            datastore["PORTS"] = str(ports)
        if "Payload" not in datastore and payload:
            datastore["Payload"] = str(payload)

        try:
            outcome = self._execute_rpc(
                host=host,
                port=port,
                ssl=ssl,
                password=password,
                module_type=module_type,
                module_name=module_name,
                datastore=datastore,
            )
        except ToolError as exc:
            # Retries exhausted (UNAVAILABLE) or auth failure (ERROR/AUTH).
            return ToolResult.from_tool_error(
                self.NAME, exc, duration_ms=_elapsed_ms(start)
            )
        except Exception as exc:  # xmlrpc Faults, module errors, API drift...
            self.logger.exception("metasploit RPC call failed unexpectedly")
            return ToolResult.failed(
                self.NAME,
                f"metasploit RPC call failed: {exc}",
                data={"module": module_name, "module_type": module_type},
                duration_ms=_elapsed_ms(start),
            )

        self.report_progress(
            f"module {module_type}/{module_name} finished (job id {outcome.get('job_id', 0)})",
            1.0,
        )
        data: Dict[str, Any] = {
            "module": module_name,
            "module_type": module_type,
            "datastore": datastore,
            "job_id": outcome.get("job_id", 0),
        }
        response_text = str(outcome.get("res") or "")
        if len(response_text) > 4000:
            data["response_truncated"] = True
            data["response"] = response_text[:4000] + "... [truncated]"
        elif response_text:
            data["response"] = response_text

        result = ToolResult.success(
            self.NAME,
            data=data,
            raw_stdout=response_text,
            duration_ms=_elapsed_ms(start),
        )
        if outcome.get("job_id"):
            session = context.setdefault("session", {})
            session.setdefault("metasploit", {})["last_run"] = {
                "module": module_name,
                "module_type": module_type,
                "job_id": outcome["job_id"],
                "started_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
        return result

    # ------------------------------------------------------------------
    # RPC internals
    # ------------------------------------------------------------------
    @staticmethod
    def _maybe_load_dotenv() -> None:
        try:
            from dotenv import load_dotenv

            load_dotenv()
        except Exception:
            pass  # .env support is best-effort

    @classmethod
    def _rpc_config(cls) -> Tuple[str, int, bool, str]:
        host = os.environ.get(_ENV_HOST, "127.0.0.1").strip() or "127.0.0.1"
        port = int(os.environ.get(_ENV_PORT, "55553"))
        ssl = os.environ.get(_ENV_SSL, "").strip().lower() in ("1", "true", "yes", "on")
        password = (os.environ.get(_ENV_PASSWORD) or "").strip()
        if not password:
            raise ToolError(
                f"{_ENV_PASSWORD} is not set; start msfrpcd and export it.",
                category=ErrorCategory.MISSING,
                module=cls.NAME,
            )
        return host, port, ssl, password

    @staticmethod
    def _load_msf_libs() -> Tuple[Type, Type]:
        """Import pymetasploit3 lazily so the module stays importable without it."""
        try:
            from pymetasploit3.msfrpc import MsfAuthError, MsfRpcClient
        except ImportError as exc:
            raise ToolError(
                "pymetasploit3 is not installed. Install dependencies with: "
                "pip install -r requirements.txt",
                category=ErrorCategory.MISSING,
                module="metasploit",
            ) from exc
        return MsfRpcClient, MsfAuthError

    def _execute_rpc(
        self,
        *,
        host: str,
        port: int,
        ssl: bool,
        password: str,
        module_type: str,
        module_name: str,
        datastore: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Ping-checked execute with exponential backoff (max 2 retries)."""
        client_cls, auth_error_cls = self._load_msf_libs()
        retryable = (
            ConnectionRefusedError,
            xmlrpc.client.ProtocolError,
            OSError,
            TimeoutError,
        )
        last_error: Optional[BaseException] = None

        for attempt in range(_MAX_RETRIES + 1):
            client = None
            try:
                self.report_progress(
                    f"connecting to Metasploit RPC at {host}:{port} "
                    f"(attempt {attempt + 1}/{_MAX_RETRIES + 1})",
                    0.2 + attempt * 0.1,
                )
                client = self._connect(
                    client_cls, auth_error_cls, host, port, ssl, password
                )
                # Ping check: never reach modules.execute() against a dead daemon.
                self.report_progress("daemon reachable — executing module", 0.6)
                client.call("core.version")
                return self._invoke_module(client, module_type, module_name, datastore)
            except auth_error_cls as exc:
                raise ToolError(
                    f"Metasploit RPC authentication failed: {exc}",
                    category=ErrorCategory.AUTH,
                    module=self.NAME,
                    cause=exc,
                ) from exc
            except retryable as exc:
                last_error = exc
                if attempt >= _MAX_RETRIES:
                    break
                delay = _BACKOFF_BASE_SECONDS * (2 ** attempt)
                self.report_progress(
                    f"RPC attempt {attempt + 1} failed ({type(exc).__name__}); "
                    f"retrying in {delay:.1f}s",
                    None,
                )
                self.logger.warning(
                    "metasploit RPC attempt %d/%d failed (%s); retrying in %.1fs",
                    attempt + 1,
                    _MAX_RETRIES + 1,
                    exc,
                    delay,
                )
                time.sleep(delay)
            finally:
                self._disconnect(client)

        category = ErrorCategory.TIMEOUT if isinstance(
            last_error, TimeoutError
        ) else ErrorCategory.RESOURCE
        raise ToolError(
            f"Metasploit RPC unreachable after {_MAX_RETRIES} retries "
            f"({host}:{port}): {last_error}",
            category=category,
            module=self.NAME,
            cause=last_error,
        )

    @staticmethod
    def _connect(
        client_cls: Type,
        auth_error_cls: Type,
        host: str,
        port: int,
        ssl: bool,
        password: str,
    ):
        """Build an MsfRpcClient, tolerating constructor signature drift."""
        kwargs: Dict[str, Any] = {"server": host, "port": int(port), "timeout": _RPC_CALL_TIMEOUT}
        if ssl:
            kwargs["ssl"] = True
        try:
            return client_cls(password, **kwargs)
        except TypeError:
            kwargs.pop("timeout", None)
            try:
                return client_cls(password, **kwargs)
            except TypeError:
                # oldest pymetasploit3 builds only take (password, server, port)
                return client_cls(password, host, int(port))

    @staticmethod
    def _invoke_module(
        client, module_type: str, module_name: str, datastore: Dict[str, Any]
    ) -> Dict[str, Any]:
        """client.modules.execute(), falling back to use()+execute() on API drift."""
        modules = getattr(client, "modules", None)
        if modules is None:
            raise ToolError(
                "RPC client exposes no 'modules' API",
                category=ErrorCategory.RESOURCE,
                module="metasploit",
            )
        direct = getattr(modules, "execute", None)
        if callable(direct):
            try:
                result = direct(module_type, module_name, datastore or {})
                if isinstance(result, dict):
                    return result
            except TypeError:
                pass  # signature differs from expectations — try the classic path
        mod = modules.use(module_type, module_name)
        result = mod.execute(datastore or {})
        return result if isinstance(result, dict) else {"res": str(result)}

    @staticmethod
    def _disconnect(client) -> None:
        """Best-effort logout; never raises."""
        if client is None:
            return
        try:
            token = getattr(client, "token", None)
            if token:
                client.call("auth.logout", [token])
        except Exception:
            pass


def _elapsed_ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000.0
