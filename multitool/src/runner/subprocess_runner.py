"""Generic, hardened wrapper around every CLI tool the framework shells out to.

Guarantees:

* ``Popen`` + ``communicate(timeout=...)`` so every invocation is time-bounded.
* On ``TimeoutExpired`` the child is ``terminate()``-d, given one second to
  exit, then ``kill()``-d — zombie processes are never left behind.
* A ``try/finally`` guarantees the process handle and every pipe is released
  even when an unexpected exception escapes.
* Every ``ToolResult`` this runner produces is written to the audit trail.
"""
from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess
import time
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Union

from src.errors.registry import ErrorCategory, ToolError
from src.logging_utils import audit, get_logger
from src.models.tool_result import ResultStatus, ToolResult

_GRACE_SECONDS = 1.0
_REAP_TIMEOUT = 5.0


def _decode(data: Optional[Union[bytes, str]]) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


class SubprocessRunner:
    """Run one external CLI command to completion with strict resource hygiene."""

    def __init__(self, *, default_timeout: float = 120.0) -> None:
        self.default_timeout = float(default_timeout)
        self._logger: logging.Logger = get_logger("subprocess")

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------
    def run(
        self,
        executable: str,
        args: Optional[Sequence[Any]] = None,
        *,
        timeout: Optional[float] = None,
        cwd: Optional[str] = None,
        env: Optional[Mapping[str, str]] = None,
        input_text: Optional[str] = None,
    ) -> ToolResult:
        """Execute ``executable`` and return a fully-populated ToolResult.

        Raises:
            ToolError(category=MISSING): the executable cannot be located or started.
        """
        command = [executable] + [str(a) for a in (args or ())]
        effective_timeout = self.default_timeout if timeout is None else float(timeout)
        module_name = os.path.basename(executable)
        start = time.perf_counter()

        self._ensure_executable(executable)
        proc: Optional[subprocess.Popen] = None
        timed_out = False
        stdout = ""
        stderr = ""
        self._logger.debug(
            "exec: %s (timeout=%.1fs)", " ".join(command), effective_timeout
        )
        try:
            try:
                proc = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    cwd=cwd,
                    env=dict(env) if env is not None else None,
                    start_new_session=True,
                )
            except (OSError, ValueError) as exc:
                raise ToolError(
                    f"failed to start {executable!r}: {exc}",
                    category=ErrorCategory.MISSING,
                    module=module_name,
                    cause=exc,
                ) from exc

            # The timeout handling mandated by the design:
            # TimeoutExpired -> terminate() -> wait 1s -> kill().
            try:
                stdout, stderr = proc.communicate(input=input_text, timeout=effective_timeout)
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                stdout = _decode(getattr(exc, "output", None))
                self._logger.warning(
                    "%s timed out after %.1fs — terminating pid %d",
                    executable,
                    effective_timeout,
                    proc.pid,
                )
                self._hard_stop(proc)
                tail_out, tail_err = self._drain(proc)
                stdout = (stdout + tail_out) if stdout else tail_out
                stderr = tail_err
                stderr += (
                    f"\n[runner] {executable} was terminated after "
                    f"{effective_timeout}s and then killed.\n"
                )
            returncode = proc.returncode
        finally:
            # try/finally: the handle and pipes are always released.
            if proc is not None and proc.poll() is None:
                self._logger.warning("%s still alive after run; force-stopping", executable)
                self._hard_stop(proc)
            for stream in (proc.stdout, proc.stderr, proc.stdin):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass

        duration_ms = (time.perf_counter() - start) * 1000.0
        if timed_out:
            result = ToolResult(
                status=ResultStatus.TIMEOUT,
                module=module_name,
                data={"returncode": None, "timeout_s": effective_timeout},
                raw_stdout=stdout,
                raw_stderr=stderr,
                duration_ms=duration_ms,
                error_category=ErrorCategory.TIMEOUT,
            )
        elif returncode == 0:
            result = ToolResult(
                status=ResultStatus.SUCCESS,
                module=module_name,
                data={"returncode": 0},
                raw_stdout=stdout,
                raw_stderr=stderr,
                duration_ms=duration_ms,
            )
        else:
            result = ToolResult(
                status=ResultStatus.ERROR,
                module=module_name,
                data={"returncode": returncode, "command": " ".join(command)},
                raw_stdout=stdout,
                raw_stderr=stderr,
                duration_ms=duration_ms,
            )
        audit(result, module=f"{module_name}@subprocess")
        return result

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------
    @staticmethod
    def _ensure_executable(executable: str) -> None:
        if os.path.sep in executable or os.path.isabs(executable):
            if not os.path.isfile(executable) or not os.access(executable, os.X_OK):
                raise ToolError(
                    f"executable is not runnable: {executable!r}",
                    category=ErrorCategory.MISSING,
                    module=os.path.basename(executable),
                )
            return
        if shutil.which(executable) is None:
            raise ToolError(
                f"executable not found on PATH: {executable!r}. Install it via "
                "your OS package manager or adjust PATH.",
                category=ErrorCategory.MISSING,
                module=executable,
            )

    @staticmethod
    def _hard_stop(proc: subprocess.Popen) -> None:
        """terminate() -> wait 1s -> kill(), then reap the whole process group."""
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
        except OSError:
            pass
        try:
            proc.wait(timeout=_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass
        except Exception:  # pragma: no cover - defensive
            pass
        try:
            proc.wait(timeout=_REAP_TIMEOUT)
        except Exception:  # pragma: no cover - defensive
            pass
        # Children of start_new_session=True live in their own process group;
        # kill the group so nothing lingers as a zombie or orphan.
        killpg = getattr(os, "killpg", None)
        if killpg is not None and hasattr(signal, "SIGKILL"):
            try:
                killpg(proc.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass

    @staticmethod
    def _drain(proc: subprocess.Popen) -> tuple[str, str]:
        """Read whatever a (now dead) process left in its pipes."""
        out = ""
        err = ""
        for stream in (proc.stdout, proc.stderr):
            if stream is None:
                continue
            try:
                data = stream.read()
                out = data if stream is proc.stdout else out
                err = data if stream is proc.stderr else err
            except (OSError, ValueError):
                continue
        return _decode(out), _decode(err)
