"""The universal result envelope produced by every tool invocation.

A :class:`ToolResult` travels from the low-level subprocess wrapper up to the
orchestrator, carrying both structured data and the raw tool output so that
failures can always be audited and debugged.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict

from src.errors.registry import ErrorCategory, ToolError


class ResultStatus(str, Enum):
    """Lifecycle states a tool run can end in.

    SUCCESS      - the tool ran and its output was fully consumed.
    PARTIAL      - the tool ran but part of its output was lost / degraded.
    ERROR        - the tool failed (bad input, tool error, auth failure...).
    TIMEOUT      - the tool was killed by the subprocess runner.
    UNAVAILABLE  - the backing service (e.g. the MSF RPC daemon) is unreachable.
    """

    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    UNAVAILABLE = "UNAVAILABLE"


class ToolResult(BaseModel):
    """Structured outcome of a single tool/module invocation."""

    model_config = ConfigDict(extra="forbid")

    status: ResultStatus = ResultStatus.SUCCESS
    data: Optional[Dict[str, Any]] = None
    raw_stdout: str = ""
    raw_stderr: str = ""
    duration_ms: float = 0.0
    error_category: Optional[ErrorCategory] = None
    module: str = "unknown"

    # ------------------------------------------------------------------
    # factories
    # ------------------------------------------------------------------
    @classmethod
    def success(
        cls,
        module: str,
        *,
        data: Optional[Dict[str, Any]] = None,
        raw_stdout: str = "",
        raw_stderr: str = "",
        duration_ms: float = 0.0,
    ) -> "ToolResult":
        return cls(
            status=ResultStatus.SUCCESS,
            module=module,
            data=data,
            raw_stdout=raw_stdout,
            raw_stderr=raw_stderr,
            duration_ms=duration_ms,
        )

    @classmethod
    def partial(
        cls,
        module: str,
        *,
        data: Optional[Dict[str, Any]] = None,
        raw_stdout: str = "",
        raw_stderr: str = "",
        duration_ms: float = 0.0,
        error_category: ErrorCategory = ErrorCategory.PARTIAL,
    ) -> "ToolResult":
        return cls(
            status=ResultStatus.PARTIAL,
            module=module,
            data=data,
            raw_stdout=raw_stdout,
            raw_stderr=raw_stderr,
            duration_ms=duration_ms,
            error_category=error_category,
        )

    @classmethod
    def failed(
        cls,
        module: str,
        message: str,
        *,
        category: Optional[ErrorCategory] = None,
        data: Optional[Dict[str, Any]] = None,
        raw_stdout: str = "",
        raw_stderr: str = "",
        duration_ms: float = 0.0,
    ) -> "ToolResult":
        """Build an ERROR result, merging ``message`` into ``data``."""
        payload: Dict[str, Any] = dict(data or {})
        payload.setdefault("error", message)
        return cls(
            status=_status_for_category(category),
            module=module,
            data=payload,
            raw_stdout=raw_stdout,
            raw_stderr=raw_stderr or message,
            duration_ms=duration_ms,
            error_category=category,
        )

    @classmethod
    def from_tool_error(
        cls,
        module: str,
        error: ToolError,
        *,
        raw_stdout: str = "",
        raw_stderr: str = "",
        duration_ms: float = 0.0,
        data: Optional[Dict[str, Any]] = None,
    ) -> "ToolResult":
        """Encode a :class:`ToolError` into a non-raising ToolResult.

        ``RESOURCE`` maps to ``UNAVAILABLE``, ``TIMEOUT`` maps to ``TIMEOUT``,
        and everything else maps to ``ERROR`` while preserving the category.
        """
        category = error.category
        payload: Dict[str, Any] = dict(data or {})
        payload.setdefault("error", error.message or str(error))
        return cls(
            status=_status_for_category(category),
            module=module,
            data=payload,
            raw_stdout=raw_stdout,
            raw_stderr=raw_stderr or str(error),
            duration_ms=duration_ms,
            error_category=category,
        )

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    @property
    def ok(self) -> bool:
        """True when the outcome is usable (SUCCESS or PARTIAL)."""
        return self.status in (ResultStatus.SUCCESS, ResultStatus.PARTIAL)

    @property
    def status_name(self) -> str:
        return self.status.value

    @property
    def category_name(self) -> str:
        return self.error_category.value if self.error_category is not None else ""


def _status_for_category(category: Optional[ErrorCategory]) -> ResultStatus:
    """Map an error category to the most descriptive overall status."""
    if category == ErrorCategory.TIMEOUT:
        return ResultStatus.TIMEOUT
    if category == ErrorCategory.RESOURCE:
        return ResultStatus.UNAVAILABLE
    if category == ErrorCategory.PARTIAL:
        return ResultStatus.PARTIAL
    return ResultStatus.ERROR
