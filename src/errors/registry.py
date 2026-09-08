"""Central error taxonomy shared by every module of the framework.

Every failure is expressed as a :class:`ToolError` carrying one of the six
canonical :class:`ErrorCategory` values, so the orchestrator can catch,
log, audit, and continue instead of crashing.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional


class ErrorCategory(str, Enum):
    """The exact set of error categories understood by the orchestrator.

    MISSING    - a required binary, python package, or configuration value is absent.
    TIMEOUT    - an operation exceeded its allowed wall-clock time.
    PARSE      - tool output could not be parsed into structured data.
    AUTH       - authentication / authorization to a remote service failed.
    RESOURCE   - an external resource (RPC daemon, socket, host) is unavailable.
    PARTIAL    - the operation succeeded only partially.
    """

    MISSING = "MISSING"
    TIMEOUT = "TIMEOUT"
    PARSE = "PARSE"
    AUTH = "AUTH"
    RESOURCE = "RESOURCE"
    PARTIAL = "PARTIAL"


class ToolError(Exception):
    """Base exception for the entire codebase.

    Modules raise ``ToolError`` (never raw exceptions) so callers can rely on
    a stable, categorised failure contract. ``cause`` optionally chains the
    original exception for traceability in logs.
    """

    def __init__(
        self,
        message: str,
        category: ErrorCategory | str | None = None,
        *,
        module: Optional[str] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(message)
        self.message: str = str(message)
        self.category: Optional[ErrorCategory] = (
            ErrorCategory(category) if category is not None else None
        )
        self.module: Optional[str] = module
        self.cause: Optional[BaseException] = cause

    @property
    def category_name(self) -> str:
        """Human-readable category, falling back to ``UNKNOWN``."""
        return self.category.value if self.category is not None else "UNKNOWN"

    def __str__(self) -> str:
        prefix = f"[{self.category_name}]"
        suffix = f" ({self.module})" if self.module else ""
        return f"{prefix}{suffix} {self.message}"
