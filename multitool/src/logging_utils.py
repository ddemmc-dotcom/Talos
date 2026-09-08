"""Logging and structured audit-trail helpers.

Every module logs through :func:`get_logger`, which propagates to the root
logger backed by a :class:`RotatingFileHandler` writing ``logs/toolkit.log``.
Every finished :class:`~src.models.tool_result.ToolResult` is additionally
recorded as one JSON line in ``logs/audit.jsonl`` (its own rotating handler)
with a UTC timestamp and the originating module name.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional

from src.models.tool_result import ToolResult

# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).resolve().parents[1]
LOG_DIR: Path = PROJECT_ROOT / "logs"
TOOLKIT_LOG: Path = LOG_DIR / "toolkit.log"
AUDIT_LOG: Path = LOG_DIR / "audit.jsonl"

_TOOLKIT_MAX_BYTES = 5 * 1024 * 1024
_AUDIT_MAX_BYTES = 20 * 1024 * 1024
_BACKUP_COUNT = 5

_FORMATTER = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
_AUDIT_FORMATTER = logging.Formatter("%(message)s")

_configured = False


def _ensure_dirs() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def _install_file_handlers() -> None:
    """Attach the rotating file handlers exactly once per process."""
    global _configured
    if _configured:
        return
    _configured = True
    _ensure_dirs()

    root = logging.getLogger()
    if not any(isinstance(h, RotatingFileHandler) for h in root.handlers):
        handler = RotatingFileHandler(
            TOOLKIT_LOG,
            maxBytes=_TOOLKIT_MAX_BYTES,
            backupCount=_BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setFormatter(_FORMATTER)
        handler.setLevel(logging.INFO)
        root.addHandler(handler)
    root.setLevel(logging.INFO)

    audit_logger = logging.getLogger("toolkit.audit")
    if not any(isinstance(h, RotatingFileHandler) for h in audit_logger.handlers):
        handler = RotatingFileHandler(
            AUDIT_LOG,
            maxBytes=_AUDIT_MAX_BYTES,
            backupCount=_BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setFormatter(_AUDIT_FORMATTER)
        handler.setLevel(logging.INFO)
        audit_logger.addHandler(handler)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False


def get_logger(name: str) -> logging.Logger:
    """Return a module logger backed by the rotating file handler."""
    _install_file_handlers()
    return logging.getLogger(name)


def set_logging(verbose: bool = False) -> None:
    """Tune console verbosity. File logging (rotating) is always active."""
    _install_file_handlers()
    root = logging.getLogger()
    stream = next((h for h in root.handlers if isinstance(h, logging.StreamHandler)), None)
    if stream is None:
        stream = logging.StreamHandler()
        stream.setFormatter(_FORMATTER)
        root.addHandler(stream)
    stream.setLevel(logging.DEBUG if verbose else logging.WARNING)


def _clip(text: str, limit: int) -> tuple[str, bool]:
    """Clip ``text`` to ``limit`` chars; report whether it was truncated."""
    if len(text) <= limit:
        return text, False
    return text[:limit] + f"... [truncated {len(text) - limit} chars]", True


def audit(result: ToolResult, module: Optional[str] = None) -> None:
    """Append one JSON line for ``result`` to ``logs/audit.jsonl``.

    The record always contains the UTC timestamp and the module name; raw
    stdout/stderr are clipped so the audit file stays rotation-friendly.
    """
    _install_file_handlers()
    stdout, stdout_truncated = _clip(result.raw_stdout or "", 8000)
    stderr, stderr_truncated = _clip(result.raw_stderr or "", 4000)
    record: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "module": module or result.module,
        "status": result.status.value,
        "error_category": result.error_category.value
        if result.error_category is not None
        else None,
        "duration_ms": round(float(result.duration_ms or 0.0), 3),
        "data": result.data,
        "raw_stdout": stdout,
        "raw_stderr": stderr,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
    }
    try:
        line = json.dumps(record, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        line = json.dumps(
            {k: str(v) for k, v in record.items()}, default=str, ensure_ascii=False
        )
    logging.getLogger("toolkit.audit").info("%s", line)
