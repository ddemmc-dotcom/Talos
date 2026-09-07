"""The orchestrator: module discovery, immutable Context, safe execution.

Responsibilities
----------------
* discover every tool module under ``src/modules`` at startup;
* preflight each module with ``validate_environment()`` (never crashing when
  a binary/service is missing — that surfaces as a ``ToolResult``);
* maintain an **immutable Context** dictionary: modules only ever receive a
  ``copy.deepcopy()`` of the current context, and the authoritative copy is
  replaced wholesale on commit — never mutated in place;
* validate module writes: if a module writes keys outside the allow-list (or
  raises ``KeyError``), the orchestrator reverts to the previous snapshot;
* audit every returned ``ToolResult`` to ``logs/audit.jsonl``.
"""
from __future__ import annotations

import copy
import logging
import pkgutil
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Type

from src.errors.registry import ErrorCategory, ToolError
from src.logging_utils import audit, get_logger
from src.models.tool_result import ResultStatus, ToolResult


class BaseModule(ABC):
    """Contract implemented by every tool module."""

    NAME: str = ""
    DESCRIPTION: str = ""

    def __init__(self) -> None:
        self._progress: Any = None

    # ------------------------------------------------------------------
    # progress reporting (runner-provided sink)
    # ------------------------------------------------------------------
    def set_progress_sink(self, sink: Any) -> None:
        """Attach a ``sink(message=None, fraction=None)`` callable.

        Long-running modules call :meth:`report_progress` at stage boundaries;
        with no sink attached the calls are harmless no-ops (the module never
        imports UI code).  The TUI attaches a thread-safe sink, the CLI and
        the standalone scripts attach :func:`src.core.progress.cli_sink`.
        """
        self._progress = sink

    def report_progress(
        self, message: Optional[str] = None, fraction: Optional[float] = None
    ) -> None:
        """Emit one progress event: a step log and/or a live-bar fraction.

        ``fraction`` is 0..1 when the module can measure real progress (e.g.
        credentials tested), ``None`` when the stage is indeterminate (e.g.
        an nmap subprocess is running).
        """
        if self._progress is not None:
            try:
                self._progress(message, fraction)
            except Exception:  # pragma: no cover - a broken sink never kills
                pass

    @classmethod
    @abstractmethod
    def validate_environment(cls) -> None:
        """Raise ToolError(MISSING) when a required binary/service is absent."""

    @abstractmethod
    def run(self, context: Dict[str, Any]) -> ToolResult:
        """Execute against a deep copy of the orchestrator Context.

        The module may mutate the copy it receives (publishing results,
        sessions, ...) but may only touch top-level keys in
        :attr:`Orchestrator.ALLOWED_CONTEXT_KEYS`.
        """

    @property
    def logger(self) -> logging.Logger:
        return get_logger(self.NAME or self.__class__.__name__)


class Orchestrator:
    """Engine that owns the Context and executes modules safely."""

    #: Top-level keys a module is allowed to write into the Context.
    ALLOWED_CONTEXT_KEYS = frozenset(
        {"target", "ports", "options", "results", "session", "state"}
    )

    def __init__(self, *, discover: bool = True) -> None:
        self._logger = get_logger("orchestrator")
        self._context: Dict[str, Any] = {"results": {}}
        self.modules: Dict[str, Type[BaseModule]] = {}
        if discover:
            self.load_modules()

    # ------------------------------------------------------------------
    # context access
    # ------------------------------------------------------------------
    @property
    def context(self) -> Dict[str, Any]:
        """Read-only snapshot of the current Context (defensive copy)."""
        return copy.deepcopy(self._context)

    # ------------------------------------------------------------------
    # discovery
    # ------------------------------------------------------------------
    def load_modules(self) -> List[str]:
        """Import every module under ``src.modules`` and register subclasses."""
        from src import modules as modules_pkg

        found: Dict[str, Type[BaseModule]] = {}
        for _finder, name, _is_pkg in pkgutil.iter_modules(modules_pkg.__path__):
            if name.startswith("_"):
                continue
            try:
                imported = __import__(
                    f"{modules_pkg.__name__}.{name}", fromlist=[name]
                )
            except Exception as exc:  # a broken module must not break discovery
                self._logger.warning("skipping module package %r: %s", name, exc)
                continue
            for value in vars(imported).values():
                if (
                    isinstance(value, type)
                    and issubclass(value, BaseModule)
                    and value is not BaseModule
                    and value.NAME
                ):
                    found.setdefault(value.NAME, value)
        self.modules.update(found)
        self._logger.info(
            "loaded %d module(s): %s", len(found), ", ".join(sorted(found)) or "(none)"
        )
        return sorted(found)

    def module_names(self) -> List[str]:
        return sorted(self.modules)

    # ------------------------------------------------------------------
    # execution
    # ------------------------------------------------------------------
    def execute(
        self,
        module_name: str,
        *,
        progress_sink: Any = None,
        **params: Any,
    ) -> ToolResult:
        """Run a module against the current Context snapshot.

        ``progress_sink`` (optional) is attached to the module instance so
        long-running modules can report step logs / bar fractions through
        ``BaseModule.report_progress`` (see :mod:`src.core.progress`).

        Never raises for tool-level failures: every path returns a
        :class:`ToolResult` (audited before returning).
        """
        module_cls = self.modules.get(module_name)
        if module_cls is None:
            known = ", ".join(self.module_names()) or "(none)"
            result = ToolResult.failed(
                module_name,
                f"unknown module {module_name!r}; available modules: {known}",
                category=ErrorCategory.MISSING,
            )
            audit(result, module_name)
            return result

        invalid_params = sorted(k for k in params if k not in self.ALLOWED_CONTEXT_KEYS)
        if invalid_params:
            result = ToolResult.failed(
                module_name,
                f"parameters use keys outside the Context allow-list: "
                f"{', '.join(invalid_params)}",
                category=ErrorCategory.PARSE,
            )
            audit(result, module_name)
            return result

        # 1) Environment preflight — a MISSING dependency is logged, not fatal.
        try:
            module_cls.validate_environment()
        except ToolError as exc:
            self._logger.error("module %s unavailable: %s", module_name, exc)
            result = ToolResult.from_tool_error(module_name, exc)
            audit(result, module_name)
            return result
        except Exception as exc:
            self._logger.exception("validate_environment() crashed for %s", module_name)
            result = ToolResult.failed(
                module_name,
                f"environment validation failed unexpectedly: {exc!r}",
                category=ErrorCategory.RESOURCE,
            )
            audit(result, module_name)
            return result

        # 2) Immutable-context discipline: snapshot + deep copy for the module.
        snapshot = copy.deepcopy(self._context)
        work_context = copy.deepcopy(snapshot)
        work_context.update(params)

        self._logger.info("executing module=%s", module_name)
        module = module_cls()
        if progress_sink is not None:
            module.set_progress_sink(progress_sink)
        try:
            result = module.run(work_context)
        except KeyError as exc:
            # A module touched a key that does not exist -> revert to snapshot.
            self._logger.error(
                "module %s raised KeyError (%s); reverting Context to previous snapshot",
                module_name,
                exc,
            )
            result = ToolResult.failed(
                module_name,
                f"module fault: context key {exc} was missing; Context reverted",
                category=ErrorCategory.PARSE,
            )
            audit(result, module_name)
            return result
        except ToolError as exc:
            self._logger.error("module %s failed: %s", module_name, exc)
            result = ToolResult.from_tool_error(module_name, exc)
            audit(result, module_name)
            return result
        except Exception as exc:
            self._logger.exception("module %s crashed", module_name)
            result = ToolResult.failed(
                module_name,
                f"unexpected module failure: {exc!r}",
                category=ErrorCategory.RESOURCE,
            )
            audit(result, module_name)
            return result

        if not isinstance(result, ToolResult):
            result = ToolResult.failed(
                module_name,
                f"module returned {type(result).__name__}, not a ToolResult",
                category=ErrorCategory.RESOURCE,
            )
            audit(result, module_name)
            return result

        # 3) Validate the module's writes to the Context.
        added_keys = set(work_context).difference(snapshot)
        removed_keys = set(snapshot).difference(work_context)
        invalid_added = added_keys.difference(self.ALLOWED_CONTEXT_KEYS)
        if invalid_added or removed_keys:
            self._logger.error(
                "module %s wrote invalid Context keys (added=%s, removed=%s); "
                "reverting to previous snapshot",
                module_name,
                sorted(invalid_added) or "-",
                sorted(removed_keys) or "-",
            )
            result = result.model_copy(
                update={
                    "data": {
                        **(result.data or {}),
                        "context_reverted": True,
                        "context_invalid_keys": sorted(invalid_added),
                    }
                }
            )
        else:
            # Commit: the authoritative Context is *replaced*, never mutated.
            self._context = work_context

        audit(result, module_name)
        self._logger.info(
            "module=%s finished status=%s duration_ms=%.1f",
            module_name,
            result.status.value,
            result.duration_ms,
        )
        return result
