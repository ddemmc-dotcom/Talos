"""Persistent session context for the TALOS multi-tool.

One :class:`Session` lives for the whole menu run and carries the data a user
sets (target IP / domain) plus a results dictionary that lets modules pass
data to each other.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


class Session:
    """Mutable, single-owner context shared by every menu module."""

    def __init__(self, name: str = "talos") -> None:
        self._name: str = name
        self._target_ip: Optional[str] = None
        self._target_domain: Optional[str] = None
        self._scan_results: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # identity
    # ------------------------------------------------------------------
    @property
    def name(self) -> str:
        return self._name

    # ------------------------------------------------------------------
    # target ip
    # ------------------------------------------------------------------
    @property
    def target_ip(self) -> Optional[str]:
        """The currently selected target IP/host, or None."""
        return self._target_ip

    @target_ip.setter
    def target_ip(self, value: Optional[str]) -> None:
        value = (value or "").strip()
        self._target_ip = value or None

    # ------------------------------------------------------------------
    # target domain
    # ------------------------------------------------------------------
    @property
    def target_domain(self) -> Optional[str]:
        """The currently selected target domain, or None."""
        return self._target_domain

    @target_domain.setter
    def target_domain(self, value: Optional[str]) -> None:
        value = (value or "").strip()
        self._target_domain = value or None

    # ------------------------------------------------------------------
    # scan results (module-to-module hand-off)
    # ------------------------------------------------------------------
    @property
    def scan_results(self) -> Dict[str, Any]:
        """Shared results dictionary (modules may read and write it)."""
        return self._scan_results

    def set_result(self, key: str, value: Any) -> None:
        self._scan_results[key] = value

    def get_result(self, key: str, default: Any = None) -> Any:
        return self._scan_results.get(key, default)

    def clear_results(self) -> None:
        self._scan_results.clear()

    # ------------------------------------------------------------------
    # presentation helpers
    # ------------------------------------------------------------------
    def summary(self) -> List[str]:
        """Short lines describing the session, shown under the menu header."""
        lines = [
            f"session    : {self._name}",
            f"target ip  : {self._target_ip or '-'}",
            f"target dom : {self._target_domain or '-'}",
            f"result sets: {len(self._scan_results)}",
        ]
        return lines

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"Session(name={self._name!r}, target_ip={self._target_ip!r}, "
            f"target_domain={self._target_domain!r}, "
            f"scan_results={sorted(self._scan_results)!r})"
        )
