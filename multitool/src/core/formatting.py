"""Shared terminal formatting palette (single source of truth).

Everything colourful in the tool goes through here: the big banner, the
module list, report headings and status tags. Colour is switched off
automatically when stdout is not a TTY or when ``NO_COLOR`` is set, so
pipes and log files stay clean. This module is stdlib-only and imports
nothing internal, so every layer (core, modules, ui) may use it freely.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Iterable, List, Optional

# ---------------------------------------------------------------------------
# colour state
# ---------------------------------------------------------------------------
_USE_COLOR: bool = False

_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_DIM = "\x1b[2m"
_WHITE = "\x1b[97m"
_CYAN = "\x1b[96m"
_MAGENTA = "\x1b[95m"
_YELLOW = "\x1b[93m"
_GREEN = "\x1b[92m"
_RED = "\x1b[91m"
_BLUE = "\x1b[94m"


def init_color() -> None:
    """Enable colour only for an interactive TTY (honours ``NO_COLOR``)."""
    global _USE_COLOR
    if os.environ.get("NO_COLOR"):
        _USE_COLOR = False
        return
    try:
        import colorama  # noqa: PLC0415

        colorama.just_fix_windows_console()
    except Exception:
        pass
    _USE_COLOR = bool(sys.stdout.isatty())


def color_enabled() -> bool:
    return _USE_COLOR


# ---------------------------------------------------------------------------
# low-level paint helpers
# ---------------------------------------------------------------------------
def paint(text: str, code: str, bold: bool = False) -> str:
    if not _USE_COLOR:
        return text
    prefix = _BOLD if bold else ""
    return f"{prefix}{code}{text}{_RESET}"


def white(text: str, bold: bool = False) -> str:
    return paint(text, _WHITE, bold)


def cyan(text: str, bold: bool = False) -> str:
    return paint(text, _CYAN, bold)


def magenta(text: str, bold: bool = False) -> str:
    return paint(text, _MAGENTA, bold)


def yellow(text: str, bold: bool = False) -> str:
    return paint(text, _YELLOW, bold)


def green(text: str, bold: bool = False) -> str:
    return paint(text, _GREEN, bold)


def red(text: str, bold: bool = False) -> str:
    return paint(text, _RED, bold)


def blue(text: str, bold: bool = False) -> str:
    return paint(text, _BLUE, bold)


def dim(text: str) -> str:
    return paint(text, _DIM)


def strip_ansi(text: str) -> str:
    """Remove ANSI colour sequences (used for width alignment)."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def ansi_len(text: str) -> int:
    return len(strip_ansi(text))


# ---------------------------------------------------------------------------
# boxes (double-lined, like the banner frame)
# ---------------------------------------------------------------------------
def box(lines: Iterable[str], accent: str = _CYAN, bold: bool = False) -> List[str]:
    """Wrap ``lines`` in a double-lined box (╔═╗ / ║ ║ / ╚═╝)."""
    content = [str(line) for line in lines]
    width = max((ansi_len(line) for line in content), default=0)
    pad = 2
    out = [paint("╔" + "═" * (width + pad * 2) + "╗", accent, bold)]
    for line in content:
        inner = line + " " * (width - ansi_len(line) + pad - 1)
        out.append(paint("║", accent, bold) + " " + inner + paint("║", accent, bold))
    out.append(paint("╚" + "═" * (width + pad * 2) + "╝", accent, bold))
    return out


def print_box(lines: Iterable[str], accent: str = _CYAN, bold: bool = False) -> None:
    for line in box(lines, accent, bold):
        print(line)


# ---------------------------------------------------------------------------
# status tags (ASCII-safe glyphs: [+] [i] [!] [x] [-])
# Colours are resolved per call so they respect the NO_COLOR / TTY state
# even when colour was initialised after this module was imported.
# ---------------------------------------------------------------------------
def tag_ok(text: str) -> str:
    return f"{paint('[+]', _GREEN, bold=True)} {text}"


def tag_info(text: str) -> str:
    return f"{paint('[i]', _CYAN, bold=True)} {text}"


def tag_warn(text: str) -> str:
    return f"{paint('[!]', _YELLOW, bold=True)} {text}"


def tag_error(text: str) -> str:
    return f"{paint('[x]', _RED, bold=True)} {text}"


def tag_action(text: str) -> str:
    return f"{paint('[-]', _DIM)} {text}"


# ---------------------------------------------------------------------------
# multi-column layout (module picker grid)
# ---------------------------------------------------------------------------
def column_split(items, columns: int):
    """Split ``items`` into ``columns`` roughly equal column-major chunks.

    With 38 modules and 3 columns this yields 13/13/12 — reading order runs
    top→bottom down each column (the picker then wraps to the next column),
    so short module lists also fill the screen naturally.
    """
    items = list(items)
    if columns <= 1 or not items:
        return [items]
    rows = max(1, -(-len(items) // columns))  # ceil
    cols = [items[row * rows:(row + 1) * rows] for row in range(columns)]
    return [col for col in cols if col]


def render_columns(
    rows_of_cells,
    *,
    gap: int = 6,
    min_width: int = 26,
) -> List[str]:
    """Render rows of equally-sized cells as full-width aligned text lines.

    Args:
        rows_of_cells: iterable of rows; each row is an iterable of cells
            (``str`` or already-coloured text). Cells shorter than the column
            width are padded so all columns line up. Returns one string per
            printed line.
    """
    data = [[str(cell) for cell in row] for row in rows_of_cells]
    if not data:
        return []
    width = max(ansi_len(cell) for row in data for cell in row)
    if width < min_width:
        width = min_width
    lines: List[str] = []
    for row in data:
        line = " " * gap
        for cell in row:
            line += cell + " " * (width - ansi_len(cell)) + " " * gap
        lines.append(line.rstrip())
    return lines


def terminal_width(fallback: int = 110) -> int:
    """Best-effort current terminal width (stdlib only)."""
    try:
        import shutil  # noqa: PLC0415

        return shutil.get_terminal_size((fallback, 24)).columns
    except Exception:  # pragma: no cover - defensive
        return fallback


def fit_width(available: int, cells: int, gap: int = 6, minimum: int = 26) -> int:
    """Shrink column width so ``cells`` columns fit ``available`` columns."""
    usable = max(10, available - gap * (cells + 1))
    return max(minimum, usable // max(1, cells))
