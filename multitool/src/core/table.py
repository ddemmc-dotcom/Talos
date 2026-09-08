"""Minimal aligned table renderer (stdlib only, no colors).

Kept deliberately plain so module output stays readable in logs and pipes
as well as on a real terminal.
"""
from __future__ import annotations

from typing import Iterable, List, Sequence, Tuple


def _cell(value: object) -> str:
    return "-" if value is None else str(value)


def render_table(headers: Sequence[str], rows: Iterable[Sequence[object]]) -> List[str]:
    """Return the lines of an aligned table.

    Args:
        headers: column titles.
        rows: iterable of rows; a short row is padded, a long one truncated
            to the header count.
    """
    data: List[Tuple[str, ...]] = [tuple(_cell(v) for v in headers)]
    for row in rows:
        values = [_cell(v) for v in row]
        values = (values + [""] * len(headers))[: len(headers)]
        data.append(tuple(values))
    if len(data) <= 1:
        return ["(no rows)"]
    widths = [max(len(row[i]) for row in data) for i in range(len(headers))]
    lines: List[str] = []
    for index, row in enumerate(data):
        padded = "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))
        if index == 0:
            lines.append(padded)
            lines.append("  ".join("-" * widths[i] for i in range(len(headers))))
        else:
            lines.append(padded)
    return lines


def print_table(headers: Sequence[str], rows: Iterable[Sequence[object]]) -> None:
    """Print :func:`render_table` output, one line per row."""
    for line in render_table(headers, rows):
        print(f"  {line}")
