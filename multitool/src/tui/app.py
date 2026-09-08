"""Clean, keyboard-driven, full-screen terminal UI for the multi-tool.

Design rules
------------
* **No buttons, no tabs.** The whole screen is one keyboard flow:
  a big **three-column module grid** fills the left/top of the screen and a
  run panel (target / ports / options + **live progress bar** and a scrolling
  **progress log**) sits on the right/bottom.
* Arrow keys move a highlight across the 3-column grid (↑ ↓ ← →); ``ENTER``
  on a highlighted module selects it and jumps to the target field;
  ``Ctrl+S`` (or ENTER in an input) runs the selected module.
* While a module runs, its engine events (``BaseModule.report_progress``)
  stream into the UI: step messages appear in the progress log and bar
  fractions move the ``ProgressBar`` — so you see *"pinging host X …",
  "scanning port 22/50 …"*-style logs live, exactly as in the CLI menu.
* Modules run in worker threads (``asyncio.to_thread``); a thread-safe queue
  carries progress events back to the UI loop (no direct widget writes from
  worker threads).

Keys:  ↑/↓/←/→ move the module highlight   ENTER select & focus target
       Ctrl+S run selected module           Q quit
"""
from __future__ import annotations

import asyncio
import queue
import time
from typing import Any, Dict, List, Optional, Type

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from rich.text import Text
from textual.widgets import Footer, Input, ProgressBar, RichLog, Static, TextArea

from src.core import report
from src.errors.registry import ToolError
from src.logging_utils import get_logger
from src.models.tool_result import ToolResult
from src.orchestrator import BaseModule, Orchestrator

#: Per-module hint shown in the options box (one KEY=VALUE per line).
_OPTION_HINTS: Dict[str, str] = {
    "nmap": (
        "service_scan=true        # -sV service/version detection\n"
        "udp=false\n"
        "no_ping=false            # -Pn when the host ignores ping\n"
        "top_ports=100            # or type a list in the PORTS box\n"
        "timeout=300              # seconds\n"
        "extra_args=--min-rate=50 # optional raw nmap args"
    ),
    "nmap_vuln": (
        "nse_scripts=vuln         # NSE script family (default: vuln)\n"
        "service_scan=true\n"
        "timeout=900              # vuln scripts are slow — allow time"
    ),
    "http_bruteforce": (
        "mode=basic               # basic | form (login form needs markers)\n"
        "user=admin               # single user, or users_file=/path/list.txt\n"
        "passwords_file=/path/words.txt   # omit to use built-in small list\n"
        "delay=0.1                # seconds between attempts (rate limit)\n"
        "timeout=8\n"
        "# form mode:\n"
        "# success_marker=Welcome back\n"
        "# fail_marker=Invalid login\n"
        "# user_field=username  pass_field=password"
    ),
    "metasploit": (
        "msf_type=auxiliary       # auxiliary | exploit | post\n"
        "msf_module=scanner/portscan/tcp   # required\n"
        "THREADS=10               # datastore option, any KEY=VALUE\n"
        "RHOSTS=10.0.0.5          # overrides auto-wiring from TARGET"
    ),
}

#: How many columns the module grid uses.
_GRID_COLUMNS = 3


def _parse_value(raw: str) -> Any:
    """Turn a KEY=VALUE string into the most useful Python type."""
    value = raw.strip()
    lowered = value.lower()
    if lowered in ("true", "yes", "on", "1"):
        return True
    if lowered in ("false", "no", "off", "0"):
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


class ToolkitTuiApp(App[None]):
    """Full-screen, keyboard-driven module console with live progress."""

    TITLE = "TALOS multi-tool"
    SUB_TITLE = "keyboard-driven · 3-column module grid · live progress"

    CSS = """
    Screen { layout: vertical; }
    #brand {
        height: 3;
        content-align: center middle;
        background: $panel;
        color: $text;
        text-style: bold;
        border-bottom: heavy $primary;
    }
    #body { height: 1fr; }
    #grid_panel { width: 62%; border-right: heavy $secondary; }
    #grid_scroll { height: 1fr; }
    #module_grid {
        grid-size: 3;
        grid-gutter: 1 1;
        padding: 1 1;
    }
    .tile {
        height: 7;
        border: tall $primary-darken-2;
        padding: 1 1;
    }
    .tile.selected { border: heavy $success; }
    .tile .name { text-style: bold; color: $text; }
    .tile .desc { color: $text-muted; text-style: italic; }
    .tile .status { color: $success; }
    .tile .status.off { color: $error; }
    #side { padding: 1 2; }
    #doc { height: auto; max-height: 6; }
    .panel_title { color: $primary; text-style: bold; margin-top: 1; }
    Input, TextArea { margin-bottom: 1; }
    #options { height: 8; }
    #progress_row { height: 3; margin-bottom: 1; }
    #bar { height: 1; margin-top: 1; }
    #log {
        height: 1fr;
        border: round $secondary;
        margin-bottom: 1;
    }
    #status { height: auto; color: $text-muted; }
    """

    BINDINGS = [
        Binding("ctrl+s", "run_module", "Run module", show=True, priority=True),
        Binding("q", "quit", "Quit", show=True),
        Binding("escape", "back_to_grid", "Back to grid", show=False),
        Binding("enter", "grid_select", "Select module", show=False),
        Binding("up", "grid_move(-1, 0)", "Up", show=False),
        Binding("down", "grid_move(1, 0)", "Down", show=False),
        Binding("left", "grid_move(0, -1)", "Left", show=False),
        Binding("right", "grid_move(0, 1)", "Right", show=False),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.orchestrator: Orchestrator = Orchestrator(discover=True)
        # NOTE: must NOT be named ``_logger`` — Textual's own App._logger
        # backs ``self.log`` and would be clobbered.
        self._tool_logger = get_logger("tui")
        self._names: List[str] = []
        self._meta: Dict[str, Dict[str, Any]] = {}
        self._cursor = 0
        self._module_running = False
        self._progress_q: "queue.Queue[Optional[tuple]]" = queue.Queue()
        self._jobs_run = 0

    # ------------------------------------------------------------------
    # layout
    # ------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Static(
            "TALOS  multi-tool   ·   ↑↓←→ move  ·  ENTER select  ·  "
            "Ctrl+S run  ·  Q quit",
            id="brand",
        )
        with Horizontal(id="body"):
            with Vertical(id="grid_panel"):
                yield Static("MODULES", classes="panel_title")
                with VerticalScroll(id="grid_scroll"):
                    yield Grid(id="module_grid")
            with Vertical(id="side"):
                yield Static("", id="doc")
                yield Static("TARGET", classes="panel_title")
                yield Input(
                    placeholder="host / IP / URL (optional for this module)",
                    id="target",
                )
                yield Static("PORTS", classes="panel_title")
                yield Input(
                    placeholder="22,80,443 (optional — modules that use ports)",
                    id="ports",
                )
                yield Static("OPTIONS — one KEY=VALUE per line", classes="panel_title")
                yield TextArea("", id="options", soft_wrap=True)
                with Vertical(id="progress_row"):
                    yield ProgressBar(id="bar", total=100, show_eta=False)
                yield RichLog(id="log", wrap=True, markup=False, max_lines=2000)
                yield Static("", id="status")
        yield Footer()

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def on_mount(self) -> None:
        # The scroll/grid containers must never grab focus: arrow keys belong
        # to grid navigation (and to the text inputs when they are focused).
        self.query_one("#grid_scroll", VerticalScroll).can_focus = False
        self.query_one("#module_grid", Grid).can_focus = False
        self.query_one("#log", RichLog).can_focus = False
        self._set_text_fields_focusable(False)  # start on the grid, not typing
        self._populate_modules()
        self._render_grid()
        if self._names:
            self._set_current(self._names[0])
        self.screen.focus(None)

    def _populate_modules(self) -> None:
        names = sorted(self.orchestrator.module_names())
        self._meta = {}
        for name in names:
            cls = self.orchestrator.modules[name]
            ready, reason = self._check_readiness(cls)
            self._meta[name] = {
                "cls": cls,
                "description": str(getattr(cls, "DESCRIPTION", "") or ""),
                "ready": ready,
                "reason": reason,
            }
        # Ready modules first, then alphabetical within each group.
        self._names = sorted(
            names, key=lambda n: (not self._meta[n]["ready"], n)
        )

    def _render_grid(self) -> None:
        grid = self.query_one("#module_grid", Grid)
        for child in list(grid.children):
            child.remove()
        for index, name in enumerate(self._names):
            meta = self._meta[name]
            if meta["ready"]:
                status = Static("READY", classes="status")
            else:
                status = Static(f"unavailable: {meta['reason'][:44]}", classes="status off")
            tile = Vertical(
                Static(name, classes="name"),
                Static((meta["description"] or "")[:72], classes="desc"),
                status,
                classes=f"tile{' selected' if index == self._cursor else ''}",
                id=f"tile_{index}",
            )
            grid.mount(tile)
        self._paint_cursor()

    def _paint_cursor(self) -> None:
        for index, name in enumerate(self._names):
            tile = self.query_one(f"#tile_{index}", Vertical)
            tile.set_class(index == self._cursor, "selected")

    @staticmethod
    def _check_readiness(cls: Type[BaseModule]):
        try:
            cls.validate_environment()
        except ToolError as exc:
            return False, exc.message
        except Exception as exc:  # defensive
            return False, str(exc)[:80]
        return True, ""

    # ------------------------------------------------------------------
    # grid navigation
    # ------------------------------------------------------------------
    def _module_is_busy(self) -> bool:
        return self._module_running

    def _set_text_fields_focusable(self, enabled: bool) -> None:
        """Toggle the target/ports/options fields' focusability.

        While False (default, and after ESC / after a run) all arrow keys
        drive the module grid; ENTER arms the fields so they can be edited
        and Tab cycles between them.
        """
        for widget_id in ("target", "ports", "options"):
            widget = self.query_one(f"#{widget_id}")
            widget.can_focus = enabled

    def action_back_to_grid(self) -> None:
        """Leave the text fields and hand every key back to the grid."""
        if self._module_running:
            return
        self._set_text_fields_focusable(False)
        self.screen.focus(None)

    def action_grid_move(self, rows: int, cols: int) -> None:
        """Move the highlight across the 3-column grid (respecting bounds)."""
        if not self._names or self._module_running:
            return
        focused = self.screen.focused
        # While editing a single-line field, keep ←/→ for the text cursor;
        # ↑/↓ may still move the grid highlight.
        if cols and isinstance(focused, (Input, TextArea)):
            return
        total = len(self._names)
        columns = min(_GRID_COLUMNS, total)
        rows_count = -(-total // columns)  # ceil
        row, col = divmod(self._cursor, columns)
        new_row = max(0, min(rows_count - 1, row + rows))
        new_col = max(0, min(columns - 1, col + cols))
        index = new_row * columns + new_col
        if index >= total:
            index = total - 1 if rows or cols > 0 else index
        index = max(0, min(total - 1, index))
        if index != self._cursor:
            self._cursor = index
            self._paint_cursor()
            tile = self.query_one(f"#tile_{self._cursor}", Vertical)
            tile.scroll_visible()
            self._set_current(self._names[self._cursor])

    def action_grid_select(self) -> None:
        """ENTER on the grid: arm + focus the TARGET field for the module."""
        if not self._names or self._module_running:
            return
        if isinstance(self.screen.focused, (Input, TextArea)):
            return  # ENTER in a text field submits/edits instead
        self._set_current(self._names[self._cursor])
        self._set_text_fields_focusable(True)
        self.query_one("#target", Input).focus()

    # ------------------------------------------------------------------
    # selection
    # ------------------------------------------------------------------
    def _set_current(self, name: str) -> None:
        meta = self._meta.get(name)
        if not meta:
            return
        lines = [f"[bold]{name}[/]"]
        if meta["description"]:
            lines.append(f"[dim]{meta['description']}[/]")
        if not meta["ready"]:
            lines.append(f"[red]environment: {meta['reason']}[/]")
        else:
            lines.append("[green]environment ready[/]")
        self.query_one("#doc", Static).update("\n".join(lines))
        hint = _OPTION_HINTS.get(name, "# type the module's KEY=VALUE options here")
        self.query_one("#options", TextArea).placeholder = hint

    # ------------------------------------------------------------------
    # run
    # ------------------------------------------------------------------
    def action_run_module(self) -> None:
        if self._module_running:
            self._log_status("a module is already running — wait for it to finish")
            return
        if not self._names:
            self._log_status("no modules available")
            return
        name = self._names[self._cursor]
        asyncio.create_task(self._run_current(name))

    async def _run_current(self, name: str) -> None:
        out = self.query_one("#log", RichLog)
        bar = self.query_one("#bar", ProgressBar)
        meta = self._meta.get(name) or {}
        cls = meta.get("cls")
        if cls is None:
            return
        if not meta.get("ready"):
            out.write(Text(f"module {name} is unavailable — nothing was run", style="red"))
            return

        target = str(self.query_one("#target", Input).value or "").strip()
        ports = str(self.query_one("#ports", Input).value or "").strip()
        raw_options = str(self.query_one("#options", TextArea).text or "")
        options: Dict[str, Any] = {}
        for raw_line in raw_options.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                out.write(Text(f"skipped option {line!r} — expected KEY=VALUE", style="red"))
                continue
            key, _, value = line.partition("=")
            options[key.strip()] = _parse_value(value)

        params: Dict[str, Any] = {"options": options}
        if target:
            params["target"] = target
        if ports:
            params["ports"] = ports

        # Prepare the live progress widgets.
        self._module_running = True
        self._progress_q = queue.Queue()
        bar.update(total=100, progress=0)
        out.write(Text(f"> running {name} ...", style="cyan bold"))
        self._log_status(f"running {name} — progress streams below")
        self._jobs_run += 1
        started = time.perf_counter()

        def sink(message: Optional[str], fraction: Optional[float]) -> None:
            self._progress_q.put((message, fraction))

        drain = self.set_interval(1 / 30, self._drain_progress)
        try:
            result = await asyncio.to_thread(
                self.orchestrator.execute, name, progress_sink=sink, **params
            )
        except Exception as exc:  # pragma: no cover - execute() never raises
            self._tool_logger.exception("unexpected UI error running %s", name)
            result = ToolResult.failed(name, f"unexpected UI-side error: {exc!r}")
        finally:
            drain.stop()
            self._drain_progress()  # flush everything still queued

        elapsed = time.perf_counter() - started
        bar.update(total=100, progress=100)
        for line in report.render_result(result):
            out.write(line)
        final_style = "green bold" if result.ok else "red bold"
        out.write(
            Text(
                f"{result.status.value} · {elapsed:.2f}s · "
                f"{result.category_name or 'no error'}",
                style=final_style,
            )
        )
        self._module_running = False
        self._set_text_fields_focusable(False)
        self.screen.focus(None)
        self._log_status(
            f"last run: {name} → {result.status.value} in {elapsed:.2f}s "
            f"({self._jobs_run} run(s) this session; audit → logs/audit.jsonl)"
        )

    def _drain_progress(self) -> None:
        """Move queued engine progress events onto the ProgressBar + log."""
        bar = self.query_one("#bar", ProgressBar)
        log_widget = self.query_one("#log", RichLog)
        while True:
            try:
                message, fraction = self._progress_q.get_nowait()
            except queue.Empty:
                return
            if fraction is not None:
                bar.update(progress=max(0.0, min(100.0, fraction * 100.0)))
            if message:
                log_widget.write(Text(f"└ {message}", style="cyan"))
                log_widget.scroll_end(animate=False)

    # ------------------------------------------------------------------
    # input submit -> run
    # ------------------------------------------------------------------
    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id in ("target", "ports"):
            self.action_run_module()

    def _log_status(self, text: str) -> None:
        self.query_one("#status", Static).update(text)


if __name__ == "__main__":  # pragma: no cover
    ToolkitTuiApp().run()
