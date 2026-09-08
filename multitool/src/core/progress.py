"""Shared progress helpers: step logs, live bars and progress sinks.

The multi-tool has two audiences for progress:

* **Terminal (CLI menu + standalone scripts).** Modules that walk many items
  (hosts, ports, subdomains, credentials) drive a :class:`LiveBar` that is
  redrawn in place with ``\\r`` when stdout is a real TTY and degrades to
  milestone log lines when it is a pipe/log, so redirected runs stay clean.
* **Engine modules (orchestrator / TUI).** A module never imports UI code.
  Instead it calls ``self.report_progress(message, fraction)`` and a sink
  attached by the runner decides how to display the event.  The TUI installs
  a thread-safe sink that posts events to a queue; the CLI runners attach
  :func:`cli_sink` which renders a live bar / step lines.

This module is stdlib-only apart from :mod:`src.core.formatting` (also
stdlib-only), so every layer may use it freely.
"""
from __future__ import annotations

import sys
import time
from typing import Callable, Optional

from src.core import formatting as fmt

_BAR_WIDTH = 24


# ---------------------------------------------------------------------------
# small building blocks
# ---------------------------------------------------------------------------
def bar_text(fraction: float, width: int = _BAR_WIDTH) -> str:
    """Render a fraction (0..1) as ``[██████████░░░░░░░░░░░░]  42%``."""
    fraction = max(0.0, min(1.0, float(fraction)))
    if not fmt.color_enabled():
        # ASCII-safe fallback keeps piped output readable.
        filled = int(round(fraction * width))
        blocks = "#" * filled + "-" * (width - filled)
        return f"[{blocks}] {fraction * 100:5.1f}%"
    filled = int(round(fraction * width))
    color = fmt._GREEN if fraction >= 1.0 else fmt._CYAN
    blocks = (
        fmt.paint("█" * filled, color)
        + fmt.paint("░" * (width - filled), fmt._DIM)
    )
    return f"[{blocks}{fmt._RESET}] {fraction * 100:5.1f}%"


def log(message: str, level: str = "info") -> None:
    """Print one clean step-log line: ``  [i] message`` / ``  [+] message``."""
    if level == "ok":
        print(fmt.tag_ok(message))
    elif level == "warn":
        print(fmt.tag_warn(message))
    elif level == "error":
        print(fmt.tag_error(message))
    else:
        print(fmt.tag_info(message))


def spinner_frame(now: Optional[float] = None) -> str:
    """Return the current braille-ish spinner character."""
    now = time.monotonic() if now is None else now
    glyphs = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    return glyphs[int(now * 10) % len(glyphs)]


# ---------------------------------------------------------------------------
# LiveBar — redraw one status line inside a counting loop
# ---------------------------------------------------------------------------
class LiveBar:
    """A one-line progress indicator for loops with a known item count.

    Usage::

        bar = LiveBar(total=len(ports), label="probing ports")
        for port in ports:
            ... scan port ...
            bar.advance(f"port {port} done")
        bar.finish("scan complete")

    On a TTY each :meth:`advance` redraws a ``\\r``-based bar + message. On a
    non-TTY (pipe, log, automated run) the bar prints milestone lines at each
    25 % boundary and :meth:`finish` prints the final 100 % summary, so logs
    never contain carriage-return noise.
    """

    def __init__(
        self,
        total: int,
        label: str = "",
        *,
        width: int = _BAR_WIDTH,
        every: float = 0.25,
    ) -> None:
        self.total = max(1, int(total))
        self.label = label
        self.width = width
        self.every = every
        self.count = 0
        self._last_milestone = 0.0
        self._tty = bool(sys.stdout.isatty()) and fmt.color_enabled()
        self._start = time.monotonic()

    # ------------------------------------------------------------------
    @property
    def fraction(self) -> float:
        return self.count / self.total

    # ------------------------------------------------------------------
    def advance(self, message: str = "") -> None:
        """Advance by one completed item and redraw (or milestone-log)."""
        self.count = min(self.total, self.count + 1)
        self._render(message or self.label, force=False)

    def step_to(self, count: int, message: str = "") -> None:
        """Set the completed count directly (useful for unordered workers)."""
        self.count = max(0, min(self.total, int(count)))
        self._render(message or self.label, force=False)

    # ------------------------------------------------------------------
    def log(self, message: str, level: str = "info") -> None:
        """Print a discrete step log without breaking the live bar.

        On a TTY the current bar line is cleared first, the message is
        printed on its own line, then the bar is redrawn underneath — so
        meaningful events ("host X responded", "found subdomain Y") read as
        real logs while the bar keeps updating.
        """
        if self._tty:
            sys.stdout.write("\r" + " " * 80 + "\r")
            sys.stdout.flush()
        log(message, level=level)
        if self._tty and self.count < self.total:
            self._render(self.label, force=False)

    def finish(self, message: str = "") -> None:
        """Finalise at 100 % — newline after the live bar, or a summary log."""
        self.count = self.total
        text = message or self.label
        if self._tty:
            self._render(text, force=True)
            print()
        else:
            done = f"✓ {text} ({self.total} item(s), {self._elapsed():.1f}s)"
            print(fmt.tag_ok(done))

    # ------------------------------------------------------------------
    def _elapsed(self) -> float:
        return time.monotonic() - self._start

    def _render(self, message: str, *, force: bool) -> None:
        fraction = self.fraction
        if not self._tty:
            milestone = self.count / self.total
            if force or milestone >= self._last_milestone + self.every:
                self._last_milestone = milestone
                percent = f"{fraction * 100:5.1f}%"
                print(f"  [..] {self.count}/{self.total} ({percent})  {message}")
            return
        elapsed = self._elapsed()
        suffix = f"{elapsed:4.1f}s" if elapsed >= 10 else f"{elapsed:.1f}s"
        line = f"  {bar_text(fraction, self.width)}  {message or self.label}  {suffix}  "
        if force:
            line = line.rstrip()
        sys.stdout.write("\r" + line.ljust(80))
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# progress sinks (engine events -> display)
# ---------------------------------------------------------------------------
ProgressCallback = Callable[[Optional[str], Optional[float]], None]


_last_tty_bar: dict = {"line": "", "last_frac": -1.0}


def cli_sink(message: Optional[str] = None, fraction: Optional[float] = None) -> None:
    """Default sink for CLI runners: step lines + a live bar for fractions.

    Attach to an engine module with ``module.set_progress(cli_sink)`` so the
    brute-forcer / nmap / Metasploit runs show progress in the CLI menu and
    the standalone scripts, exactly like the TUI shows it.  On a non-TTY the
    bar is throttled to ~5 % steps so redirected logs stay readable.
    """
    tty = bool(sys.stdout.isatty()) and fmt.color_enabled()
    if fraction is None:
        if _last_tty_bar["line"] and tty:
            sys.stdout.write("\r" + " " * 80 + "\r")
            _last_tty_bar["line"] = ""
            sys.stdout.flush()
        if message:
            print(fmt.tag_action(message))
        return
    fraction = max(0.0, min(1.0, float(fraction)))
    if not tty:
        if fraction - _last_tty_bar["last_frac"] >= 0.05 or fraction >= 1.0:
            _last_tty_bar["last_frac"] = fraction
            print(f"  [..] {bar_text(fraction)}  {message or ''}".rstrip())
        return
    if message and fraction - _last_tty_bar["last_frac"] >= 0.02:
        _last_tty_bar["last_frac"] = fraction
        sys.stdout.write("\r" + " " * 80 + "\r")
        print(fmt.tag_action(message))
    line = f"  {bar_text(fraction)}  {message or ''}".ljust(80)
    sys.stdout.write("\r" + line)
    _last_tty_bar["line"] = line
    sys.stdout.flush()


def clear_cli_line() -> None:
    """Erase any pending live CLI bar (call before printing a final report)."""
    if _last_tty_bar["line"] and bool(sys.stdout.isatty()) and fmt.color_enabled():
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()
    _last_tty_bar["line"] = ""
