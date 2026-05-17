"""Structured CLI output primitives for IronMesh operator commands.

Goals from `docs/ROADMAP.md` v0.9.4 CLI ergonomics bundle:

- Color-coded (green/yellow/red) status text.
- Icon-prefixed lines (✓ ⚠ ✗).
- Section headers and key/value rows that read cleanly at a glance.
- Auto-disable color + icons on non-TTY output (pipes, CI logs) so
  `ironmesh status | grep ...` and CI captures stay clean.

Design notes:

- ANSI escape codes only — no curses, no third-party deps. Works
  on any modern terminal including Windows 10+ Terminal, VS Code,
  and the GitHub Actions runner.
- Honors the `NO_COLOR` env var (https://no-color.org/).
- Honors `IRONMESH_COLOR=always|auto|never` for explicit control.
- All emit functions go through `print()` to a configurable stream
  so tests can capture without monkey-patching stdout.
"""

from __future__ import annotations

import io
import os
import sys
from dataclasses import dataclass
from enum import Enum
from typing import IO, Optional

# ---- ANSI palette --------------------------------------------------

class _ANSI:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"


# ---- Status taxonomy ----------------------------------------------

class Status(Enum):
    """Three-state status. Maps to color + icon."""
    OK = "ok"            # green ✓
    WARN = "warn"        # yellow ⚠
    FAIL = "fail"        # red ✗
    INFO = "info"        # cyan •
    MUTED = "muted"      # gray ·


_ICON = {
    Status.OK: "✓",
    Status.WARN: "⚠",
    Status.FAIL: "✗",
    Status.INFO: "•",
    Status.MUTED: "·",
}

_COLOR = {
    Status.OK: _ANSI.GREEN,
    Status.WARN: _ANSI.YELLOW,
    Status.FAIL: _ANSI.RED,
    Status.INFO: _ANSI.CYAN,
    Status.MUTED: _ANSI.GRAY,
}


# ---- TTY detection -------------------------------------------------

def _color_enabled(stream: IO) -> bool:
    """Decide whether to emit ANSI codes for `stream`.

    Order of precedence:
      1. `NO_COLOR` env var (any non-empty value) → never
      2. `IRONMESH_COLOR=always` → always
      3. `IRONMESH_COLOR=never` → never
      4. `IRONMESH_COLOR=auto` (or unset) → only if stream is a TTY
    """
    if os.environ.get("NO_COLOR"):
        return False
    pref = (os.environ.get("IRONMESH_COLOR") or "auto").lower()
    if pref == "always":
        return True
    if pref == "never":
        return False
    # auto
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


# ---- Formatter ----------------------------------------------------

@dataclass
class Output:
    """Stream-bound formatter. One per command invocation typically."""

    stream: IO = sys.stdout
    color: Optional[bool] = None  # None = auto-detect from stream
    use_icons: Optional[bool] = None  # None = same as color

    def __post_init__(self) -> None:
        if self.color is None:
            self.color = _color_enabled(self.stream)
        if self.use_icons is None:
            self.use_icons = self.color  # icons piggyback on color decision

    def paint(self, text: str, status: Status) -> str:
        """Wrap text with the color escape for `status`. No-op when
        color is disabled."""
        if not self.color:
            return text
        return f"{_COLOR[status]}{text}{_ANSI.RESET}"

    def bold(self, text: str) -> str:
        if not self.color:
            return text
        return f"{_ANSI.BOLD}{text}{_ANSI.RESET}"

    def dim(self, text: str) -> str:
        if not self.color:
            return text
        return f"{_ANSI.DIM}{text}{_ANSI.RESET}"

    def icon(self, status: Status) -> str:
        """Return the icon for `status`, or empty string if icons
        are disabled. Includes a trailing space when emitted so
        callers can concatenate without bookkeeping."""
        if not self.use_icons:
            return ""
        return _ICON[status] + " "

    # ---- emit helpers ---------------------------------------------

    def line(self, status: Status, text: str) -> None:
        """One status-prefixed line.

            ✓ trust store has 12 peers
            ⚠ daemon listening only on 127.0.0.1
            ✗ keys.json missing
        """
        prefix = self.icon(status)
        body = self.paint(text, status) if self.color else text
        print(f"{prefix}{body}", file=self.stream)

    def kv(self, key: str, value: str, status: Status = Status.MUTED,
           key_width: int = 18) -> None:
        """Aligned key/value row. Status colors the value, not the key.

            peers          12 trusted, 8 online
            listen         0.0.0.0:8765
            audit chain    intact (4231 entries)
        """
        k = key.ljust(key_width)
        v = self.paint(value, status) if self.color else value
        print(f"  {self.dim(k)} {v}", file=self.stream)

    def section(self, title: str) -> None:
        """Header for a logical section. Bold + spacer above."""
        print("", file=self.stream)
        print(self.bold(title), file=self.stream)

    def summary(self, status: Status, headline: str) -> None:
        """Single-line top-of-output banner. The `--verbose`-toggle
        target: when verbose is off, summary + a few key kv() lines
        is the whole output."""
        prefix = self.icon(status)
        body = self.paint(headline, status) if self.color else headline
        print(f"{prefix}{self.bold(body)}", file=self.stream)

    def blank(self) -> None:
        print("", file=self.stream)

    def detail(self, text: str) -> None:
        """Verbose-only line. Caller decides whether to emit; this
        helper just dims the text so it visually subordinates to the
        summary."""
        print(f"  {self.dim(text)}", file=self.stream)


# ---- Convenience factory -------------------------------------------

def for_stream(stream: IO = sys.stdout,
               *, force_color: Optional[bool] = None,
               force_icons: Optional[bool] = None) -> Output:
    """Build an `Output` bound to `stream`. Defaults follow
    `_color_enabled()` — pass `force_color=True` or `False` to
    override (useful in tests)."""
    return Output(stream=stream, color=force_color,
                   use_icons=force_icons)


# ---- Pipe-safe entrypoint for ad-hoc usage -------------------------

def write_summary_only(headline: str, status: Status = Status.OK,
                        stream: IO = sys.stdout) -> None:
    """Single-line emit for the simplest case (e.g. `ironmesh
    status` summary mode). Used directly when the caller doesn't
    want to construct an Output."""
    out = for_stream(stream)
    out.summary(status, headline)


# ---- StringIO capture for tests + parent processes -----------------

def capture() -> tuple[io.StringIO, Output]:
    """Return a (buffer, output) pair where the output's stream is
    a StringIO. Used by tests and by parent processes that want to
    parse the structured output."""
    buf = io.StringIO()
    return buf, Output(stream=buf, color=False, use_icons=False)
