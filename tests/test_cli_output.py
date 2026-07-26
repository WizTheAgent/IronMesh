"""Tests for `ironmesh.cli_output`.

Covers the output primitives (color toggling, icons, sections,
key/value rows, summary lines) used by v0.9.4 short verbs.
"""

from __future__ import annotations

import io
import os

import pytest

from ironmesh import cli_output as co
from ironmesh.cli_output import Output, Status


# ---- helpers ------------------------------------------------------

def _capture(force_color=None, force_icons=None):
    buf = io.StringIO()
    out = Output(stream=buf, color=force_color, use_icons=force_icons)
    return buf, out


# ---- color enable/disable ----------------------------------------

def test_color_disabled_on_non_tty(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("IRONMESH_COLOR", "auto")
    # StringIO is not a TTY; auto should disable color.
    buf, out = _capture()
    out.line(Status.OK, "ready")
    assert "\033[" not in buf.getvalue()
    assert "✓" not in buf.getvalue()  # icons off when color off
    assert "ready" in buf.getvalue()


def test_color_enabled_on_force(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("IRONMESH_COLOR", "always")
    buf = io.StringIO()
    out = Output(stream=buf)
    out.line(Status.OK, "ready")
    assert "\033[" in buf.getvalue()
    assert "✓" in buf.getvalue()


def test_no_color_env_overrides_force_always(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("IRONMESH_COLOR", "always")
    buf = io.StringIO()
    out = Output(stream=buf)
    out.line(Status.OK, "ready")
    assert "\033[" not in buf.getvalue()


def test_ironmesh_color_never_disables(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("IRONMESH_COLOR", "never")
    buf = io.StringIO()
    out = Output(stream=buf)
    out.line(Status.WARN, "uh oh")
    assert "\033[" not in buf.getvalue()
    assert "uh oh" in buf.getvalue()


# ---- emit primitives ----------------------------------------------

def test_line_with_color(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("IRONMESH_COLOR", "always")
    buf = io.StringIO()
    out = Output(stream=buf)
    out.line(Status.FAIL, "broken")
    raw = buf.getvalue()
    assert "✗" in raw
    assert "\033[31m" in raw  # red ANSI
    assert "broken" in raw
    assert raw.endswith("\033[0m\n")  # reset before newline


def test_kv_alignment(monkeypatch):
    monkeypatch.setenv("IRONMESH_COLOR", "never")
    buf = io.StringIO()
    out = Output(stream=buf)
    out.kv("peers", "12 trusted")
    out.kv("listen", "0.0.0.0:8765")
    lines = buf.getvalue().splitlines()
    # Each line starts with two spaces, then the key padded to width.
    assert all(l.startswith("  ") for l in lines)
    # Keys should align at the same column for the value.
    val_starts = [l.index("12 trusted") if "12 trusted" in l
                  else l.index("0.0.0.0") for l in lines]
    assert val_starts[0] == val_starts[1]


def test_section_header_emits_blank_line_above(monkeypatch):
    monkeypatch.setenv("IRONMESH_COLOR", "never")
    buf = io.StringIO()
    out = Output(stream=buf)
    out.line(Status.OK, "first")
    out.section("Mesh state")
    lines = buf.getvalue().splitlines()
    # Pattern: first, "", Mesh state
    assert lines[0].endswith("first")
    assert lines[1] == ""
    assert lines[2] == "Mesh state"


def test_summary_line(monkeypatch):
    monkeypatch.setenv("IRONMESH_COLOR", "never")
    buf = io.StringIO()
    out = Output(stream=buf)
    out.summary(Status.OK, "8/8 peers online")
    raw = buf.getvalue()
    assert "8/8 peers online" in raw
    # No color codes when never.
    assert "\033[" not in raw


def test_capture_helper_returns_color_disabled():
    buf, out = co.capture()
    assert out.color is False
    assert out.use_icons is False
    out.line(Status.OK, "captured")
    assert "\033[" not in buf.getvalue()
    assert "captured" in buf.getvalue()


# ---- icon mapping --------------------------------------------------

@pytest.mark.parametrize("status,icon", [
    (Status.OK, "✓"),
    (Status.WARN, "⚠"),
    (Status.FAIL, "✗"),
    (Status.INFO, "•"),
    (Status.MUTED, "·"),
])
def test_icon_mapping(monkeypatch, status, icon):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("IRONMESH_COLOR", "always")
    buf = io.StringIO()
    out = Output(stream=buf)
    out.line(status, "x")
    assert icon in buf.getvalue()


def test_icon_omitted_when_disabled(monkeypatch):
    monkeypatch.setenv("IRONMESH_COLOR", "never")
    buf = io.StringIO()
    out = Output(stream=buf)
    out.line(Status.OK, "ready")
    assert "✓" not in buf.getvalue()


# ---- write_summary_only convenience -------------------------------

def test_write_summary_only(monkeypatch):
    monkeypatch.setenv("IRONMESH_COLOR", "never")
    buf = io.StringIO()
    co.write_summary_only("All systems nominal", Status.OK, stream=buf)
    assert "All systems nominal" in buf.getvalue()
    assert "\033[" not in buf.getvalue()


# ---- non-TTY pipe simulation --------------------------------------

def test_pipe_target_disables_decoration(monkeypatch):
    """Simulates `ironmesh doctor | grep peers` — stdout is not a
    TTY, output should be plain text."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("IRONMESH_COLOR", "auto")
    buf = io.StringIO()
    # StringIO.isatty() returns False, mimicking a pipe.
    out = Output(stream=buf)
    out.line(Status.OK, "peers: 8")
    out.kv("listen", "0.0.0.0:8765")
    raw = buf.getvalue()
    assert "\033[" not in raw
    assert "✓" not in raw
    assert "peers: 8" in raw
    assert "listen" in raw and "0.0.0.0:8765" in raw
