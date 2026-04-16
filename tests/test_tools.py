"""Tests for the v0.8.2 tool registry (examples/llm_tools pathway)."""
from __future__ import annotations

import asyncio
import os

import pytest

from ironmesh.tools import (
    DEFAULT_MAX_RESULT_BYTES,
    build_registry,
    describe_tools,
    expand_tool_calls,
    run_tool,
)


class TestRegistry:

    def test_build_empty(self):
        assert build_registry([]) == {}

    def test_echo_tool(self):
        reg = build_registry(["echo"])
        assert "echo" in reg
        assert reg["echo"].run("hi") == "hi"

    def test_unknown_tool_raises(self):
        with pytest.raises(ValueError, match="Unknown tool"):
            build_registry(["bogus"])

    def test_file_read_requires_allowlist(self):
        with pytest.raises(ValueError, match="allow"):
            build_registry(["file-read"])

    def test_file_read_ok_with_allowlist(self, tmp_path):
        p = tmp_path / "hello.txt"
        p.write_text("hello from tool")
        reg = build_registry(["file-read"], file_read_allowlist=[str(tmp_path)])
        out = reg["file-read"].run(str(p))
        assert "hello from tool" in out

    def test_file_read_rejects_outside_allowlist(self, tmp_path):
        from ironmesh.tools import ToolError
        p = tmp_path / "ok.txt"
        p.write_text("x")
        reg = build_registry(["file-read"], file_read_allowlist=[str(tmp_path)])
        # Try a path outside the allowlist.
        outside = os.path.join(os.path.dirname(str(tmp_path)), "..", "windows-passwd")
        with pytest.raises(ToolError, match="not in allowlist"):
            reg["file-read"].run(outside)


class TestDescribe:

    def test_empty_is_empty(self):
        assert describe_tools({}) == ""

    def test_nonempty_mentions_each_tool(self):
        reg = build_registry(["echo"])
        desc = describe_tools(reg)
        assert "<tool" in desc
        assert "echo" in desc


class TestRun:

    def test_run_unknown_tool_returns_error(self):
        reg = build_registry(["echo"])
        out = asyncio.run(run_tool(reg, "not-there", "args"))
        assert "[tool-error:" in out and "unknown tool" in out

    def test_run_echo(self):
        reg = build_registry(["echo"])
        assert asyncio.run(run_tool(reg, "echo", "abc")) == "abc"

    def test_run_timeout(self):
        # Synthetic tool that sleeps past the timeout.
        from ironmesh.tools import ToolSpec
        reg = {"slow": ToolSpec("slow", "", lambda _a: _sleepy_tool())}
        out = asyncio.run(run_tool(reg, "slow", "", timeout=0.2))
        assert "[tool-error:" in out and "timed out" in out


def _sleepy_tool():
    import time
    time.sleep(2.0)
    return "done"


class TestExpand:

    def test_no_markers_returns_input(self):
        reg = build_registry(["echo"])
        text = "no tool calls here"
        out, calls = asyncio.run(expand_tool_calls(reg, text))
        assert out == text
        assert calls == 0

    def test_single_echo_expansion(self):
        reg = build_registry(["echo"])
        text = 'before <tool name="echo">hi</tool> after'
        out, calls = asyncio.run(expand_tool_calls(reg, text))
        assert calls == 1
        assert "<tool-out" in out
        assert "hi" in out
        assert "before" in out
        assert "after" in out

    def test_unknown_tool_gets_error_inline(self):
        reg = build_registry(["echo"])
        text = 'go <tool name="bogus">x</tool>'
        out, calls = asyncio.run(expand_tool_calls(reg, text))
        assert calls == 1
        assert "[tool-error:" in out
        assert "unknown tool" in out

    def test_max_calls_caps_expansion(self):
        reg = build_registry(["echo"])
        text = "".join(f'<tool name="echo">{i}</tool> ' for i in range(10))
        out, calls = asyncio.run(expand_tool_calls(reg, text, max_calls=3))
        assert calls == 3
        # first 3 expanded, rest left as-is
        assert out.count("<tool-out") == 3


class TestResultTruncation:

    def test_http_get_truncation_constant_exists(self):
        # We can't hit the network from CI; just pin the default size cap.
        assert DEFAULT_MAX_RESULT_BYTES >= 1024
