"""Minimal tool registry for IronMesh LLM bridges (v0.8.2+).

Keeps the surface deliberately small. The bridge wires three safe-by-
default tools:

* ``echo`` — trivial, for smoke-testing the tool path.
* ``http-get`` — fetch a URL, return the first N bytes as text.
* ``file-read`` — read a file from a configured allowlist of paths.

Enabling a tool is opt-in: the bridge takes a ``--tools`` flag with a
comma-separated list of tool names. Each tool has a hard timeout
(default 8 s) and a result-size cap (default 4 KiB) so a runaway tool
can't starve the bridge or blow up the reply payload.

How the LLM calls them
----------------------
When tools are enabled the bridge appends a short rider to the system
prompt that tells the model:

    When you need to call a tool, respond with ``<tool name="X">args
    here</tool>``. The tool's output will be inlined in your reply.

The bridge parses that marker out of the model's response, calls the
tool, and substitutes the tool's output in place of the marker. The
assembled text is sent back to the peer. A second model call is
*not* made — the substitution is mechanical. That keeps latency
bounded and avoids recursive tool storms.
"""
from __future__ import annotations

import asyncio
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional

DEFAULT_TOOL_TIMEOUT = 8.0  # seconds
DEFAULT_MAX_RESULT_BYTES = 4096
DEFAULT_MAX_TOOL_CALLS = 4  # per response, total

_TOOL_CALL_RE = re.compile(
    r'<tool\s+name="(?P<name>[a-zA-Z][A-Za-z0-9_-]*)"\s*>'
    r'(?P<args>.*?)'
    r'</tool>',
    re.DOTALL,
)


@dataclass
class ToolSpec:
    name: str
    describe: str
    run: Callable[[str], str]  # args -> result text (sync); bridge wraps in thread


class ToolError(Exception):
    pass


# ---------------------------------------------------------------------------
# Built-in tools
# ---------------------------------------------------------------------------

def _tool_echo(args: str) -> str:
    return args


def _make_http_get(max_bytes: int) -> Callable[[str], str]:
    def _run(args: str) -> str:
        url = args.strip()
        if not (url.startswith("http://") or url.startswith("https://")):
            raise ToolError("http-get: URL must start with http:// or https://")
        req = urllib.request.Request(url, headers={"User-Agent": "IronMesh-tool/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = resp.read(max_bytes + 1)
        except urllib.error.URLError as e:
            raise ToolError(f"http-get: {e.reason}") from e
        text = data[:max_bytes].decode("utf-8", errors="replace")
        if len(data) > max_bytes:
            text += f"\n[truncated at {max_bytes} bytes]"
        return text
    return _run


def _make_file_read(allowed_paths: list[str], max_bytes: int) -> Callable[[str], str]:
    # Canonicalize the allowlist once so we don't re-resolve on every call.
    allowed = [os.path.realpath(os.path.expanduser(p)) for p in allowed_paths]

    def _run(args: str) -> str:
        target = os.path.realpath(os.path.expanduser(args.strip()))
        if not any(target == a or target.startswith(a + os.sep) for a in allowed):
            raise ToolError(f"file-read: path {target!r} not in allowlist")
        if not os.path.isfile(target):
            raise ToolError(f"file-read: not a file: {target!r}")
        with open(target, "rb") as f:
            data = f.read(max_bytes + 1)
        text = data[:max_bytes].decode("utf-8", errors="replace")
        if len(data) > max_bytes:
            text += f"\n[truncated at {max_bytes} bytes]"
        return text
    return _run


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def build_registry(
    enabled: list[str],
    *,
    max_result_bytes: int = DEFAULT_MAX_RESULT_BYTES,
    file_read_allowlist: Optional[list[str]] = None,
) -> dict[str, ToolSpec]:
    """Return a dict of {tool_name: ToolSpec} for the requested tools.

    Raises ``ValueError`` if a requested tool is not bundled or if
    ``file-read`` is requested without a non-empty allowlist.
    """
    registry: dict[str, ToolSpec] = {}
    for name in enabled:
        name = name.strip()
        if not name:
            continue
        if name == "echo":
            registry["echo"] = ToolSpec(
                "echo",
                "Returns whatever arguments you pass, verbatim. Useful for "
                "checking whether the tool path works.",
                _tool_echo,
            )
        elif name == "http-get":
            registry["http-get"] = ToolSpec(
                "http-get",
                "Fetches a URL over HTTP(S) and returns the response body as "
                f"text, truncated to {max_result_bytes} bytes. Argument: the URL.",
                _make_http_get(max_result_bytes),
            )
        elif name == "file-read":
            if not file_read_allowlist:
                raise ValueError(
                    "file-read tool requires a non-empty --file-read-allow list",
                )
            registry["file-read"] = ToolSpec(
                "file-read",
                "Reads a file from an operator-configured allowlist of paths, "
                f"truncated to {max_result_bytes} bytes. Argument: absolute path.",
                _make_file_read(file_read_allowlist, max_result_bytes),
            )
        else:
            raise ValueError(f"Unknown tool {name!r}")
    return registry


def describe_tools(registry: dict[str, ToolSpec]) -> str:
    """Human-readable snippet appended to the LLM's system prompt."""
    if not registry:
        return ""
    lines = [
        "",
        "You have tools available. When you need to use one, emit the "
        "marker ``<tool name=\"TOOL\">ARGS</tool>`` anywhere in your reply "
        "and the tool's output will be substituted in place of the marker. "
        "You do NOT need to wait for a follow-up turn.",
        "",
        "Available tools:",
    ]
    for name, spec in sorted(registry.items()):
        lines.append(f"- {name}: {spec.describe}")
    return "\n".join(lines)


async def run_tool(
    registry: dict[str, ToolSpec],
    name: str,
    args: str,
    *,
    timeout: float = DEFAULT_TOOL_TIMEOUT,
) -> str:
    """Call a tool by name and return its output (or an error message)."""
    spec = registry.get(name)
    if spec is None:
        return f"[tool-error: unknown tool {name!r}]"
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(spec.run, args),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return f"[tool-error: {name} timed out after {timeout}s]"
    except ToolError as e:
        return f"[tool-error: {e}]"
    except Exception as e:
        return f"[tool-error: {name}: {type(e).__name__}: {e}]"


async def expand_tool_calls(
    registry: dict[str, ToolSpec],
    text: str,
    *,
    max_calls: int = DEFAULT_MAX_TOOL_CALLS,
    timeout: float = DEFAULT_TOOL_TIMEOUT,
) -> tuple[str, int]:
    """Replace each ``<tool name=X>args</tool>`` in ``text`` with tool output.

    Caps at ``max_calls`` tool invocations per response. Returns
    ``(expanded_text, number_of_calls_made)``.
    """
    if not registry:
        return text, 0
    matches = list(_TOOL_CALL_RE.finditer(text))
    if not matches:
        return text, 0
    calls = 0
    out_parts: list[str] = []
    cursor = 0
    for m in matches:
        if calls >= max_calls:
            break
        out_parts.append(text[cursor:m.start()])
        name = m.group("name")
        args = m.group("args").strip()
        result = await run_tool(registry, name, args, timeout=timeout)
        out_parts.append(f"<tool-out name=\"{name}\">{result}</tool-out>")
        cursor = m.end()
        calls += 1
    out_parts.append(text[cursor:])
    return "".join(out_parts), calls
