"""ironmesh-mcp entrypoint: env-driven identity, stdio-first startup, orphan guard.

MCP hosts (Claude Desktop, OpenClaw, ...) configure a server through env vars
only, so the entrypoint must honour IRONMESH_NAME / IRONMESH_PORT /
IRONMESH_KEYS_PATH / IRONMESH_DB_PATH, with explicit argv still winning.
Before this, an MCP server spawned next to a real node silently used
~/.ironmesh and the default port, sharing one identity and one sqlite file
with that node.
"""

import io
import json
import sys
import threading

import pytest

import ironmesh_mcp.server as srv


class _Built(Exception):
    """Raised by the fake daemon so main() stops right after construction."""


@pytest.fixture
def captured(monkeypatch):
    """Replace BridgeDaemon in the entrypoint and capture its kwargs."""
    seen = {}

    class _FakeDaemon:
        def __init__(self, **kwargs):
            seen.update(kwargs)
            raise _Built()

    monkeypatch.setattr(srv, "BridgeDaemon", _FakeDaemon)
    for var in ("IRONMESH_NAME", "IRONMESH_PORT", "IRONMESH_KEYS_PATH",
                "IRONMESH_DB_PATH", "IRONMESH_MCP_INIT_TIMEOUT"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("IRONMESH_PASSPHRASE", "mcp-env-test-passphrase")
    return seen


def _run_main(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["ironmesh-mcp", *argv])
    with pytest.raises(_Built):
        srv.main()


class TestEnvIdentity:
    def test_defaults_without_env_or_argv(self, captured, monkeypatch):
        _run_main(monkeypatch, [])
        assert captured["name"] == "mcp-agent"
        assert captured["port"] == 8767
        # No path override -> BridgeDaemon keeps its own ~/.ironmesh defaults.
        assert "keys_path" not in captured
        assert "db_path" not in captured

    def test_env_sets_name_port_and_paths(self, captured, monkeypatch, tmp_path):
        monkeypatch.setenv("IRONMESH_NAME", "env-node")
        monkeypatch.setenv("IRONMESH_PORT", "9123")
        monkeypatch.setenv("IRONMESH_KEYS_PATH", str(tmp_path / "k" / "keys.json"))
        monkeypatch.setenv("IRONMESH_DB_PATH", str(tmp_path / "d" / "data.db"))
        _run_main(monkeypatch, [])
        assert captured["name"] == "env-node"
        assert captured["port"] == 9123
        assert captured["keys_path"] == str(tmp_path / "k" / "keys.json")
        assert captured["db_path"] == str(tmp_path / "d" / "data.db")

    def test_keys_path_alone_leaves_db_to_daemon_derivation(
            self, captured, monkeypatch, tmp_path):
        # BridgeDaemon derives db/routes/capabilities/trust next to a
        # non-default keys file; the entrypoint must not pin db_path itself.
        monkeypatch.setenv("IRONMESH_KEYS_PATH", str(tmp_path / "keys.json"))
        _run_main(monkeypatch, [])
        assert captured["keys_path"] == str(tmp_path / "keys.json")
        assert "db_path" not in captured

    def test_argv_wins_over_env(self, captured, monkeypatch):
        monkeypatch.setenv("IRONMESH_NAME", "env-node")
        monkeypatch.setenv("IRONMESH_PORT", "9123")
        _run_main(monkeypatch, ["--name", "argv-node", "--port", "9456"])
        assert captured["name"] == "argv-node"
        assert captured["port"] == 9456

    def test_malformed_port_env_warns_and_uses_default(
            self, captured, monkeypatch, capsys):
        monkeypatch.setenv("IRONMESH_PORT", "abc")
        _run_main(monkeypatch, [])
        assert captured["port"] == 8767
        assert "IRONMESH_PORT='abc' is not an integer" in capsys.readouterr().err


def _frames(*msgs):
    return io.StringIO("".join(json.dumps(m) + "\n" for m in msgs))


def _replies(stdout):
    return {r["id"]: r for r in map(json.loads, stdout.getvalue().splitlines())}


class TestStdioFirstStartup:
    def test_initialize_and_list_answer_while_mesh_is_starting(self):
        stdin = _frames(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "ironmesh_get_mesh_stats", "arguments": {}}},
        )
        stdout = io.StringIO()
        never_ready = threading.Event()
        srv.serve(object(), None, stdin=stdin, stdout=stdout,
                  loop_ready=never_ready, loop_holder={},
                  mesh_wait_seconds=0.2)
        replies = _replies(stdout)
        assert replies[1]["result"]["serverInfo"] == srv.SERVER_INFO
        assert len(replies[2]["result"]["tools"]) == len(srv.TOOL_SPECS)
        text = replies[3]["result"]["content"][0]["text"]
        assert "still starting" in text

    def test_tools_call_reports_mesh_startup_failure(self):
        stdin = _frames(
            {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
             "params": {"name": "ironmesh_get_mesh_stats", "arguments": {}}},
        )
        stdout = io.StringIO()
        ready = threading.Event()
        ready.set()
        srv.serve(object(), None, stdin=stdin, stdout=stdout,
                  loop_ready=ready,
                  loop_holder={"error": OSError("port in use")})
        text = _replies(stdout)[7]["result"]["content"][0]["text"]
        assert "mesh daemon failed to start: port in use" in text


class _HeldOpenStdin:
    """A host that holds the pipe open but never writes a frame."""

    def __init__(self):
        self.release = threading.Event()

    def readline(self):
        self.release.wait(10)
        return ""


class TestInitWatchdog:
    def test_exits_when_host_never_speaks(self, monkeypatch):
        exited = []
        fired = threading.Event()

        def _fake_exit(code):
            exited.append(code)
            fired.set()

        monkeypatch.setattr(srv.os, "_exit", _fake_exit)
        stdin = _HeldOpenStdin()
        t = threading.Thread(
            target=srv.serve, args=(object(), None),
            kwargs=dict(stdin=stdin, stdout=io.StringIO(),
                        loop_ready=threading.Event(), loop_holder={},
                        init_timeout_seconds=0.2),
            daemon=True)
        t.start()
        try:
            assert fired.wait(5), "watchdog never fired"
            assert exited == [3]
        finally:
            stdin.release.set()
            t.join(5)

    @pytest.mark.parametrize("timeout", [-1, 0])
    def test_non_positive_timeout_never_fires(self, monkeypatch, timeout):
        # serve() is also callable directly; a non-positive value must mean
        # "no watchdog", never an immediate exit.
        exited = []
        monkeypatch.setattr(srv.os, "_exit", exited.append)
        stdin = _HeldOpenStdin()
        t = threading.Thread(
            target=srv.serve, args=(object(), None),
            kwargs=dict(stdin=stdin, stdout=io.StringIO(),
                        loop_ready=threading.Event(), loop_holder={},
                        init_timeout_seconds=timeout),
            daemon=True)
        t.start()
        try:
            threading.Event().wait(0.5)
            assert exited == []
        finally:
            stdin.release.set()
            t.join(5)

    def test_disarmed_once_the_host_speaks(self, monkeypatch):
        exited = []
        monkeypatch.setattr(srv.os, "_exit", exited.append)
        stdin = _frames({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                         "params": {}})
        srv.serve(object(), None, stdin=stdin, stdout=io.StringIO(),
                  loop_ready=threading.Event(), loop_holder={},
                  init_timeout_seconds=0.2)
        threading.Event().wait(0.5)
        assert exited == []
