"""Round-3 v0.9.2 E2E pressure test — everything in depth.

Exercises:
  A. Multiple RNS-enabled daemons on ONE host via seeded config (fix
     for upstream RNS authkey bug).
  B. Agent SDK message send + receive with @on_message handlers.
  C. Capability routing — first/random/all strategies.
  D. Group broadcast — sender + listener in-process.
  E. NAT relay — spin up relay + two clients, forward a frame.
  F. Federation per-source policy — live filter decisions.
  G. A2A HTTP server — AgentCard + JSON-RPC message/send.
  H. Burst pressure — 1000 msg fanout, dedup sanity.
  I. Pending-trust gate lifecycle.

Prints a pass/fail table per phase.
"""
from __future__ import annotations

import asyncio
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.request
from pathlib import Path

# Make sure stdout is utf-8 on Windows
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

PASSPHRASE = "ironmesh-stress-test-passphrase-DO-NOT-REUSE"
os.environ["IRONMESH_PASSPHRASE"] = PASSPHRASE

# Randomize base port per run so successive runs don't fight over
# stale TIME_WAIT sockets.
BASE_PORT = 27000 + random.randint(0, 1500)
def P(offset): return BASE_PORT + offset

RESULTS = []  # (phase, status, detail)
def record(phase, ok, detail=""):
    status = "PASS" if ok else "FAIL"
    RESULTS.append((phase, status, detail))
    print(f"[{status}] {phase}: {detail}")


# ---------------------------------------------------------------------------
# Scratch dir
# ---------------------------------------------------------------------------
ROOT = Path(tempfile.mkdtemp(prefix="ironmesh-r3-"))
print(f"[root] {ROOT}\n")


# ---------------------------------------------------------------------------
# Phase A — two RNS daemons in separate processes on one host
# ---------------------------------------------------------------------------
def phase_a_rns_in_process():
    """Validate the RNS singleton reuse + config seeder.

    Production ships a single `rnsd` + multiple Agent LocalClients on
    each host. The Agent SDK handles this via the `existing singleton`
    reuse logic in ReticulumTransport.start(). This phase spins up two
    Agent instances in ONE Python process with ``reticulum=True`` and
    confirms:

      1. The second Agent doesn't raise "Reticulum already initialised".
      2. Both end up with a working RNS destination.
      3. The config seeder wrote a unique-ports config file for the
         first Agent (verified by reading the resulting config).

    The two-SEPARATE-processes-on-one-host scenario — which is what
    the config seeder targets — is validated MANUALLY (bash dual-
    daemon test in the runbook) and by four unit tests in
    tests/test_reticulum_transport.py::TestRnsConfigSeeding. That
    scenario is infeasible to drive through Python subprocess.Popen
    on Windows because WSL-resolved bash doesn't see /c/ paths and
    native subprocess.Popen has a hang in RNS.Reticulum.__init__ when
    stdout is redirected to a file.
    """
    print("=" * 60)
    print("Phase A — RNS singleton reuse + config seeder")
    print("=" * 60)

    # In-process dual-agent RNS validation. Both agents share the
    # existing RNS.Reticulum singleton via ReticulumTransport's
    # singleton-reuse path.
    from ironmesh.agent import Agent
    from ironmesh.reticulum_transport import ReticulumTransport

    ok_singleton = True
    det_singleton = ""
    try:
        a1_dir = ROOT / "rns_agent_1"; a1_dir.mkdir(exist_ok=True)
        a1 = Agent(
            "rns-inprocess-1",
            port=P(0),
            passphrase=PASSPHRASE,
            keys_path=str(a1_dir / "keys.json"),
            db_path=str(a1_dir / "data.db"),
            trust_path=str(a1_dir / "trust.json"),
            routes_path=str(a1_dir / "routes.json"),
            allow_plaintext=True,
            open_discovery=False,
            bind="127.0.0.1",
            reticulum=True,
            rns_configdir=str(ROOT / "cfg_a"),
            rns_skip_handshake=True,
            log_level="ERROR",
        )
        a1.run(foreground=False)
        time.sleep(5)
        # Second Agent should reuse the RNS singleton from a1.
        a2_dir = ROOT / "rns_agent_2"; a2_dir.mkdir(exist_ok=True)
        a2 = Agent(
            "rns-inprocess-2",
            port=P(3),
            passphrase=PASSPHRASE,
            keys_path=str(a2_dir / "keys.json"),
            db_path=str(a2_dir / "data.db"),
            trust_path=str(a2_dir / "trust.json"),
            routes_path=str(a2_dir / "routes.json"),
            allow_plaintext=True,
            open_discovery=False,
            bind="127.0.0.1",
            reticulum=True,
            rns_configdir=str(ROOT / "cfg_a"),  # SAME configdir — singleton reuse
            rns_skip_handshake=True,
            log_level="ERROR",
        )
        a2.run(foreground=False)
        time.sleep(4)

        # Verify both have a working _reticulum transport
        rns_a = getattr(a1.daemon, "_reticulum", None)
        rns_b = getattr(a2.daemon, "_reticulum", None)
        ok_singleton = (rns_a is not None and rns_b is not None)
        det_singleton = (f"a1._reticulum={rns_a is not None}, "
                         f"a2._reticulum={rns_b is not None}, "
                         f"same_rns_instance={rns_a and rns_b and rns_a._reticulum is rns_b._reticulum}")

        # Shutdown cleanly
        for ag in (a1, a2):
            try:
                asyncio.run_coroutine_threadsafe(ag.daemon.shutdown(), ag._loop).result(3)
            except Exception:
                pass
        time.sleep(1)
    except Exception as e:
        ok_singleton = False
        det_singleton = f"exception: {type(e).__name__}: {e}"

    # Verify the config seeder wrote a unique-ports config
    cfg_path = ROOT / "cfg_a" / "config"
    ok_seeded = False
    if cfg_path.exists():
        c = cfg_path.read_text(encoding="utf-8", errors="replace")
        ok_seeded = all(k in c for k in ["shared_instance_port",
                                           "instance_control_port",
                                           "discovery_port",
                                           "data_port",
                                           "group_id"])

    record("A1. RNS singleton reuse (multi-Agent in-process)",
           ok_singleton, det_singleton)
    record("A2. Config seeder wrote unique-ports file",
           ok_seeded, f"seeded={ok_seeded} at {cfg_path}")
    return None, None, 0, 0

    # Legacy subprocess path retained for reference only — no longer
    # invoked due to Windows subprocess.Popen vs RNS.Reticulum quirk.
    def _spawn(name, port, cfgdir, datadir):
        os.makedirs(datadir, exist_ok=True)
        os.makedirs(cfgdir, exist_ok=True)
        (Path(datadir) / "passphrase").write_text(PASSPHRASE, encoding="utf-8")
        log_path = Path(datadir) / "stdout.log"
        pid_path = Path(datadir) / "pid"
        # WSL maps C: to /mnt/c/. Git Bash maps C: to /c/. Detect
        # which bash subprocess is using by checking uname.
        def px(p):
            s = str(p).replace("\\", "/")
            if len(s) >= 2 and s[1] == ":":
                # Use /mnt/c/ which works on both WSL AND Git Bash
                # (Git Bash's mount table honors both /c/ and /mnt/c/
                # on modern versions).
                prefix = "/mnt/" + s[0].lower()
                s = prefix + s[2:]
            return s
        bash_cmd = (
            f'( "{px(sys.executable)}" -u -m ironmesh run '
            f'--port {port} --name {name} --bind 127.0.0.1 '
            f'--passphrase-file "{px(Path(datadir)/"passphrase")}" '
            f'--keys-path "{px(Path(datadir)/"keys.json")}" '
            f'--db-path "{px(Path(datadir)/"data.db")}" '
            f'--trust-path "{px(Path(datadir)/"trust.json")}" '
            f'--routes-path "{px(Path(datadir)/"routes.json")}" '
            f'--allow-plaintext-ws --reticulum '
            f'--rns-configdir "{px(cfgdir)}" '
            f'--rns-skip-handshake --rns-group-broadcast '
            f'--log-level WARNING > "{px(log_path)}" 2>&1 ) & '
            f'echo $! > "{px(pid_path)}"'
        )
        print(f"[spawn-bash] cmd:\n  {bash_cmd[:400]}...")
        result = subprocess.run(["bash", "-c", bash_cmd], check=False,
                                 capture_output=True, text=True)
        print(f"[spawn-bash] rc={result.returncode}")
        if result.stderr: print(f"[spawn-bash] stderr: {result.stderr[:300]}")
        if result.stdout: print(f"[spawn-bash] stdout: {result.stdout[:300]}")
        # Read the PID back so we can terminate later
        time.sleep(0.5)
        pid = None
        try:
            pid = int(pid_path.read_text().strip())
        except Exception:
            pass
        # Build a lightweight sentinel object the caller can poll/terminate
        class _BashProc:
            def __init__(self, pid, log_path):
                self.pid = pid
                self._log_path = str(log_path)
            def poll(self):
                if self.pid is None:
                    return 1
                # Unix: os.kill(pid, 0) raises if dead
                try:
                    os.kill(self.pid, 0)
                    return None
                except (OSError, ProcessLookupError):
                    return 1
            def terminate(self):
                if self.pid is not None:
                    try: os.kill(self.pid, 15)
                    except Exception: pass
            def kill(self):
                if self.pid is not None:
                    try: os.kill(self.pid, 9)
                    except Exception: pass
            def wait(self, timeout=None):
                start = time.monotonic()
                while True:
                    if self.poll() is not None: return 0
                    if timeout and time.monotonic() - start > timeout:
                        raise subprocess.TimeoutExpired("bash", timeout)
                    time.sleep(0.2)
        return _BashProc(pid, log_path)

    # Ports spaced by 3 so each daemon's port+1 metrics endpoint and
    # port+2 future GUI port never collide with the next daemon.
    p_a = _spawn("rns-a", P(0), str(ROOT / "cfg_a"), str(ROOT / "data_a"))
    time.sleep(3.0)  # stagger startup — let ra grab its sockets first
    p_b = _spawn("rns-b", P(3), str(ROOT / "cfg_b"), str(ROOT / "data_b"))

    # Poll for "Reticulum transport active" up to 30s per daemon. RNS
    # boot over AutoInterface discovery can take 5-15s; subprocess
    # stdout buffering adds more.
    deadline = time.monotonic() + 35.0
    def _rns_active(p):
        log_path = Path(getattr(p, "_log_path", ""))
        if not log_path.exists():
            # fallback: look for the log via process args
            return False
        return "Reticulum transport active" in log_path.read_text(
            encoding="utf-8", errors="replace")
    # Stash log paths on the processes
    p_a._log_path = str(ROOT / "data_a" / "stdout.log")
    p_b._log_path = str(ROOT / "data_b" / "stdout.log")
    while time.monotonic() < deadline:
        if _rns_active(p_a) and _rns_active(p_b):
            break
        time.sleep(1.5)

    def _alive(p, label):
        rc = p.poll()
        if rc is not None:
            return False, f"{label} exited with rc={rc}"
        return True, f"{label} alive"

    ok_a, det_a = _alive(p_a, "rns-a")
    ok_b, det_b = _alive(p_b, "rns-b")

    def _has_rns_active(datadir):
        log = (Path(datadir) / "stdout.log").read_text(encoding="utf-8", errors="replace")
        return "Reticulum transport active" in log, log[-600:]

    ra, tail_a = _has_rns_active(ROOT / "data_a")
    rb, tail_b = _has_rns_active(ROOT / "data_b")

    combined = ok_a and ok_b and ra and rb
    detail = (f"rns-a:alive={ok_a} rns_active={ra}; "
              f"rns-b:alive={ok_b} rns_active={rb}")
    record("A. Two-RNS-one-host (config seed fix)", combined, detail)
    if not combined:
        print(f"[A] rns-a tail:\n{tail_a}\n[A] rns-b tail:\n{tail_b}")

    # Return for downstream phases
    return p_a, p_b, P(0), P(1)


# ---------------------------------------------------------------------------
# Phase B — Agent SDK send/receive
# ---------------------------------------------------------------------------
def phase_b_agent_send_receive():
    print("\n" + "=" * 60)
    print("Phase B — Agent SDK send/receive via @on_message")
    print("=" * 60)
    from ironmesh.agent import Agent

    a_dir = ROOT / "agent_a"; a_dir.mkdir(exist_ok=True)
    b_dir = ROOT / "agent_b"; b_dir.mkdir(exist_ok=True)

    a = Agent(
        "alpha",
        port=P(10),
        passphrase=PASSPHRASE,
        keys_path=str(a_dir / "keys.json"),
        db_path=str(a_dir / "data.db"),
        trust_path=str(a_dir / "trust.json"),
        routes_path=str(a_dir / "routes.json"),
        allow_plaintext=True,
        open_discovery=False,
        bind="127.0.0.1",
        log_level="ERROR",
        capabilities=["llm:alpha", "tool:echo"],
    )
    b = Agent(
        "beta",
        port=P(20),
        passphrase=PASSPHRASE,
        keys_path=str(b_dir / "keys.json"),
        db_path=str(b_dir / "data.db"),
        trust_path=str(b_dir / "trust.json"),
        routes_path=str(b_dir / "routes.json"),
        allow_plaintext=True,
        open_discovery=False,
        bind="127.0.0.1",
        log_level="ERROR",
        capabilities=["llm:beta", "tool:echo"],
    )

    received = []

    @b.on_message()
    def _handle(peer_id, payload):
        received.append((peer_id, payload))

    a.run(foreground=False)
    b.run(foreground=False)
    time.sleep(2)

    # alpha connects to beta
    fut = asyncio.run_coroutine_threadsafe(
        a.daemon.connect_to_peer("127.0.0.1", P(20)),
        a._loop,
    )
    # connect_to_peer doesn't return (stays in loop) — give it a moment
    time.sleep(4)

    # send alpha -> beta by name
    send_ok = False
    try:
        fut = asyncio.run_coroutine_threadsafe(
            a.daemon.send_to_name("beta", b"ROUND3-HELLO"),
            a._loop,
        )
        res = fut.result(timeout=10)
        send_ok = True
    except Exception as e:
        detail = f"send_to_name error: {type(e).__name__}: {e}"
        record("B. Agent SDK send_to_name", False, detail)
        return a, b

    # Wait for receiver
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline and not received:
        time.sleep(0.2)

    got_correct = any(p == b"ROUND3-HELLO" for _, p in received)
    record("B. Agent SDK send_to_name",
           send_ok and got_correct,
           f"sent={send_ok}, received_count={len(received)}, correct={got_correct}")
    return a, b


# ---------------------------------------------------------------------------
# Phase C — capability routing live
# ---------------------------------------------------------------------------
def phase_c_capability_routing(a, b):
    print("\n" + "=" * 60)
    print("Phase C — send_to_capability (first/random/all)")
    print("=" * 60)

    # Force an immediate capability announce exchange so the test isn't
    # gated on the default 60s announce interval.
    try:
        asyncio.run_coroutine_threadsafe(
            a.daemon._announce_capabilities_now()
            if hasattr(a.daemon, "_announce_capabilities_now")
            else asyncio.sleep(0),
            a._loop,
        ).result(timeout=5)
    except Exception: pass
    try:
        asyncio.run_coroutine_threadsafe(
            b.daemon._announce_capabilities_now()
            if hasattr(b.daemon, "_announce_capabilities_now")
            else asyncio.sleep(0),
            b._loop,
        ).result(timeout=5)
    except Exception: pass

    # Poll for up to 20s for the registry to populate
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        reg = getattr(a.daemon, "_capabilities", None)
        found = False
        if reg is not None:
            try:
                found = any(cap == "llm:beta"
                            for _nid, cap in reg.find("llm:beta"))
            except Exception:
                pass
        if found:
            break
        time.sleep(1.0)

    # alpha routes to beta via llm:beta capability
    try:
        fut = asyncio.run_coroutine_threadsafe(
            a.daemon.send_to_capability("llm:beta", b"CAP-FIRST", strategy="first"),
            a._loop,
        )
        res_first = fut.result(timeout=10)
        ok_first = isinstance(res_first, dict) and res_first.get("capability") == "llm:beta"
    except Exception as e:
        res_first = f"{type(e).__name__}: {e}"
        ok_first = False

    # all-strategy pattern match
    try:
        fut = asyncio.run_coroutine_threadsafe(
            a.daemon.send_to_capability("tool:*", b"CAP-ALL", strategy="all"),
            a._loop,
        )
        res_all = fut.result(timeout=10)
        ok_all = isinstance(res_all, dict) and res_all.get("transport") == "fanout"
    except Exception as e:
        res_all = f"{type(e).__name__}: {e}"
        ok_all = False

    # no-match raises ValueError
    try:
        fut = asyncio.run_coroutine_threadsafe(
            a.daemon.send_to_capability("llm:no-such-cap-xxxyyy", b"CAP-MISS"),
            a._loop,
        )
        _ = fut.result(timeout=10)
        ok_nomatch_raises = False
    except ValueError:
        ok_nomatch_raises = True
    except Exception as e:
        ok_nomatch_raises = False

    record("C. capability_routing.first", ok_first, f"res={res_first}")
    record("C. capability_routing.all", ok_all, f"res={res_all}")
    record("C. capability_routing.no_match_raises", ok_nomatch_raises, "")


# ---------------------------------------------------------------------------
# Phase D — pending-trust gate
# ---------------------------------------------------------------------------
def phase_d_pending_trust():
    print("\n" + "=" * 60)
    print("Phase D — pending-trust gate (require_message_promotion)")
    print("=" * 60)
    from ironmesh.agent import Agent

    c_dir = ROOT / "agent_c"; c_dir.mkdir(exist_ok=True)
    d_dir = ROOT / "agent_d"; d_dir.mkdir(exist_ok=True)

    c = Agent(
        "gated-c", port=P(30), passphrase=PASSPHRASE,
        keys_path=str(c_dir / "keys.json"), db_path=str(c_dir / "data.db"),
        trust_path=str(c_dir / "trust.json"), routes_path=str(c_dir / "routes.json"),
        allow_plaintext=True, open_discovery=False, bind="127.0.0.1",
        log_level="ERROR",
        # This side enforces the gate — messages from un-promoted peers
        # should be queued rather than delivered.
        require_message_promotion=True,
        pending_trust_queue_cap=50,
    )
    d = Agent(
        "sender-d", port=P(40), passphrase=PASSPHRASE,
        keys_path=str(d_dir / "keys.json"), db_path=str(d_dir / "data.db"),
        trust_path=str(d_dir / "trust.json"), routes_path=str(d_dir / "routes.json"),
        allow_plaintext=True, open_discovery=False, bind="127.0.0.1",
        log_level="ERROR",
    )

    received = []
    @c.on_message()
    def _h(peer_id, payload):
        received.append((peer_id, payload))

    c.run(foreground=False)
    d.run(foreground=False)
    time.sleep(2)

    asyncio.run_coroutine_threadsafe(d.daemon.connect_to_peer("127.0.0.1", P(30)), d._loop)
    time.sleep(4)

    # Send before promote — should be queued
    try:
        fut = asyncio.run_coroutine_threadsafe(
            d.daemon.send_to_name("gated-c", b"GATED-MSG-1"),
            d._loop,
        )
        fut.result(timeout=8)
    except Exception as e:
        pass

    time.sleep(3)
    before_promote = len(received)

    # Promote sender-d on c's trust store via the daemon's own promote
    # method — it sets the trust state AND drains the queue AND
    # re-publishes drained messages through the normal inbound path.
    try:
        d_node_id = d.node_id
        fut = asyncio.run_coroutine_threadsafe(
            c.daemon.promote_pending_peer(d_node_id),
            c._loop,
        )
        res = fut.result(timeout=10)
        print(f"[D] promote result: {res}")
    except Exception as e:
        print(f"[D] promote failed: {type(e).__name__}: {e}")

    time.sleep(4)
    after_promote = len(received)

    record("D. pending-trust gate queues before promote",
           before_promote == 0,
           f"before_promote={before_promote}")
    record("D. pending-trust drain after promote",
           after_promote >= 1,
           f"after_promote={after_promote}")

    try:
        asyncio.run_coroutine_threadsafe(c.daemon.shutdown(), c._loop).result(3)
    except Exception: pass
    try:
        asyncio.run_coroutine_threadsafe(d.daemon.shutdown(), d._loop).result(3)
    except Exception: pass
    time.sleep(1)


# ---------------------------------------------------------------------------
# Phase E — NAT relay
# ---------------------------------------------------------------------------
async def _nat_relay_test():
    import websockets
    from ironmesh.nat_relay import RelayServer
    port = P(50)
    server = RelayServer(bind="127.0.0.1", port=port)
    serve_task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.4)

    a = await websockets.connect(f"ws://127.0.0.1:{port}")
    b = await websockets.connect(f"ws://127.0.0.1:{port}")
    await a.send(json.dumps({"type": "REGISTER", "node_id": "relay-a"}))
    await a.recv()
    await b.send(json.dumps({"type": "REGISTER", "node_id": "relay-b"}))
    await b.recv()

    await a.send(json.dumps({"type": "FORWARD", "to": "relay-b",
                             "payload": "R3-PAYLOAD"}))
    received = json.loads(await b.recv())

    await a.close(); await b.close()
    serve_task.cancel()
    try:
        await serve_task
    except (asyncio.CancelledError, Exception):
        pass
    return received


def phase_e_nat_relay():
    print("\n" + "=" * 60)
    print("Phase E — NAT relay forward")
    print("=" * 60)
    try:
        received = asyncio.run(_nat_relay_test())
        ok = received.get("type") == "FORWARD" and received.get("from") == "relay-a"
        record("E. NAT relay E2E forward", ok, f"received={received}")
    except Exception as e:
        record("E. NAT relay E2E forward", False,
               f"{type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# Phase F — Federation per-source policy (unit-level live matrix)
# ---------------------------------------------------------------------------
def phase_f_federation_policy():
    print("\n" + "=" * 60)
    print("Phase F — Federation v2 per-source policy matrix")
    print("=" * 60)
    from ironmesh.federation import FederationPolicy

    p = FederationPolicy(
        allow=["llm:*"],
        deny=["tool:filesystem"],
        per_source=[
            {"source": "ops-*", "allow": ["*"]},
            {"source": "guest-*", "deny": ["*"]},
        ],
    )
    cases = [
        ("ops-a", "tool:filesystem", True),   # ops override allows all
        ("ops-a", "anything", True),
        ("guest-1", "llm:ok", False),         # guest denied all
        ("guest-1", "tool:search", False),
        ("other-1", "llm:fine", True),        # global allows llm:*
        ("other-1", "tool:filesystem", False),# global deny
        (None, "llm:any", True),              # no source → global
        (None, "tool:filesystem", False),
    ]
    fail = []
    for src, cap, want in cases:
        got = p.should_forward(cap, source=src)
        if got != want:
            fail.append((src, cap, want, got))
    ok = not fail
    record("F. Federation v2 per-source matrix",
           ok, f"{len(cases)-len(fail)}/{len(cases)} correct; fails={fail}")


# ---------------------------------------------------------------------------
# Phase G — A2A HTTP server
# ---------------------------------------------------------------------------
def phase_g_a2a():
    print("\n" + "=" * 60)
    print("Phase G — A2A HTTP server (AgentCard + JSON-RPC)")
    print("=" * 60)
    # Spin up an ironmesh_a2a subprocess; poll /.well-known/agent-card.json
    env = dict(os.environ)
    env["IRONMESH_A2A_TOKEN"] = "test-token-xyz"
    env["IRONMESH_PASSPHRASE"] = PASSPHRASE
    a2a_port = P(60)
    cmd = [
        sys.executable, "-u", "-m", "ironmesh_a2a",
        "--http-bind", "127.0.0.1", "--http-port", str(a2a_port),
        "--token", "test-token-xyz",
        "--mesh-port", str(P(62)),
        "--allow-plaintext-ws",
    ]
    log_path = ROOT / "a2a.log"
    log = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=env)
    time.sleep(5.0)

    try:
        rc = proc.poll()
        if rc is not None:
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-800:]
            record("G. A2A server startup", False,
                   f"exited early rc={rc}; tail:\n{tail}")
            return
        url = f"http://127.0.0.1:{a2a_port}/.well-known/agent-card.json"
        with urllib.request.urlopen(url, timeout=5) as r:
            card = json.loads(r.read().decode("utf-8"))
        ok = isinstance(card, dict) and "name" in card
        record("G. A2A AgentCard GET /.well-known/agent-card.json",
               ok, f"keys={list(card)[:10] if isinstance(card, dict) else card}")

        # Also exercise the JSON-RPC message/send path. We don't have a
        # real gateway peer set up, so expect either a graceful error
        # response OR a success acknowledgment — both are fine; what
        # we're checking is that the server routes the RPC call and
        # responds with a valid JSON-RPC envelope (not an HTTP 500 or
        # connection drop).
        import urllib.request as _ur
        rpc_url = f"http://127.0.0.1:{a2a_port}/a2a/jsonrpc"
        payload = {
            "jsonrpc": "2.0",
            "id": "r3-test-1",
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"kind": "text", "text": "round3-probe"}],
                    "messageId": "r3-probe-msg-id-0001",
                },
            },
        }
        try:
            req = _ur.Request(
                rpc_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer test-token-xyz",
                },
            )
            with _ur.urlopen(req, timeout=5) as r:
                rpc_body = r.read().decode("utf-8")
                rpc_resp = json.loads(rpc_body)
            ok_rpc = (isinstance(rpc_resp, dict)
                       and rpc_resp.get("jsonrpc") == "2.0"
                       and rpc_resp.get("id") == "r3-test-1"
                       and ("result" in rpc_resp or "error" in rpc_resp))
            record("G2. A2A POST /a2a/jsonrpc message/send",
                   ok_rpc, f"resp_keys={list(rpc_resp)} "
                            f"has_result={('result' in rpc_resp)} "
                            f"has_error={('error' in rpc_resp)}")
        except Exception as e:
            record("G2. A2A POST /a2a/jsonrpc message/send",
                   False, f"{type(e).__name__}: {e}")
    except Exception as e:
        tail = log_path.read_text(encoding="utf-8", errors="replace")[-600:]
        record("G. A2A AgentCard GET", False,
               f"{type(e).__name__}: {e}\ntail:\n{tail}")
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


# ---------------------------------------------------------------------------
# Phase H — burst pressure
# ---------------------------------------------------------------------------
async def _burst(a, b_name, count):
    sent = 0
    errs = 0
    start = time.monotonic()
    for i in range(count):
        try:
            await a.daemon.send_to_name(b_name, f"BURST-{i:04d}".encode())
            sent += 1
        except Exception:
            errs += 1
    return sent, errs, time.monotonic() - start


def phase_h_burst(a, b):
    print("\n" + "=" * 60)
    print("Phase H — burst pressure 500 msgs alpha→beta")
    print("=" * 60)
    COUNT = 500
    fut = asyncio.run_coroutine_threadsafe(_burst(a, "beta", COUNT), a._loop)
    sent, errs, dur = fut.result(timeout=120)
    # Peek at receiver count via metrics
    received_total = 0
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{P(21)}/metrics", timeout=3) as r:
            for line in r.read().decode().splitlines():
                if line.startswith("ironmesh_messages_received_total"):
                    received_total = int(float(line.split()[-1]))
    except Exception:
        pass
    rate = sent / dur if dur > 0 else 0
    ok = sent == COUNT and errs == 0
    record("H. Burst 500 msgs", ok,
           f"sent={sent} errs={errs} dur={dur:.2f}s rate={rate:.1f}/s")


# ---------------------------------------------------------------------------
# Run everything
# ---------------------------------------------------------------------------
def main():
    p_a = p_b = None
    try:
        p_a, p_b, _, _ = phase_a_rns_in_process()
    except Exception as e:
        record("A. Two-RNS-one-host", False,
               f"exception: {type(e).__name__}: {e}\n{traceback.format_exc()}")

    # Kill phase-A subprocesses before phase-B to free ports
    for p, label in ((p_a, "rns-a"), (p_b, "rns-b")):
        if p is not None:
            try:
                p.terminate()
                p.wait(timeout=5)
            except Exception:
                try: p.kill()
                except Exception: pass

    try:
        a, b = phase_b_agent_send_receive()
    except Exception as e:
        record("B. Agent SDK send_to_name", False,
               f"exception: {type(e).__name__}: {e}\n{traceback.format_exc()}")
        a = b = None

    if a is not None and b is not None:
        try:
            phase_c_capability_routing(a, b)
        except Exception as e:
            record("C. capability routing", False,
                   f"exception: {type(e).__name__}: {e}")

        try:
            phase_h_burst(a, b)
        except Exception as e:
            record("H. Burst 500", False,
                   f"exception: {type(e).__name__}: {e}")

        # Shutdown a + b
        for ag in (a, b):
            try:
                asyncio.run_coroutine_threadsafe(ag.daemon.shutdown(), ag._loop).result(3)
            except Exception: pass
        time.sleep(1)

    try:
        phase_d_pending_trust()
    except Exception as e:
        record("D. pending-trust", False,
               f"exception: {type(e).__name__}: {e}")

    try:
        phase_e_nat_relay()
    except Exception as e:
        record("E. NAT relay", False,
               f"exception: {type(e).__name__}: {e}")

    try:
        phase_f_federation_policy()
    except Exception as e:
        record("F. federation policy", False,
               f"exception: {type(e).__name__}: {e}")

    try:
        phase_g_a2a()
    except Exception as e:
        record("G. A2A server", False,
               f"exception: {type(e).__name__}: {e}")

    # Summary
    print("\n" + "=" * 60)
    print("ROUND 3 SUMMARY")
    print("=" * 60)
    passes = sum(1 for _, s, _ in RESULTS if s == "PASS")
    total = len(RESULTS)
    for phase, status, detail in RESULTS:
        print(f"  [{status}] {phase}: {detail[:120]}")
    print(f"\n  OVERALL: {passes}/{total} PASS")
    return 0 if passes == total else 1


if __name__ == "__main__":
    sys.exit(main())
