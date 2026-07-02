"""RNS link-binding tests (protocol ironmesh/0.9, Reticulum transport).

On RNS Links, 0.9+ peers bind their HELLO to the id of the specific
RNS Link it travels on: ``rns_link_id`` rides inside the signed HELLO
canonical body, and receivers reject any HELLO whose claimed link id
does not match the link it actually arrived on. The stage-1 handshake
skip REFUSES to run without a verified binding. The WebSocket path
never carries the field and rejects it if present.

These tests cover four layers:

1. ``protocol.canonical_hello_bytes`` — the optional sixth key, and
   byte-compatibility of the five-key form.
2. ``RNSLinkAdapter.link_id_hex`` — deriving the binding value from
   the underlying link.
3. The pure policy helpers (``_rns_hello_link_binding`` /
   ``_evaluate_rns_hello_binding``) plus the skip-eligibility gate.
4. Wire level against real daemon code — scripted RNS peers on both
   sides of the handshake, driven over an in-memory adapter (no RNS
   hardware; follows the scripted-peer style of
   test_hello_domain_separation.py).
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import socket
import tempfile
import time
from unittest.mock import MagicMock

import pytest

from ironmesh import Agent
from ironmesh import crypto as ew_crypto
from ironmesh import keys as ew_keys
from ironmesh import protocol as ew_protocol
from ironmesh.bridge import BridgeDaemon
from ironmesh.handshake import PROTOCOL_VERSION, RNSLinkAdapter

PASSPHRASE = "rns-link-binding-test-passphrase"
LEGACY_VERSION = "ironmesh/0.8"
LINK_ID = bytes(range(16))
LINK_ID_HEX = LINK_ID.hex()
OTHER_LINK_ID_HEX = (b"\xff" * 16).hex()
IDENTITY_HASH = "cd" * 16


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _mk_agent(name: str) -> Agent:
    tmp = tempfile.mkdtemp(prefix=f"rns-bind-{name}-")
    a = Agent(
        name,
        port=_free_port(),
        passphrase=PASSPHRASE,
        bind="127.0.0.1",
        open_discovery=False,
        allow_plaintext=True,
        keys_path=os.path.join(tmp, "k.json"),
        db_path=os.path.join(tmp, "d.db"),
        routes_path=os.path.join(tmp, "r.json"),
        capabilities_path=os.path.join(tmp, "c.json"),
    )
    a.run(foreground=False)
    return a


def _wait_sync(pred, timeout: float = 15.0, step: float = 0.1) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(step)
    return False


class _ScriptedIdentity:
    def __init__(self):
        from nacl.signing import SigningKey
        self.sk = SigningKey.generate()
        self.identity_b64 = base64.b64encode(bytes(self.sk.verify_key)).decode()
        self.node_id = ew_keys.get_fingerprint(bytes(self.sk.verify_key))
        _, eph_pub = ew_keys.generate_ephemeral()
        self.eph_b64 = base64.b64encode(bytes(eph_pub)).decode()
        self.name = "scripted-rns-peer"


class ScriptedRNSAdapter(RNSLinkAdapter):
    """In-memory RNSLinkAdapter double for driving real handshake code.

    Subclasses the real adapter class so ``isinstance`` checks inside
    the daemon take the RNS path, but replaces the constructor and the
    I/O surface with two asyncio queues: ``to_daemon`` feeds the
    daemon's ``recv()``/``async for``; everything the daemon ``send()``s
    is JSON-decoded into ``from_daemon``.
    """

    def __init__(self, link_id_hex=LINK_ID_HEX,
                 identity_hash=IDENTITY_HASH, dest_hash_hex="ab" * 16):
        # Deliberately does NOT call super().__init__ — no RNS needed.
        self._link_id_val = link_id_hex
        self.remote_identity_hash = identity_hash
        self._dest_hash_hex = dest_hash_hex
        self._closed = False
        self.peer_id = None
        self.peer_supports_resource = False
        self.to_daemon: asyncio.Queue = asyncio.Queue()
        self.from_daemon: asyncio.Queue = asyncio.Queue()

    @property
    def link_id_hex(self):
        return self._link_id_val

    @property
    def remote_address(self):
        return (f"rns:{self._dest_hash_hex}", 0)

    @property
    def open(self):
        return not self._closed

    async def send(self, data) -> None:
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        self.from_daemon.put_nowait(json.loads(data))

    async def recv(self):
        import websockets
        item = await self.to_daemon.get()
        if item is None:
            raise websockets.ConnectionClosed(None, None)
        return item

    async def close(self) -> None:
        self._closed = True

    def __aiter__(self):
        return self

    async def __anext__(self):
        import websockets
        try:
            return await self.recv()
        except websockets.ConnectionClosed:
            raise StopAsyncIteration


# ---------------------------------------------------------------------------
# 1. Canonicalization — the optional sixth key
# ---------------------------------------------------------------------------

class TestCanonicalRnsLinkId:
    def _kwargs(self):
        return {
            "channel_binding": "aa" * 32,
            "ephemeral_public": base64.b64encode(b"e" * 32).decode(),
            "identity_public": base64.b64encode(b"i" * 32).decode(),
            "name": "sample-agent",
            "protocol_version": PROTOCOL_VERSION,
        }

    def test_none_is_byte_identical_to_five_key_form(self):
        # The WebSocket path and pre-0.9 RNS peers must keep producing
        # the exact bytes they produced before the field existed.
        base = ew_protocol.canonical_hello_bytes(**self._kwargs())
        with_none = ew_protocol.canonical_hello_bytes(
            **self._kwargs(), rns_link_id=None,
        )
        assert base == with_none
        assert b"rns_link_id" not in base

    def test_link_id_is_covered_by_canonical_bytes(self):
        base = ew_protocol.canonical_hello_bytes(**self._kwargs())
        bound = ew_protocol.canonical_hello_bytes(
            **self._kwargs(), rns_link_id=LINK_ID_HEX,
        )
        assert bound != base
        other = ew_protocol.canonical_hello_bytes(
            **self._kwargs(), rns_link_id=OTHER_LINK_ID_HEX,
        )
        assert other != bound

    def test_link_id_sorted_into_compact_json(self):
        bound = ew_protocol.canonical_hello_bytes(
            **self._kwargs(), rns_link_id=LINK_ID_HEX,
        )
        kwargs = self._kwargs()
        expected = json.dumps(
            {**kwargs, "rns_link_id": LINK_ID_HEX},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        assert bound == expected

    def test_rejects_empty_or_non_string_link_id(self):
        with pytest.raises(ValueError):
            ew_protocol.canonical_hello_bytes(**self._kwargs(), rns_link_id="")
        with pytest.raises(ValueError):
            ew_protocol.canonical_hello_bytes(
                **self._kwargs(), rns_link_id=123,  # type: ignore[arg-type]
            )


# ---------------------------------------------------------------------------
# 2. RNSLinkAdapter.link_id_hex
# ---------------------------------------------------------------------------

class TestLinkIdHexProperty:
    def _bare_adapter(self, link):
        adapter = RNSLinkAdapter.__new__(RNSLinkAdapter)
        adapter._link = link
        return adapter

    def test_bytes_link_id_becomes_hex(self):
        link = MagicMock()
        link.link_id = LINK_ID
        assert self._bare_adapter(link).link_id_hex == LINK_ID_HEX

    def test_missing_or_non_bytes_link_id_is_none(self):
        link = MagicMock()
        link.link_id = None
        assert self._bare_adapter(link).link_id_hex is None
        link.link_id = "not-bytes"
        assert self._bare_adapter(link).link_id_hex is None
        link.link_id = b""
        assert self._bare_adapter(link).link_id_hex is None

    def test_no_link_is_none(self):
        assert self._bare_adapter(None).link_id_hex is None


# ---------------------------------------------------------------------------
# 3. Policy helpers
# ---------------------------------------------------------------------------

class _FakeBridge:
    """Bind the real binding helpers from BridgeDaemon onto a stub —
    same harness pattern as test_handshake_skip.py."""

    def __init__(self):
        self._rns_require_link_binding = False
        self._rns_skip_handshake = False
        self._rns_discovered = {}
        self._rns_hello_link_binding = (
            BridgeDaemon._rns_hello_link_binding.__get__(self)
        )
        self._evaluate_rns_hello_binding = (
            BridgeDaemon._evaluate_rns_hello_binding.__get__(self)
        )
        self._peer_advertises_hskip = (
            BridgeDaemon._peer_advertises_hskip.__get__(self)
        )
        self._handshake_skip_eligible_server = (
            BridgeDaemon._handshake_skip_eligible_server.__get__(self)
        )


def _rns_ws(link_id_hex=LINK_ID_HEX):
    ws = MagicMock(spec=RNSLinkAdapter)
    ws.link_id_hex = link_id_hex
    ws.remote_identity_hash = IDENTITY_HASH
    return ws


class TestSenderBindingHelper:
    def test_websocket_never_binds(self):
        bridge = _FakeBridge()
        plain_ws = MagicMock()  # not an RNSLinkAdapter
        assert bridge._rns_hello_link_binding(plain_ws, PROTOCOL_VERSION) is None

    def test_rns_to_new_peer_binds_local_link_id(self):
        bridge = _FakeBridge()
        assert (bridge._rns_hello_link_binding(_rns_ws(), PROTOCOL_VERSION)
                == LINK_ID_HEX)

    def test_rns_to_legacy_peer_omits_binding(self):
        # Pre-0.9 peers reconstruct the five-key canonical body; a
        # sixth key would fail their signature verification.
        bridge = _FakeBridge()
        assert bridge._rns_hello_link_binding(_rns_ws(), LEGACY_VERSION) is None

    def test_unreadable_link_id_omits_binding(self):
        bridge = _FakeBridge()
        assert bridge._rns_hello_link_binding(
            _rns_ws(link_id_hex=None), PROTOCOL_VERSION,
        ) is None


class TestReceiverBindingPolicy:
    def test_websocket_without_field_ok(self):
        bridge = _FakeBridge()
        ok, claimed, _ = bridge._evaluate_rns_hello_binding(
            MagicMock(), {}, PROTOCOL_VERSION, False,
        )
        assert ok is True
        assert claimed is None

    def test_websocket_with_field_rejected(self):
        # Explicit rule: the binding field is RNS-only.
        bridge = _FakeBridge()
        ok, _, reason = bridge._evaluate_rns_hello_binding(
            MagicMock(), {"rns_link_id": LINK_ID_HEX}, PROTOCOL_VERSION, False,
        )
        assert ok is False
        assert "Reticulum" in reason

    def test_rns_matching_claim_ok_and_returned_for_canonical(self):
        bridge = _FakeBridge()
        ok, claimed, _ = bridge._evaluate_rns_hello_binding(
            _rns_ws(), {"rns_link_id": LINK_ID_HEX}, PROTOCOL_VERSION, False,
        )
        assert ok is True
        assert claimed == LINK_ID_HEX

    def test_rns_mismatched_claim_rejected(self):
        bridge = _FakeBridge()
        ok, _, reason = bridge._evaluate_rns_hello_binding(
            _rns_ws(), {"rns_link_id": OTHER_LINK_ID_HEX},
            PROTOCOL_VERSION, False,
        )
        assert ok is False
        assert "does not match" in reason

    def test_rns_malformed_claim_rejected(self):
        bridge = _FakeBridge()
        for bad in ("", 12345, ["x"]):
            ok, _, _ = bridge._evaluate_rns_hello_binding(
                _rns_ws(), {"rns_link_id": bad}, PROTOCOL_VERSION, False,
            )
            assert ok is False, bad

    def test_rns_claim_with_unreadable_local_link_rejected(self):
        bridge = _FakeBridge()
        ok, _, _ = bridge._evaluate_rns_hello_binding(
            _rns_ws(link_id_hex=None), {"rns_link_id": LINK_ID_HEX},
            PROTOCOL_VERSION, False,
        )
        assert ok is False

    def test_rns_absent_from_new_peer_rejected(self):
        # The 0.9 RNS contract: 0.9+ peers MUST bind.
        bridge = _FakeBridge()
        ok, _, reason = bridge._evaluate_rns_hello_binding(
            _rns_ws(), {}, PROTOCOL_VERSION, False,
        )
        assert ok is False
        assert "0.9" in reason

    def test_rns_absent_from_legacy_peer_allowed_by_default(self):
        # Legacy peers keep the pre-0.9 behavior; the residual note in
        # SECURITY.md stays scoped to exactly this case.
        bridge = _FakeBridge()
        ok, claimed, _ = bridge._evaluate_rns_hello_binding(
            _rns_ws(), {}, LEGACY_VERSION, False,
        )
        assert ok is True
        assert claimed is None

    def test_rns_absent_from_legacy_peer_rejected_when_required(self):
        bridge = _FakeBridge()
        bridge._rns_require_link_binding = True
        ok, _, reason = bridge._evaluate_rns_hello_binding(
            _rns_ws(), {}, LEGACY_VERSION, False,
        )
        assert ok is False
        assert "rns_require_link_binding" in reason

    def test_skip_path_requires_binding_regardless_of_version(self):
        bridge = _FakeBridge()
        for version in (PROTOCOL_VERSION, LEGACY_VERSION, ""):
            ok, _, reason = bridge._evaluate_rns_hello_binding(
                _rns_ws(), {}, version, True,
            )
            assert ok is False, version
            assert "skip" in reason


class TestSkipEligibilityRequiresLinkId:
    def test_server_does_not_offer_skip_without_local_link_id(self):
        bridge = _FakeBridge()
        bridge._rns_skip_handshake = True
        bridge._rns_discovered = {
            "x": {"identity_hash": IDENTITY_HASH, "features": ["hskip"]},
        }
        assert bridge._handshake_skip_eligible_server(
            _rns_ws(link_id_hex=None)) is False
        assert bridge._handshake_skip_eligible_server(_rns_ws()) is True


# ---------------------------------------------------------------------------
# 4a. Wire level — scripted RNS clients against a real daemon (server side)
# ---------------------------------------------------------------------------

async def _drive_scripted_client(
    adapter: ScriptedRNSAdapter,
    *,
    version: str = PROTOCOL_VERSION,
    binding: str | None = "correct",
    sign_mode: str | None = "context",
) -> dict:
    """Speak the client half of the handshake over the adapter queues.

    ``binding``: "correct" (bind to the adapter's link id), a literal
    hex string (bind to that), or None (omit the field entirely).
    ``sign_mode``: "context", "legacy", or None (unsigned HELLO).
    """
    ident = _ScriptedIdentity()
    out: dict = {"identity": ident}
    first = await asyncio.wait_for(adapter.from_daemon.get(), 15)
    out["first"] = first
    if first["type"] == "SKIP_OFFER":
        nonce = bytes.fromhex(first["channel_binding"])
    else:
        assert first["type"] == "PASSPHRASE_CHALLENGE", first
        nonce = bytes.fromhex(first["nonce"])
        proof = ew_protocol.Handshake.compute_passphrase_proof(
            PASSPHRASE, nonce,
        )
        adapter.to_daemon.put_nowait(json.dumps({
            "type": "PASSPHRASE_CHALLENGE",
            "from": ident.node_id,
            "proof": proof,
        }))
        verified = await asyncio.wait_for(adapter.from_daemon.get(), 15)
        assert verified["type"] == "PASSPHRASE_VERIFIED", verified

    link_binding = adapter.link_id_hex if binding == "correct" else binding
    canonical = ew_protocol.canonical_hello_bytes(
        channel_binding=nonce.hex(),
        ephemeral_public=ident.eph_b64,
        identity_public=ident.identity_b64,
        name=ident.name,
        protocol_version=version,
        rns_link_id=link_binding,
    )
    hello = {
        "type": "HELLO",
        "from": ident.node_id,
        "name": ident.name,
        "ephemeral_public": ident.eph_b64,
        "protocol_version": version,
        "channel_binding": nonce.hex(),
    }
    if link_binding is not None:
        hello["rns_link_id"] = link_binding
    if sign_mode == "context":
        sig = ew_crypto.sign_detached_with_context(
            ident.sk, ew_crypto.SIG_CTX_HELLO, canonical,
        )
        hello["identity_public"] = ident.identity_b64
        hello["signature"] = base64.b64encode(sig).decode()
    elif sign_mode == "legacy":
        sig = ew_crypto.sign_message(ident.sk, canonical)
        hello["identity_public"] = ident.identity_b64
        hello["signature"] = base64.b64encode(sig).decode()
    # sign_mode None → unsigned HELLO (no identity, no signature)
    adapter.to_daemon.put_nowait(json.dumps(hello))
    out["reply"] = await asyncio.wait_for(adapter.from_daemon.get(), 15)
    return out


def _wait_loop(agent: Agent) -> None:
    assert _wait_sync(
        lambda: getattr(agent, "_loop", None) is not None
        and agent._loop.is_running()
    ), "agent loop never started"


def _run_server_session(agent: Agent, adapter: ScriptedRNSAdapter, **kw) -> dict:
    """Run _handle_connection + the scripted client on the daemon loop."""
    _wait_loop(agent)
    agent.daemon._ip_rate_limiters.clear()

    async def _session():
        server_task = asyncio.ensure_future(
            agent.daemon._handle_connection(adapter),
        )
        try:
            out = await asyncio.wait_for(
                _drive_scripted_client(adapter, **kw), 25,
            )
        finally:
            adapter.to_daemon.put_nowait(None)  # end the message loop
            try:
                await asyncio.wait_for(server_task, 15)
            except Exception:
                pass
        return out

    fut = asyncio.run_coroutine_threadsafe(_session(), agent._loop)
    return fut.result(timeout=60)


@pytest.fixture(scope="class")
def server_agent():
    a = _mk_agent("rns-bind-server")
    yield a
    a.stop()


class TestServerSideWire:
    def test_bound_hello_accepted_and_server_binds_back(self, server_agent):
        adapter = ScriptedRNSAdapter()
        out = _run_server_session(server_agent, adapter, binding="correct")
        reply = out["reply"]
        assert reply["type"] == "HELLO", reply
        node_id = out["identity"].node_id
        assert node_id in server_agent.daemon.peers
        peer = server_agent.daemon.peers[node_id]
        assert peer.hello_sig_scheme == "context-v1"
        assert peer.transport_type == "rns"
        # The server's HELLO must carry ITS binding for the same link,
        # covered by its context signature — verify at the byte level.
        assert reply["rns_link_id"] == LINK_ID_HEX
        from nacl.signing import VerifyKey
        verify_key = VerifyKey(base64.b64decode(reply["identity_public"]))
        canonical = ew_protocol.canonical_hello_bytes(
            channel_binding=reply["channel_binding"],
            ephemeral_public=reply["ephemeral_public"],
            identity_public=reply["identity_public"],
            name=reply["name"],
            protocol_version=reply["protocol_version"],
            rns_link_id=reply["rns_link_id"],
        )
        assert ew_crypto.verify_detached_with_context(
            verify_key, ew_crypto.SIG_CTX_HELLO, canonical,
            base64.b64decode(reply["signature"]),
        )

    def test_mismatched_binding_rejected(self, server_agent):
        adapter = ScriptedRNSAdapter()
        out = _run_server_session(
            server_agent, adapter, binding=OTHER_LINK_ID_HEX,
        )
        assert out["reply"]["type"] == "ERROR"
        assert out["reply"]["code"] == "AUTH_FAILED"
        assert out["identity"].node_id not in server_agent.daemon.peers

    def test_new_peer_without_binding_rejected(self, server_agent):
        adapter = ScriptedRNSAdapter()
        out = _run_server_session(server_agent, adapter, binding=None)
        assert out["reply"]["type"] == "ERROR"
        assert out["reply"]["code"] == "AUTH_FAILED"
        assert out["identity"].node_id not in server_agent.daemon.peers

    def test_legacy_peer_without_binding_keeps_working(self, server_agent):
        # Mixed-version behavior, explicit: pre-0.9 RNS peers cannot
        # produce the binding and stay on the legacy path by default.
        adapter = ScriptedRNSAdapter()
        out = _run_server_session(
            server_agent, adapter, version=LEGACY_VERSION,
            binding=None, sign_mode="legacy",
        )
        assert out["reply"]["type"] == "HELLO"
        node_id = out["identity"].node_id
        assert node_id in server_agent.daemon.peers
        assert server_agent.daemon.peers[node_id].hello_sig_scheme == "legacy"
        # And the server's reply to a legacy peer keeps the five-key
        # canonical body (no binding field the peer can't verify).
        assert "rns_link_id" not in out["reply"]

    def test_legacy_peer_rejected_when_binding_required(self, server_agent):
        server_agent.daemon._rns_require_link_binding = True
        try:
            adapter = ScriptedRNSAdapter()
            out = _run_server_session(
                server_agent, adapter, version=LEGACY_VERSION,
                binding=None, sign_mode="legacy",
            )
            assert out["reply"]["type"] == "ERROR"
            assert out["reply"]["code"] == "AUTH_FAILED"
            assert out["identity"].node_id not in server_agent.daemon.peers
        finally:
            server_agent.daemon._rns_require_link_binding = False


class TestServerSideSkipWire:
    """Stage-1 skip: the server offers, and the post-skip HELLO must be
    signed AND bound or the connection is rejected."""

    def _enable_skip(self, agent, adapter):
        agent.daemon._rns_skip_handshake = True
        agent.daemon._rns_discovered = {
            adapter._dest_hash_hex: {
                "identity_hash": adapter.remote_identity_hash,
                "features": ["hskip"],
                "node_id": "scripted",
            },
        }

    def _disable_skip(self, agent):
        agent.daemon._rns_skip_handshake = False
        agent.daemon._rns_discovered = {}

    def test_skip_with_bound_signed_hello_accepted(self, server_agent):
        adapter = ScriptedRNSAdapter()
        self._enable_skip(server_agent, adapter)
        try:
            out = _run_server_session(server_agent, adapter, binding="correct")
            assert out["first"]["type"] == "SKIP_OFFER"
            assert out["reply"]["type"] == "HELLO"
            node_id = out["identity"].node_id
            assert node_id in server_agent.daemon.peers
            assert (server_agent.daemon.peers[node_id].hello_sig_scheme
                    == "context-v1")
        finally:
            self._disable_skip(server_agent)

    def test_skip_refused_without_binding(self, server_agent):
        adapter = ScriptedRNSAdapter()
        self._enable_skip(server_agent, adapter)
        try:
            out = _run_server_session(server_agent, adapter, binding=None)
            assert out["first"]["type"] == "SKIP_OFFER"
            assert out["reply"]["type"] == "ERROR"
            assert out["identity"].node_id not in server_agent.daemon.peers
        finally:
            self._disable_skip(server_agent)

    def test_skip_refused_for_unsigned_hello(self, server_agent):
        adapter = ScriptedRNSAdapter()
        self._enable_skip(server_agent, adapter)
        try:
            out = _run_server_session(
                server_agent, adapter, binding="correct", sign_mode=None,
            )
            assert out["first"]["type"] == "SKIP_OFFER"
            assert out["reply"]["type"] == "ERROR"
        finally:
            self._disable_skip(server_agent)

    def test_skip_not_offered_when_link_id_unreadable(self, server_agent):
        # Eligibility falls back to the full handshake when the local
        # link id can't be read — the client then sees a normal
        # PASSPHRASE_CHALLENGE, not a doomed SKIP_OFFER.
        adapter = ScriptedRNSAdapter(link_id_hex=None)
        self._enable_skip(server_agent, adapter)
        try:
            out = _run_server_session(
                server_agent, adapter, version=LEGACY_VERSION,
                binding=None, sign_mode="legacy",
            )
            assert out["first"]["type"] == "PASSPHRASE_CHALLENGE"
        finally:
            self._disable_skip(server_agent)


# ---------------------------------------------------------------------------
# 4b. Wire level — real daemon as client against scripted RNS servers
# ---------------------------------------------------------------------------

async def _drive_scripted_server(
    adapter: ScriptedRNSAdapter,
    *,
    version: str = PROTOCOL_VERSION,
    offer_skip: bool = False,
    binding: str | None = "correct",
    sign_mode: str = "context",
    stop_after_offer: bool = False,
) -> dict:
    """Speak the server half over the adapter queues."""
    ident = _ScriptedIdentity()
    rec: dict = {"identity": ident}
    if offer_skip:
        nonce = ew_protocol.Handshake.skip_channel_binding()
        adapter.to_daemon.put_nowait(json.dumps({
            "type": "SKIP_OFFER",
            "from": ident.node_id,
            "channel_binding": nonce.hex(),
            "protocol_version": version,
        }))
        if stop_after_offer:
            return rec  # refusal cases: the client sends nothing back
    else:
        nonce = ew_protocol.Handshake.generate_server_nonce()
        adapter.to_daemon.put_nowait(json.dumps({
            "type": "PASSPHRASE_CHALLENGE",
            "from": ident.node_id,
            "nonce": nonce.hex(),
            "protocol_version": version,
        }))
        proof_msg = await asyncio.wait_for(adapter.from_daemon.get(), 15)
        assert ew_protocol.Handshake.verify_passphrase_proof(
            proof_msg["proof"], PASSPHRASE, nonce,
        )
        adapter.to_daemon.put_nowait(json.dumps({
            "type": "PASSPHRASE_VERIFIED",
            "from": ident.node_id,
            "status": "verified",
            "server_proof": ew_protocol.Handshake.compute_passphrase_proof(
                PASSPHRASE, nonce[::-1],
            ),
        }))
    rec["client_hello"] = await asyncio.wait_for(adapter.from_daemon.get(), 15)
    rec["nonce_hex"] = nonce.hex()

    link_binding = adapter.link_id_hex if binding == "correct" else binding
    canonical = ew_protocol.canonical_hello_bytes(
        channel_binding=nonce.hex(),
        ephemeral_public=ident.eph_b64,
        identity_public=ident.identity_b64,
        name=ident.name,
        protocol_version=version,
        rns_link_id=link_binding,
    )
    if sign_mode == "context":
        sig = ew_crypto.sign_detached_with_context(
            ident.sk, ew_crypto.SIG_CTX_HELLO, canonical,
        )
    else:
        sig = ew_crypto.sign_message(ident.sk, canonical)
    hello = {
        "type": "HELLO",
        "from": ident.node_id,
        "name": ident.name,
        "ephemeral_public": ident.eph_b64,
        "identity_public": ident.identity_b64,
        "protocol_version": version,
        "channel_binding": nonce.hex(),
        "signature": base64.b64encode(sig).decode(),
    }
    if link_binding is not None:
        hello["rns_link_id"] = link_binding
    adapter.to_daemon.put_nowait(json.dumps(hello))
    return rec


def _run_client_session(agent: Agent, adapter: ScriptedRNSAdapter, **kw):
    _wait_loop(agent)

    async def _session():
        client_task = asyncio.ensure_future(
            agent.daemon._do_client_handshake(adapter, "rns:test-peer"),
        )
        try:
            rec = await asyncio.wait_for(
                _drive_scripted_server(adapter, **kw), 25,
            )
        finally:
            adapter.to_daemon.put_nowait(None)  # end the message loop
        result = await asyncio.wait_for(client_task, 20)
        return rec, result

    fut = asyncio.run_coroutine_threadsafe(_session(), agent._loop)
    return fut.result(timeout=60)


@pytest.fixture(scope="class")
def client_agent():
    a = _mk_agent("rns-bind-client")
    yield a
    a.stop()


class TestClientSideWire:
    def test_client_binds_hello_and_accepts_bound_server(self, client_agent):
        adapter = ScriptedRNSAdapter()
        rec, result = _run_client_session(client_agent, adapter)
        # The real client bound its HELLO to the link, byte-verified:
        hello = rec["client_hello"]
        assert hello["rns_link_id"] == LINK_ID_HEX
        from nacl.signing import VerifyKey
        verify_key = VerifyKey(base64.b64decode(hello["identity_public"]))
        canonical = ew_protocol.canonical_hello_bytes(
            channel_binding=rec["nonce_hex"],
            ephemeral_public=hello["ephemeral_public"],
            identity_public=hello["identity_public"],
            name=hello["name"],
            protocol_version=hello["protocol_version"],
            rns_link_id=hello["rns_link_id"],
        )
        assert ew_crypto.verify_detached_with_context(
            verify_key, ew_crypto.SIG_CTX_HELLO, canonical,
            base64.b64decode(hello["signature"]),
        )
        # And it accepted the correctly-bound server HELLO.
        assert result == rec["identity"].node_id
        assert result in client_agent.daemon.peers

    def test_client_rejects_server_hello_with_wrong_binding(self, client_agent):
        adapter = ScriptedRNSAdapter()
        rec, result = _run_client_session(
            client_agent, adapter, binding=OTHER_LINK_ID_HEX,
        )
        assert result is None
        assert rec["identity"].node_id not in client_agent.daemon.peers

    def test_client_rejects_new_server_hello_without_binding(self, client_agent):
        adapter = ScriptedRNSAdapter()
        rec, result = _run_client_session(client_agent, adapter, binding=None)
        assert result is None
        assert rec["identity"].node_id not in client_agent.daemon.peers

    def test_client_interoperates_with_legacy_server(self, client_agent):
        adapter = ScriptedRNSAdapter()
        rec, result = _run_client_session(
            client_agent, adapter, version=LEGACY_VERSION,
            binding=None, sign_mode="legacy",
        )
        # Legacy server advertised 0.8 → the client omits the binding
        # (five-key canonical) and accepts the unbound legacy HELLO.
        assert "rns_link_id" not in rec["client_hello"]
        assert result == rec["identity"].node_id

    def test_client_refuses_legacy_server_when_binding_required(self, client_agent):
        client_agent.daemon._rns_require_link_binding = True
        try:
            adapter = ScriptedRNSAdapter()
            rec, result = _run_client_session(
                client_agent, adapter, version=LEGACY_VERSION,
                binding=None, sign_mode="legacy",
            )
            assert result is None
        finally:
            client_agent.daemon._rns_require_link_binding = False


class TestClientSideSkipWire:
    def test_skip_proceeds_with_binding(self, client_agent):
        adapter = ScriptedRNSAdapter()
        before = client_agent.daemon.metrics.handshake_skips_activated
        rec, result = _run_client_session(
            client_agent, adapter, offer_skip=True,
        )
        assert rec["client_hello"]["rns_link_id"] == LINK_ID_HEX
        assert result == rec["identity"].node_id
        assert (client_agent.daemon.metrics.handshake_skips_activated
                == before + 1)

    def test_skip_refused_when_link_id_unreadable(self, client_agent):
        adapter = ScriptedRNSAdapter(link_id_hex=None)
        before = client_agent.daemon.metrics.handshake_skips_rejected
        rec, result = _run_client_session(
            client_agent, adapter, offer_skip=True, stop_after_offer=True,
        )
        assert result is None
        assert (client_agent.daemon.metrics.handshake_skips_rejected
                == before + 1)

    def test_skip_refused_from_legacy_server(self, client_agent):
        # A pre-0.9 server cannot produce a bound HELLO — the client
        # refuses its SKIP_OFFER instead of running an unbound skip.
        adapter = ScriptedRNSAdapter()
        before = client_agent.daemon.metrics.handshake_skips_rejected
        rec, result = _run_client_session(
            client_agent, adapter, offer_skip=True,
            version=LEGACY_VERSION, stop_after_offer=True,
        )
        assert result is None
        assert (client_agent.daemon.metrics.handshake_skips_rejected
                == before + 1)

    def test_skip_rejects_server_hello_without_binding(self, client_agent):
        adapter = ScriptedRNSAdapter()
        rec, result = _run_client_session(
            client_agent, adapter, offer_skip=True, binding=None,
        )
        assert result is None
        assert rec["identity"].node_id not in client_agent.daemon.peers
