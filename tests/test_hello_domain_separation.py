"""HELLO domain-separation tests (protocol version ironmesh/0.9).

The HELLO Ed25519 signature migrated from the legacy attached form
(``crypto.sign_message``) to a domain-separated detached signature under
``crypto.SIG_CTX_HELLO`` (``crypto.sign_detached_with_context``),
version-gated so mixed-version meshes keep working:

- Both peers advertise ironmesh/0.9+  → context-signed HELLO (required).
- Either peer is older               → legacy attached signature.

These tests cover four layers:

1. ``protocol.canonical_hello_bytes`` — byte-exact canonicalization.
2. The version gate helper + version constants.
3. Pure-crypto binding: wrong context label / tampered canonical fail.
4. Wire-level interop against real daemon code — scripted new/old peers
   on both sides of the handshake, plus a full new<->new daemon pair.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import socket
import tempfile
import time

import pytest
import websockets
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from ironmesh import Agent
from ironmesh import crypto as ew_crypto
from ironmesh import keys as ew_keys
from ironmesh import protocol as ew_protocol
from ironmesh.handshake import (
    HELLO_CTX_MIN_VERSION,
    PROTOCOL_VERSION,
    _peer_supports_hello_ctx,
)

PASSPHRASE = "hello-domain-sep-test-passphrase"
LEGACY_VERSION = "ironmesh/0.8"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _mk_agent(name: str) -> Agent:
    tmp = tempfile.mkdtemp(prefix=f"hello-ds-{name}-")
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


async def _wait_port(port: int, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            return
        except OSError:
            await asyncio.sleep(0.1)
    raise TimeoutError(f"port {port} never came up")


async def _wait_async(pred, timeout: float = 15.0, step: float = 0.1) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        await asyncio.sleep(step)
    return False


def _sample_canonical_kwargs() -> dict:
    return {
        "channel_binding": "aa" * 32,
        "ephemeral_public": base64.b64encode(b"e" * 32).decode(),
        "identity_public": base64.b64encode(b"i" * 32).decode(),
        "name": "sample-agent",
        "protocol_version": PROTOCOL_VERSION,
    }


# ---------------------------------------------------------------------------
# 1. Canonicalization
# ---------------------------------------------------------------------------

class TestCanonicalHelloBytes:
    def test_matches_sorted_compact_json(self):
        kwargs = _sample_canonical_kwargs()
        expected = json.dumps(
            {
                "channel_binding": kwargs["channel_binding"],
                "ephemeral_public": kwargs["ephemeral_public"],
                "identity_public": kwargs["identity_public"],
                "name": kwargs["name"],
                "protocol_version": kwargs["protocol_version"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        assert ew_protocol.canonical_hello_bytes(**kwargs) == expected

    def test_channel_binding_nonce_is_covered(self):
        # The channel-binding nonce is the cross-connection replay defense;
        # it MUST alter the canonical bytes (and therefore the signature).
        a = ew_protocol.canonical_hello_bytes(**_sample_canonical_kwargs())
        kwargs = _sample_canonical_kwargs()
        kwargs["channel_binding"] = "bb" * 32
        b = ew_protocol.canonical_hello_bytes(**kwargs)
        assert a != b

    def test_every_field_is_covered(self):
        base = ew_protocol.canonical_hello_bytes(**_sample_canonical_kwargs())
        for field in (
            "channel_binding", "ephemeral_public", "identity_public",
            "name", "protocol_version",
        ):
            kwargs = _sample_canonical_kwargs()
            kwargs[field] = kwargs[field] + "x"
            assert ew_protocol.canonical_hello_bytes(**kwargs) != base, field

    def test_rejects_missing_key_material(self):
        kwargs = _sample_canonical_kwargs()
        kwargs["ephemeral_public"] = ""
        with pytest.raises(ValueError):
            ew_protocol.canonical_hello_bytes(**kwargs)
        kwargs = _sample_canonical_kwargs()
        kwargs["identity_public"] = None  # type: ignore[assignment]
        with pytest.raises(ValueError):
            ew_protocol.canonical_hello_bytes(**kwargs)

    def test_rejects_non_string_fields(self):
        kwargs = _sample_canonical_kwargs()
        kwargs["name"] = None  # type: ignore[assignment]
        with pytest.raises(ValueError):
            ew_protocol.canonical_hello_bytes(**kwargs)


# ---------------------------------------------------------------------------
# 2. Version gate
# ---------------------------------------------------------------------------

class TestHelloVersionGate:
    def test_new_version_is_registered(self):
        assert PROTOCOL_VERSION == "ironmesh/0.9"
        assert HELLO_CTX_MIN_VERSION == "ironmesh/0.9"
        assert ew_protocol.is_known_protocol_version("ironmesh/0.9")

    @pytest.mark.parametrize("version,expected", [
        ("ironmesh/0.9", True),
        ("ironmesh/0.10", True),
        ("ironmesh/1.0", True),
        ("ironmesh/0.8", False),
        ("ironmesh/0.3", False),
        ("", False),
        ("garbage", False),
    ])
    def test_gate(self, version, expected):
        assert _peer_supports_hello_ctx(version) is expected


# ---------------------------------------------------------------------------
# 3. Pure-crypto binding on canonical HELLO bytes
# ---------------------------------------------------------------------------

class TestHelloContextBinding:
    def test_wrong_context_label_fails_verification(self):
        # The core domain-separation property: a HELLO signed under a
        # DIFFERENT context label must not verify as a HELLO.
        sk = SigningKey.generate()
        canonical = ew_protocol.canonical_hello_bytes(**_sample_canonical_kwargs())
        for wrong_ctx in (
            ew_crypto.SIG_CTX_CAPABILITY_ANNOUNCE,
            ew_crypto.SIG_CTX_FUTURE_FRAME_OUTER,
            ew_crypto.SIG_CTX_FUTURE_REVOCATION,
        ):
            sig = ew_crypto.sign_detached_with_context(sk, wrong_ctx, canonical)
            with pytest.raises(BadSignatureError):
                ew_crypto.verify_detached_with_context(
                    sk.verify_key, ew_crypto.SIG_CTX_HELLO, canonical, sig
                )

    def test_tampered_canonical_field_fails_verification(self):
        sk = SigningKey.generate()
        canonical = ew_protocol.canonical_hello_bytes(**_sample_canonical_kwargs())
        sig = ew_crypto.sign_detached_with_context(
            sk, ew_crypto.SIG_CTX_HELLO, canonical
        )
        for field in (
            "channel_binding", "ephemeral_public", "identity_public",
            "name", "protocol_version",
        ):
            kwargs = _sample_canonical_kwargs()
            kwargs[field] = kwargs[field] + "x"
            tampered = ew_protocol.canonical_hello_bytes(**kwargs)
            with pytest.raises(BadSignatureError):
                ew_crypto.verify_detached_with_context(
                    sk.verify_key, ew_crypto.SIG_CTX_HELLO, tampered, sig
                )

    def test_legacy_signature_does_not_verify_as_context_signature(self):
        # The two schemes must be mutually exclusive: a legacy attached
        # signature must never pass the detached-context check.
        sk = SigningKey.generate()
        canonical = ew_protocol.canonical_hello_bytes(**_sample_canonical_kwargs())
        legacy = ew_crypto.sign_message(sk, canonical)
        with pytest.raises((BadSignatureError, ValueError)):
            ew_crypto.verify_detached_with_context(
                sk.verify_key, ew_crypto.SIG_CTX_HELLO, canonical, legacy
            )

    def test_context_signature_does_not_verify_as_legacy_signature(self):
        sk = SigningKey.generate()
        canonical = ew_protocol.canonical_hello_bytes(**_sample_canonical_kwargs())
        ctx_sig = ew_crypto.sign_detached_with_context(
            sk, ew_crypto.SIG_CTX_HELLO, canonical
        )
        with pytest.raises((BadSignatureError, ValueError)):
            extracted = ew_crypto.verify_signature(sk.verify_key, ctx_sig)
            # Even if libsodium accepted the blob shape, the payload
            # could never equal the canonical body.
            if extracted != canonical:
                raise ValueError("payload mismatch")


# ---------------------------------------------------------------------------
# 4a. Wire level — scripted clients against a real daemon (server side)
# ---------------------------------------------------------------------------

class _ScriptedIdentity:
    def __init__(self, name: str):
        self.name = name
        self.sk = SigningKey.generate()
        self.identity_b64 = base64.b64encode(bytes(self.sk.verify_key)).decode()
        self.node_id = ew_keys.get_fingerprint(bytes(self.sk.verify_key))
        eph_priv, eph_pub = ew_keys.generate_ephemeral()
        self.eph_b64 = base64.b64encode(bytes(eph_pub)).decode()


async def _scripted_client(
    port: int,
    *,
    version: str,
    sign_mode: str,
    tamper_field: str | None = None,
) -> dict:
    """Speak the client half of the handshake by hand and return what
    happened. ``sign_mode`` is "context", "legacy", or "wrong-context".
    """
    ident = _ScriptedIdentity("scripted-client")
    out: dict = {"identity": ident}
    async with websockets.connect(f"ws://127.0.0.1:{port}") as ws:
        challenge = json.loads(await asyncio.wait_for(ws.recv(), 15))
        assert challenge["type"] == "PASSPHRASE_CHALLENGE"
        out["server_advertised_version"] = challenge.get("protocol_version", "")
        nonce = bytes.fromhex(challenge["nonce"])
        proof = ew_protocol.Handshake.compute_passphrase_proof(PASSPHRASE, nonce)
        await ws.send(json.dumps({
            "type": "PASSPHRASE_CHALLENGE",
            "from": ident.node_id,
            "proof": proof,
        }))
        verified = json.loads(await asyncio.wait_for(ws.recv(), 15))
        assert verified["type"] == "PASSPHRASE_VERIFIED"

        canonical = ew_protocol.canonical_hello_bytes(
            channel_binding=nonce.hex(),
            ephemeral_public=ident.eph_b64,
            identity_public=ident.identity_b64,
            name=ident.name,
            protocol_version=version,
        )
        if sign_mode == "context":
            sig = ew_crypto.sign_detached_with_context(
                ident.sk, ew_crypto.SIG_CTX_HELLO, canonical
            )
        elif sign_mode == "wrong-context":
            sig = ew_crypto.sign_detached_with_context(
                ident.sk, ew_crypto.SIG_CTX_FUTURE_FRAME_OUTER, canonical
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
        if tamper_field:
            hello[tamper_field] = hello[tamper_field] + "-tampered"
        await ws.send(json.dumps(hello))
        out["reply"] = json.loads(await asyncio.wait_for(ws.recv(), 15))
    return out


def _verify_server_hello(reply: dict, *, expect_scheme: str) -> None:
    """Assert the daemon's HELLO reply is signed under the expected scheme
    — checked at the byte level, not just 'the handshake worked'."""
    assert reply["type"] == "HELLO"
    verify_key = VerifyKey(base64.b64decode(reply["identity_public"]))
    canonical = ew_protocol.canonical_hello_bytes(
        channel_binding=reply["channel_binding"],
        ephemeral_public=reply["ephemeral_public"],
        identity_public=reply["identity_public"],
        name=reply["name"],
        protocol_version=reply["protocol_version"],
    )
    sig = base64.b64decode(reply["signature"])
    if expect_scheme == "context-v1":
        assert len(sig) == 64  # detached form
        assert ew_crypto.verify_detached_with_context(
            verify_key, ew_crypto.SIG_CTX_HELLO, canonical, sig
        )
        # Domain separation binds: the same signature must NOT verify
        # under a different context label.
        with pytest.raises(BadSignatureError):
            ew_crypto.verify_detached_with_context(
                verify_key, ew_crypto.SIG_CTX_FUTURE_REVOCATION, canonical, sig
            )
    else:
        assert len(sig) == 64 + len(canonical)  # attached form
        extracted = ew_crypto.verify_signature(verify_key, sig)
        assert extracted == canonical


@pytest.fixture(scope="class")
def server_agent():
    a = _mk_agent("hello-ds-server")
    yield a
    a.stop()


class TestServerSideWire:
    """Scripted clients (new + old + malicious) against a real daemon."""

    @pytest.fixture(autouse=True)
    async def _ready(self, server_agent):
        await _wait_port(server_agent.daemon.port)
        # Tests in this class open several connections from 127.0.0.1 in
        # quick succession; reset the per-IP connection budget so the
        # rate limiter (burst 5) doesn't bleed across tests.
        server_agent.daemon._ip_rate_limiters.clear()

    async def test_new_client_uses_context_signature(self, server_agent):
        out = await _scripted_client(
            server_agent.daemon.port, version=PROTOCOL_VERSION,
            sign_mode="context",
        )
        # Server advertised 0.9+ in its challenge (client-side gate input).
        assert _peer_supports_hello_ctx(out["server_advertised_version"])
        # Server accepted the context-signed HELLO and context-signed its own.
        _verify_server_hello(out["reply"], expect_scheme="context-v1")
        node_id = out["identity"].node_id
        assert await _wait_async(
            lambda: node_id in server_agent.daemon.peers
        )
        assert server_agent.daemon.peers[node_id].hello_sig_scheme == "context-v1"

    async def test_old_client_falls_back_to_legacy_and_interoperates(self, server_agent):
        out = await _scripted_client(
            server_agent.daemon.port, version=LEGACY_VERSION,
            sign_mode="legacy",
        )
        # Server answers an old client with a legacy attached signature.
        _verify_server_hello(out["reply"], expect_scheme="legacy")
        node_id = out["identity"].node_id
        assert await _wait_async(
            lambda: node_id in server_agent.daemon.peers
        )
        assert server_agent.daemon.peers[node_id].hello_sig_scheme == "legacy"

    async def test_new_version_client_with_legacy_signature_rejected(self, server_agent):
        # A peer advertising 0.9+ MUST context-sign. Accepting legacy here
        # would let an attacker who strips the (unsigned) server version
        # advertisement silently downgrade the scheme.
        out = await _scripted_client(
            server_agent.daemon.port, version=PROTOCOL_VERSION,
            sign_mode="legacy",
        )
        assert out["reply"]["type"] == "ERROR"
        assert out["reply"]["code"] == "AUTH_FAILED"
        assert out["identity"].node_id not in server_agent.daemon.peers

    async def test_hello_signed_under_wrong_context_rejected(self, server_agent):
        out = await _scripted_client(
            server_agent.daemon.port, version=PROTOCOL_VERSION,
            sign_mode="wrong-context",
        )
        assert out["reply"]["type"] == "ERROR"
        assert out["reply"]["code"] == "AUTH_FAILED"
        assert out["identity"].node_id not in server_agent.daemon.peers

    @pytest.mark.parametrize("field", ["name", "protocol_version"])
    async def test_tampered_hello_field_rejected(self, server_agent, field):
        # Sign a correct canonical body, then mutate the wire field the
        # verifier reconstructs from — verification must fail.
        out = await _scripted_client(
            server_agent.daemon.port, version=PROTOCOL_VERSION,
            sign_mode="context", tamper_field=field,
        )
        assert out["reply"]["type"] == "ERROR"
        assert out["reply"]["code"] == "AUTH_FAILED"
        assert out["identity"].node_id not in server_agent.daemon.peers


# ---------------------------------------------------------------------------
# 4b. Wire level — real daemon as client against scripted servers
# ---------------------------------------------------------------------------

async def _scripted_server_handler(ws, *, version: str, sign_mode: str, record: dict):
    """Speak the server half of the handshake by hand."""
    ident = _ScriptedIdentity("scripted-server")
    record["identity"] = ident
    nonce = ew_protocol.Handshake.generate_server_nonce()
    challenge = {
        "type": "PASSPHRASE_CHALLENGE",
        "from": ident.node_id,
        "nonce": nonce.hex(),
        "protocol_version": version,
    }
    await ws.send(json.dumps(challenge))
    proof_msg = json.loads(await asyncio.wait_for(ws.recv(), 15))
    assert ew_protocol.Handshake.verify_passphrase_proof(
        proof_msg["proof"], PASSPHRASE, nonce
    )
    server_proof = ew_protocol.Handshake.compute_passphrase_proof(
        PASSPHRASE, nonce[::-1]
    )
    await ws.send(json.dumps({
        "type": "PASSPHRASE_VERIFIED",
        "from": ident.node_id,
        "status": "verified",
        "server_proof": server_proof,
    }))
    record["client_hello"] = json.loads(await asyncio.wait_for(ws.recv(), 15))
    record["nonce_hex"] = nonce.hex()

    canonical = ew_protocol.canonical_hello_bytes(
        channel_binding=nonce.hex(),
        ephemeral_public=ident.eph_b64,
        identity_public=ident.identity_b64,
        name=ident.name,
        protocol_version=version,
    )
    if sign_mode == "context":
        sig = ew_crypto.sign_detached_with_context(
            ident.sk, ew_crypto.SIG_CTX_HELLO, canonical
        )
    elif sign_mode == "wrong-context":
        sig = ew_crypto.sign_detached_with_context(
            ident.sk, ew_crypto.SIG_CTX_TRUST_PIN_EXPORT, canonical
        )
    else:
        sig = ew_crypto.sign_message(ident.sk, canonical)
    await ws.send(json.dumps({
        "type": "HELLO",
        "from": ident.node_id,
        "name": ident.name,
        "ephemeral_public": ident.eph_b64,
        "identity_public": ident.identity_b64,
        "protocol_version": version,
        "channel_binding": nonce.hex(),
        "signature": base64.b64encode(sig).decode(),
    }))
    record["hello_sent"] = True
    # Hold the connection open while the test inspects the daemon, then
    # let the test close the server (client sits in its message loop).
    try:
        await asyncio.wait_for(ws.recv(), 30)
    except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
        pass


def _assert_client_hello_scheme(client_hello: dict, nonce_hex: str, *, scheme: str):
    """Byte-level check of the signature the REAL client code produced."""
    verify_key = VerifyKey(base64.b64decode(client_hello["identity_public"]))
    canonical = ew_protocol.canonical_hello_bytes(
        channel_binding=nonce_hex,
        ephemeral_public=client_hello["ephemeral_public"],
        identity_public=client_hello["identity_public"],
        name=client_hello["name"],
        protocol_version=client_hello["protocol_version"],
    )
    sig = base64.b64decode(client_hello["signature"])
    # The client always advertises its true version, even on the legacy
    # fallback path — the scheme downgrades, the advertisement does not.
    assert client_hello["protocol_version"] == PROTOCOL_VERSION
    if scheme == "context-v1":
        assert len(sig) == 64
        assert ew_crypto.verify_detached_with_context(
            verify_key, ew_crypto.SIG_CTX_HELLO, canonical, sig
        )
    else:
        assert len(sig) == 64 + len(canonical)
        assert ew_crypto.verify_signature(verify_key, sig) == canonical


@pytest.fixture(scope="class")
def client_agent():
    a = _mk_agent("hello-ds-client")
    yield a
    a.stop()


class TestClientSideWire:
    """The real daemon dials scripted new/old servers."""

    async def _run_client_against_scripted_server(
        self, client_agent, *, version: str, sign_mode: str
    ):
        record: dict = {}

        async def handler(ws):
            await _scripted_server_handler(
                ws, version=version, sign_mode=sign_mode, record=record
            )

        port = _free_port()
        server = await websockets.serve(handler, "127.0.0.1", port)
        try:
            fut = asyncio.run_coroutine_threadsafe(
                client_agent.daemon.connect_to_peer("127.0.0.1", port),
                client_agent._loop,
            )
            return record, asyncio.wrap_future(fut)
        finally:
            # Server closes after the test inspects state; callers manage it.
            record["_server"] = server

    async def test_client_context_signs_for_new_server(self, client_agent):
        await _wait_port(client_agent.daemon.port)
        record, fut = await self._run_client_against_scripted_server(
            client_agent, version=PROTOCOL_VERSION, sign_mode="context",
        )
        try:
            assert await _wait_async(lambda: record.get("hello_sent"))
            _assert_client_hello_scheme(
                record["client_hello"], record["nonce_hex"], scheme="context-v1"
            )
            peer_id = record["identity"].node_id
            assert await _wait_async(
                lambda: peer_id in client_agent.daemon.peers
                and client_agent.daemon.peers[peer_id].verified
            )
            assert (
                client_agent.daemon.peers[peer_id].hello_sig_scheme
                == "context-v1"
            )
        finally:
            record["_server"].close()
            await record["_server"].wait_closed()
            await asyncio.wait_for(fut, 15)

    async def test_client_falls_back_to_legacy_for_old_server(self, client_agent):
        await _wait_port(client_agent.daemon.port)
        record, fut = await self._run_client_against_scripted_server(
            client_agent, version=LEGACY_VERSION, sign_mode="legacy",
        )
        try:
            assert await _wait_async(lambda: record.get("hello_sent"))
            _assert_client_hello_scheme(
                record["client_hello"], record["nonce_hex"], scheme="legacy"
            )
            peer_id = record["identity"].node_id
            assert await _wait_async(
                lambda: peer_id in client_agent.daemon.peers
                and client_agent.daemon.peers[peer_id].verified
            )
            assert (
                client_agent.daemon.peers[peer_id].hello_sig_scheme == "legacy"
            )
        finally:
            record["_server"].close()
            await record["_server"].wait_closed()
            await asyncio.wait_for(fut, 15)

    async def test_client_rejects_new_server_hello_under_wrong_context(self, client_agent):
        await _wait_port(client_agent.daemon.port)
        record, fut = await self._run_client_against_scripted_server(
            client_agent, version=PROTOCOL_VERSION, sign_mode="wrong-context",
        )
        try:
            # The client must refuse the mis-signed server HELLO.
            result = await asyncio.wait_for(fut, 30)
            assert result is None
            peer_id = record["identity"].node_id
            assert peer_id not in client_agent.daemon.peers
        finally:
            record["_server"].close()
            await record["_server"].wait_closed()

    async def test_client_rejects_new_server_hello_with_legacy_signature(self, client_agent):
        # A server that advertises 0.9+ inside its signed HELLO body but
        # attaches a legacy signature must be refused — this is the
        # anti-downgrade rule on the client side.
        await _wait_port(client_agent.daemon.port)
        record, fut = await self._run_client_against_scripted_server(
            client_agent, version=PROTOCOL_VERSION, sign_mode="legacy",
        )
        try:
            result = await asyncio.wait_for(fut, 30)
            assert result is None
            peer_id = record["identity"].node_id
            assert peer_id not in client_agent.daemon.peers
        finally:
            record["_server"].close()
            await record["_server"].wait_closed()


# ---------------------------------------------------------------------------
# 4c. Full new<->new daemon pair
# ---------------------------------------------------------------------------

def _wait_sync(pred, timeout: float = 15.0, step: float = 0.1) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(step)
    return False


def _port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


class TestNewToNewEndToEnd:
    # Synchronous on purpose: Agent.run(foreground=False) spins up its own
    # event loop thread and must not be called from inside a running loop.
    def test_both_directions_use_context_scheme(self):
        a = _mk_agent("hello-ds-a")
        b = _mk_agent("hello-ds-b")
        try:
            assert _wait_sync(lambda: _port_open(a.daemon.port))
            assert _wait_sync(lambda: _port_open(b.daemon.port))
            asyncio.run_coroutine_threadsafe(
                a.daemon.connect_to_peer("127.0.0.1", b.daemon.port),
                a._loop,
            )

            def _linked():
                return (
                    a.daemon.node_id in b.daemon.peers
                    and b.daemon.node_id in a.daemon.peers
                )

            assert _wait_sync(_linked, timeout=30), "daemons never linked"
            # Not just "the handshake succeeded": both sides must have
            # taken the domain-separated verification path.
            assert (
                a.daemon.peers[b.daemon.node_id].hello_sig_scheme
                == "context-v1"
            )
            assert (
                b.daemon.peers[a.daemon.node_id].hello_sig_scheme
                == "context-v1"
            )
            assert (
                a.daemon.peers[b.daemon.node_id].protocol_version
                == PROTOCOL_VERSION
            )
        finally:
            a.stop()
            b.stop()
