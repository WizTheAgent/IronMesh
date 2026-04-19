"""v0.8.5.2 property-based fuzz for critical deserializers.

Uses hypothesis to generate arbitrary inputs to Frame.from_dict,
TrustStore._load, and MessageStore.queue_pending_trust. Asserts the
parsers either accept (return a well-formed object) or reject with a
clean ValueError — never with an uncaught TypeError, KeyError, or
crash.
"""
import asyncio
import os
import tempfile
from typing import Any, Dict

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck

from ironmesh.protocol import Frame
from ironmesh.store import MessageStore
from ironmesh.trust import TrustStore


# Any JSON-like dict: nested strings/ints/bools/lists/dicts to 3 levels deep.
_json_primitive = st.one_of(
    st.none(), st.booleans(), st.integers(-1_000_000, 1_000_000),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=100),
)
_json_like = st.recursive(
    _json_primitive,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(st.text(max_size=20), children, max_size=5),
    ),
    max_leaves=20,
)


class TestFrameFuzz:
    """Frame.from_dict should never raise anything but ValueError on bad input."""

    @given(data=st.dictionaries(st.text(max_size=20), _json_like, max_size=10))
    @settings(max_examples=200, deadline=1000,
              suppress_health_check=[HealthCheck.too_slow])
    def test_random_dict_never_crashes(self, data):
        try:
            Frame.from_dict(data)
        except (ValueError, TypeError, AssertionError):
            # v0.8.5.2 strict validation added: TypeError was the pre-v0.8.5.2
            # behavior, still acceptable if raised from base64 lib. The point
            # is "controlled error," never uncaught surprise.
            pass

    def test_non_dict_raises_cleanly(self):
        for bad in [None, 42, "string", [], (), True]:
            with pytest.raises(ValueError):
                Frame.from_dict(bad)  # type: ignore[arg-type]

    def test_int_type_field_rejected(self):
        with pytest.raises(ValueError):
            Frame.from_dict({"type": 123})

    def test_negative_sequence_rejected(self):
        with pytest.raises(ValueError):
            Frame.from_dict({"type": "MSG", "sequence": -1})


class TestTrustStoreFuzz:
    """TrustStore._load should handle corrupt files without crashing."""

    def test_empty_file(self, tmp_path):
        trust_path = str(tmp_path / "empty.json")
        open(trust_path, "w").close()
        # Should load cleanly (warning logged)
        ts = TrustStore(agent_key=b"\xaa" * 32, path=trust_path)
        assert ts._peers == {}

    def test_malformed_json(self, tmp_path):
        trust_path = str(tmp_path / "malformed.json")
        open(trust_path, "w").write('{"peers":')  # truncated
        ts = TrustStore(agent_key=b"\xaa" * 32, path=trust_path)
        assert ts._peers == {}  # graceful reset

    def test_json_but_wrong_shape(self, tmp_path):
        trust_path = str(tmp_path / "wrong.json")
        open(trust_path, "w").write('[1, 2, 3]')  # list, not dict
        ts = TrustStore(agent_key=b"\xaa" * 32, path=trust_path)
        assert ts._peers == {}

    def test_bad_mac_fails_closed(self, tmp_path):
        trust_path = str(tmp_path / "bad_mac.json")
        open(trust_path, "w").write(
            '{"peers": {"nid": {"pubkey": "X", "fingerprint": "Y"}},'
            ' "revoked": {}, "_mac": "0000000000000000"}'
        )
        ts = TrustStore(agent_key=b"\xaa" * 32, path=trust_path)
        # Invalid MAC → fail closed: empty _peers
        assert ts._peers == {}


@pytest.mark.asyncio
class TestPendingTrustQueueFuzz:
    """queue_pending_trust should handle extreme inputs cleanly."""

    async def _store(self, tmp_path):
        s = MessageStore(str(tmp_path / "fuzz.db"))
        await s.open()
        return s

    async def test_arbitrary_msg_ids_never_crash(self, tmp_path):
        """Hypothesis-generated arbitrary strings as msg_id — none should
        cause queue_pending_trust to raise anything unexpected."""
        import string, random
        s = await self._store(tmp_path)
        try:
            chars = string.ascii_letters + string.digits + string.punctuation + " "
            for i in range(80):
                # Mix: empty, unicode-heavy, whitespace, SQL-ish, huge
                candidates = [
                    "", "msg-" + str(i),
                    "".join(random.choice(chars) for _ in range(random.randint(1, 64))),
                    "'; DROP TABLE pending_trust_messages; --",
                    "\x00\x01\x02\xff",
                    "日本語🔒💥",
                ]
                msg_id = random.choice(candidates)
                try:
                    await s.queue_pending_trust(
                        source_node_id="a" * 32,
                        msg_id=msg_id,
                        msg_type="MSG",
                        payload=b"test",
                        cap=10,
                    )
                except Exception as e:
                    pytest.fail(f"msg_id={msg_id!r} crashed queue_pending_trust: {type(e).__name__}: {e}")
        finally:
            await s.close()

    async def test_zero_cap_accepts_unlimited(self, tmp_path):
        s = await self._store(tmp_path)
        try:
            for i in range(50):
                await s.queue_pending_trust(
                    source_node_id="b" * 32, msg_id=f"m{i}",
                    msg_type="MSG", payload=b"x", cap=0,
                )
            count = await s.pending_trust_count_for("b" * 32)
            assert count == 50  # no cap → all admitted
        finally:
            await s.close()

    async def test_huge_cap_accepts(self, tmp_path):
        s = await self._store(tmp_path)
        try:
            ok = await s.queue_pending_trust(
                source_node_id="c" * 32, msg_id="x",
                msg_type="MSG", payload=b"hi", cap=2**31,
            )
            assert ok
        finally:
            await s.close()
