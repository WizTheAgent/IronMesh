"""Tests for the v0.8.2 structured CONV envelope."""
from __future__ import annotations

import json

import pytest

from ironmesh.conversation import (
    Budget,
    ConvEnvelope,
    CONV_ENVELOPE_VERSION,
    END_GOAL_ACHIEVED,
    END_TURN_LIMIT,
    KIND_END,
    KIND_PROMPT,
    KIND_RESPONSE,
    is_terminal,
    make_reply,
)


class TestRoundTrip:

    def test_minimal_prompt_roundtrip(self):
        env = ConvEnvelope(conv_id="abc", turn=0, max_turns=3, body="hello")
        wire = env.encode()
        parsed = ConvEnvelope.decode(wire)
        assert parsed.conv_id == "abc"
        assert parsed.turn == 0
        assert parsed.max_turns == 3
        assert parsed.body == "hello"
        assert parsed.kind == KIND_PROMPT  # default
        assert parsed.budget is None

    def test_full_envelope_roundtrip(self):
        env = ConvEnvelope(
            conv_id="c-1",
            turn=2,
            max_turns=5,
            kind=KIND_RESPONSE,
            body="a response",
            reply_to="msg-123",
            from_role="security-analyst",
            to_role="network-engineer",
            budget=Budget(max_seconds=30.0, max_tokens=500),
        )
        parsed = ConvEnvelope.decode(env.encode())
        assert parsed.conv_id == "c-1"
        assert parsed.turn == 2
        assert parsed.max_turns == 5
        assert parsed.kind == KIND_RESPONSE
        assert parsed.body == "a response"
        assert parsed.reply_to == "msg-123"
        assert parsed.from_role == "security-analyst"
        assert parsed.to_role == "network-engineer"
        assert parsed.budget is not None
        assert parsed.budget.max_seconds == 30.0
        assert parsed.budget.max_tokens == 500
        assert parsed.budget.max_bytes is None

    def test_version_tag_on_wire(self):
        env = ConvEnvelope(conv_id="x")
        d = json.loads(env.encode())
        assert d["v"] == CONV_ENVELOPE_VERSION

    def test_unicode_body_preserved(self):
        env = ConvEnvelope(conv_id="u", body="héllo ✓ 日本語")
        parsed = ConvEnvelope.decode(env.encode())
        assert parsed.body == "héllo ✓ 日本語"


class TestForwardCompat:

    def test_unknown_keys_preserved_in_extra(self):
        payload = json.dumps({
            "v": 1, "conv_id": "f", "turn": 1, "max_turns": 3,
            "kind": "response", "body": "x",
            "future_field": {"nested": True},
            "another_future": 42,
        }).encode()
        parsed = ConvEnvelope.decode(payload)
        assert parsed.extra["future_field"] == {"nested": True}
        assert parsed.extra["another_future"] == 42

    def test_roundtrip_preserves_extra(self):
        original = json.dumps({
            "v": 1, "conv_id": "rt", "kind": "prompt", "body": "hi",
            "custom_tag": "preserve-me",
        }).encode()
        parsed = ConvEnvelope.decode(original)
        reencoded = parsed.encode()
        reparsed = ConvEnvelope.decode(reencoded)
        assert reparsed.extra.get("custom_tag") == "preserve-me"


class TestValidation:

    def test_missing_conv_id_rejected(self):
        with pytest.raises(ValueError, match="conv_id"):
            ConvEnvelope.decode(json.dumps({"body": "x"}).encode())

    def test_empty_conv_id_rejected(self):
        with pytest.raises(ValueError, match="conv_id"):
            ConvEnvelope.decode(json.dumps({"conv_id": "", "body": "x"}).encode())

    def test_invalid_kind_rejected(self):
        with pytest.raises(ValueError, match="invalid kind"):
            ConvEnvelope.decode(json.dumps({
                "conv_id": "x", "kind": "chat", "body": "y",
            }).encode())

    def test_negative_turn_rejected(self):
        with pytest.raises(ValueError, match="turn"):
            ConvEnvelope.decode(json.dumps({
                "conv_id": "x", "turn": -1,
            }).encode())

    def test_non_json_rejected(self):
        with pytest.raises(ValueError, match="UTF-8 JSON"):
            ConvEnvelope.decode(b"\xff\xfe not json")

    def test_non_object_rejected(self):
        with pytest.raises(ValueError, match="JSON object"):
            ConvEnvelope.decode(b"[1, 2, 3]")

    def test_body_must_be_string(self):
        with pytest.raises(ValueError, match="body"):
            ConvEnvelope.decode(json.dumps({
                "conv_id": "x", "body": {"nested": True},
            }).encode())


class TestMakeReply:

    def test_reply_increments_turn(self):
        parent = ConvEnvelope(conv_id="c", turn=0, max_turns=5,
                              from_role="alice", to_role="bob", body="q")
        child = make_reply(parent, "answer")
        assert child.turn == 1
        assert child.max_turns == 5
        assert child.conv_id == "c"
        assert child.kind == KIND_RESPONSE
        assert child.body == "answer"

    def test_reply_swaps_roles_by_default(self):
        parent = ConvEnvelope(conv_id="c", from_role="alice", to_role="bob")
        child = make_reply(parent, "x")
        assert child.from_role == "bob"
        assert child.to_role == "alice"

    def test_reply_preserves_budget(self):
        parent = ConvEnvelope(
            conv_id="c",
            budget=Budget(max_seconds=10, max_tokens=100),
        )
        child = make_reply(parent, "x")
        assert child.budget is not None
        assert child.budget.max_seconds == 10
        assert child.budget.max_tokens == 100


class TestTerminal:

    def test_end_is_terminal(self):
        assert is_terminal(ConvEnvelope(
            conv_id="x", kind=KIND_END, end_reason=END_TURN_LIMIT,
        ))

    def test_error_is_terminal(self):
        assert is_terminal(ConvEnvelope(conv_id="x", kind="error"))

    def test_prompt_and_response_not_terminal(self):
        assert not is_terminal(ConvEnvelope(conv_id="x", kind=KIND_PROMPT))
        assert not is_terminal(ConvEnvelope(conv_id="x", kind=KIND_RESPONSE))


class TestBudget:

    def test_omits_none_fields_on_wire(self):
        b = Budget(max_seconds=30.0)
        d = b.to_dict()
        assert d == {"max_seconds": 30.0}

    def test_from_dict_none_is_none(self):
        assert Budget.from_dict(None) is None
        assert Budget.from_dict({}) is None

    def test_end_reason_emitted(self):
        env = ConvEnvelope(
            conv_id="c", kind=KIND_END,
            body="ok", end_reason=END_GOAL_ACHIEVED,
        )
        d = json.loads(env.encode())
        assert d["end_reason"] == END_GOAL_ACHIEVED
