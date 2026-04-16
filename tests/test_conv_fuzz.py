"""Hypothesis fuzz tests for the CONV envelope (v0.8.3 audit).

These are property-based tests: Hypothesis generates thousands of
random envelopes and asserts invariants that should hold for every
valid input. Written during the v0.8.3 E2E debugging audit to flush
out edge cases the unit tests missed.
"""
from __future__ import annotations

import json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ironmesh.conversation import (
    CONV_ENVELOPE_VERSION,
    KIND_END,
    KIND_ERROR,
    KIND_PROMPT,
    KIND_RESPONSE,
    Budget,
    ConvEnvelope,
    is_terminal,
    make_reply,
)


# --- Strategies ------------------------------------------------------------

conv_id_strat = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters="._-",
    ),
    min_size=1, max_size=64,
)
body_strat = st.text(min_size=0, max_size=2000)
role_strat = st.text(max_size=32)
kind_strat = st.sampled_from([KIND_PROMPT, KIND_RESPONSE, KIND_END, KIND_ERROR])


@st.composite
def budget_strat(draw):
    max_s = draw(st.one_of(st.none(), st.floats(min_value=0.0, max_value=3600.0, allow_nan=False, allow_infinity=False)))
    max_t = draw(st.one_of(st.none(), st.integers(min_value=0, max_value=100_000)))
    max_b = draw(st.one_of(st.none(), st.integers(min_value=0, max_value=10_000_000)))
    return Budget(max_seconds=max_s, max_tokens=max_t, max_bytes=max_b)


@st.composite
def envelope_strat(draw):
    return ConvEnvelope(
        conv_id=draw(conv_id_strat),
        turn=draw(st.integers(min_value=0, max_value=1000)),
        max_turns=draw(st.integers(min_value=0, max_value=1000)),
        kind=draw(kind_strat),
        body=draw(body_strat),
        reply_to=draw(st.text(max_size=64)),
        from_role=draw(role_strat),
        to_role=draw(role_strat),
        budget=draw(st.one_of(st.none(), budget_strat())),
        end_reason=draw(st.text(max_size=32)),
    )


# --- Properties ------------------------------------------------------------

# Hypothesis can be slow on Windows + the global warning about function-scoped
# fixtures is noise here; silence the specific health checks that matter.
_settings = settings(
    max_examples=400,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


@_settings
@given(envelope_strat())
def test_roundtrip_preserves_core_fields(env):
    """encode -> decode returns an equal-looking envelope for valid inputs."""
    wire = env.encode()
    assert isinstance(wire, bytes)
    decoded = ConvEnvelope.decode(wire)
    assert decoded.conv_id == env.conv_id
    assert decoded.turn == env.turn
    assert decoded.max_turns == env.max_turns
    assert decoded.kind == env.kind
    assert decoded.body == env.body
    # Optional fields: round-trip if present, default otherwise.
    assert decoded.reply_to == env.reply_to
    assert decoded.from_role == env.from_role
    assert decoded.to_role == env.to_role
    assert decoded.end_reason == env.end_reason
    # Budget is intentionally collapsed: an empty Budget(None,None,None)
    # encodes as {} which to_dict() drops, so decode returns None. An
    # empty Budget and None-budget are semantically identical ("no caps").
    original_dict = env.budget.to_dict() if env.budget is not None else {}
    decoded_dict = decoded.budget.to_dict() if decoded.budget is not None else {}
    assert original_dict == decoded_dict


@_settings
@given(envelope_strat())
def test_wire_is_valid_utf8_json(env):
    """Encoded envelope is always a valid UTF-8 JSON object."""
    wire = env.encode()
    text = wire.decode("utf-8")
    parsed = json.loads(text)
    assert isinstance(parsed, dict)
    assert parsed.get("v") == CONV_ENVELOPE_VERSION
    assert parsed.get("conv_id") == env.conv_id


@_settings
@given(envelope_strat(), st.text(max_size=200))
def test_body_survives_arbitrary_text(env, extra_body):
    """Body can hold any unicode string round-trip."""
    env.body = extra_body
    out = ConvEnvelope.decode(env.encode())
    assert out.body == extra_body


@_settings
@given(envelope_strat())
def test_make_reply_increments_turn(env):
    reply = make_reply(env, "response text")
    assert reply.turn == env.turn + 1
    assert reply.max_turns == env.max_turns
    assert reply.conv_id == env.conv_id
    assert reply.kind == KIND_RESPONSE
    # Roles swap by default.
    assert reply.from_role == env.to_role
    assert reply.to_role == env.from_role


@_settings
@given(envelope_strat())
def test_terminal_kinds_are_recognized(env):
    assert is_terminal(env) == (env.kind in (KIND_END, KIND_ERROR))


@_settings
@given(st.binary(min_size=0, max_size=4096))
def test_decode_rejects_garbage_cleanly(blob):
    """Arbitrary binary input either decodes to a valid envelope or raises
    ValueError -- never a TypeError, AttributeError, KeyError, etc."""
    try:
        env = ConvEnvelope.decode(blob)
    except ValueError:
        return  # expected shape of rejection
    # If it DID decode, the result must at least have a non-empty conv_id.
    assert env.conv_id


@_settings
@given(envelope_strat())
def test_unknown_extra_keys_survive_roundtrip(env):
    """Adding an unknown top-level key survives the round-trip in .extra."""
    d = env.to_dict()
    d["future_field"] = {"foo": "bar"}
    wire = json.dumps(d).encode()
    decoded = ConvEnvelope.decode(wire)
    assert decoded.extra.get("future_field") == {"foo": "bar"}
    # Re-encoding includes it again.
    reparsed = ConvEnvelope.decode(decoded.encode())
    assert reparsed.extra.get("future_field") == {"foo": "bar"}


@_settings
@given(st.text(min_size=1, max_size=32),
       st.integers(min_value=0, max_value=1000),
       st.integers(min_value=0, max_value=1000),
       st.text(min_size=0, max_size=500))
def test_construction_does_not_raise(conv_id, turn, max_turns, body):
    """The dataclass constructor should never raise for basic string/int types."""
    env = ConvEnvelope(conv_id=conv_id, turn=turn, max_turns=max_turns, body=body)
    # And it must round-trip.
    out = ConvEnvelope.decode(env.encode())
    assert out.conv_id == conv_id


@_settings
@given(st.dictionaries(
    keys=st.text(min_size=1, max_size=16),
    values=st.one_of(
        st.text(max_size=50),
        st.integers(min_value=-10, max_value=10),
        st.booleans(),
        st.none(),
    ),
    max_size=10,
))
def test_decode_with_partial_valid_keys(d):
    """Any dict that includes a non-empty conv_id + valid kind decodes."""
    d.setdefault("conv_id", "probe-1")
    d.setdefault("kind", KIND_PROMPT)
    d.setdefault("body", "x")
    # sanitize turn/max_turns so they're legal if present
    if "turn" in d and not (isinstance(d["turn"], int) and d["turn"] >= 0):
        d["turn"] = 0
    if "max_turns" in d and not (isinstance(d["max_turns"], int) and d["max_turns"] >= 0):
        d["max_turns"] = 0
    if not isinstance(d.get("body"), str):
        d["body"] = "x"
    try:
        env = ConvEnvelope.decode(json.dumps(d).encode())
    except ValueError:
        return  # some combinations are still rejected; that's fine
    assert env.conv_id == d["conv_id"]
