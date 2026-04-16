"""IronMesh structured-conversation envelope (v0.8.2+).

Multi-turn agent-to-agent dialogue needs more metadata than a plain
``MSG`` payload carries — conversation id, turn counter, reply-to, role
labels, budgets, termination reason. Rather than embedding that in a
``[CONV:...]`` text prefix (which we still accept for one release), we
use a dedicated ``MessageType.CONV`` frame whose payload is a JSON
envelope:

    {
      "v": 1,
      "conv_id": "<opaque id>",
      "turn": 0,
      "max_turns": 5,
      "kind": "prompt" | "response" | "end" | "error",
      "body": "<utf-8 text>",
      "reply_to": "<msg_id of the message this replies to>",
      "from_role": "<optional, e.g. security-analyst>",
      "to_role": "<optional, e.g. network-engineer>",
      "budget": {
        "max_seconds": 60,
        "max_tokens": 800,
        "max_bytes": 16384
      },
      "end_reason": "<turn-limit | goal-achieved | budget-exceeded | error>"
    }

``body`` is always the human-readable text. When ``kind == "end"`` the
body is a short reason string and ``end_reason`` names the cause.
``budget`` is optional; any missing field means "no limit for that
dimension". ``v`` is the envelope version for forward compatibility.

Wire-level framing is a single Frame of type ``MessageType.CONV`` with
``payload = json.dumps(envelope).encode("utf-8")``. The frame
inherits the same encryption, signing, and replay protection as any
other MSG.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

CONV_ENVELOPE_VERSION = 1

# Valid `kind` values.
KIND_PROMPT = "prompt"
KIND_RESPONSE = "response"
KIND_END = "end"
KIND_ERROR = "error"

# Valid `end_reason` values.
END_TURN_LIMIT = "turn-limit"
END_GOAL_ACHIEVED = "goal-achieved"
END_BUDGET_EXCEEDED = "budget-exceeded"
END_ERROR = "error"


@dataclass
class Budget:
    """Optional per-conversation resource caps. None = no limit."""
    max_seconds: Optional[float] = None
    max_tokens: Optional[int] = None
    max_bytes: Optional[int] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in {
            "max_seconds": self.max_seconds,
            "max_tokens": self.max_tokens,
            "max_bytes": self.max_bytes,
        }.items() if v is not None}

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> Optional["Budget"]:
        if not d:
            return None
        return cls(
            max_seconds=d.get("max_seconds"),
            max_tokens=d.get("max_tokens"),
            max_bytes=d.get("max_bytes"),
        )


@dataclass
class ConvEnvelope:
    """A parsed ``MessageType.CONV`` payload.

    Use ``ConvEnvelope.decode(bytes)`` on the receive side and
    ``envelope.encode()`` to produce wire bytes.
    """
    conv_id: str
    turn: int = 0
    max_turns: int = 0
    kind: str = KIND_PROMPT
    body: str = ""
    reply_to: str = ""
    from_role: str = ""
    to_role: str = ""
    budget: Optional[Budget] = None
    end_reason: str = ""
    extra: dict = field(default_factory=dict)  # forward-compat pass-through

    def to_dict(self) -> dict:
        d = {
            "v": CONV_ENVELOPE_VERSION,
            "conv_id": self.conv_id,
            "turn": self.turn,
            "max_turns": self.max_turns,
            "kind": self.kind,
            "body": self.body,
        }
        # Optional fields: only emit when non-default.
        if self.reply_to:
            d["reply_to"] = self.reply_to
        if self.from_role:
            d["from_role"] = self.from_role
        if self.to_role:
            d["to_role"] = self.to_role
        if self.budget is not None:
            b = self.budget.to_dict()
            if b:
                d["budget"] = b
        if self.end_reason:
            d["end_reason"] = self.end_reason
        if self.extra:
            d.update(self.extra)
        return d

    def encode(self) -> bytes:
        return json.dumps(self.to_dict(), separators=(",", ":")).encode("utf-8")

    @classmethod
    def decode(cls, raw: bytes) -> "ConvEnvelope":
        """Parse wire bytes into an envelope.

        Raises ``ValueError`` on malformed input. Unknown top-level
        keys are stashed in ``extra`` so a future field added by an
        updated peer doesn't break decoding here.
        """
        try:
            d = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise ValueError(f"CONV envelope: not valid UTF-8 JSON ({e})") from e
        if not isinstance(d, dict):
            raise ValueError("CONV envelope: top-level must be a JSON object")
        # Required.
        try:
            conv_id = d["conv_id"]
        except KeyError as e:
            raise ValueError("CONV envelope: missing conv_id") from e
        if not isinstance(conv_id, str) or not conv_id:
            raise ValueError("CONV envelope: conv_id must be a non-empty string")
        kind = d.get("kind", KIND_PROMPT)
        if kind not in (KIND_PROMPT, KIND_RESPONSE, KIND_END, KIND_ERROR):
            raise ValueError(f"CONV envelope: invalid kind {kind!r}")
        turn = d.get("turn", 0)
        max_turns = d.get("max_turns", 0)
        if not isinstance(turn, int) or turn < 0:
            raise ValueError("CONV envelope: turn must be a non-negative int")
        if not isinstance(max_turns, int) or max_turns < 0:
            raise ValueError("CONV envelope: max_turns must be a non-negative int")
        body = d.get("body", "")
        if not isinstance(body, str):
            raise ValueError("CONV envelope: body must be a string")
        # Keep unknown keys so round-tripping from newer peers survives.
        known = {"v", "conv_id", "turn", "max_turns", "kind", "body",
                 "reply_to", "from_role", "to_role", "budget", "end_reason"}
        extra = {k: v for k, v in d.items() if k not in known}
        return cls(
            conv_id=conv_id,
            turn=turn,
            max_turns=max_turns,
            kind=kind,
            body=body,
            reply_to=d.get("reply_to", "") or "",
            from_role=d.get("from_role", "") or "",
            to_role=d.get("to_role", "") or "",
            budget=Budget.from_dict(d.get("budget")),
            end_reason=d.get("end_reason", "") or "",
            extra=extra,
        )


def make_reply(
    parent: ConvEnvelope,
    body: str,
    *,
    kind: str = KIND_RESPONSE,
    from_role: str = "",
    reply_to: str = "",
    end_reason: str = "",
) -> ConvEnvelope:
    """Build a response envelope whose turn is ``parent.turn + 1``.

    Preserves ``conv_id``, ``max_turns``, ``budget``, and swaps roles
    so the downstream orchestrator can route to the right peer.
    """
    return ConvEnvelope(
        conv_id=parent.conv_id,
        turn=parent.turn + 1,
        max_turns=parent.max_turns,
        kind=kind,
        body=body,
        reply_to=reply_to,
        from_role=from_role or parent.to_role,
        to_role=parent.from_role,
        budget=parent.budget,
        end_reason=end_reason,
    )


def is_terminal(env: ConvEnvelope) -> bool:
    """True iff this envelope ends the conversation."""
    return env.kind in (KIND_END, KIND_ERROR)
