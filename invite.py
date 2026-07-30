"""IronMesh bootstrap invite tokens (ephemeral, single-use).

An invite token gets a new node PAST first-contact identity verification
without ever transmitting the mesh passphrase. It pins the inviter's
current Ed25519 identity key plus the inviter's bootstrap endpoint, is
signed under a domain-separated context, expires quickly, and is consumed
exactly once.

Trust model summary (full spec in ``docs/CONFIGURATION.md``):

* **Payload** — inviter identity public key (to pin), inviter endpoint
  (host:port or ``rns:<dest>``), a single-use nonce, an issued/expires
  window, and two hints (suggested ``--allowed-peers`` + deployment
  profile). NEVER the passphrase or any root secret.
* **Signature** — detached Ed25519 over ``protocol.canonical_invite_bytes``
  under ``crypto.SIG_CTX_INVITE``. A signature captured from any other
  IronMesh surface (HELLO, capability announce) cannot be replayed as an
  invite because the domain-separation label differs.
* **Expiry** — per-profile default (tactical 5 min, lan/homelab 15 min,
  lora/offline 30 min), overridable at create time. Reuses the same clock
  arithmetic as the rest of the protocol.
* **Single-use** — the INVITING node is authoritative. The token pins the
  inviter's endpoint, so the joiner first-contacts the inviter directly;
  the inviter holds a small persisted spent-nonce ledger (:class:`InviteLedger`)
  and marks the token spent at its TOFU pin point on a successful join. No
  distributed / quorum consumption, no mesh-wide gossip.
* **Verified-first-use** — the joiner validates the token's pinned inviter
  identity against the identity presented in the handshake HELLO, so the
  first pin is verified, not blind TOFU.
* **Resulting trust** — ``pending``, NOT auto-trust. An invited joiner
  always lands in the pending-trust gate for explicit operator approval,
  regardless of the global ``require_message_promotion`` flag. The peer
  record carries an optional ``pinned_via="invite"`` provenance marker.

SIO / FROST alignment is DEFERRED to the keying RFC: this pins the current
Ed25519 identity now (forward-compatible, not forward-implemented).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Optional

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from ironmesh import crypto as ew_crypto, protocol as ew_protocol

logger = logging.getLogger("ironmesh.invite")

# Compact wire prefix so a pasted string is recognisably an IronMesh
# invite and cannot be confused with, e.g., a base64 key blob.
INVITE_PREFIX = "ironmesh-invite-v1:"

# Small clock-skew tolerance (seconds) applied to expiry checks, matching
# the leniency the rest of the protocol grants to cross-host clocks.
INVITE_CLOCK_SKEW = 30.0

DEFAULT_LEDGER_PATH = "~/.ironmesh/invite_ledger.json"

# Prune spent-nonce ledger entries this long after the token they record
# has expired. The ledger only needs to remember a nonce until it can no
# longer be presented; keeping it a while past expiry is belt-and-braces
# against clock skew without unbounded growth.
LEDGER_RETENTION_AFTER_EXPIRY = 3600.0


class InviteError(Exception):
    """Base class for invite validation failures."""


class InviteExpired(InviteError):
    """The token is past its ``expires_at`` (plus skew tolerance)."""


class InviteSpent(InviteError):
    """The token's nonce is already recorded as consumed."""


class InviteIdentityMismatch(InviteError):
    """The presented identity does not match the token's pinned inviter."""


class InviteMalformed(InviteError):
    """The token string / body could not be parsed."""


class InviteBadSignature(InviteError):
    """The token signature did not verify under ``SIG_CTX_INVITE``."""


@dataclass(frozen=True)
class InviteToken:
    """A parsed, signature-carrying invite token.

    ``signature`` is base64. Everything else mirrors the canonical body in
    ``protocol.canonical_invite_bytes``.
    """

    version: int
    nonce: str
    inviter_id: str
    inviter_key: str  # base64 Ed25519 identity public
    endpoint: str  # "host:port" or "rns:<dest-hash>"
    issued_at: float
    expires_at: float
    allowed_peers: str
    profile: str
    signature: str  # base64 Ed25519 over canonical_invite_bytes

    # -- serialization ---------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "nonce": self.nonce,
            "inviter_id": self.inviter_id,
            "inviter_key": self.inviter_key,
            "endpoint": self.endpoint,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "allowed_peers": self.allowed_peers,
            "profile": self.profile,
            "signature": self.signature,
        }

    def to_string(self) -> str:
        """Serialize to the compact, pasteable transport string.

        Shape: ``ironmesh-invite-v1:<base64url(json)>``. base64url (no
        padding) keeps the string free of ``+`` / ``/`` so it survives
        being pasted into a shell, a chat message, or a QR code.
        """
        raw = json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        return INVITE_PREFIX + encoded

    def canonical_bytes(self) -> bytes:
        """The exact bytes the signature binds to (no signature field)."""
        return ew_protocol.canonical_invite_bytes(
            nonce=self.nonce,
            inviter_id=self.inviter_id,
            inviter_key=self.inviter_key,
            endpoint=self.endpoint,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            allowed_peers=self.allowed_peers,
            profile=self.profile,
            version=self.version,
        )

    # -- checks ----------------------------------------------------------

    def is_expired(self, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        return now > (self.expires_at + INVITE_CLOCK_SKEW)

    def verify_signature(self) -> None:
        """Raise :class:`InviteBadSignature` unless the signature verifies
        under the pinned inviter key and ``SIG_CTX_INVITE``."""
        try:
            vk = VerifyKey(base64.b64decode(self.inviter_key))
            sig = base64.b64decode(self.signature)
        except (ValueError, TypeError) as exc:
            raise InviteMalformed(f"invite key/signature not base64: {exc}") from exc
        try:
            ew_crypto.verify_detached_with_context(
                vk, ew_crypto.SIG_CTX_INVITE, self.canonical_bytes(), sig
            )
        except (BadSignatureError, ValueError) as exc:
            raise InviteBadSignature("invite signature verification failed") from exc

    def matches_identity(self, presented_identity_b64: Optional[str]) -> bool:
        """True iff ``presented_identity_b64`` equals the pinned inviter
        key. Used for verified-first-use in the joiner handshake."""
        if not presented_identity_b64:
            return False
        return presented_identity_b64 == self.inviter_key


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------

def create_invite(
    keypair,
    endpoint: str,
    *,
    profile: Optional[str] = None,
    ttl_seconds: Optional[float] = None,
    allowed_peers: str = "",
    now: Optional[float] = None,
) -> InviteToken:
    """Issue a signed, single-use invite from ``keypair`` for ``endpoint``.

    Args:
        keypair: The inviter's :class:`ironmesh.keys.AgentKeys` — its
            current Ed25519 identity is pinned into the token.
        endpoint: The inviter's bootstrap endpoint the joiner connects to
            first: ``"host:port"`` or ``"rns:<dest-hash>"``.
        profile: Deployment profile hint. Also selects the default TTL
            when ``ttl_seconds`` is not given.
        ttl_seconds: Explicit lifetime override (seconds). Falls back to
            the per-profile default from ``protocol.invite_max_age_for_profile``.
        allowed_peers: Suggested ``--allowed-peers`` for the joiner (hint).
        now: Injectable clock for tests.

    Returns:
        A fully-signed :class:`InviteToken`.
    """
    if not endpoint or not isinstance(endpoint, str):
        raise ValueError("endpoint must be a non-empty 'host:port' or 'rns:<dest>' string")
    issued_at = time.time() if now is None else now
    if ttl_seconds is None:
        ttl_seconds = ew_protocol.invite_max_age_for_profile(profile)
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    expires_at = issued_at + float(ttl_seconds)
    nonce = secrets.token_hex(16)
    inviter_id = keypair.get_fingerprint()
    inviter_key = keypair.get_public_key_base64()
    profile_str = profile or ""

    canonical = ew_protocol.canonical_invite_bytes(
        nonce=nonce,
        inviter_id=inviter_id,
        inviter_key=inviter_key,
        endpoint=endpoint,
        issued_at=issued_at,
        expires_at=expires_at,
        allowed_peers=allowed_peers,
        profile=profile_str,
    )
    signature = ew_crypto.sign_detached_with_context(
        keypair.get_signing_key(), ew_crypto.SIG_CTX_INVITE, canonical
    )
    return InviteToken(
        version=ew_protocol.INVITE_SIGNED_VERSION,
        nonce=nonce,
        inviter_id=inviter_id,
        inviter_key=inviter_key,
        endpoint=endpoint,
        issued_at=issued_at,
        expires_at=expires_at,
        allowed_peers=allowed_peers,
        profile=profile_str,
        signature=base64.b64encode(signature).decode("ascii"),
    )


# ---------------------------------------------------------------------------
# Parse / validate
# ---------------------------------------------------------------------------

def parse_invite(token_str: str) -> InviteToken:
    """Parse a transport string into an :class:`InviteToken`.

    Does NOT check expiry, signature, or single-use — call
    :meth:`InviteToken.verify_signature` / :meth:`InviteToken.is_expired`
    / the ledger separately. Raises :class:`InviteMalformed` on any
    structural problem.
    """
    if not isinstance(token_str, str):
        raise InviteMalformed("invite token must be a string")
    s = token_str.strip()
    if not s.startswith(INVITE_PREFIX):
        raise InviteMalformed(
            f"invite token must start with {INVITE_PREFIX!r}"
        )
    b64 = s[len(INVITE_PREFIX):]
    # Restore base64url padding.
    pad = "=" * (-len(b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(b64 + pad)
        body = json.loads(raw.decode("utf-8"))
    except (ValueError, TypeError, UnicodeDecodeError) as exc:
        raise InviteMalformed(f"invite body not decodable: {exc}") from exc
    if not isinstance(body, dict):
        raise InviteMalformed("invite body is not an object")

    required = (
        "version", "nonce", "inviter_id", "inviter_key", "endpoint",
        "issued_at", "expires_at", "allowed_peers", "profile", "signature",
    )
    missing = [k for k in required if k not in body]
    if missing:
        raise InviteMalformed(f"invite missing fields: {', '.join(missing)}")

    try:
        return InviteToken(
            version=int(body["version"]),
            nonce=str(body["nonce"]),
            inviter_id=str(body["inviter_id"]),
            inviter_key=str(body["inviter_key"]),
            endpoint=str(body["endpoint"]),
            issued_at=float(body["issued_at"]),
            expires_at=float(body["expires_at"]),
            allowed_peers=str(body["allowed_peers"]),
            profile=str(body["profile"]),
            signature=str(body["signature"]),
        )
    except (TypeError, ValueError) as exc:
        raise InviteMalformed(f"invite field has wrong type: {exc}") from exc


def validate_invite(
    token: InviteToken,
    *,
    now: Optional[float] = None,
    presented_identity_b64: Optional[str] = None,
) -> None:
    """Run the joiner-side validation gauntlet on a parsed token.

    Order: signature (identity authenticity), then expiry, then — if a
    handshake identity was presented — the verified-first-use identity
    match. Single-use is enforced INVITER-side (see :class:`InviteLedger`)
    and is deliberately NOT checked here: the joiner cannot be
    authoritative about consumption.

    Raises the specific :class:`InviteError` subclass on the first failure.
    """
    token.verify_signature()
    if token.is_expired(now=now):
        raise InviteExpired(
            f"invite expired at {token.expires_at} (nonce {token.nonce[:8]}…)"
        )
    if presented_identity_b64 is not None and not token.matches_identity(
        presented_identity_b64
    ):
        raise InviteIdentityMismatch(
            "handshake identity does not match the invite's pinned inviter key"
        )


# ---------------------------------------------------------------------------
# Single-use ledger (inviter-authoritative)
# ---------------------------------------------------------------------------

class InviteLedger:
    """Persisted spent-nonce ledger for single-use enforcement.

    Lives on the INVITING node. On a successful join the inviter records
    the token's nonce here; any later presentation of the same nonce is
    rejected. Storage is a small JSON file (nonce -> {spent_at, expires_at}).

    Thread-safe within a process via a lock; cross-process safety is not
    required because the ledger is only written from the daemon's single
    handshake path. Expired entries are pruned on load/save so the file
    stays bounded.
    """

    def __init__(self, path: str = DEFAULT_LEDGER_PATH):
        self.path = os.path.expanduser(path)
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._lock = threading.RLock()
        self._spent: dict = {}  # nonce -> {"spent_at": float, "expires_at": float}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError) as exc:
            # A corrupt ledger must FAIL CLOSED for security: if we cannot
            # read which nonces were consumed, we cannot prove a token is
            # unused. Rather than silently start empty (which would let
            # every past token be replayed once), surface the problem.
            logger.error("invite ledger unreadable at %s: %s", self.path, exc)
            raise
        if isinstance(data, dict) and isinstance(data.get("spent"), dict):
            self._spent = dict(data["spent"])
        self._prune(persist=False)

    def _prune(self, *, persist: bool = True, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        cutoff = now - LEDGER_RETENTION_AFTER_EXPIRY
        before = len(self._spent)
        self._spent = {
            nonce: rec
            for nonce, rec in self._spent.items()
            if float(rec.get("expires_at", 0.0)) >= cutoff
        }
        if persist and len(self._spent) != before:
            self._save()

    def _save(self) -> None:
        tmp = f"{self.path}.{os.getpid()}.{threading.get_ident()}.tmp"
        payload = json.dumps(
            {"version": 1, "spent": self._spent},
            sort_keys=True, separators=(",", ":"),
        )
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(payload)
            f.flush()
            # Durability for the single-use guarantee: without fsync, a
            # power loss (not a mere process crash) in the writeback window
            # could lose a just-recorded spent nonce and make its token
            # replayable once. Best-effort — some filesystems reject fsync.
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp, self.path)
        from ironmesh.keys import restrict_file_to_owner
        restrict_file_to_owner(self.path)

    def is_spent(self, nonce: str) -> bool:
        with self._lock:
            return nonce in self._spent

    def mark_spent(self, token: InviteToken, now: Optional[float] = None) -> None:
        """Record ``token``'s nonce as consumed. Idempotent."""
        now = time.time() if now is None else now
        with self._lock:
            self._spent[token.nonce] = {
                "spent_at": float(now),
                "expires_at": float(token.expires_at),
            }
            self._prune(persist=False, now=now)
            self._save()

    def check_and_reject_if_spent(self, token: InviteToken) -> None:
        """Raise :class:`InviteSpent` if this token's nonce was consumed."""
        if self.is_spent(token.nonce):
            raise InviteSpent(
                f"invite nonce {token.nonce[:8]}… already consumed"
            )
