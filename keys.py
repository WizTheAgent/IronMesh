"""IronMesh key management — Ed25519 identity keys + X25519 ephemeral keys.

Provides:
- Ed25519 signing keypair generation (identity)
- X25519 ephemeral keypair generation (per-session ECDH)
- Key serialization/deserialization with optional passphrase protection
- Fingerprinting for peer identification
"""

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Optional

import nacl.bindings
import nacl.signing
from nacl.public import PrivateKey as X25519PrivateKey
from nacl.pwhash import argon2id
from nacl.signing import SigningKey, VerifyKey

# Audit L-05: shared constant for 128-bit fingerprints (first 32 hex
# chars of SHA-256). Use this everywhere a fingerprint is computed.
FINGERPRINT_HEX_CHARS = 32


@dataclass
class AgentKeys:
    """Ed25519 identity keys for an agent."""
    ed25519_secret: bytes
    ed25519_public: bytes
    agent_name: str = ""

    def get_fingerprint(self) -> str:
        """SHA-256 fingerprint of the Ed25519 public key (first 16 hex chars)."""
        return hashlib.sha256(self.ed25519_public).hexdigest()[:32]

    def get_public_key_base64(self) -> str:
        """Base64-encoded Ed25519 public key."""
        return base64.b64encode(self.ed25519_public).decode()

    def get_signing_key(self) -> SigningKey:
        """Return nacl SigningKey from stored secret bytes."""
        return SigningKey(self.ed25519_secret)

    def get_verify_key(self) -> VerifyKey:
        """Return nacl VerifyKey from stored public bytes."""
        return VerifyKey(self.ed25519_public)


def generate_keypair(agent_name: str = "") -> AgentKeys:
    """Generate a new Ed25519 identity keypair.

    These keys are for signing/identity only. For ECDH, use generate_ephemeral().
    """
    signing = SigningKey.generate()
    return AgentKeys(
        ed25519_secret=bytes(signing),
        ed25519_public=bytes(signing.verify_key),
        agent_name=agent_name,
    )


def generate_ephemeral():
    """Generate an ephemeral X25519 keypair for ECDH key exchange.

    Returns (private_key, public_key) as nacl.public.PrivateKey/PublicKey.
    These should be generated per-session and never persisted.
    """
    private = X25519PrivateKey.generate()
    return private, private.public_key


def ed25519_to_curve25519_public(ed25519_public: bytes) -> bytes:
    """Convert Ed25519 public key to Curve25519 (X25519) public key.

    Useful for verifying identity of an ECDH peer.
    """
    return nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(ed25519_public)


def ed25519_to_curve25519_secret(ed25519_secret: bytes) -> bytes:
    """Convert Ed25519 secret key to Curve25519 (X25519) secret key.

    The intermediate 64-byte buffer (seed+public) is held
    in a ``bytearray`` and zeroed after use so the secret half doesn't
    linger in the heap.
    """
    # nacl.bindings expects the full 64-byte ed25519 secret key (seed + public)
    if len(ed25519_secret) == 32:
        signing = SigningKey(ed25519_secret)
        full_key = bytearray(bytes(signing) + bytes(signing.verify_key))
    else:
        full_key = bytearray(ed25519_secret)
    try:
        return nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(bytes(full_key))
    finally:
        for i in range(len(full_key)):
            full_key[i] = 0


# ---------------------------------------------------------------------------
# Key persistence
# ---------------------------------------------------------------------------

def save_keys(keys: AgentKeys, path: str, passphrase: Optional[str] = None,
              allow_plaintext: bool = False):
    """Save agent keys to disk.

    Args:
        keys: AgentKeys to save.
        path: File path (will create parent dirs).
        passphrase: Passphrase to encrypt the secret key at rest
                    using Argon2id key derivation. Required unless
                    allow_plaintext=True.
        allow_plaintext: If True, allow saving without encryption.
                         Default False — forces encryption for safety.

    Raises:
        ValueError: If no passphrase and allow_plaintext is False.
    """
    if not passphrase and not allow_plaintext:
        raise ValueError(
            "Passphrase is required to encrypt identity keys at rest. "
            "Identity private keys must not be stored in plaintext. "
            "Pass allow_plaintext=True only for testing or ephemeral keys."
        )

    path = os.path.expanduser(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    data = {
        "version": 2,
        "agent_name": keys.agent_name,
        "ed25519_public": base64.b64encode(keys.ed25519_public).decode(),
    }

    if passphrase:
        # Encrypt the secret key with Argon2id-derived key
        salt = os.urandom(16)
        derived = argon2id.kdf(
            32,
            passphrase.encode(),
            salt,
            opslimit=argon2id.OPSLIMIT_MODERATE,
            memlimit=argon2id.MEMLIMIT_MODERATE,
        )
        from nacl.secret import SecretBox
        box = SecretBox(derived)
        encrypted_secret = bytes(box.encrypt(keys.ed25519_secret))
        data["ed25519_secret_encrypted"] = base64.b64encode(encrypted_secret).decode()
        data["salt"] = base64.b64encode(salt).decode()
        data["encrypted"] = True
    else:
        import logging
        logging.getLogger("ironmesh.keys").warning(
            "Saving identity key in PLAINTEXT (allow_plaintext=True). "
            "This is insecure for production use."
        )
        data["ed25519_secret"] = base64.b64encode(keys.ed25519_secret).decode()
        data["encrypted"] = False

    # v0.8.5.6 B13 fix: atomic write via temp + rename + fsync.
    # save_keys is called rarely (initial generation + key rotation),
    # but an interrupted write here permanently destroys the
    # daemon's identity — unrecoverable without external backups.
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2)
        f.flush()
        try:
            os.fsync(f.fileno())
        except (OSError, AttributeError):
            pass
    try:
        # chmod the tmp before rename so the production file is
        # never briefly world-readable on a file system that
        # respects mode bits.
        os.chmod(tmp_path, 0o600)
    except OSError:
        pass  # Windows doesn't support chmod the same way
    os.replace(tmp_path, path)


def load_keys(path: str, passphrase: Optional[str] = None) -> AgentKeys:
    """Load agent keys from disk.

    Args:
        path: File path to load from.
        passphrase: Passphrase to decrypt if key file is encrypted.

    Returns:
        AgentKeys instance.

    Raises:
        ValueError: If key format is invalid or wrong passphrase.
        FileNotFoundError: If key file doesn't exist.
    """
    path = os.path.expanduser(path)
    with open(path) as f:
        data = json.load(f)

    # Key-file schema version — read for forward-compat diagnostics but
    # parsing is identical across versions 1 and 2 today.
    _version = data.get("version", 1)

    # Audit M-03: bound base64 input before decoding. An Ed25519 key
    # encodes to 44 chars; 100 is generous headroom for whitespace.
    pub_b64 = data["ed25519_public"]
    if not isinstance(pub_b64, str) or len(pub_b64) > 100:
        raise ValueError(f"Invalid Ed25519 public key base64 (length={len(pub_b64)!r})")
    ed25519_public = base64.b64decode(pub_b64)
    if len(ed25519_public) != 32:
        raise ValueError(f"Invalid Ed25519 public key length: {len(ed25519_public)}")

    if data.get("encrypted", False):
        if not passphrase:
            raise ValueError("Key file is encrypted but no passphrase provided")
        salt = base64.b64decode(data["salt"])
        derived = argon2id.kdf(
            32,
            passphrase.encode(),
            salt,
            opslimit=argon2id.OPSLIMIT_MODERATE,
            memlimit=argon2id.MEMLIMIT_MODERATE,
        )
        from nacl.exceptions import CryptoError
        from nacl.secret import SecretBox
        box = SecretBox(derived)
        try:
            encrypted_secret = base64.b64decode(data["ed25519_secret_encrypted"])
            ed25519_secret = bytes(box.decrypt(encrypted_secret))
        except CryptoError:
            raise ValueError("Wrong passphrase or corrupted key file")
    else:
        ed25519_secret = base64.b64decode(data["ed25519_secret"])

    if len(ed25519_secret) != 32:
        raise ValueError(f"Invalid Ed25519 secret key length: {len(ed25519_secret)}")

    # Verify that the secret key matches the public key
    signing = SigningKey(ed25519_secret)
    if bytes(signing.verify_key) != ed25519_public:
        raise ValueError("Ed25519 secret key does not match public key")

    return AgentKeys(
        ed25519_secret=ed25519_secret,
        ed25519_public=ed25519_public,
        agent_name=data.get("agent_name", ""),
    )


def get_fingerprint(public_key_bytes: bytes) -> str:
    """Compute SHA-256 fingerprint of a public key (first 16 hex chars)."""
    return hashlib.sha256(public_key_bytes).hexdigest()[:32]
