"""IronMesh encryption — NaCl ECDH key exchange, SecretBox encryption, Ed25519 signing.

Provides:
- X25519 ECDH key exchange for forward-secret session keys
- XSalsa20-Poly1305 (SecretBox) authenticated encryption
- Ed25519 message signing and verification
- Detached Ed25519 signatures (sign/verify without concatenation)
- Best-effort secure memory wiping
- Legacy encrypt/decrypt helpers for backward compatibility
"""

import base64
import json
import logging

from nacl.public import Box, PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey

logger = logging.getLogger("ironmesh.crypto")


# ---------------------------------------------------------------------------
# ECDH key exchange
# ---------------------------------------------------------------------------

def generate_ephemeral_keypair():
    """Generate an ephemeral X25519 keypair for ECDH key exchange.

    Returns (private_key, public_key) as nacl objects.
    """
    private = PrivateKey.generate()
    return private, private.public_key


def ecdh_exchange(my_private: PrivateKey, their_public: PublicKey) -> bytes:
    """X25519 ECDH key exchange -> 32-byte shared secret suitable for SecretBox.

    Args:
        my_private: Our ephemeral X25519 PrivateKey.
        their_public: Peer's ephemeral X25519 PublicKey.

    Returns:
        32-byte shared secret.
    """
    box = Box(my_private, their_public)
    return box.shared_key()


# ---------------------------------------------------------------------------
# SecretBox encryption (XSalsa20-Poly1305)
# ---------------------------------------------------------------------------

def encrypt_message(shared_key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext using XSalsa20-Poly1305 SecretBox.

    Args:
        shared_key: 32-byte shared secret from ECDH exchange.
        plaintext: Data to encrypt.

    Returns:
        Nonce + ciphertext as raw bytes.
    """
    box = SecretBox(shared_key)
    return bytes(box.encrypt(plaintext))


def decrypt_message(shared_key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext using XSalsa20-Poly1305 SecretBox.

    Args:
        shared_key: 32-byte shared secret from ECDH exchange.
        ciphertext: Nonce + ciphertext bytes (as returned by encrypt_message).

    Returns:
        Decrypted plaintext bytes.

    Raises:
        nacl.exceptions.CryptoError: On decryption failure.
    """
    # Audit M-04: reject obviously-too-short ciphertext before handing
    # to libsodium. A valid SecretBox ciphertext has a 24-byte nonce
    # plus a 16-byte Poly1305 tag (40 bytes minimum).
    if len(ciphertext) < 40:
        raise ValueError(f"Ciphertext too short ({len(ciphertext)} < 40 bytes)")
    box = SecretBox(shared_key)
    return bytes(box.decrypt(ciphertext))


def make_secretbox(shared_key: bytes) -> SecretBox:
    """Create a SecretBox from a shared key (for Frame encrypt/decrypt)."""
    return SecretBox(shared_key)


# ---------------------------------------------------------------------------
# Ed25519 signing
# ---------------------------------------------------------------------------

def sign_message(signing_key: SigningKey, message: bytes) -> bytes:
    """Sign message with Ed25519.

    Returns signature + message concatenated (64-byte sig + original message).
    """
    return bytes(signing_key.sign(message))


def verify_signature(verify_key: VerifyKey, signed: bytes) -> bytes:
    """Verify Ed25519 signature and return the original message.

    Raises nacl.exceptions.BadSignatureError on invalid signature.
    """
    return bytes(verify_key.verify(signed))


# ---------------------------------------------------------------------------
# Detached Ed25519 signatures
# ---------------------------------------------------------------------------

def sign_detached(signing_key: SigningKey, message: bytes) -> bytes:
    """Sign message with Ed25519 and return only the 64-byte signature.

    Unlike sign_message(), this does NOT concatenate the message.
    The signature directly binds to the exact bytes of `message`.
    """
    signed = signing_key.sign(message)
    return bytes(signed.signature)  # First 64 bytes only


def verify_detached(verify_key: VerifyKey, message: bytes, signature: bytes) -> bool:
    """Verify a detached Ed25519 signature against a message.

    Args:
        verify_key: Ed25519 verify key.
        message: The exact bytes that were signed.
        signature: 64-byte detached signature.

    Returns:
        True on success (audit L-04: explicit success return for
        readable call sites).

    Raises:
        nacl.exceptions.BadSignatureError: If verification fails.
    """
    verify_key.verify(message, signature)
    return True


# ---------------------------------------------------------------------------
# Secure memory wiping
# ---------------------------------------------------------------------------

def secure_wipe(obj):
    """Zero sensitive data in-place (audit C-02).

    Works on ``bytearray`` and ``memoryview`` writable buffers. For
    immutable ``bytes`` Python's memory model prevents reliable
    zeroing — callers holding key material must use ``bytearray``.

    If libsodium's ``sodium_memzero`` binding is available via PyNaCl,
    it's preferred over the pure-Python loop.

    Args:
        obj: A bytearray, memoryview, or nacl PrivateKey (whose private
             buffer will be attempted).
    """
    # Attempt nacl PrivateKey first — extract raw secret
    if hasattr(obj, "_private_key"):
        try:
            raw = obj._private_key
            if isinstance(raw, bytearray):
                _zero(raw)
                return
        except (AttributeError, TypeError) as e:
            logger.debug("secure_wipe: cannot access nacl private key: %s", e)
        # Fall through: best-effort. Immutable bytes path has no
        # reliable wipe in pure Python; log and continue.
        logger.debug("secure_wipe: nacl object holds immutable bytes — cannot wipe")
        return

    if isinstance(obj, bytearray):
        _zero(obj)
        return
    if isinstance(obj, memoryview):
        if obj.readonly:
            logger.warning(
                "secure_wipe called on read-only memoryview — cannot wipe. "
                "Use bytearray for key material."
            )
            return
        _zero(obj)
        return

    # bytes and other immutable types cannot be reliably zeroed in Python.
    logger.warning(
        "secure_wipe: cannot zero %s (immutable); use bytearray for key material",
        type(obj).__name__,
    )


def _zero(buf):
    """Zero a writable buffer, preferring libsodium if available."""
    try:
        from nacl.bindings import sodium_memzero  # type: ignore[attr-defined]
        sodium_memzero(buf)
        return
    except (ImportError, AttributeError, TypeError):
        pass
    for i in range(len(buf)):
        buf[i] = 0


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------

def encrypt_json(obj, shared_key: bytes) -> str:
    """Encrypt a JSON-serializable object, return base64-encoded ciphertext."""
    plaintext = json.dumps(obj, separators=(",", ":")).encode()
    encrypted = encrypt_message(shared_key, plaintext)
    return base64.b64encode(encrypted).decode()


def decrypt_json(cipherb64: str, shared_key: bytes):
    """Decrypt a base64-encoded ciphertext and parse as JSON."""
    raw = base64.b64decode(cipherb64)
    plaintext = decrypt_message(shared_key, raw)
    return json.loads(plaintext)


# ---------------------------------------------------------------------------
# Legacy compatibility aliases (used by older code paths)
# ---------------------------------------------------------------------------

def encrypt(plaintext_bytes: bytes, shared_secret: bytes) -> str:
    """Legacy: encrypt and return base64 string."""
    encrypted = encrypt_message(shared_secret, plaintext_bytes)
    return base64.b64encode(encrypted).decode()


def decrypt(cipherb64: str, shared_secret: bytes) -> bytes:
    """Legacy: decrypt base64 string and return plaintext bytes."""
    raw = base64.b64decode(cipherb64)
    return decrypt_message(shared_secret, raw)
