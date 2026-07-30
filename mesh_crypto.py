"""IronMesh end-to-end encryption — NaCl SealedBox over X25519 derived keys.

Per-hop SecretBox encryption protects messages between adjacent peers, but
relay nodes must decrypt-and-re-encrypt to forward, so they see plaintext.
This module provides an additional end-to-end layer that only the destination
can decrypt.

Design:
    - We derive an X25519 keypair from each node's existing Ed25519 identity
      via the libsodium-blessed ``crypto_sign_ed25519_*_to_curve25519`` helpers
      already wrapped in ``ironmesh.keys``.
    - The sender uses NaCl ``SealedBox`` to encrypt to the destination's
      derived X25519 public key. SealedBox generates a fresh ephemeral X25519
      keypair per message and discards the private side, providing
      forward secrecy *for each individual message*.
    - Only the destination — holder of the matching X25519 secret derived from
      its Ed25519 secret — can decrypt.

Wire surface:
    - Cipher: NaCl SealedBox (XSalsa20-Poly1305 with ephemeral X25519)
    - Public key: 32 bytes
    - Ciphertext overhead: 48 bytes (32 ephemeral pubkey + 16 Poly1305 tag)

Threat model:
    - The sealed ``e2e_payload`` is readable ONLY by the destination. Whether a
      relay can also read the body depends on the confidentiality mode:
        * Default (wire-compatible): the sealed copy rides ALONGSIDE the per-hop
          ``frame.payload``, so a relay that decrypts its per-hop layer to route
          can read the body. Confidentiality-from-relays is NOT provided in this
          mode — it exists so every node version can forward the frame.
        * Opt-in (``--e2e-strict-confidentiality``, on a fully-upgraded mesh):
          the send path strips ``frame.payload`` so the body travels SOLELY in
          ``e2e_payload``. A relay decrypting its per-hop layer then finds no
          readable body — only this sealed field, which only the destination
          can unseal. This is the mode that delivers relay-confidentiality.
    - When the body is stripped, a relay cannot verify the inner source
      signature over it; verification is deferred to the destination
      (post-unseal). A relay simply forwards sealed frames.
    - Fallback: when the destination's key is unknown the frame is NOT sealed
      (per-hop encryption only) and a relay can read the body — routing.py
      logs a warning in that case.
    - Relay nodes CAN see source, destination, msg_id, timestamp, message type
      (header metadata is required for routing).
    - Inner Ed25519 source signature provides authenticity end-to-end.
"""

from typing import Optional

from nacl.exceptions import CryptoError
from nacl.public import PrivateKey as X25519PrivateKey, PublicKey as X25519PublicKey, SealedBox

from ironmesh.keys import ed25519_to_curve25519_public, ed25519_to_curve25519_secret


def seal_to_destination(
    plaintext: bytes,
    dest_ed25519_pub: bytes,
    dest_x25519_pub: Optional[bytes] = None,
) -> bytes:
    """End-to-end encrypt ``plaintext`` for the holder of ``dest_ed25519_pub``.

    Args:
        plaintext: Bytes to encrypt.
        dest_ed25519_pub: Destination's Ed25519 public key (32 bytes).
            Used for legacy derivation when no master-seed X25519 public
            is supplied; also kept as the canonical identity reference
            for diagnostics.
        dest_x25519_pub: v0.9.4 Phase 2 — when present, use this X25519
            public directly for SealedBox encryption. The caller is
            responsible for having verified this key is bound to
            ``dest_ed25519_pub`` (typically via the HELLO
            ``x25519_binding_signature``). When None, falls back to the
            legacy ``ed25519_to_curve25519_public`` derivation so
            mixed-version meshes keep working.

    Returns:
        SealedBox ciphertext (48 bytes longer than plaintext).

    Raises:
        ValueError: If the destination key is not a valid 32-byte key.
    """
    if not isinstance(dest_ed25519_pub, (bytes, bytearray)):
        raise ValueError("dest_ed25519_pub must be bytes")
    if len(dest_ed25519_pub) != 32:
        raise ValueError(
            f"dest_ed25519_pub must be 32 bytes, got {len(dest_ed25519_pub)}"
        )
    if not isinstance(plaintext, (bytes, bytearray)):
        raise ValueError("plaintext must be bytes")

    if dest_x25519_pub is not None:
        if not isinstance(dest_x25519_pub, (bytes, bytearray)):
            raise ValueError("dest_x25519_pub must be bytes when provided")
        if len(dest_x25519_pub) != 32:
            raise ValueError(
                f"dest_x25519_pub must be 32 bytes, got {len(dest_x25519_pub)}"
            )
        x25519_pub = bytes(dest_x25519_pub)
    else:
        x25519_pub = ed25519_to_curve25519_public(bytes(dest_ed25519_pub))
    box = SealedBox(X25519PublicKey(x25519_pub))
    return bytes(box.encrypt(bytes(plaintext)))


def unseal_from_source(
    sealed: bytes,
    my_ed25519_secret: bytes,
    my_x25519_secret: Optional[bytes] = None,
) -> bytes:
    """End-to-end decrypt a SealedBox payload addressed to us.

    Args:
        sealed: SealedBox ciphertext from ``seal_to_destination``.
        my_ed25519_secret: Our Ed25519 secret key (32 bytes). Used for
            legacy derivation when ``my_x25519_secret`` is None.
        my_x25519_secret: v0.9.4 Phase 2 — when present, use this
            X25519 secret directly for decryption. Typically the
            master-seed-derived ``x25519_seed`` from
            ``AgentKeys.get_x25519_secret()``. When None, falls back to
            the legacy ``ed25519_to_curve25519_secret`` derivation.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: If decryption fails (wrong recipient, corruption,
                    truncation, or tampering).
    """
    if not isinstance(my_ed25519_secret, (bytes, bytearray)):
        raise ValueError("my_ed25519_secret must be bytes")
    if not isinstance(sealed, (bytes, bytearray)):
        raise ValueError("sealed must be bytes")

    if my_x25519_secret is not None:
        if not isinstance(my_x25519_secret, (bytes, bytearray)):
            raise ValueError("my_x25519_secret must be bytes when provided")
        if len(my_x25519_secret) != 32:
            raise ValueError(
                f"my_x25519_secret must be 32 bytes, got {len(my_x25519_secret)}"
            )
        x25519_priv_bytes = bytes(my_x25519_secret)
    else:
        x25519_priv_bytes = ed25519_to_curve25519_secret(bytes(my_ed25519_secret))
    box = SealedBox(X25519PrivateKey(x25519_priv_bytes))
    try:
        return bytes(box.decrypt(bytes(sealed)))
    except CryptoError as e:
        raise ValueError(f"E2E decryption failed: {e}")


def can_seal_to(dest_ed25519_pub: Optional[bytes]) -> bool:
    """Return True if we have a usable destination key for sealing."""
    return isinstance(dest_ed25519_pub, (bytes, bytearray)) and len(
        dest_ed25519_pub
    ) == 32
