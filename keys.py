"""IronMesh key management — Ed25519 identity keys + X25519 ephemeral keys.

Provides:
- Ed25519 signing keypair generation (identity)
- X25519 ephemeral keypair generation (per-session ECDH)
- Key serialization/deserialization with optional passphrase protection
- Fingerprinting for peer identification
- v0.9.4 master-seed envelope (Phase 1 of the Ed25519/X25519 dual-use
  split): a v3 keys.json carries an additional 32-byte `x25519_seed`
  derived via HKDF-SHA256 from the existing Ed25519 seed + per-node
  random salt. The Ed25519 seed itself is preserved byte-for-byte so
  every existing TOFU pin survives the migration. The X25519 subkey is
  stored on disk but Phase 1 does NOT switch wire-level X25519 derivation
  to consume it — Phase 2 (v0.9.4) adds the HELLO advertisement and the
  receiver-prefers-advertised-key fallback. Phase 1 is purely a disk
  format upgrade.
"""

import base64
import hashlib
import hmac as _hmac
import json
import logging
import os
from dataclasses import dataclass
from typing import Optional

import nacl.bindings
import nacl.signing
from nacl.public import PrivateKey as X25519PrivateKey
from nacl.pwhash import argon2id
from nacl.signing import SigningKey, VerifyKey

logger = logging.getLogger("ironmesh.keys")


def restrict_file_to_owner(path) -> None:
    """Best-effort: restrict a sensitive file to the owning user.

    POSIX: ``chmod 0600``. Windows/NTFS: ``os.chmod`` only toggles the
    read-only bit (it does NOT produce an owner-only ACL), so additionally
    run ``icacls`` to drop inherited ACEs and grant the current user only.
    Best-effort throughout — the file's contents are Argon2id-encrypted at
    rest regardless, so a failure here degrades defense-in-depth, not
    confidentiality of the key material itself.
    """
    import stat as _stat
    try:
        os.chmod(path, _stat.S_IRUSR | _stat.S_IWUSR)  # 0600 (POSIX-effective)
    except OSError:
        pass
    if os.name != "nt":
        return
    try:
        import getpass
        import subprocess
        user = os.environ.get("USERNAME") or getpass.getuser()
        if not user:
            return
        result = subprocess.run(
            ["icacls", os.fspath(path), "/inheritance:r",
             "/grant:r", f"{user}:F"],
            check=False, capture_output=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            timeout=10,
        )
        if result.returncode != 0:
            # Best-effort by design (contents are Argon2id-encrypted at rest),
            # but surface the failure so an operator relying on owner-only ACLs
            # — especially with --plaintext-keys — is not misled into thinking
            # the file is locked down when it is not (FAT/exFAT volume,
            # unresolvable account, icacls off PATH, etc.).
            logger.warning(
                "Could not restrict %s to owner-only via icacls (exit %d): %s",
                path, result.returncode,
                (result.stderr or b"").decode("utf-8", "replace").strip(),
            )
    except Exception as e:
        logger.warning("Owner-only ACL restriction of %s skipped: %s", path, e)

# Audit L-05: shared constant for 128-bit fingerprints (first 32 hex
# chars of SHA-256). Use this everywhere a fingerprint is computed.
FINGERPRINT_HEX_CHARS = 32

# Shared remediation text appended to every "encrypted key file could
# not be decrypted" error so operators always see the full menu of
# passphrase sources, in precedence order.
KEYS_PASSPHRASE_SOURCES_HELP = (
    "Supply the key-file passphrase via one of:\n"
    "  --keys-passphrase-file <path>   (file containing the passphrase; "
    "chmod 600 recommended)\n"
    "  IRONMESH_KEYS_PASSPHRASE        (environment variable)\n"
    "  an interactive terminal         (you will be prompted)\n"
    "  --keys-passphrase <pass>        (DISCOURAGED: argv is visible in "
    "the process list)\n"
    "Note: `ironmesh setup` encrypts the key file with the mesh "
    "passphrase, so the daemon tries the mesh passphrase automatically "
    "before prompting."
)

# v0.9.4 master-seed envelope (Phase 1).
KEYS_FORMAT_MASTER_SEED_V1 = "master-seed-v1"

# HKDF-SHA256 info labels for the two subkey roles. NUL-terminated to
# avoid any future label being a prefix of another label.
HKDF_INFO_X25519 = b"ironmesh-identity-x25519-v1\x00"
# Reserved for future use (Phase 3+) when ALL subkeys are HKDF-derived;
# Phase 1 keeps Ed25519 at the raw seed bytes to preserve TOFU pins.
HKDF_INFO_ED25519 = b"ironmesh-identity-ed25519-v1\x00"


def _x25519_public_from_seed(x25519_seed: bytes) -> bytes:
    """Derive the X25519 public key from a 32-byte X25519 secret seed.

    The seed is used as the raw scalar input to the curve25519 scalar-
    base-mult. PyNaCl wraps ``PrivateKey(seed).public_key`` which
    performs the standard clamping internally.
    """
    if len(x25519_seed) != 32:
        raise ValueError(f"x25519_seed must be 32 bytes, got {len(x25519_seed)}")
    return bytes(X25519PrivateKey(x25519_seed).public_key)


def _compute_x25519_binding(ed25519_secret: bytes, x25519_public: bytes) -> bytes:
    """Sign the X25519 public under the Ed25519 identity with the
    ``SIG_CTX_X25519_BINDING`` domain-separation context. The output
    travels with the X25519 public in HELLO so a receiver can verify
    the advertised X25519 actually belongs to the pinned Ed25519
    identity.
    """
    from ironmesh.crypto import SIG_CTX_X25519_BINDING, sign_detached_with_context
    return sign_detached_with_context(
        SigningKey(ed25519_secret),
        SIG_CTX_X25519_BINDING,
        x25519_public,
    )


def _hkdf_sha256(secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 (RFC 5869). Library helper — kept inline so keys.py
    has zero new external deps. ``length`` <= 32 covers all current uses.
    """
    if length <= 0 or length > 32 * 255:
        raise ValueError(f"HKDF length {length} out of range")
    # Extract.
    prk = _hmac.new(salt, secret, hashlib.sha256).digest()
    # Expand (one block at a time, T(i) = HMAC(prk, T(i-1) || info || i)).
    output = b""
    t = b""
    counter = 1
    while len(output) < length:
        t = _hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        output += t
        counter += 1
    return output[:length]


@dataclass
class AgentKeys:
    """Ed25519 identity keys for an agent.

    v0.9.4 (Phase 1) extends the dataclass with an optional pre-derived
    ``x25519_seed`` (32 bytes) and ``hkdf_salt`` (16 bytes). Legacy v1/v2
    files load with both as None; v3 master-seed files populate them.
    Consumers needing the X25519 subkey should call
    ``get_x25519_secret()`` which handles both code paths.

    v0.9.4 (Phase 2) extends further with ``x25519_public`` (32 bytes,
    the published X25519 KEX public key) and ``x25519_binding_signature``
    (64-byte Ed25519 detached signature of
    ``SIG_CTX_X25519_BINDING || x25519_public`` under the Ed25519
    identity key). The binding is computed once at master-seed
    generation / migration and shipped verbatim in HELLO so receivers
    can verify the advertised X25519 public actually belongs to the
    peer whose Ed25519 identity they have pinned. Both fields are None
    for legacy v1/v2 loads — the receiver falls back to deriving
    X25519 via ``ed25519_to_curve25519`` from the peer's pinned Ed25519.
    """
    ed25519_secret: bytes
    ed25519_public: bytes
    agent_name: str = ""
    # v0.9.4 master-seed Phase 1 fields. Optional for legacy compat.
    x25519_seed: Optional[bytes] = None
    hkdf_salt: Optional[bytes] = None
    # v0.9.4 Phase 2 fields. Optional for Phase 1 + legacy compat.
    x25519_public: Optional[bytes] = None
    x25519_binding_signature: Optional[bytes] = None

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

    def is_master_seed_format(self) -> bool:
        """True iff the v3 master-seed format is active for this AgentKeys."""
        return self.x25519_seed is not None and self.hkdf_salt is not None

    def get_x25519_secret(self) -> bytes:
        """Return the X25519 ECDH secret for this identity.

        v0.9.4 Phase 2: prefers the master-seed-derived ``x25519_seed``
        when present; falls back to the historical
        ``ed25519_to_curve25519_secret`` transform when the master-seed
        fields are absent (legacy v1/v2 load).
        """
        if self.x25519_seed is not None:
            return self.x25519_seed
        return ed25519_to_curve25519_secret(self.ed25519_secret)

    def get_x25519_public(self) -> bytes:
        """Return the X25519 ECDH public key for this identity.

        Companion to :meth:`get_x25519_secret`. v0.9.4: stored
        ``x25519_public`` (computed once at master-seed generation /
        migration) when master-seed format is active; legacy fallback
        re-derives via ``ed25519_to_curve25519_public(ed25519_public)``.
        """
        if self.x25519_public is not None:
            return self.x25519_public
        return ed25519_to_curve25519_public(self.ed25519_public)


def generate_keypair(agent_name: str = "",
                     master_seed_format: bool = True) -> AgentKeys:
    """Generate a new Ed25519 identity keypair.

    These keys are for signing/identity only. For ECDH, use generate_ephemeral().

    v0.9.4 (Phase 1): new keys default to the master-seed format
    (Ed25519 seed at the raw bytes, X25519 subkey HKDF-derived,
    16-byte per-node random salt). Pass ``master_seed_format=False`` to
    produce a legacy v1/v2-shaped AgentKeys for tests that need to
    reproduce pre-v0.9.4 disk-format paths.
    """
    signing = SigningKey.generate()
    ed25519_secret = bytes(signing)
    ed25519_public = bytes(signing.verify_key)
    if master_seed_format:
        hkdf_salt = os.urandom(16)
        x25519_seed = _hkdf_sha256(
            ed25519_secret, hkdf_salt, HKDF_INFO_X25519, length=32,
        )
        # v0.9.4: compute the public + identity-binding signature so
        # the HELLO advertisement path has them ready.
        x25519_public = _x25519_public_from_seed(x25519_seed)
        x25519_binding = _compute_x25519_binding(ed25519_secret, x25519_public)
        return AgentKeys(
            ed25519_secret=ed25519_secret,
            ed25519_public=ed25519_public,
            agent_name=agent_name,
            x25519_seed=x25519_seed,
            hkdf_salt=hkdf_salt,
            x25519_public=x25519_public,
            x25519_binding_signature=x25519_binding,
        )
    return AgentKeys(
        ed25519_secret=ed25519_secret,
        ed25519_public=ed25519_public,
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

    v0.9.4 Phase 1: when ``keys.is_master_seed_format()`` is true (i.e.
    a v0.9.4-generated or migrated AgentKeys with ``x25519_seed`` +
    ``hkdf_salt`` populated), the envelope is written at version 3 with
    ``format = "master-seed-v1"`` and the additional fields. Otherwise
    the historical v2 envelope is written, exactly as in v0.9.3 and
    earlier — no behaviour change for legacy callers.
    """
    if not passphrase and not allow_plaintext:
        raise ValueError(
            "Passphrase is required to encrypt identity keys at rest. "
            "Identity private keys must not be stored in plaintext. "
            "Pass allow_plaintext=True only for testing or ephemeral keys."
        )

    path = os.path.expanduser(path)
    _parent = os.path.dirname(path)
    if _parent:
        os.makedirs(_parent, exist_ok=True)

    use_master_seed = keys.is_master_seed_format()
    data = {
        "version": 3 if use_master_seed else 2,
        "agent_name": keys.agent_name,
        "ed25519_public": base64.b64encode(keys.ed25519_public).decode(),
    }
    if use_master_seed:
        data["format"] = KEYS_FORMAT_MASTER_SEED_V1
        data["hkdf_salt"] = base64.b64encode(keys.hkdf_salt).decode()
        # v0.9.4: include the X25519 public + identity-binding signature
        # so the daemon doesn't have to re-derive + re-sign on every
        # start. Both fields are non-secret; stored in cleartext
        # alongside the encrypted subkey.
        if keys.x25519_public is not None:
            data["x25519_public"] = base64.b64encode(keys.x25519_public).decode()
        if keys.x25519_binding_signature is not None:
            data["x25519_binding_signature"] = base64.b64encode(
                keys.x25519_binding_signature,
            ).decode()

    if passphrase:
        # Encrypt secret material with Argon2id-derived key. Master-seed
        # format encrypts BOTH the Ed25519 seed and the X25519 subkey under
        # the same Argon2id-derived box, with distinct field names so the
        # loader can pick them apart on the way back in.
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
        if use_master_seed:
            encrypted_x25519 = bytes(box.encrypt(keys.x25519_seed))
            data["x25519_seed_encrypted"] = base64.b64encode(encrypted_x25519).decode()
    else:
        import logging
        logging.getLogger("ironmesh.keys").warning(
            "Saving identity key in PLAINTEXT (allow_plaintext=True). "
            "This is insecure for production use."
        )
        data["ed25519_secret"] = base64.b64encode(keys.ed25519_secret).decode()
        data["encrypted"] = False
        if use_master_seed:
            data["x25519_seed"] = base64.b64encode(keys.x25519_seed).decode()

    # v0.8.5.6: atomic write via temp + rename + fsync.
    # save_keys is called rarely (initial generation + key rotation),
    # but an interrupted write here permanently destroys the
    # daemon's identity — unrecoverable without external backups.
    #
    # v0.9.4: tmp path is process-id + thread-id qualified so two
    # daemons starting concurrently against the same keystore each get
    # their own scratch file and never collide on the rename. The final
    # ``os.replace`` is atomic on every POSIX + Windows filesystem we
    # support; whichever rename lands last wins, and the loser sees a
    # consistent file on its next read.
    import threading as _threading
    tmp_path = "{}.{}.{}.tmp".format(path, os.getpid(), _threading.get_ident())
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2)
        f.flush()
        try:
            os.fsync(f.fileno())
        except (OSError, AttributeError):
            pass
    # Restrict the tmp before rename so the production file is never briefly
    # world-readable (owner-only ACL on Windows, 0600 on POSIX).
    restrict_file_to_owner(tmp_path)
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

    v0.9.4 Phase 1: also accepts the v3 master-seed envelope. When
    ``format == "master-seed-v1"`` the returned AgentKeys carries both
    ``x25519_seed`` and ``hkdf_salt`` populated. Legacy v1/v2 envelopes
    return AgentKeys with those fields = None and the historical
    ``ed25519_to_curve25519_secret`` fallback path runs at the call sites.
    """
    path = os.path.expanduser(path)
    with open(path) as f:
        data = json.load(f)

    # Key-file schema version — used to pick parsing branches. Versions
    # 1 and 2 are byte-compatible; version 3 carries the master-seed
    # envelope's extra fields.
    _version = data.get("version", 1)
    fmt = data.get("format")
    is_master_seed = fmt == KEYS_FORMAT_MASTER_SEED_V1

    # Bound base64 input before decoding. An Ed25519 key encodes to
    # 44 chars; 100 is generous headroom for whitespace.
    pub_b64 = data["ed25519_public"]
    if not isinstance(pub_b64, str) or len(pub_b64) > 100:
        raise ValueError(f"Invalid Ed25519 public key base64 (length={len(pub_b64)!r})")
    ed25519_public = base64.b64decode(pub_b64)
    if len(ed25519_public) != 32:
        raise ValueError(f"Invalid Ed25519 public key length: {len(ed25519_public)}")

    x25519_seed: Optional[bytes] = None
    hkdf_salt: Optional[bytes] = None

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
            if is_master_seed and "x25519_seed_encrypted" in data:
                encrypted_x25519 = base64.b64decode(data["x25519_seed_encrypted"])
                x25519_seed = bytes(box.decrypt(encrypted_x25519))
        except CryptoError:
            raise ValueError("Wrong passphrase or corrupted key file")
    else:
        ed25519_secret = base64.b64decode(data["ed25519_secret"])
        if is_master_seed and "x25519_seed" in data:
            x25519_seed = base64.b64decode(data["x25519_seed"])

    if len(ed25519_secret) != 32:
        raise ValueError(f"Invalid Ed25519 secret key length: {len(ed25519_secret)}")

    # Verify that the secret key matches the public key
    signing = SigningKey(ed25519_secret)
    if bytes(signing.verify_key) != ed25519_public:
        raise ValueError("Ed25519 secret key does not match public key")

    if is_master_seed:
        if x25519_seed is None or len(x25519_seed) != 32:
            raise ValueError(
                "master-seed envelope missing or malformed x25519_seed"
            )
        hkdf_salt_b64 = data.get("hkdf_salt")
        if not isinstance(hkdf_salt_b64, str):
            raise ValueError("master-seed envelope missing hkdf_salt")
        hkdf_salt = base64.b64decode(hkdf_salt_b64)
        if len(hkdf_salt) != 16:
            raise ValueError(
                f"master-seed hkdf_salt has wrong length: {len(hkdf_salt)}"
            )
        # Integrity check: the stored x25519_seed must reproduce from
        # HKDF(ed25519_secret, hkdf_salt, INFO_X25519). Catches a
        # tampered-on-disk x25519_seed even if the surrounding envelope
        # decrypts cleanly with the operator's passphrase.
        expected_x25519 = _hkdf_sha256(
            ed25519_secret, hkdf_salt, HKDF_INFO_X25519, length=32,
        )
        if not _hmac.compare_digest(expected_x25519, x25519_seed):
            raise ValueError(
                "master-seed x25519_seed does not match HKDF derivation "
                "from ed25519_secret + hkdf_salt"
            )

    # v0.9.4: optional X25519 public + binding signature for HELLO
    # advertisement. Phase 1 keystores written by v0.9.4 daemons may
    # not have these fields yet; load them when present, compute on
    # the fly when absent, and verify the binding either way before
    # exposing it to consumers.
    x25519_public: Optional[bytes] = None
    x25519_binding_signature: Optional[bytes] = None
    if is_master_seed:
        x25519_public_b64 = data.get("x25519_public")
        x25519_binding_b64 = data.get("x25519_binding_signature")
        if isinstance(x25519_public_b64, str) and isinstance(x25519_binding_b64, str):
            x25519_public = base64.b64decode(x25519_public_b64)
            x25519_binding_signature = base64.b64decode(x25519_binding_b64)
        elif x25519_seed is not None:
            # Phase 1 keystore (no Phase 2 fields on disk yet) — compute
            # them from the stored x25519_seed. The compute path keeps
            # disk-format Phase 1 keystores forward-compatible without
            # requiring an explicit re-migrate.
            x25519_public = _x25519_public_from_seed(x25519_seed)
            x25519_binding_signature = _compute_x25519_binding(
                ed25519_secret, x25519_public,
            )

        # Always verify the binding actually matches the on-disk
        # public + secret pair. A tampered x25519_public on disk would
        # otherwise be advertised in HELLO before any peer-side check.
        if x25519_public is not None and x25519_binding_signature is not None:
            # Derivable consistency: x25519_public MUST equal
            # scalar_base_mult(x25519_seed).
            expected_pub = _x25519_public_from_seed(x25519_seed)
            if not _hmac.compare_digest(expected_pub, x25519_public):
                raise ValueError(
                    "master-seed x25519_public does not match scalar "
                    "base mult of x25519_seed"
                )
            # Binding signature MUST verify under our own Ed25519.
            from ironmesh.crypto import (
                SIG_CTX_X25519_BINDING,
                verify_detached_with_context,
            )
            try:
                verify_detached_with_context(
                    SigningKey(ed25519_secret).verify_key,
                    SIG_CTX_X25519_BINDING,
                    x25519_public,
                    x25519_binding_signature,
                )
            except Exception as e:
                raise ValueError(
                    f"x25519_binding_signature failed to verify: {e}"
                )

    return AgentKeys(
        ed25519_secret=ed25519_secret,
        ed25519_public=ed25519_public,
        agent_name=data.get("agent_name", ""),
        x25519_seed=x25519_seed,
        hkdf_salt=hkdf_salt,
        x25519_public=x25519_public,
        x25519_binding_signature=x25519_binding_signature,
    )


def _is_master_seed_file(path: str) -> bool:
    """Best-effort check that a key file on disk is the master-seed v3 envelope.

    Used by ``migrate_keys_to_master_seed`` to disambiguate a Windows
    ``PermissionError`` raised by a concurrent racer's ``os.replace``
    from a real permission failure: if the file already has the v3
    format tag, the racer's loser should surface the same idempotent
    ``ValueError`` as the explicit pre-check.

    Returns False on any read/decode error — the caller will then
    re-raise the original ``PermissionError``.
    """
    try:
        with open(path) as f:
            data = json.load(f)
        return data.get("format") == KEYS_FORMAT_MASTER_SEED_V1
    except (OSError, ValueError):
        return False


def migrate_keys_to_master_seed(path: str,
                                 passphrase: Optional[str] = None,
                                 allow_plaintext: bool = False) -> AgentKeys:
    """Migrate a legacy v1/v2 key file in place to the v3 master-seed envelope.

    Preserves the existing Ed25519 seed byte-for-byte — every TOFU pin
    that referenced this node's fingerprint stays valid. Adds an
    HKDF-derived 32-byte ``x25519_seed`` + 16-byte ``hkdf_salt`` so the
    Phase 2 wire-level X25519 derivation has its inputs ready.

    The pre-migration file is preserved as ``<path>.legacy.bak`` so an
    operator can roll back to a pre-v0.9.4 daemon if needed. The backup
    stays for one full release cycle.

    Returns the migrated AgentKeys.

    Raises:
        ValueError: If the file is already in master-seed format
                    (idempotency contract — second call is a no-op
                    surfaced as a ValueError so callers notice).
    """
    path = os.path.expanduser(path)
    with open(path) as f:
        data = json.load(f)
    if data.get("format") == KEYS_FORMAT_MASTER_SEED_V1:
        raise ValueError(
            f"{path} is already in master-seed format (no migration needed)"
        )

    keys = load_keys(path, passphrase=passphrase)
    if keys.x25519_seed is not None:
        raise ValueError("internal: load_keys produced x25519_seed for a legacy file")

    # Generate the master-seed envelope deterministically from the
    # existing Ed25519 seed so the legacy seed becomes the master and
    # the X25519 subkey is HKDF-derived from it (Phase 1 design).
    hkdf_salt = os.urandom(16)
    x25519_seed = _hkdf_sha256(
        keys.ed25519_secret, hkdf_salt, HKDF_INFO_X25519, length=32,
    )
    # v0.9.4 Phase 2 — compute the public + binding so the migrated
    # key file is HELLO-advertisement-ready without a second pass.
    x25519_public = _x25519_public_from_seed(x25519_seed)
    x25519_binding = _compute_x25519_binding(keys.ed25519_secret, x25519_public)
    migrated = AgentKeys(
        ed25519_secret=keys.ed25519_secret,
        ed25519_public=keys.ed25519_public,
        agent_name=keys.agent_name,
        x25519_seed=x25519_seed,
        hkdf_salt=hkdf_salt,
        x25519_public=x25519_public,
        x25519_binding_signature=x25519_binding,
    )

    # Preserve the legacy file before overwriting. ``os.replace`` is
    # atomic but unrecoverable if save_keys later raises mid-write — the
    # backup is the operator's escape hatch.
    backup_path = path + ".legacy.bak"
    if not os.path.exists(backup_path):
        # First migration — preserve the original file as the canonical
        # rollback target. Subsequent migrations (re-migrating after a
        # partial failure) MUST NOT clobber the original backup.
        import shutil
        try:
            shutil.copy2(path, backup_path)
        except PermissionError:
            # Windows-only race: another thread/process is in the
            # middle of replacing ``path`` with the migrated envelope.
            # If the file is now in master-seed format, this call is
            # the losing racer — surface the idempotent ValueError so
            # callers handle it like the explicit pre-check above.
            if _is_master_seed_file(path):
                raise ValueError(
                    f"{path} is already in master-seed format "
                    "(migration completed by a concurrent caller)"
                ) from None
            raise

    try:
        save_keys(migrated, path, passphrase=passphrase,
                  allow_plaintext=allow_plaintext)
    except PermissionError:
        if _is_master_seed_file(path):
            raise ValueError(
                f"{path} is already in master-seed format "
                "(migration completed by a concurrent caller)"
            ) from None
        raise
    return migrated


def get_fingerprint(public_key_bytes: bytes) -> str:
    """Compute SHA-256 fingerprint of a public key (first 16 hex chars)."""
    return hashlib.sha256(public_key_bytes).hexdigest()[:32]
