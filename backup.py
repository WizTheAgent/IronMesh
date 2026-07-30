"""IronMesh backup/restore — encrypted archive of node state.

Bundles the identity keys, trust store, and a tail of the audit log into
a single tar.gz stream, then encrypts the stream with Argon2id-derived
SecretBox.  Same crypto pattern as :mod:`ironmesh.keys`.

The archive contains:
    manifest.json     — version, node_id (if derivable), created_at
    keys.json         — copy of ~/.ironmesh/keys.json
    known_peers.json  — copy of ~/.ironmesh/known_peers.json
    audit.log         — last ~10k lines of ~/.ironmesh/audit.log

Usage::

    ironmesh backup --out node-backup.imb
    ironmesh restore --in node-backup.imb
"""

from __future__ import annotations

import io
import json
import logging
import os
import tarfile
import time
from typing import Optional

from nacl.pwhash import argon2id
from nacl.secret import SecretBox

logger = logging.getLogger("ironmesh.backup")

_MAGIC = b"IMB1"  # IronMesh Backup v1
_SALT_LEN = 16
_AUDIT_TAIL_LINES = 10000
_VERSION = 1


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from passphrase + salt using Argon2id."""
    return argon2id.kdf(
        32,
        passphrase.encode(),
        salt,
        opslimit=argon2id.OPSLIMIT_MODERATE,
        memlimit=argon2id.MEMLIMIT_MODERATE,
    )


def _tail_file(path: str, max_lines: int) -> bytes:
    """Return the last ``max_lines`` lines of ``path`` as bytes."""
    if not os.path.isfile(path):
        return b""
    # Simple implementation: read whole file if small, else use seek
    size = os.path.getsize(path)
    if size < 1_000_000:
        with open(path, "rb") as f:
            data = f.read()
        lines = data.splitlines(keepends=True)
        return b"".join(lines[-max_lines:])
    # Large file — read last 1 MB and keep complete lines
    with open(path, "rb") as f:
        f.seek(-1_000_000, os.SEEK_END)
        chunk = f.read()
    # Drop first partial line
    nl = chunk.find(b"\n")
    if nl != -1:
        chunk = chunk[nl + 1:]
    lines = chunk.splitlines(keepends=True)
    return b"".join(lines[-max_lines:])


def create_backup(
    out_path: str,
    passphrase: str,
    keys_path: str = "~/.ironmesh/keys.json",
    trust_path: str = "~/.ironmesh/known_peers.json",
    audit_path: str = "~/.ironmesh/audit.log",
    node_id: Optional[str] = None,
) -> None:
    """Create an encrypted backup bundle.

    Args:
        out_path: Destination file path.
        passphrase: Backup encryption passphrase (>=12 chars).
        keys_path: Source path to identity keys JSON.
        trust_path: Source path to trust store.
        audit_path: Source path to audit log.
        node_id: Optional node ID to record in manifest.

    Raises:
        ValueError: If passphrase is too short or no files exist to back up.
    """
    if len(passphrase) < 12:
        raise ValueError("Backup passphrase must be at least 12 characters")

    keys_path = os.path.expanduser(keys_path)
    trust_path = os.path.expanduser(trust_path)
    audit_path = os.path.expanduser(audit_path)
    out_path = os.path.expanduser(out_path)

    # Build manifest
    manifest = {
        "version": _VERSION,
        "created_at": time.time(),
        "node_id": node_id,
        "includes": {
            "keys": os.path.isfile(keys_path),
            "trust": os.path.isfile(trust_path),
            "audit": os.path.isfile(audit_path),
        },
    }

    if not any(manifest["includes"].values()):
        raise ValueError("No source files found to back up")

    # Pack tar.gz in memory
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w:gz") as tar:
        mbytes = json.dumps(manifest, indent=2).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size = len(mbytes)
        info.mtime = int(time.time())
        tar.addfile(info, io.BytesIO(mbytes))

        # Audit L-06: file may disappear between the existence check
        # and the actual add — survive gracefully.
        if manifest["includes"]["keys"]:
            try:
                tar.add(keys_path, arcname="keys.json")
            except FileNotFoundError:
                logger.warning("Keys file disappeared during backup: %s", keys_path)
        if manifest["includes"]["trust"]:
            try:
                tar.add(trust_path, arcname="known_peers.json")
            except FileNotFoundError:
                logger.warning("Trust file disappeared during backup: %s", trust_path)
        if manifest["includes"]["audit"]:
            tail = _tail_file(audit_path, _AUDIT_TAIL_LINES)
            info = tarfile.TarInfo("audit.log")
            info.size = len(tail)
            info.mtime = int(time.time())
            tar.addfile(info, io.BytesIO(tail))

    plaintext = tar_buf.getvalue()

    # Encrypt
    salt = os.urandom(_SALT_LEN)
    key = _derive_key(passphrase, salt)
    box = SecretBox(key)
    ciphertext = bytes(box.encrypt(plaintext))

    # Write: [MAGIC:4][VERSION:1][SALT:16][CIPHERTEXT]
    with open(out_path, "wb") as f:
        f.write(_MAGIC)
        f.write(bytes([_VERSION]))
        f.write(salt)
        f.write(ciphertext)
    from ironmesh.keys import restrict_file_to_owner
    restrict_file_to_owner(out_path)

    logger.info("Backup written to %s (%d bytes plaintext, %d bytes on disk)",
                out_path, len(plaintext), len(ciphertext) + 21)


def restore_backup(
    in_path: str,
    passphrase: str,
    keys_path: str = "~/.ironmesh/keys.json",
    trust_path: str = "~/.ironmesh/known_peers.json",
    audit_path: str = "~/.ironmesh/audit.log",
    force: bool = False,
) -> dict:
    """Restore an encrypted backup bundle.

    Args:
        in_path: Backup file path.
        passphrase: Backup encryption passphrase.
        keys_path, trust_path, audit_path: Destination paths.
        force: If False, refuse to overwrite existing files.

    Returns:
        The manifest dict from the archive.

    Raises:
        ValueError: If the file is malformed, the passphrase is wrong, or
                    destinations exist and ``force=False``.
    """
    in_path = os.path.expanduser(in_path)
    keys_path = os.path.expanduser(keys_path)
    trust_path = os.path.expanduser(trust_path)
    audit_path = os.path.expanduser(audit_path)

    with open(in_path, "rb") as f:
        magic = f.read(4)
        if magic != _MAGIC:
            raise ValueError(f"Not an IronMesh backup file (magic={magic!r})")
        version = f.read(1)[0]
        if version != _VERSION:
            raise ValueError(f"Unsupported backup version: {version}")
        salt = f.read(_SALT_LEN)
        ciphertext = f.read()

    key = _derive_key(passphrase, salt)
    box = SecretBox(key)
    try:
        plaintext = box.decrypt(ciphertext)
    except Exception as e:
        raise ValueError("Decryption failed — wrong passphrase?") from e

    # Extract
    tar_buf = io.BytesIO(plaintext)
    manifest = None
    files_to_write = {}
    with tarfile.open(fileobj=tar_buf, mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            if ".." in member.name or member.name.startswith("/") or "\\" in member.name:
                logger.warning("Skipping unsafe tar member path: %s", member.name)
                continue
            f = tar.extractfile(member)
            if f is None:
                continue
            data = f.read()
            if member.name == "manifest.json":
                manifest = json.loads(data.decode())
            elif member.name == "keys.json":
                files_to_write[keys_path] = data
            elif member.name == "known_peers.json":
                files_to_write[trust_path] = data
            elif member.name == "audit.log":
                files_to_write[audit_path] = data

    if manifest is None:
        raise ValueError("Backup is missing manifest.json")

    # Check for conflicts
    if not force:
        existing = [p for p in files_to_write if os.path.isfile(p)]
        if existing:
            raise ValueError(
                f"Destination files exist (use --force to overwrite): {existing}"
            )

    # Write files
    from ironmesh.keys import restrict_file_to_owner
    for dest, data in files_to_write.items():
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as f:
            f.write(data)
        restrict_file_to_owner(dest)
        logger.info("Restored %s (%d bytes)", dest, len(data))

    return manifest
