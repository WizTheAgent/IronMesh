"""OS-native passphrase storage via the `keyring` library.

This is an optional backend. The daemon works fine without it via
passphrase-file or env var. Install with:

    pip install ironmesh[keychain]

The wrapper imports `keyring` lazily and surfaces clear errors when
it is missing, so importing this module on a vanilla install does
not fail.

Service identifier convention:
    service  = "ironmesh"
    username = "<node_name>"

This lets multiple node configs on the same machine coexist
(`ironmesh:alice`, `ironmesh:bob`).
"""
from __future__ import annotations

from typing import Optional

SERVICE = "ironmesh"


class KeychainUnavailable(RuntimeError):
    """The `keyring` library is not installed or no backend is available."""


def _import_keyring():
    try:
        import keyring  # type: ignore[import-untyped]
        import keyring.errors  # type: ignore[import-untyped]
    except ImportError as exc:
        raise KeychainUnavailable(
            "The `keyring` library is not installed. Install with:\n"
            "    pip install ironmesh[keychain]"
        ) from exc
    return keyring


def store(node_name: str, passphrase: str) -> None:
    """Persist `passphrase` in the OS keychain under (`ironmesh`, node_name).

    Raises KeychainUnavailable if `keyring` is not installed.
    Raises RuntimeError on any backend error.
    """
    if not node_name:
        raise ValueError("node_name is required")
    if not passphrase:
        raise ValueError("passphrase is required")
    keyring = _import_keyring()
    try:
        keyring.set_password(SERVICE, node_name, passphrase)
    except Exception as exc:
        raise RuntimeError(
            f"Failed to write passphrase to OS keychain: {exc}"
        ) from exc


def load(node_name: str) -> Optional[str]:
    """Return the stored passphrase for `node_name`, or None if absent.

    Raises KeychainUnavailable if `keyring` is not installed.
    Raises RuntimeError on any backend error other than not-found.
    """
    if not node_name:
        raise ValueError("node_name is required")
    keyring = _import_keyring()
    try:
        return keyring.get_password(SERVICE, node_name)
    except Exception as exc:
        raise RuntimeError(
            f"Failed to read passphrase from OS keychain: {exc}"
        ) from exc


def clear(node_name: str) -> bool:
    """Delete the stored passphrase for `node_name`. Returns True on
    success, False if no entry was present.

    Raises KeychainUnavailable if `keyring` is not installed.
    """
    if not node_name:
        raise ValueError("node_name is required")
    keyring = _import_keyring()
    try:
        keyring.delete_password(SERVICE, node_name)
        return True
    except Exception as exc:
        # `keyring.errors.PasswordDeleteError` is the typical not-found
        # signal but the exception class differs by backend. Easier to
        # detect by introspection: if there's nothing to delete, the
        # subsequent `get_password` will return None.
        try:
            still_there = load(node_name)
        except Exception:
            still_there = None
        if still_there is None:
            return False
        raise RuntimeError(
            f"Failed to delete passphrase from OS keychain: {exc}"
        ) from exc


def is_available() -> bool:
    """True if the `keyring` library can be imported AND has a usable
    backend. False otherwise. Never raises."""
    try:
        keyring = _import_keyring()
    except KeychainUnavailable:
        return False
    try:
        # Some backends raise lazily on first use. Force one no-op
        # round-trip to surface that.
        keyring.get_password(SERVICE, "__ironmesh_probe__")
    except Exception:
        return False
    return True
