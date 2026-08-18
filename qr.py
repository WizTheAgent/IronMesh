"""QR rendering for invite tokens — optional, degrades gracefully.

IronMesh can emit an invite token as a QR code so it can be scanned off
one screen onto another node WITHOUT the raw string transiting a chat app
or clipboard sync. The token is ephemeral and single-use, so the QR (like
the string) is useless after it is consumed or expires — that is what
makes screen-scanning an acceptable transport.

Design constraints:

* NO heavy new REQUIRED dependency. QR rendering is provided by the
  ``segno`` package behind the optional ``[qr]`` extra. ``segno`` is a
  small pure-Python library with no native build step.
* When the extra is NOT installed, every entry point degrades to the raw
  token string plus a clear note — never a hard failure. The token string
  is itself a complete, valid transport; the QR is only a convenience.
* ASCII QR (in-terminal) is preferred over PNG. A PNG can only be scanned
  by a phone camera, and phone camera rolls commonly sync to the cloud —
  so PNG output prints an explicit warning. The single-use, short-lived
  nature of the token is what makes that exposure acceptable.

This module NEVER emits the mesh passphrase — it only renders whatever
string the caller passes (an invite token).
"""

from __future__ import annotations

from typing import Optional, Tuple


def _segno():
    """Return the ``segno`` module if the optional ``[qr]`` extra is
    installed, else None. Import is lazy so the common no-QR path never
    imports it."""
    try:
        import segno  # type: ignore[import-not-found]
        return segno
    except ImportError:
        return None


def is_available() -> bool:
    """True if QR rendering (the ``[qr]`` extra) is installed."""
    return _segno() is not None


def ascii_qr(payload: str) -> Optional[str]:
    """Render ``payload`` as an ASCII-art QR string, or None if the
    optional ``[qr]`` extra is not installed.

    Error-correction level L keeps the code as small as possible for a
    long token. Two spaces / two blocks per module keeps the aspect ratio
    roughly square in a terminal.
    """
    segno = _segno()
    if segno is None:
        return None
    code = segno.make(payload, error="l")
    # segno's terminal_lines-free approach: build the ASCII ourselves so
    # the output is deterministic regardless of segno's default glyphs.
    dark, light = "██", "  "
    quiet = 2
    matrix = list(code.matrix)
    size = len(matrix)
    lines = []
    border = light * (size + 2 * quiet)
    for _ in range(quiet):
        lines.append(border)
    for row in matrix:
        cells = light * quiet
        for bit in row:
            cells += dark if bit else light
        cells += light * quiet
        lines.append(cells)
    for _ in range(quiet):
        lines.append(border)
    return "\n".join(lines)


def png_qr(payload: str, path: str) -> bool:
    """Write ``payload`` as a PNG QR to ``path``. Returns True on success,
    False if the optional ``[qr]`` extra is not installed (caller should
    degrade to ASCII / the raw string).
    """
    segno = _segno()
    if segno is None:
        return False
    segno.make(payload, error="l").save(path, scale=6, border=4)
    return True


def render_for_terminal(payload: str) -> Tuple[Optional[str], Optional[str]]:
    """Best-effort ASCII QR for a token string.

    Returns ``(ascii_art, note)``:

    * ``(ascii_art, None)`` when the ``[qr]`` extra is installed.
    * ``(None, note)`` when it is not — the note tells the operator to copy
      the raw token string instead (or install ``ironmesh[qr]`` to get a
      scannable code). Never raises.
    """
    art = ascii_qr(payload)
    if art is not None:
        return art, None
    return None, (
        "In-terminal QR needs the optional QR extra "
        "(`pip install ironmesh[qr]`). Copy the token string below instead "
        "— it is a complete, valid transport on its own."
    )
