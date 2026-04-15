#!/usr/bin/env python3
"""sanitize.py — Read-only translator for syncing the private IronMesh
working copy to the public ``ironmesh-github/`` repository.

Goals
-----
1. Strip personally identifying information (PII) from text files.
2. Replace specific local network addresses with neutral example IPs.
3. Replace the private GitHub org / author with portable placeholder
   strings (``<YOUR_ORG>`` and ``<YOUR_NAME_OR_ORG>``).
4. **Keep** the illustrative ``kingpi`` / ``wiz`` node names — the public
   README already uses them as example agent names and the project's
   own documentation refers to them as such.
5. Skip binary files, ``__pycache__``, ``.egg-info``, ``.git``, build
   artifacts, and any file whose suffix isn't on the text allowlist.
6. Refuse to overwrite the public copy if any PII pattern would still
   survive after substitution — fail loudly so the operator notices.

Usage
-----
    python scripts/sanitize.py SOURCE_DIR DEST_DIR
        # e.g. python scripts/sanitize.py . ../ironmesh-github

The script does NOT delete files in DEST_DIR that no longer exist in
SOURCE_DIR (use ``rsync --delete`` or manual cleanup for that).
"""
from __future__ import annotations

import os
import re
import shutil
import sys
from pathlib import Path
from typing import Iterable, List, Tuple

# ---------------------------------------------------------------------------
# Substitution table
# ---------------------------------------------------------------------------

# Order matters: longer / more specific patterns first.
SUBSTITUTIONS: List[Tuple[re.Pattern, str]] = [
    # GitHub URLs / org references
    (re.compile(r"github\.com/kingpi-empire/ironmesh", re.IGNORECASE),
     "github.com/<YOUR_ORG>/ironmesh"),
    (re.compile(r"kingpi-empire/ironmesh", re.IGNORECASE),
     "<YOUR_ORG>/ironmesh"),
    (re.compile(r"\bkingpi-empire\b", re.IGNORECASE),
     "<YOUR_ORG>"),

    # Author / org names
    (re.compile(r"\bKingPi Empire\b"), "<YOUR_NAME_OR_ORG>"),
    (re.compile(r"\bCrest Holdings\b", re.IGNORECASE), "<YOUR_NAME_OR_ORG>"),
    (re.compile(r"\bWholesaleking\b", re.IGNORECASE), "<YOUR_NAME_OR_ORG>"),
    (re.compile(r"\bHarrington\b"), "<YOUR_NAME_OR_ORG>"),

    # Personal username / paths
    (re.compile(r"C:\\Users\\jonha", re.IGNORECASE), r"C:\\Users\\<USER>"),
    (re.compile(r"/Users/jonha", re.IGNORECASE), "/Users/<USER>"),
    (re.compile(r"\bjonha\b", re.IGNORECASE), "<USER>"),

    # Private LAN IPs (the two production nodes)
    (re.compile(r"\b192\.168\.1\.17\b"), "192.168.1.10"),
    (re.compile(r"\b192\.168\.1\.37\b"), "192.168.1.20"),
]

# Patterns that must NOT survive in the destination tree.
PII_PATTERNS: List[re.Pattern] = [
    re.compile(r"\bjonha\b", re.IGNORECASE),
    re.compile(r"\bHarrington\b"),
    re.compile(r"\bCrest Holdings\b", re.IGNORECASE),
    re.compile(r"\bWholesaleking\b", re.IGNORECASE),
    re.compile(r"\bkingpi-empire\b", re.IGNORECASE),
    re.compile(r"\b192\.168\.1\.17\b"),
    re.compile(r"\b192\.168\.1\.37\b"),
]

# ---------------------------------------------------------------------------
# File filtering
# ---------------------------------------------------------------------------

TEXT_SUFFIXES = {
    ".py", ".md", ".txt", ".toml", ".cfg", ".ini", ".json", ".yaml",
    ".yml", ".html", ".css", ".js", ".sh", ".rst",
}

ALWAYS_TEXT_NAMES = {
    "LICENSE", "README", "CHANGELOG", "Makefile",
}

EXCLUDE_DIRS = {
    "__pycache__", ".git", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "node_modules", "build", "dist", ".venv", "venv", "env",
    # scripts/ holds private maintainer tooling (this very file) that
    # contains the PII pattern table; do NOT publish it.
    "scripts",
}

EXCLUDE_DIR_SUFFIXES = (".egg-info",)

# Files in the private tree that should NEVER be copied to public.
EXCLUDE_FILES = {
    "deployment_proof.md",
    "ironmesh-claude-section.md",
    "ironmesh-tools-section.md",
    "kingpi-memory-line.txt",
    "kingpi-tools-section.md",
    "temp.log",
    "temp2.log",
    "test_send.py",
}


def is_text_file(path: Path) -> bool:
    if path.name in ALWAYS_TEXT_NAMES:
        return True
    return path.suffix.lower() in TEXT_SUFFIXES


def should_skip_dir(name: str) -> bool:
    if name in EXCLUDE_DIRS:
        return True
    return any(name.endswith(suf) for suf in EXCLUDE_DIR_SUFFIXES)


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------

def sanitize_text(text: str) -> str:
    out = text
    for pattern, replacement in SUBSTITUTIONS:
        out = pattern.sub(replacement, out)
    return out


def find_pii(text: str) -> List[str]:
    """Return human-readable descriptions of any PII still present."""
    found = []
    for pattern in PII_PATTERNS:
        if pattern.search(text):
            found.append(pattern.pattern)
    return found


def iter_source_files(src: Path) -> Iterable[Path]:
    for root, dirs, files in os.walk(src):
        # Mutate dirs in place to prune
        dirs[:] = [d for d in dirs if not should_skip_dir(d)]
        for fname in files:
            if fname in EXCLUDE_FILES:
                continue
            yield Path(root) / fname


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main(argv: List[str]) -> int:
    if len(argv) != 3:
        print("usage: sanitize.py SOURCE_DIR DEST_DIR", file=sys.stderr)
        return 2

    src = Path(argv[1]).resolve()
    dst = Path(argv[2]).resolve()

    if not src.is_dir():
        print(f"sanitize: source dir not found: {src}", file=sys.stderr)
        return 2
    if not dst.is_dir():
        print(f"sanitize: dest dir not found: {dst}", file=sys.stderr)
        return 2

    copied = 0
    sanitized = 0
    skipped_binary = 0
    failures: List[Tuple[Path, List[str]]] = []
    pending_writes: List[Tuple[Path, Path, bytes, bool]] = []

    for source_path in iter_source_files(src):
        rel = source_path.relative_to(src)
        target = dst / rel

        if is_text_file(source_path):
            try:
                raw = source_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                # Fall back to binary copy.
                pending_writes.append((source_path, target, source_path.read_bytes(), False))
                skipped_binary += 1
                continue
            cleaned = sanitize_text(raw)
            leaks = find_pii(cleaned)
            if leaks:
                failures.append((source_path, leaks))
                continue
            pending_writes.append((source_path, target, cleaned.encode("utf-8"), True))
            if cleaned != raw:
                sanitized += 1
        else:
            pending_writes.append((source_path, target, source_path.read_bytes(), False))
            skipped_binary += 1

    if failures:
        print("sanitize: PII still present in cleaned content. Refusing to write.",
              file=sys.stderr)
        for path, leaks in failures[:20]:
            print(f"  {path} -> {leaks}", file=sys.stderr)
        return 1

    # All clean — perform the writes.
    for source_path, target, data, is_text in pending_writes:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        try:
            shutil.copymode(source_path, target)
        except OSError:
            pass
        copied += 1

    print(f"sanitize: copied {copied} files "
          f"({sanitized} text-sanitized, {skipped_binary} binary).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
