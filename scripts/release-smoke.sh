#!/usr/bin/env bash
# release-smoke.sh — the real gate between `python -m build` and `twine upload`.
#
# What this catches that CI doesn't:
#   - Packaging misdeclarations in pyproject.toml (missing subpackages).
#     CI's unit tests pass against an editable install, where every file on
#     disk is importable by path. The WHEEL is a different artifact — if
#     `[tool.setuptools] packages = [...]` misses a subpackage, the wheel
#     physically excludes it and every `pip install ironmesh` user hits
#     ModuleNotFoundError. v0.8.3 shipped a packaging fix for exactly this;
#     this script is the regression gate.
#   - Entry-point misconfiguration in [project.scripts].
#   - Runtime-required dependencies that happen to be installed as dev deps.
#
# What it does:
#   1. Clean dist/ and rebuild
#   2. Assert both wheel + sdist were produced
#   3. Verify critical files are physically in the wheel
#   4. Create a throwaway venv, install the wheel (not editable, not from source)
#   5. Run smoke imports of every public module + subpackage
#   6. Run the CLI entry point (`ironmesh --help`)
#   7. Report pass/fail
#
# Usage:
#   bash scripts/release-smoke.sh
#   bash scripts/release-smoke.sh --keep-venv   # leave the smoke venv for inspection
#
# Exit codes:
#   0  — clean, safe to `twine upload`
#   1  — a check failed; do NOT upload until fixed

set -eu

KEEP_VENV=0
for arg in "$@"; do
    case "$arg" in
        --keep-venv) KEEP_VENV=1 ;;
        *) echo "Unknown arg: $arg" >&2; exit 1 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

VERSION="$(python -c "import re; print(re.search(r'^version *= *\"([^\"]+)\"', open('pyproject.toml').read(), re.M).group(1))")"
echo "═══ release-smoke · ironmesh $VERSION ═══"

# ───── 1. clean + build ─────
echo
echo "[1/7] cleaning + building"
rm -rf dist/ build/ ironmesh.egg-info
python -m build >/dev/null 2>&1 || { echo "FAIL: python -m build errored"; exit 1; }

# ───── 2. both artifacts produced ─────
echo "[2/7] verifying dist/ artifacts"
WHL="dist/ironmesh-${VERSION}-py3-none-any.whl"
SDIST="dist/ironmesh-${VERSION}.tar.gz"
[ -f "$WHL" ]    || { echo "FAIL: wheel missing at $WHL"; exit 1; }
[ -f "$SDIST" ]  || { echo "FAIL: sdist missing at $SDIST"; exit 1; }
echo "       OK  $WHL ($(wc -c < "$WHL" | tr -d ' ') bytes)"
echo "       OK  $SDIST ($(wc -c < "$SDIST" | tr -d ' ') bytes)"

# ───── 3. critical subpackages physically present in wheel ─────
echo "[3/7] verifying wheel contents"
python - <<PY
import sys, zipfile
z = zipfile.ZipFile("$WHL")
names = set(z.namelist())
required = [
    "ironmesh/__init__.py",
    "ironmesh/bridge.py",
    "ironmesh/protocol.py",
    "ironmesh/conversation.py",
    "ironmesh/roles.py",
    "ironmesh/tools.py",
    "ironmesh/agent.py",
    "ironmesh/adapters/__init__.py",
    "ironmesh/adapters/langchain_adapter.py",
    "ironmesh/adapters/crewai_adapter.py",
    "ironmesh/adapters/autogen_adapter.py",
    "ironmesh_mcp/__init__.py",
    "ironmesh_mcp/server.py",
]
missing = [p for p in required if p not in names]
if missing:
    print("FAIL: wheel missing required paths:")
    for p in missing: print(f"       MISSING  {p}")
    sys.exit(1)
print(f"       OK  {len(required)} critical paths present")
PY

# ───── 4. throwaway venv + wheel install ─────
echo "[4/7] creating throwaway venv + installing wheel"
SMOKE_VENV="$(mktemp -d -t ironmesh-smoke-XXXXXX)"
python -m venv "$SMOKE_VENV" >/dev/null
# Cross-platform Python path (Git Bash on Windows puts it under Scripts/)
if [ -x "$SMOKE_VENV/bin/python" ]; then
    SMOKE_PY="$SMOKE_VENV/bin/python"
else
    SMOKE_PY="$SMOKE_VENV/Scripts/python.exe"
fi
"$SMOKE_PY" -m pip install --quiet "$WHL" 2>/dev/null || {
    echo "FAIL: pip install of wheel failed"
    exit 1
}
echo "       OK  venv at $SMOKE_VENV"

# ───── 5. public module imports ─────
echo "[5/7] smoke-importing every public module"
"$SMOKE_PY" - <<'PY' || { echo "FAIL: import smoke test failed"; exit 1; }
import sys
mods = [
    "ironmesh",
    "ironmesh.agent",
    "ironmesh.bridge",
    "ironmesh.protocol",
    "ironmesh.crypto",
    "ironmesh.keys",
    "ironmesh.mesh",
    "ironmesh.mesh_crypto",
    "ironmesh.discovery",
    "ironmesh.store",
    "ironmesh.trust",
    "ironmesh.audit",
    "ironmesh.capabilities",
    "ironmesh.conversation",
    "ironmesh.federation",
    "ironmesh.roles",
    "ironmesh.tools",
    "ironmesh.hooks",
    "ironmesh.config",
    "ironmesh.cli",
    "ironmesh.backup",
    "ironmesh.adapters",
    # Adapter submodules deliberately excluded — they raise ImportError by
    # design when their optional third-party dep isn't installed, which is
    # the expected smoke-venv state. Their presence as files is checked
    # in step [3] via wheel inspection.
    "ironmesh_mcp",
    "ironmesh_mcp.server",
]
for m in mods:
    __import__(m)
import ironmesh
print(f"       OK  {len(mods)} modules imported · ironmesh.__version__ = {ironmesh.__version__}")
PY

# ───── 6. CLI entry point ─────
echo "[6/7] exercising CLI entry point"
if [ -x "$SMOKE_VENV/bin/ironmesh" ]; then
    SMOKE_CLI="$SMOKE_VENV/bin/ironmesh"
else
    SMOKE_CLI="$SMOKE_VENV/Scripts/ironmesh.exe"
fi
"$SMOKE_CLI" --help >/dev/null 2>&1 || { echo "FAIL: ironmesh --help errored"; exit 1; }
echo "       OK  ironmesh --help"

# ───── 7. cleanup + summary ─────
echo "[7/7] cleanup"
if [ "$KEEP_VENV" = "1" ]; then
    echo "       kept  $SMOKE_VENV (--keep-venv)"
else
    rm -rf "$SMOKE_VENV"
    echo "       OK  removed smoke venv"
fi

echo
echo "═══ PASS · ironmesh $VERSION is safe to publish ═══"
echo
echo "Next step:"
echo "  python -m twine upload dist/ironmesh-${VERSION}*"
