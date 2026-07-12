#!/usr/bin/env bash
# check-site-version.sh — fail a release when the marketing site's
# published version has drifted behind the daemon version.
#
# Why this exists: the marketing site lives in a SEPARATE repository /
# working directory (it is not a submodule of this repo), so the normal
# doc-sync gate — which only sees files tracked in THIS repo — cannot
# catch the site falling a release behind. That drift is a recurring
# defect: the site keeps advertising an older version than the shipped
# daemon. This script reads the daemon version from pyproject.toml and
# compares it against the site's SITE_VERSION.json `version` field.
#
# Because the site directory only exists on a machine that has both repos
# checked out, this script NO-OPS CLEANLY (exit 0 with a notice) when the
# site directory is absent — so CI on a clean daemon-only checkout never
# fails on a path it can't see. It only returns non-zero on a real,
# observed mismatch.
#
# The site location defaults to a sibling checkout but is overridable:
#   IRONMESH_SITE_DIR=/path/to/site bash scripts/check-site-version.sh
# or point directly at the JSON file:
#   IRONMESH_SITE_VERSION_FILE=/path/to/SITE_VERSION.json bash scripts/check-site-version.sh
#
# Run locally:  bash scripts/check-site-version.sh
# Exit 0 = in sync, or site not present (skipped). Exit 1 = real mismatch.
set -uo pipefail
cd "$(dirname "$0")/.."

# Daemon version — the source of truth.
VERSION="$(python -c "import re; m=re.search(r'^version *= *\"([^\"]+)\"', open('pyproject.toml').read(), re.M); print(m.group(1) if m else '')")"
if [ -z "$VERSION" ]; then
    echo "  [FAIL] could not read version from pyproject.toml"
    exit 1
fi

# Resolve the SITE_VERSION.json path. Precedence:
#   1. IRONMESH_SITE_VERSION_FILE — an explicit path to the JSON file.
#   2. IRONMESH_SITE_DIR/SITE_VERSION.json — an explicit site directory.
#   3. A sibling "ironmesh-site" checkout next to this repo (the common
#      operator layout), tried at a couple of typical relative roots.
SITE_FILE="${IRONMESH_SITE_VERSION_FILE:-}"
if [ -z "$SITE_FILE" ]; then
    SITE_DIR="${IRONMESH_SITE_DIR:-}"
    if [ -n "$SITE_DIR" ]; then
        SITE_FILE="${SITE_DIR%/}/SITE_VERSION.json"
    else
        for cand in \
            "../ironmesh-site/SITE_VERSION.json" \
            "../../ironmesh-site/SITE_VERSION.json"; do
            if [ -f "$cand" ]; then
                SITE_FILE="$cand"
                break
            fi
        done
    fi
fi

if [ -z "$SITE_FILE" ] || [ ! -f "$SITE_FILE" ]; then
    echo "  [skip] site version file not found — skipping site drift check."
    echo "         (set IRONMESH_SITE_DIR or IRONMESH_SITE_VERSION_FILE to enable it.)"
    exit 0
fi

# Read the site's advertised version. Prefer json parsing; fall back to a
# regex so the check still works without a JSON tool on PATH.
SITE_VERSION="$(python -c "
import json, sys
try:
    print(json.load(open(sys.argv[1])).get('version', ''))
except Exception:
    pass
" "$SITE_FILE" 2>/dev/null || true)"
if [ -z "$SITE_VERSION" ]; then
    SITE_VERSION="$(grep -oE '\"version\"[[:space:]]*:[[:space:]]*\"[^\"]+\"' "$SITE_FILE" 2>/dev/null \
        | head -1 | grep -oE '[0-9][0-9A-Za-z.\-]*' | head -1 || true)"
fi

if [ -z "$SITE_VERSION" ]; then
    echo "  [FAIL] could not read 'version' from ${SITE_FILE}"
    exit 1
fi

if [ "$SITE_VERSION" = "$VERSION" ]; then
    echo "  [ok]   site version ${SITE_VERSION} matches daemon ${VERSION} (${SITE_FILE})"
    exit 0
else
    echo "  [FAIL] site version ${SITE_VERSION} != daemon ${VERSION}"
    echo "         update 'version' (and 'version_tag') in ${SITE_FILE} to ${VERSION}"
    echo "         before tagging the release, then redeploy the site."
    exit 1
fi
