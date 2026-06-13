#!/usr/bin/env bash
# bump-version.sh — single-source a release version across the repo's hand-typed
# version strings, so cutting a release means editing one input, not N files.
# After running this, write the CHANGELOG entry + RELEASE_NOTES + the README
# banner sentence, run release-qc, then PR + tag. See RELEASING.md.
#
#   scripts/bump-version.sh X.Y.Z[.N]
set -euo pipefail
cd "$(dirname "$0")/.."

NEW="${1:?usage: scripts/bump-version.sh X.Y.Z[.N]}"
if ! printf '%s' "$NEW" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?$'; then
    echo "error: '$NEW' is not a valid version (expected X.Y.Z or X.Y.Z.N)" >&2
    exit 2
fi
TODAY="$(date +%F)"

# pyproject.toml + __init__.py — the source-of-truth version
sed -i -E "s/^version = \"[0-9.]+\"/version = \"$NEW\"/" pyproject.toml
sed -i -E "s/^__version__ = \"[0-9.]+\"/__version__ = \"$NEW\"/" __init__.py

# README.md — banner version, the "Latest:" line, and Docker tags (not :latest)
sed -i -E "s/^(> \*\*v)[0-9.]+/\1$NEW/" README.md
sed -i -E "s/Latest: \*\*v[0-9.]+\*\*/Latest: **v$NEW**/" README.md
sed -i -E "s#(wiztheagent/ironmesh:)[0-9.]+#\1$NEW#g" README.md

# CITATION.cff — version, date, and the release URLs
sed -i -E "s/^version: [0-9.]+/version: $NEW/" CITATION.cff
sed -i -E "s/^date-released: .*/date-released: $TODAY/" CITATION.cff
sed -i -E "s#(releases/tag/v)[0-9.]+#\1$NEW#g; s#(GitHub release v)[0-9.]+#\1$NEW#g" CITATION.cff
sed -i -E "s#(project/ironmesh/)[0-9.]+/#\1$NEW/#g; s#(PyPI release v)[0-9.]+#\1$NEW#g" CITATION.cff

echo "Bumped version strings to $NEW (date-released: $TODAY)."
echo
echo "Still to do by hand (the script can't write prose):"
echo "  1. Add a '## [$NEW] — $TODAY — <headline>' section to CHANGELOG.md"
echo "  2. Add docs/RELEASE_NOTES_v$NEW.md"
echo "  3. Update the README banner's feature sentence (the version is set; the prose isn't)"
echo "  4. bash scripts/release-qc.sh   # must end 'FAIL: 0'"
echo "  5. PR -> merge, then: git tag -a v$NEW -m 'IronMesh $NEW — <headline>' && git push origin v$NEW"
