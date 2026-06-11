#!/usr/bin/env bash
# doc-sync-check.sh — fail the release if public docs drift from the
# release version, or if a retired false claim reappears.
#
# Why this exists: release-qc validated pyproject<->__init__ versions and
# CHANGELOG-entry presence, but never checked that the human-readable
# version strings (README banner, Docker tags, the "Latest:" line,
# CITATION.cff) match the release, that the CHANGELOG heading chain is
# intact, or that a corrected false claim stays corrected. Those gaps let
# the README "Latest:" line, Docker tags, a stripped CHANGELOG heading, and
# a "signed tags" claim all ship stale/false at once.
#
# Run locally:   bash scripts/doc-sync-check.sh
# In CI:         invoked by scripts/release-qc.sh (step 13), which CI runs
#                on every push and tag.
#
# Exit 0 = docs are in sync. Exit 1 = at least one drift/claim failure.
set -uo pipefail
cd "$(dirname "$0")/.."

VERSION="$(python -c "import re; m=re.search(r'^version *= *\"([^\"]+)\"', open('pyproject.toml').read(), re.M); print(m.group(1) if m else '')")"
MAJOR_MINOR="$(printf '%s' "$VERSION" | cut -d. -f1,2)"

FAIL=0
ok()   { printf '  [ok]   %s\n' "$1"; }
bad()  { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); }
warn() { printf '  [warn] %s\n' "$1"; }

[ -n "$VERSION" ] || { echo "  [FAIL] could not read version from pyproject.toml"; exit 1; }
echo "doc-sync-check · target version ${VERSION}"

# 1. README "Latest:" line must equal the release version exactly.
latest="$(grep -oE 'Latest: \*\*v?[0-9][0-9.]*\*\*' README.md 2>/dev/null | head -1 | grep -oE '[0-9][0-9.]*' || true)"
if [ -z "$latest" ]; then
    warn "README has no 'Latest: **vX.Y.Z**' line to check"
elif [ "$latest" = "$VERSION" ]; then
    ok "README 'Latest:' = ${VERSION}"
else
    bad "README 'Latest:' is ${latest}, expected ${VERSION}"
fi

# 2. Docker tags in README must be the release version (or :latest).
bad_docker="$(grep -oE 'wiztheagent/ironmesh:[0-9][0-9.]*' README.md 2>/dev/null | grep -vE ":${VERSION}\$" || true)"
if [ -n "$bad_docker" ]; then
    bad "README has stale Docker tag(s) (expected :${VERSION} or :latest):"
    printf '           %s\n' $bad_docker
else
    ok "README Docker tags = :${VERSION} (or :latest)"
fi

# 3. README banner major.minor must match the release line.
banner="$(grep -oE '^> \*\*v[0-9][0-9.]*' README.md 2>/dev/null | head -1 | grep -oE '[0-9][0-9.]*' || true)"
banner_mm="$(printf '%s' "$banner" | cut -d. -f1,2)"
if [ -z "$banner" ]; then
    warn "README has no '> **vX...' banner to check"
elif [ "$banner_mm" = "$MAJOR_MINOR" ]; then
    ok "README banner v${banner} is on the ${MAJOR_MINOR}.x line"
else
    bad "README banner v${banner} is off the ${MAJOR_MINOR}.x line (release is ${VERSION})"
fi

# 4. CITATION.cff version must equal the release version.
if [ -f CITATION.cff ]; then
    cff="$(grep -oE '^version: *[0-9][0-9.]*' CITATION.cff 2>/dev/null | grep -oE '[0-9][0-9.]*' | head -1 || true)"
    if [ "$cff" = "$VERSION" ]; then
        ok "CITATION.cff version = ${VERSION}"
    else
        bad "CITATION.cff version is ${cff:-<none>}, expected ${VERSION}"
    fi
fi

# 5a. The release version must have its own CHANGELOG heading.
if grep -qE "^## \[${VERSION}\]" CHANGELOG.md; then
    ok "CHANGELOG has a ## [${VERSION}] heading"
else
    bad "CHANGELOG is missing a ## [${VERSION}] heading"
fi

# 5b. No orphaned Keep-a-Changelog title — a '— DATE — title' line whose
#     '## [version]' prefix was stripped (the exact v0.9.4.1 corruption).
orphans="$(grep -nE '^[[:space:]]*— [0-9]{4}-[0-9]{2}-[0-9]{2} —' CHANGELOG.md || true)"
if [ -n "$orphans" ]; then
    bad "CHANGELOG has orphaned heading line(s) missing the '## [x.y.z]' prefix:"
    printf '           %s\n' "$orphans"
else
    ok "CHANGELOG headings: no orphaned (prefix-stripped) version titles"
fi

# 5c. Every release tag vX.Y.Z should have a matching ## [X.Y.Z] heading
#     (pre-release / -beta tags are exempt).
missing_headings=""
for t in $(git tag --list 'v*' 2>/dev/null | sed 's/^v//' | grep -E '^[0-9]+\.[0-9]+'); do
    case "$t" in *-*) continue ;; esac
    grep -qE "^## \[${t}\]" CHANGELOG.md || missing_headings="${missing_headings} ${t}"
done
if [ -n "$missing_headings" ]; then
    warn "release tags without a CHANGELOG heading:${missing_headings}"
else
    ok "every release tag has a CHANGELOG heading"
fi

# 6. Retired-claim denylist. When a false/overstated public claim is fixed,
#    add its phrasing here so the gate blocks it from silently reappearing.
#    Scope = current docs only (CHANGELOG + per-version release notes +
#    this script are history/definition and are excluded).
DENY=(
  'signed tags'                                     # tags are annotated, not GPG/SSH-signed
  'No native service wrapper shipped'               # the Windows service wrapper ships
  'canonical fingerprint of a passphrase mismatch'  # doctor --peer overstatement
  'verify reachability + passphrase match'          # doctor --peer overstatement
  'passphrases agree'                               # doctor --peer cannot confirm this
)
scope_files="$(git ls-files '*.md' 2>/dev/null | grep -vE 'CHANGELOG\.md|docs/RELEASE_NOTES_v|REVIEW_EVIDENCE')"
deny_hits=0
for phrase in "${DENY[@]}"; do
    hits="$(grep -nIF "$phrase" $scope_files 2>/dev/null || true)"
    if [ -n "$hits" ]; then
        bad "retired claim phrase reappeared: \"${phrase}\""
        printf '           %s\n' "$hits"
        deny_hits=$((deny_hits+1))
    fi
done
[ "$deny_hits" -eq 0 ] && ok "no retired claim phrases in current docs (${#DENY[@]} on denylist)"

# 7. (warn-level) The previous tag should already have a GitHub release.
#    Needs gh + network; skipped cleanly when unavailable (e.g. local/offline).
if command -v gh >/dev/null 2>&1; then
    prev_tag="$(git tag --list 'v*' 2>/dev/null | sort -V | grep -B1 -xF "v${VERSION}" | head -1 || true)"
    if [ -n "$prev_tag" ] && [ "$prev_tag" != "v${VERSION}" ]; then
        if gh release view "$prev_tag" >/dev/null 2>&1; then
            ok "previous tag ${prev_tag} has a GitHub release"
        else
            warn "previous tag ${prev_tag} has no GitHub release (backfill the Releases page)"
        fi
    fi
else
    warn "gh not available — skipping previous-tag GitHub-release check"
fi

echo
if [ "$FAIL" -eq 0 ]; then
    echo "doc-sync-check: PASS"
    exit 0
else
    echo "doc-sync-check: ${FAIL} failure(s) — fix before tagging"
    exit 1
fi
