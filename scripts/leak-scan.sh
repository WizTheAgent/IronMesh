#!/usr/bin/env bash
# leak-scan.sh — fail if internal-only content is about to enter the public repo.
#
# Two layers of detection:
#   1. Filename patterns (high-confidence: these names are reserved for internal
#      content — see .gitignore for the same list)
#   2. Content patterns (markers that should never appear in public-shipped text:
#      milestone codes, audit hardening codes, RAZOR/Path A-B, personal IPs,
#      personal absolute paths, personal node names, internal headers)
#
# Modes:
#   bash scripts/leak-scan.sh --staged
#       Scan files staged for the next commit. Used by .githooks/pre-commit.
#
#   bash scripts/leak-scan.sh --range BASE..HEAD
#       Scan files changed in the given commit range. Used by .githooks/pre-push
#       and the CI workflow.
#
#   bash scripts/leak-scan.sh --all
#       Scan every file in the working tree. Used for one-shot audits.
#
# Exit codes:
#   0  — clean
#   1  — at least one leak detected (full report on stdout)
#   2  — usage error
#
# Bypassing this script is a deliberate act. Do not bypass without explicit
# user instruction.

set -uo pipefail

MODE="${1:-}"
ARG="${2:-}"

if [[ -z "$MODE" ]]; then
    echo "usage: $0 (--staged | --range BASE..HEAD | --all)" >&2
    exit 2
fi

# ----------------------------------------------------------------------------
# 1. Filename patterns reserved for internal content
# ----------------------------------------------------------------------------
# Mirror of the .gitignore internal-docs section. If you change one, change both.

is_internal_filename() {
    local f="$1"
    case "$f" in
        docs/v*_PLAN.md)        return 0 ;;
        docs/AUDIT_*.md)        return 0 ;;
        docs/BUG-*.md)          return 0 ;;
        docs/*_GAPS.md)         return 0 ;;
        docs/*_INTERNAL.md)     return 0 ;;
        AUDIT_SCOPING_*.md)     return 0 ;;
        *_ROADMAP.md)
            # Only a leak if at the repo root (e.g., IRONMESH_V1_ROADMAP.md).
            # docs/ROADMAP.md is the public roadmap and is allowed.
            case "$f" in
                */*) return 1 ;;
                *)   return 0 ;;
            esac
            ;;
        *)                       return 1 ;;
    esac
}

# ----------------------------------------------------------------------------
# 2. Content patterns reserved for internal context
# ----------------------------------------------------------------------------
# These markers are explicitly forbidden in any text that ships publicly:
# changelog entries, release notes, doc files, comments, commit messages.
#
# Each pattern is a Perl-compatible regex. Word-boundary anchors are used
# where needed to prevent obvious false positives (e.g., "M0" matches
# milestone codes but not the word "M0unt" — though there's no such word).
#
# Patterns are stored as strings rather than a giant regex so they can be
# disabled or extended without breaking the rest.

CONTENT_PATTERNS=(
    # Audit hardening codes — high-confidence internal markers
    'Audit H-[0-9]+'
    # Decision-tree shorthand from internal plans
    'RAZOR #?[0-9]+'
    'Path [AB]\b'
    # Milestone codes — only flag when in a context word ("M0:", "milestone M0",
    # "(M0)", "M0 spike"). Bare "M5 15" in SVG paths is excluded.
    '\bmilestone[s]? M[0-9]\b'
    '(\(|^|\s)M[0-9]:'
    'M[0-9] (spike|track|deliverable)'
    # Audit severity codes — only flag when in a context word ("severity H1",
    # "vuln C2", "finding M1"). Bare "C2:", "H1:" in test names are caught
    # separately by the "audit-coded test name" rule below.
    '(severity|vuln|finding|audit) [CHM][0-9]+'
    # Test names that begin with an audit code (e.g. "describe('C2: ...')")
    '\b(describe|it|test|def test_)[(_\s]*[\x22\x27]?[CHM][0-9]+:'
    # Internal-only header markers — see DOC_ONLY_PATTERNS below; bare
    # INTERNAL in code is allowed (e.g. enum value names)
    # Personal absolute paths
    'C:\\Users\\jonha'
    '/home/jonha'
    # Personal node names (mesh fleet) — see EXCLUDED_FROM_CONTENT_SCAN
    # for files that legitimately use them as documentation examples
    '\bkingpi\b'
    '\bgatekeeper\b'
    '\bzevault\b'
    # Mesh-wide passphrase substring (high-severity if it ever appears)
    'kingpi-empire'
    # Tone markers that shouldn't appear in shipped public docs
    'dev laptop'
)

# DOC_ONLY_PATTERNS are scanned only in shipped doc files (markdown / rst /
# txt / yml / yaml). Code legitimately uses these as identifiers, constants,
# or enum values. Add specific file paths to EXCLUDED_FROM_CONTENT_SCAN if a
# doc file genuinely needs to reference one.
DOC_ONLY_PATTERNS=(
    # Internal-only header markers
    '\bINTERNAL\b'
    '\bCONFIDENTIAL\b'
    # Personal IP ranges
    '\b10\.[0-9]+\.[0-9]+\.[0-9]+\b'
    '\b192\.168\.[0-9]+\.[0-9]+\b'
    '\b172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]+\.[0-9]+\b'
)

is_doc_file() {
    case "$1" in
        *.md|*.rst|*.txt|*.yml|*.yaml|README*|CHANGELOG*|CONTRIBUTING*|SECURITY*|LICENSE*|NOTICE*) return 0 ;;
        *) return 1 ;;
    esac
}

# Files that are EXPECTED to contain pattern names (because they document the
# patterns themselves) — exclude from content scanning to avoid the meta-bug.
EXCLUDED_FROM_CONTENT_SCAN=(
    # Files that document the patterns themselves
    'scripts/leak-scan.sh'
    '.githooks/pre-commit'
    '.githooks/pre-push'
    '.github/workflows/leak-scan.yml'
    '.github/RELEASE_CHECKLIST.md'
    '.gitignore'
    # Immutable release history — rewriting is more confusing than helpful
    'CHANGELOG.md'
    'docs/RELEASE_NOTES_v0.7.2.md'
    'docs/RELEASE_NOTES_v0.8.0.md'
    'docs/RELEASE_NOTES_v0.8.1.md'
    'docs/RELEASE_NOTES_v0.8.2.md'
    'docs/RELEASE_NOTES_v0.8.3.md'
    'docs/RELEASE_NOTES_v0.8.4.md'
    'docs/RELEASE_NOTES_v0.8.5.md'
    'docs/RELEASE_NOTES_v0.8.5.2.md'
    'docs/RELEASE_NOTES_v0.8.5.3.md'
)

is_excluded_from_content_scan() {
    local f="$1"
    local x
    for x in "${EXCLUDED_FROM_CONTENT_SCAN[@]}"; do
        if [[ "$f" == "$x" ]]; then
            return 0
        fi
    done
    return 1
}

# ----------------------------------------------------------------------------
# Collect the file list for the requested mode
# ----------------------------------------------------------------------------

case "$MODE" in
    --staged)
        # Files staged for commit, additions + modifications only
        FILES="$(git diff --cached --name-only --diff-filter=AM)"
        ;;
    --range)
        if [[ -z "$ARG" ]]; then
            echo "usage: $0 --range BASE..HEAD" >&2
            exit 2
        fi
        FILES="$(git diff --name-only --diff-filter=AM "$ARG")"
        ;;
    --all)
        FILES="$(git ls-files)"
        ;;
    *)
        echo "usage: $0 (--staged | --range BASE..HEAD | --all)" >&2
        exit 2
        ;;
esac

# ----------------------------------------------------------------------------
# Run the scans
# ----------------------------------------------------------------------------

VIOLATIONS=0

# Layer 1: filename patterns
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    if is_internal_filename "$f"; then
        echo "leak-scan: FILENAME RESERVED FOR INTERNAL CONTENT: $f"
        echo "  → move to ~/.kingpi-secure/ironmesh/internal-docs/ and remove from the repo"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
done <<< "$FILES"

# Layer 2: content patterns
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    [[ ! -f "$f" ]] && continue
    if is_excluded_from_content_scan "$f"; then
        continue
    fi
    # Only scan text-like files; skip binaries
    case "$f" in
        *.png|*.jpg|*.jpeg|*.gif|*.ico|*.pdf|*.zip|*.tar|*.tar.gz|*.whl|*.so|*.dll|*.exe)
            continue
            ;;
    esac
    for pat in "${CONTENT_PATTERNS[@]}"; do
        # Use perl-regex grep with line numbers; -I skips binary files.
        # LC_ALL=C.UTF-8 is required because some bash environments (notably
        # MSYS on Windows) refuse `grep -P` under non-UTF-8 locales.
        matches="$(LC_ALL=C.UTF-8 grep -nIP -- "$pat" "$f" 2>/dev/null || true)"
        if [[ -n "$matches" ]]; then
            echo "leak-scan: INTERNAL CONTENT MARKER /$pat/ in $f"
            echo "$matches" | sed 's/^/    /' | head -5
            VIOLATIONS=$((VIOLATIONS + 1))
        fi
    done
    # DOC_ONLY patterns: only enforced in doc files. Code can legitimately
    # contain these as constants, enum values, or identifiers.
    if is_doc_file "$f"; then
        for pat in "${DOC_ONLY_PATTERNS[@]}"; do
            matches="$(LC_ALL=C.UTF-8 grep -nIP -- "$pat" "$f" 2>/dev/null || true)"
            if [[ -n "$matches" ]]; then
                echo "leak-scan: DOC-ONLY MARKER /$pat/ in $f"
                echo "$matches" | sed 's/^/    /' | head -5
                VIOLATIONS=$((VIOLATIONS + 1))
            fi
        done
    fi
done <<< "$FILES"

# ----------------------------------------------------------------------------
# Report
# ----------------------------------------------------------------------------

if [[ $VIOLATIONS -gt 0 ]]; then
    echo ""
    echo "leak-scan: $VIOLATIONS violation(s) detected — push blocked."
    echo ""
    echo "If a match is a deliberate documentation example (e.g., describing"
    echo "a forbidden pattern in a checklist), add the file to"
    echo "EXCLUDED_FROM_CONTENT_SCAN in scripts/leak-scan.sh."
    echo ""
    echo "If you genuinely need to bypass this check (rare), use:"
    echo "  git commit --no-verify   /  git push --no-verify"
    exit 1
fi

echo "leak-scan: clean"
exit 0
