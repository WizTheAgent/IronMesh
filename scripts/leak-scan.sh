#!/usr/bin/env bash
# leak-scan.sh — fail if internal-only content is about to enter the public repo.
#
# Detection layers:
#   1. Filename patterns (high-confidence: these names are reserved for internal
#      content — see .gitignore for the same list).
#   2. Content patterns, in three classes:
#      a. HOST/IDENTIFIER (case-INSENSITIVE) — environment-specific host names,
#         private addresses, personal paths, project codenames. These are the
#         true leak vector: they must be caught regardless of capitalization
#         ("Wiz" as well as "wiz") and regardless of which file they hide in,
#         INCLUDING immutable history files that ship in the sdist. Patterns
#         load from an untracked local file (section 2b).
#      b. INTERNAL CONTENT MARKER (case-sensitive) — milestone codes, audit
#         hardening codes, decision-tree shorthand. Carefully anchored; folding
#         case would create false positives (e.g. "internal", "path a"), so
#         these stay case-sensitive and are NOT applied to history files.
#      c. DOC-ONLY MARKER (case-sensitive) — markers that code legitimately
#         uses as identifiers but that must never appear in shipped docs.
#
#   3. Self-test (--self-test) — the gate seeds known-positive canaries and
#      asserts it catches every one, including a capitalized identifier, a leak
#      inside a history file (CHANGELOG / RELEASE_NOTES), and a leak inside the
#      BUILT sdist. If the gate cannot catch its own canary, CI fails. This is
#      what converts a future coverage regression (a reverted -i, a new
#      exclusion, a pattern typo) into a red gate instead of a silent leak.
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
#       Scan every file in the working tree. Used for one-shot audits. Uses one
#       batched grep per class (seconds, not minutes) with a per-class timeout.
#
#   bash scripts/leak-scan.sh --self-test
#       Run the planted-positive self-test (see layer 3). Set
#       LEAKSCAN_SELFTEST_SDIST=0 to skip the (slower) sdist build for a quick
#       source-only tripwire; the release gates run it with the sdist assertion.
#
# Exit codes:
#   0  — clean (or self-test passed)
#   1  — at least one leak detected / self-test failed (full report on stdout)
#   2  — usage error
#
# Bypassing this script is a deliberate act. Do not bypass without explicit
# user instruction.

set -uo pipefail

MODE="${1:-}"
ARG="${2:-}"

if [[ -z "$MODE" ]]; then
    echo "usage: $0 (--staged | --range BASE..HEAD | --all | --self-test)" >&2
    exit 2
fi

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
REPO_ROOT="${REPO_ROOT:-$(pwd)}"

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
# 2. Content patterns — class (b): INTERNAL CONTENT MARKER (case-sensitive)
# ----------------------------------------------------------------------------
# These markers are forbidden in any text that ships publicly: changelog
# entries, release notes, doc files, comments, commit messages.
#
# Each pattern is a Perl-compatible regex. Word-boundary anchors prevent obvious
# false positives. Patterns are stored as strings rather than one giant regex so
# they can be disabled or extended without breaking the rest. These are scanned
# case-SENSITIVELY (folding case here would light up ordinary English) and are
# NOT applied to history files (see is_history_file).

CONTENT_PATTERNS=(
    # Audit hardening codes — high-confidence internal markers
    'Audit H-[0-9]+'
    # Decision-tree shorthand from internal plans
    'RAZOR #?[0-9]+'
    'Path [AB]\b'
    # Internal bug-tracker codes in comments or prose ("B7 fix:", "B21 fix —",
    # "B14 regression"). Narrow to "B<digits> <verb>" to avoid false positives
    # on e.g. bandit "nosec B310", flake8 rule codes, or legitimate identifiers.
    '(?<!nosec )\bB[0-9]+ (fix|regression|patch(ed)?)\b'
    # Task-tracker shorthand ("T#74", "T#76").
    '\bT#[0-9]+\b'
    # Internal revision-tag suffixes on version strings ("v0.8.5.2-R5:").
    # Matches the internal tag without catching legitimate release suffixes like
    # "-rc1" or "-beta".
    '-R[0-9]+(?=[^a-zA-Z0-9]|$)'
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
    # Tone markers that shouldn't appear in shipped public docs
    'dev laptop'
)

# ----------------------------------------------------------------------------
# 2b. Content patterns — class (a): HOST/IDENTIFIER (case-INSENSITIVE, local)
# ----------------------------------------------------------------------------
# Environment-specific identifiers (host names, private addresses, personal
# paths, credential fragments, project codenames) are deliberately NOT embedded
# in this tracked script — a public denylist of private identifiers would itself
# be a leak. They live in an untracked file: one perl-compatible regex per line;
# blank lines and #-comments are ignored. Default location is
# <repo-root>/.leak-patterns.local (gitignored); override with the
# IRONMESH_LEAK_PATTERNS environment variable. When the file is absent (e.g. in
# CI) the host/identifier class is empty and the scan runs the generic classes
# only, printing a note so the reduced coverage is visible.
#
# This class is scanned case-INSENSITIVELY and against EVERY non-meta file,
# including history files — a fleet name must never ship, historical or not.
# (The leak this closes: "Wiz"/"KingPi" shipped in RELEASE_NOTES + CHANGELOG in
# the sdist because the old scan was case-sensitive and excluded history.)

# Tracked, environment-AGNOSTIC identifier seeds — safe to ship here because
# they name no specific person, only a category. They keep the host/identifier
# class non-empty even in CI (where .leak-patterns.local is absent), so a
# personal path leaking into ANY file (including history) is still caught.
# NOTE: a generic "/home/<name>/" is deliberately NOT seeded — it false-positives
# on legitimate service-user and placeholder paths (e.g. /home/ironmesh in the
# Dockerfile, /home/me and /home/pi in doc examples). The specific personal
# POSIX home lives in the untracked file instead.
LOCAL_PATTERNS=(
    'C:[\\/]Users[\\/][A-Za-z0-9._-]+'
)
LOCAL_PATTERNS_FILE="${IRONMESH_LEAK_PATTERNS:-}"
if [[ -z "$LOCAL_PATTERNS_FILE" ]]; then
    LOCAL_PATTERNS_FILE="${REPO_ROOT}/.leak-patterns.local"
fi
if [[ -f "$LOCAL_PATTERNS_FILE" ]]; then
    while IFS= read -r _pat; do
        [[ -z "$_pat" || "$_pat" == \#* ]] && continue
        LOCAL_PATTERNS+=("$_pat")
    done < "$LOCAL_PATTERNS_FILE"
else
    echo "leak-scan: note — no local patterns file ($LOCAL_PATTERNS_FILE); scanning generic + tracked-identifier patterns only (environment-specific identifiers disabled)" >&2
fi

# ----------------------------------------------------------------------------
# 2c. Content patterns — class (c): DOC-ONLY MARKER (case-sensitive, docs only)
# ----------------------------------------------------------------------------
# Scanned only in shipped doc files. Code legitimately uses these as identifiers,
# constants, or enum values. Not applied to history files.
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

# ----------------------------------------------------------------------------
# 2d. File-class exclusions
# ----------------------------------------------------------------------------
# Two DISTINCT reasons a file is treated specially — keep them separate so the
# history carve-out never silently disables the host/identifier class:
#
#   is_meta_file    — files that DOCUMENT the patterns themselves (this script,
#                     the hooks, the CI workflows, AGENTS.md). Excluded from ALL
#                     content scanning, or the scanner flags its own definitions.
#
#   is_history_file — immutable release history (CHANGELOG, RELEASE_NOTES,
#                     migration guides). Excluded from the generic + doc-only
#                     classes (their historical milestone markers are preserved)
#                     but STILL scanned by the HOST/IDENTIFIER class — these are
#                     exactly the files that ship in the sdist, and a fleet name
#                     in them is a real leak.

is_meta_file() {
    case "$1" in
        scripts/leak-scan.sh)                  return 0 ;;
        scripts/release-qc.sh)                 return 0 ;;
        .githooks/pre-commit)                  return 0 ;;
        .githooks/pre-push)                    return 0 ;;
        .github/workflows/leak-scan.yml)       return 0 ;;
        .github/workflows/release-qc.yml)      return 0 ;;
        .github/RELEASE_CHECKLIST.md)          return 0 ;;
        .gitignore)                            return 0 ;;
        AGENTS.md)                             return 0 ;;
        *) return 1 ;;
    esac
}

is_history_file() {
    case "$1" in
        CHANGELOG.md)                          return 0 ;;
        docs/RELEASE_NOTES_v*.md)              return 0 ;;
        docs/migration/*.md)                   return 0 ;;
        *) return 1 ;;
    esac
}

# ----------------------------------------------------------------------------
# Materialize each pattern class into a temp file for batched `grep -f`
# ----------------------------------------------------------------------------
# Using -f (one grep per class over all files) instead of a per-file/per-pattern
# loop is what turns --all from minutes into seconds. Blank lines are stripped so
# grep -f never sees an empty pattern (which would match every line).

TMP_PAT_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t leakscan)"
cleanup() { rm -rf "$TMP_PAT_DIR" 2>/dev/null || true; }
trap cleanup EXIT

CONTENT_PAT_FILE="$TMP_PAT_DIR/content.pat"
LOCAL_PAT_FILE="$TMP_PAT_DIR/local.pat"
DOCONLY_PAT_FILE="$TMP_PAT_DIR/doconly.pat"

write_pat_file() {
    local dest="$1"; shift
    : > "$dest"
    local p
    for p in "$@"; do
        [[ -z "$p" ]] && continue
        printf '%s\n' "$p" >> "$dest"
    done
}

write_pat_file "$CONTENT_PAT_FILE" "${CONTENT_PATTERNS[@]}"
write_pat_file "$DOCONLY_PAT_FILE" "${DOC_ONLY_PATTERNS[@]}"
write_pat_file "$LOCAL_PAT_FILE" "${LOCAL_PATTERNS[@]+"${LOCAL_PATTERNS[@]}"}"

VIOLATIONS=0
LEAKSCAN_GREP_TIMEOUT="${LEAKSCAN_GREP_TIMEOUT:-180}"

# ----------------------------------------------------------------------------
# build_alternation PATFILE — join non-empty lines into one PCRE alternation.
# ----------------------------------------------------------------------------
# GNU grep 3.0 (still shipped on some LTS/MSYS setups) REJECTS -P with more than
# one pattern — whether supplied via -f or repeated -e — with "the -P option
# only supports a single pattern" (exit 2). So every class is scanned as ONE
# combined pattern instead of a multi-pattern file. Each source pattern is
# wrapped in a non-capturing group to preserve its semantics under the join
# (anchors like ^ and lookarounds remain valid inside (?:...)).
build_alternation() {
    local f="$1" line out="" first=1
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ $first -eq 1 ]]; then
            out="(?:$line)"; first=0
        else
            out="$out|(?:$line)"
        fi
    done < "$f"
    printf '%s' "$out"
}

# ----------------------------------------------------------------------------
# scan_class LABEL PATFILE GREPFLAGS BASE REL...
# ----------------------------------------------------------------------------
# One batched grep over all REL paths (resolved against BASE) for one pattern
# class. Prints a report block on any hit and adds the hit count to the global
# VIOLATIONS. Called directly (never in a pipe) so VIOLATIONS survives.
scan_class() {
    local label="$1" patfile="$2" flags="$3" base="$4"; shift 4
    [[ $# -eq 0 ]] && return 0
    [[ -s "$patfile" ]] || return 0
    local combined
    combined="$(build_alternation "$patfile")"
    [[ -z "$combined" ]] && return 0
    # Fail-closed on an invalid combined regex. A syntax error makes grep exit
    # >=2; if that were swallowed as "no match" the class would silently stop
    # scanning (a false clean). Validate once against empty input, where a valid
    # regex exits 1 (no match) and a broken one exits >=2.
    LC_ALL=C.UTF-8 grep -P $flags -e "$combined" < /dev/null > /dev/null 2>&1
    local probe_rc=$?
    if [[ $probe_rc -ge 2 ]]; then
        echo "leak-scan: ERROR — class '$label' produced an invalid combined regex (grep exit $probe_rc); refusing to report clean" >&2
        VIOLATIONS=$((VIOLATIONS + 1))
        return 1
    fi
    local -a abs=()
    local r
    for r in "$@"; do abs+=("$base/$r"); done
    local matches
    # Single combined -P pattern (grep-3.0 safe). -n line numbers, -I skip
    # binary, -H force filename. xargs -0 batches safely under ARG_MAX; timeout
    # bounds a pathological scan. grep/xargs exit 1/123 on no-match → tolerate
    # with || true; a regex syntax error was ruled out above, so empty output
    # here genuinely means clean.
    matches="$(printf '%s\0' "${abs[@]}" \
        | LC_ALL=C.UTF-8 timeout "$LEAKSCAN_GREP_TIMEOUT" xargs -0 grep -nIHP $flags -e "$combined" -- 2>/dev/null || true)"
    [[ -z "$matches" ]] && return 0
    local cleaned
    cleaned="$(printf '%s\n' "$matches" | sed "s#^${base}/##")"
    printf 'leak-scan: %s\n' "$label"
    printf '%s\n' "$cleaned" | sed 's/^/    /' | head -40
    local n
    n="$(printf '%s\n' "$matches" | grep -c . || true)"
    VIOLATIONS=$((VIOLATIONS + n))
}

# ----------------------------------------------------------------------------
# scan_tree BASE FILELIST
# ----------------------------------------------------------------------------
# Partition FILELIST (newline-delimited, repo-relative) into the three classes
# and run one batched grep per class. Filename-layer (is_internal_filename) is
# handled separately by the caller.
scan_tree() {
    local base="$1" filelist="$2"
    local -a local_targets=() generic_targets=() doconly_targets=()
    local rel
    while IFS= read -r rel; do
        [[ -z "$rel" ]] && continue
        [[ -f "$base/$rel" ]] || continue
        case "$rel" in
            *.png|*.jpg|*.jpeg|*.gif|*.ico|*.pdf|*.zip|*.tar|*.tgz|*.tar.gz|*.whl|*.so|*.dll|*.exe)
                continue ;;
        esac
        is_meta_file "$rel" && continue
        # Host/identifier class: every non-meta file, INCLUDING history.
        local_targets+=("$rel")
        if ! is_history_file "$rel"; then
            generic_targets+=("$rel")
            is_doc_file "$rel" && doconly_targets+=("$rel")
        fi
    done <<< "$filelist"

    [[ "${#local_targets[@]}"   -gt 0 ]] && scan_class "HOST/IDENTIFIER MARKER (case-insensitive)" "$LOCAL_PAT_FILE"   "-i" "$base" "${local_targets[@]}"
    [[ "${#generic_targets[@]}" -gt 0 ]] && scan_class "INTERNAL CONTENT MARKER"                   "$CONTENT_PAT_FILE" ""   "$base" "${generic_targets[@]}"
    [[ "${#doconly_targets[@]}" -gt 0 ]] && scan_class "DOC-ONLY MARKER"                           "$DOCONLY_PAT_FILE" ""   "$base" "${doconly_targets[@]}"
}

# ----------------------------------------------------------------------------
# --self-test : planted-positive self-verification (layer 3)
# ----------------------------------------------------------------------------
# Seeds canaries the gate is REQUIRED to catch, asserts each is caught. The
# canary pattern is injected into the host/identifier class, so the self-test is
# self-contained and runs identically in CI (no dependency on the untracked
# .leak-patterns.local). Three required modes + a filename bonus + a negative
# control.
run_self_test() {
    local st_tmp
    st_tmp="$(mktemp -d 2>/dev/null || mktemp -d -t leakscan-st)" || {
        echo "self-test: ERROR — mktemp failed" >&2; return 2; }

    local canary_pattern='xyzzy-fleet-canary-[0-9]+'
    # Planted in MIXED case: only caught if the host/identifier class is -i.
    local canary_plant='XyZzY-Fleet-Canary-4242'

    # Override the host/identifier class with JUST the canary for the self-test.
    write_pat_file "$LOCAL_PAT_FILE" "$canary_pattern"

    # Mode 1 — capitalized identifier (host/identifier class) in a source file.
    mkdir -p "$st_tmp/src" "$st_tmp/docs"
    printf '# deploy note: relay node %s handles fan-out\n' "$canary_plant" > "$st_tmp/src/node_config.py"
    # Generic class — a real INTERNAL CONTENT MARKER (exercises the multi-pattern
    # alternation; a grep-compat regression here would otherwise ship silently).
    printf '# see Audit H-99 for the rationale\n' > "$st_tmp/src/marker.py"
    # Doc-only class — a real DOC-ONLY MARKER inside a shipped doc file.
    printf '# Guide\n\nThis section is CONFIDENTIAL until launch.\n' > "$st_tmp/docs/guide.md"
    # Doc-only scoping negative — the same marker in CODE must NOT be flagged.
    printf 'CONFIDENTIAL = "enum-value"\n' > "$st_tmp/src/enum_defs.py"
    # Negative control — a clean source file must NOT be flagged.
    printf '# nothing to see here\nMESH_PORT = 8765\n' > "$st_tmp/src/clean.py"
    # Mode 2a — leak inside CHANGELOG.md (history file, ships in sdist).
    printf '# Changelog\n\n## [9.9.9]\n- decommissioned %s\n' "$canary_plant" > "$st_tmp/CHANGELOG.md"
    # Mode 2b — leak inside a RELEASE_NOTES file (history file, ships in sdist).
    mkdir -p "$st_tmp/docs"
    printf '# Release notes v9.9.9\n\nValidated on %s.\n' "$canary_plant" > "$st_tmp/docs/RELEASE_NOTES_v9.9.9.md"
    # Filename bonus — a reserved internal filename.
    printf 'internal plan\n' > "$st_tmp/docs/v9_PLAN.md"

    local filelist
    filelist=$'src/node_config.py\nsrc/marker.py\nsrc/enum_defs.py\nsrc/clean.py\ndocs/guide.md\nCHANGELOG.md\ndocs/RELEASE_NOTES_v9.9.9.md\ndocs/v9_PLAN.md'

    local report
    report="$(scan_tree "$st_tmp" "$filelist")"

    # Filename-layer check (mirrors the caller's Layer-1 loop).
    local fname_report=""
    local f
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        is_internal_filename "$f" && fname_report+="$f"$'\n'
    done <<< "$filelist"

    local rc=0
    check() {  # check DESC HAYSTACK NEEDLE  (assert NEEDLE present)
        if printf '%s' "$2" | grep -qF -- "$3"; then
            printf '  [PASS] %s\n' "$1"
        else
            printf '  [FAIL] %s (canary NOT caught: %s)\n' "$1" "$3"; rc=1
        fi
    }
    refute() {  # refute DESC HAYSTACK NEEDLE  (assert NEEDLE absent)
        if printf '%s' "$2" | grep -qF -- "$3"; then
            printf '  [FAIL] %s (false positive on: %s)\n' "$1" "$3"; rc=1
        else
            printf '  [PASS] %s\n' "$1"
        fi
    }

    echo "leak-scan self-test — planted-positive verification"
    check  "mode 1: capitalized identifier caught (case-insensitivity)" "$report" "src/node_config.py"
    check  "generic class: INTERNAL CONTENT MARKER caught (multi-pattern)" "$report" "src/marker.py"
    check  "doc-only class: DOC-ONLY MARKER in a doc caught"            "$report" "docs/guide.md"
    check  "mode 2a: leak inside CHANGELOG.md caught (history scan)"     "$report" "CHANGELOG.md"
    check  "mode 2b: leak inside RELEASE_NOTES caught (history scan)"    "$report" "docs/RELEASE_NOTES_v9.9.9.md"
    check  "filename layer: reserved internal filename caught"          "$fname_report" "docs/v9_PLAN.md"
    refute "doc-only scoping: same marker in CODE not flagged"           "$report" "src/enum_defs.py"
    refute "negative control: clean file not flagged"                    "$report" "src/clean.py"

    # Mode 3 — assert against the BUILT sdist. The RELEASE_NOTES leak only ever
    # manifested in the sdist, so verify the scanner reaches into the packaged
    # artifact, not just the source tree.
    if [[ "${LEAKSCAN_SELFTEST_SDIST:-1}" == "0" ]]; then
        echo "  [SKIP] mode 3: sdist assertion (LEAKSCAN_SELFTEST_SDIST=0)"
    else
        local dist="$st_tmp/dist"
        mkdir -p "$dist"
        if python -m build --sdist --outdir "$dist" "$REPO_ROOT" > "$st_tmp/build.log" 2>&1; then
            local sd
            sd="$(ls "$dist"/*.tar.gz 2>/dev/null | head -1)"
            if [[ -n "$sd" ]]; then
                local ex="$st_tmp/sdist"
                mkdir -p "$ex"
                tar -xzf "$sd" -C "$ex"
                local pkgroot
                pkgroot="$(find "$ex" -mindepth 1 -maxdepth 1 -type d | head -1)"
                local target_rn
                target_rn="$(ls "$pkgroot"/docs/RELEASE_NOTES_v*.md 2>/dev/null | head -1)"
                if [[ -n "$target_rn" ]]; then
                    # Plant the canary into the sdist's release-notes copy (temp
                    # extract only — the repo is never touched) and scan it.
                    printf '\nsdist canary — node %s\n' "$canary_plant" >> "$target_rn"
                    local sdist_files
                    sdist_files="$(cd "$pkgroot" && find . -type f | sed 's#^\./##')"
                    local sdist_report
                    sdist_report="$(scan_tree "$pkgroot" "$sdist_files")"
                    local rn_rel="${target_rn#"$pkgroot"/}"
                    check "mode 3: canary in BUILT sdist ($rn_rel) caught" "$sdist_report" "$rn_rel"
                else
                    echo "  [FAIL] mode 3: sdist has no docs/RELEASE_NOTES_v*.md to plant into"; rc=1
                fi
            else
                echo "  [FAIL] mode 3: sdist build produced no tarball"; rc=1
            fi
        else
            echo "  [FAIL] mode 3: 'python -m build --sdist' failed (see $st_tmp/build.log)"
            tail -20 "$st_tmp/build.log" 2>/dev/null | sed 's/^/        /'
            rc=1
        fi
    fi

    rm -rf "$st_tmp" 2>/dev/null || true
    echo ""
    if [[ $rc -eq 0 ]]; then
        echo "leak-scan self-test: PASS — the gate catches every planted canary."
    else
        echo "leak-scan self-test: FAIL — a coverage regression let a canary slip."
        echo "  Fix the gate (do NOT weaken the canary) before shipping."
    fi
    return $rc
}

if [[ "$MODE" == "--self-test" ]]; then
    run_self_test
    exit $?
fi

# ----------------------------------------------------------------------------
# Collect the file list for the requested mode
# ----------------------------------------------------------------------------
# Each git invocation below is checked explicitly. This script runs without
# `set -e`, so an unchecked failure (e.g. an invalid commit range) would yield
# an empty file list and a false "clean" verdict — the scan would silently not
# run at all.
case "$MODE" in
    --staged)
        if ! FILES="$(git diff --cached --name-only --diff-filter=AM)"; then
            echo "leak-scan: ERROR — 'git diff --cached' failed; refusing to report clean" >&2
            exit 2
        fi
        ;;
    --range)
        if [[ -z "$ARG" ]]; then
            echo "usage: $0 --range BASE..HEAD" >&2
            exit 2
        fi
        if ! FILES="$(git diff --name-only --diff-filter=AM "$ARG")"; then
            echo "leak-scan: ERROR — 'git diff $ARG' failed (bad range?); refusing to report clean" >&2
            exit 2
        fi
        ;;
    --all)
        if ! FILES="$(git ls-files)"; then
            echo "leak-scan: ERROR — 'git ls-files' failed; refusing to report clean" >&2
            exit 2
        fi
        ;;
    *)
        echo "usage: $0 (--staged | --range BASE..HEAD | --all | --self-test)" >&2
        exit 2
        ;;
esac

# ----------------------------------------------------------------------------
# Run the scans
# ----------------------------------------------------------------------------

# Layer 1: filename patterns
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    if is_internal_filename "$f"; then
        echo "leak-scan: FILENAME RESERVED FOR INTERNAL CONTENT: $f"
        echo "  → move it to your internal-docs location outside the repository"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
done <<< "$FILES"

# Layer 2: content patterns (batched per class)
scan_tree "$REPO_ROOT" "$FILES"

# ----------------------------------------------------------------------------
# Report
# ----------------------------------------------------------------------------

if [[ $VIOLATIONS -gt 0 ]]; then
    echo ""
    echo "leak-scan: $VIOLATIONS violation(s) detected — push blocked."
    echo ""
    echo "If a match is a deliberate documentation example (e.g., describing"
    echo "a forbidden pattern in a checklist), add the file to is_meta_file()"
    echo "in scripts/leak-scan.sh."
    echo ""
    echo "If you genuinely need to bypass this check (rare), use:"
    echo "  git commit --no-verify   /  git push --no-verify"
    exit 1
fi

echo "leak-scan: clean"
exit 0
