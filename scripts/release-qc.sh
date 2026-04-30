#!/usr/bin/env bash
# release-qc.sh — automated pre-release quality control.
#
# What this catches that the human eye drifts on:
#
#   1. Stale claims — "21 MCP tools" / "470+ tests" / "v0.6 footer" /
#      "0.1.0-alpha.2" — the kind of thing that's true once and stays
#      true in a doc forever, even after the underlying number moves.
#   2. Doc-vs-reality drift — pyproject version != __init__.__version__,
#      claimed test count != actual, claimed MCP tool count != actual.
#   3. Broken internal links — files renamed or deleted with .md
#      references left dangling.
#   4. mkdocs nav pointing at files that don't exist on disk (Netlify
#      404 after deploy).
#   5. Public-facing standard violations — internal milestone codes,
#      personal paths, IPs, "Audit H-N" markers leaking into shipped
#      content.
#   6. Wheel packaging regressions — the historical class of bug where
#      a subpackage is missing from setuptools.packages and every
#      `pip install` user hits ModuleNotFoundError. Delegates to
#      release-smoke.sh.
#   7. Lint regressions that would redden the tag-CI matrix after
#      artifacts have already shipped.
#
# Exit 0 = release is clean. Exit 1 = at least one check failed.
#
# CI runs this on every push and on tag pushes. Operators run it
# locally before tagging — see .github/RELEASE_CHECKLIST.md.
#
# Usage:
#   bash scripts/release-qc.sh
#   bash scripts/release-qc.sh --skip-smoke   # don't rebuild the wheel
#   bash scripts/release-qc.sh --skip-tests   # don't run pytest collect
set -eu

SKIP_SMOKE=0
SKIP_TESTS=0
for arg in "$@"; do
    case "$arg" in
        --skip-smoke) SKIP_SMOKE=1 ;;
        --skip-tests) SKIP_TESTS=1 ;;
        *) echo "Unknown arg: $arg" >&2; exit 2 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

VERSION="$(python -c "import re; print(re.search(r'^version *= *\"([^\"]+)\"', open('pyproject.toml').read(), re.M).group(1))")"
echo "═══ release-qc · ironmesh ${VERSION} ═══"
echo

PASSED=0
FAILED=0
WARNED=0

ok()   { printf "  [PASS] %s\n" "$1"; PASSED=$((PASSED+1)); }
fail() { printf "  [FAIL] %s\n" "$1"; FAILED=$((FAILED+1)); }
warn() { printf "  [WARN] %s\n" "$1"; WARNED=$((WARNED+1)); }

# ───── 1. Version consistency ─────────────────────────────────────
echo "[ 1] version consistency across pyproject.toml + __init__.py"
v_init="$(python -c "
import re
m = re.search(r'^__version__ *= *[\"\']([^\"\']+)[\"\']', open('__init__.py').read(), re.M)
print(m.group(1) if m else '')
")"
if [ "$v_init" = "$VERSION" ]; then
    ok "__init__.__version__ = pyproject.version = ${VERSION}"
else
    fail "__init__.__version__ (${v_init}) != pyproject.version (${VERSION})"
fi

# ───── 2. CHANGELOG entry ─────────────────────────────────────────
echo "[ 2] CHANGELOG entry for [${VERSION}]"
if grep -qE "^## \[${VERSION}\]" CHANGELOG.md; then
    ok "[${VERSION}] section present in CHANGELOG.md"
else
    fail "no [${VERSION}] section in CHANGELOG.md (Keep-a-Changelog format expected)"
fi

# ───── 3. Release notes file ─────────────────────────────────────
echo "[ 3] docs/RELEASE_NOTES_v${VERSION}.md"
if [ -f "docs/RELEASE_NOTES_v${VERSION}.md" ]; then
    sz="$(wc -l < "docs/RELEASE_NOTES_v${VERSION}.md")"
    ok "docs/RELEASE_NOTES_v${VERSION}.md present (${sz} lines)"
else
    fail "missing docs/RELEASE_NOTES_v${VERSION}.md"
fi

# ───── 4. ruff lint ───────────────────────────────────────────────
echo "[ 4] ruff lint (CI scope)"
if ruff check . --exclude tests --exclude examples \
        --exclude ironmesh_mcp/__pycache__ >/tmp/ruff.out 2>&1; then
    ok "ruff: All checks passed"
else
    n="$(grep -cE "^[^[:space:]]+\.py:[0-9]+:" /tmp/ruff.out || echo 0)"
    fail "ruff: ${n} errors. Run 'ruff check . --exclude tests --exclude examples'"
fi

# ───── 5. mkdocs nav files all exist on disk ─────────────────────
echo "[ 5] mkdocs nav references"
if python -c "
import sys, yaml, pathlib
nav = yaml.safe_load(open('mkdocs.yml'))['nav']
def walk(items):
    out = []
    for it in items:
        if isinstance(it, dict):
            for _, v in it.items():
                if isinstance(v, str): out.append(v)
                else: out.extend(walk(v))
        elif isinstance(it, str):
            out.append(it)
    return out
files = walk(nav)
docs = pathlib.Path('docs')
missing = [f for f in files if not (docs / f).exists()]
print(f'{len(files)}|{len(missing)}|' + ','.join(missing))
sys.exit(1 if missing else 0)
" >/tmp/mkdocs_check.out 2>&1; then
    summary="$(cat /tmp/mkdocs_check.out)"
    total="${summary%%|*}"
    ok "mkdocs nav: ${total} entries, all resolve to disk"
else
    summary="$(cat /tmp/mkdocs_check.out)"
    missing_csv="${summary##*|}"
    missing_n="${summary#*|}"; missing_n="${missing_n%%|*}"
    fail "mkdocs nav: ${missing_n} dangling entries (mkdocs --strict will fail)"
    printf '         %s\n' $(echo "$missing_csv" | tr ',' ' ')
fi

# ───── 6. Internal markdown links ────────────────────────────────
echo "[ 6] internal markdown links resolve"
ml_out="$(python -c "
import re, pathlib
checked, broken = 0, []
SKIP = ('node_modules', '.venv', '/dist/', '/build/', '/site/')
for md in pathlib.Path('.').rglob('*.md'):
    s = str(md)
    if any(p in s for p in SKIP): continue
    try:
        text = md.read_text(encoding='utf-8', errors='replace')
    except OSError:
        continue
    for link in re.findall(r'\]\((?!https?://|mailto:|#)([^)#]+)', text):
        link = link.strip()
        if not link or link.startswith(('<', '\\$')): continue
        target = (md.parent / link).resolve()
        checked += 1
        if not target.exists():
            broken.append(f'{md}: {link}')
print(f'CHECKED={checked}')
print(f'BROKEN={len(broken)}')
for b in broken[:20]: print(f'  - {b}')
")"
ml_checked="$(printf '%s\n' "$ml_out" | grep -E '^CHECKED=' | sed 's/CHECKED=//')"
ml_broken="$(printf '%s\n' "$ml_out" | grep -E '^BROKEN=' | sed 's/BROKEN=//')"
if [ "$ml_broken" = "0" ]; then
    ok "internal markdown links: ${ml_checked} checked, all resolve"
else
    fail "internal markdown links: ${ml_broken} broken (of ${ml_checked} checked)"
    printf '%s\n' "$ml_out" | grep -E '^  -'
fi

# ───── 7. Public-facing leak scan ────────────────────────────────
# False-positive carve-outs (intentional, not leaks):
#   - .gitignore — declares the .kingpi-secure/ ignore pattern
#   - AGENTS.md — describes the standard, including counter-examples
#     ("don't use M0/M1 codes")
#   - discovery.py — RFC1918 default-gateway probe constants are
#     internet-standard private IP space, not personal addresses
#   - clients/go/ — example IPs use TEST-NET-1 (192.0.2.0/24) per
#     RFC 5737; 192.0.x doesn't match the 192.168.1. private-net
#     pattern below
echo "[ 7] public-facing standard"
LEAK_PATTERNS='C:[/\\]Users[/\\][a-z]|/\.kingpi-secure|192\.168\.1\.[0-9]+|\bAudit [HCM]-[0-9]+\b|\bRAZOR #[0-9]+\b|\(M[01] (audit|fix|spike)\)|^Path [AB]\b|\bdev laptop\b'
LEAK_EXCLUDE='^(CHANGELOG\.md|docs/RELEASE_NOTES_v0\.|\.github/RELEASE_CHECKLIST\.md|\.gitignore|AGENTS\.md|discovery\.py|tests/|scripts/release-qc\.sh|scripts/leak-scan\.sh)'
LEAK_HITS="$(git ls-files \
    | grep -vE "$LEAK_EXCLUDE" \
    | xargs grep -lnE "$LEAK_PATTERNS" 2>/dev/null | head)"
if [ -z "$LEAK_HITS" ]; then
    ok "no internal markers in tracked content (with documented carve-outs)"
else
    fail "internal markers found in:"
    printf '         %s\n' $LEAK_HITS
fi

# ───── 8. MCP tool count: doc claim vs implementation ────────────
echo "[ 8] MCP tool count consistency"
actual_tools="$(grep -cE "^[[:space:]]*def tool_" ironmesh_mcp/server.py || echo 0)"
claimed_tools="$(grep -oE '[0-9]+ MCP tools' WHATS_NEW.md README.md AGENTS.md 2>/dev/null \
    | head -n 1 | grep -oE '[0-9]+' || echo "?")"
if [ "$actual_tools" = "$claimed_tools" ]; then
    ok "MCP tool count: ${actual_tools} declared in server.py, ${claimed_tools} claimed in docs"
elif [ "$claimed_tools" = "?" ]; then
    warn "MCP tool count claim not found in WHATS_NEW.md / README.md / AGENTS.md"
else
    fail "MCP tool count drift: server.py has ${actual_tools}, docs claim ${claimed_tools}"
fi

# ───── 9. Test count claim sanity check ──────────────────────────
echo "[ 9] test count sanity"
if [ "$SKIP_TESTS" = "1" ]; then
    warn "test-count check skipped (--skip-tests)"
else
    actual_tests="$(timeout 60 python -m pytest --collect-only -q tests/ 2>/dev/null \
        | grep -oE '[0-9]+ tests collected' | head -n 1 | grep -oE '^[0-9]+' || echo 0)"
    claimed_tests="$(grep -oE '[0-9]+ tests' WHATS_NEW.md CONTRIBUTING.md README.md 2>/dev/null \
        | head -n 1 | grep -oE '[0-9]+' || echo "?")"
    if [ "$claimed_tests" = "?" ]; then
        warn "no test count claim found in WHATS_NEW.md / CONTRIBUTING.md / README.md"
    elif [ "$actual_tests" = "0" ]; then
        warn "pytest --collect-only timed out or returned 0 (claim was ${claimed_tests})"
    elif [ "$actual_tests" -ge "$claimed_tests" ]; then
        ok "test count: ${actual_tests} collected, ${claimed_tests} claimed (>=)"
    else
        fail "test count drift: pytest collected ${actual_tests}, docs claim ${claimed_tests}"
    fi
fi

# ───── 10. release-smoke (wheel build + import smoke) ────────────
echo "[10] release-smoke (wheel build + import smoke)"
if [ "$SKIP_SMOKE" = "1" ]; then
    warn "release-smoke skipped (--skip-smoke)"
else
    if bash scripts/release-smoke.sh >/tmp/release-smoke.out 2>&1; then
        if grep -q "═══ PASS" /tmp/release-smoke.out; then
            ok "release-smoke: PASS"
        else
            fail "release-smoke ran but didn't print PASS — check /tmp/release-smoke.out"
        fi
    else
        fail "release-smoke errored — see /tmp/release-smoke.out"
    fi
fi

# ───── 11. tag check (informational) ─────────────────────────────
echo "[11] git tag for v${VERSION}"
if git tag --list | grep -qx "v${VERSION}"; then
    ok "tag v${VERSION} exists locally"
else
    warn "tag v${VERSION} not yet created (after this passes, run: git tag -a v${VERSION} -m '...')"
fi

# ───── 12. README structural sanity ──────────────────────────────
echo "[12] README structural sanity"
readme_lines="$(wc -l < README.md)"
duplicate_h2="$(grep -E '^## ' README.md | sort | uniq -d | head)"
if [ -n "$duplicate_h2" ]; then
    fail "README has duplicate H2 headings:"
    printf '         %s\n' "$duplicate_h2"
elif [ "$readme_lines" -gt 1200 ]; then
    warn "README is ${readme_lines} lines — likely overdue for a slim pass"
else
    ok "README: ${readme_lines} lines, no duplicate H2 headings"
fi

# ───── Summary ───────────────────────────────────────────────────
echo
echo "═══════════════════════════════════════════════════════════════"
printf "  PASS: %3d   FAIL: %3d   WARN: %3d\n" "$PASSED" "$FAILED" "$WARNED"
echo "═══════════════════════════════════════════════════════════════"
if [ "$FAILED" = "0" ]; then
    echo
    echo "  release-qc clean. v${VERSION} is safe to tag + push."
    exit 0
else
    echo
    echo "  release-qc FAILED. fix the items above before tagging."
    exit 1
fi
