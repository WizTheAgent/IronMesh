#!/usr/bin/env bash
# install-hooks.sh — point this clone's git hooks at the tracked .githooks/ dir.
# Run once after cloning. Idempotent.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

git config core.hooksPath .githooks
chmod +x .githooks/pre-commit .githooks/pre-push scripts/leak-scan.sh

echo "Hooks installed."
echo "  core.hooksPath = $(git config --get core.hooksPath)"
echo "  pre-commit     = .githooks/pre-commit (runs scripts/leak-scan.sh --staged)"
echo "  pre-push       = .githooks/pre-push   (runs scripts/leak-scan.sh --range remote..local)"
echo ""
echo "To bypass on a single commit/push (do not abuse):"
echo "  git commit --no-verify"
echo "  git push --no-verify"
