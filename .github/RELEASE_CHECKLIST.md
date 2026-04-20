# IronMesh Release Checklist

**Purpose:** every release ships with documentation in sync. No more "the README on GitHub still says the old version after we tagged."

Run this checklist top-to-bottom for every `vX.Y.Z` release. Do not push tags or upload artifacts until every box is checked.

---

## 1. Code state

- [ ] Working tree clean (`git status` shows no uncommitted changes other than the version bump commit itself)
- [ ] On `main` branch (releases off feature branches require explicit justification in the release notes)
- [ ] Local `main` is up to date with `origin/main` and not ahead by anything except this release

## 2. Version bump

- [ ] `__init__.py` `__version__` updated
- [ ] `pyproject.toml` `version` updated
- [ ] `Dockerfile` LABEL version updated (if pinned)
- [ ] `clients/go/` version constant updated (if applicable)
- [ ] `clients/ts-channel/package.json` version updated (if applicable)
- [ ] All three (or more) versions match exactly

## 3. Documentation in sync — THE PART WE KEEP MISSING

This is the section that catches the "GitHub README still says v0.8.5 after we shipped v0.8.5.2" failure mode.

- [ ] **README.md** — search for the previous version string with `rg "X\.Y\.(Z-1)"` and verify every match is intentionally a historical reference (not a current-version claim)
  - [ ] Top-of-README pre-1.0 banner reflects new version
  - [ ] Install / docker-pull command examples reference the new version
  - [ ] "Latest:" line in Distribution section reflects the new version
  - [ ] "Recent changes" section has a new paragraph for the new version (and the previous "(current)" paragraph has had "(current)" removed)
  - [ ] Test count is current (run `pytest --collect-only -q | tail -1` to verify)
  - [ ] MCP tool count is current (grep the MCP server for `@server.list_tools` registrations)
- [ ] **CHANGELOG.md** — has a new `## [X.Y.Z]` section dated for today, follows Keep-a-Changelog format
- [ ] **SECURITY.md** — version-pinned advice references the new version where relevant
- [ ] **docs/RELEASE_NOTES_vX.Y.Z.md** — exists, written, linked from README "Recent changes" paragraph
- [ ] **docs/SECURITY.md** (if separate from root SECURITY.md) — synced
- [ ] **GETTING_STARTED.md** — version refs synced
- [ ] **ARCHITECTURE.md** — version refs synced
- [ ] **clients/ts-channel/README.md** — synced
- [ ] **clients/go/README.md** (if exists) — synced
- [ ] **docs/QUICKSTART.md** — synced
- [ ] **docs/OPENCLAW_MCP_SETUP.md** + **OPENCLAW_CHANNEL_SETUP.md** — synced

**Sweep command:** `rg "0\.8\.(5|4|3)" --glob '!CHANGELOG.md' --glob '!docs/RELEASE_NOTES_*' --glob '!docs/v0.*_PLAN.md'` — every match should be a deliberate historical reference. CHANGELOG and dated release-notes are exempt because their job is to preserve history.

## 4. Site (ironmesh.org)

- [ ] Site repo / Netlify pull updated with new version badge
- [ ] Site stats refreshed (test count, MCP tool count, version)
- [ ] **Manual Netlify drag-and-drop deploy** scheduled or done

## 5. Tests + CI

- [ ] **Lint** — `ruff check . --exclude tests --exclude examples --exclude ironmesh_mcp/__pycache__` exits clean. **Required** — CI runs this and a failure here will redden the tag run after the artifacts have already shipped (we hit this on v0.8.5.4).
- [ ] Full test suite passes locally (`pytest -q`)
- [ ] Hypothesis fuzz tests pass (`pytest tests/test_*fuzz*.py`)
- [ ] Concurrency tests pass (`pytest tests/test_*concurrency*.py`)
- [ ] Integration tests pass (`pytest tests/integration` — requires test framework deps)
- [ ] Live mesh validation pass on a real ≥3-node mesh with `llm_bridge.py` / Ollama (not synthetic localhost daemons)
- [ ] CI on `main` is green (latest commit, all jobs)

## 6. Release smoke gate (mandatory)

- [ ] **Run `scripts/release-smoke.sh`** — catches wheel packaging bugs (missing subpackages) that unit tests miss. **No `twine upload` until this passes.**

## 7. Build artifacts

- [ ] `python -m build` produces both wheel and sdist with no warnings
- [ ] Wheel size sanity check (compare to previous release; surprise jumps deserve investigation)
- [ ] SBOM regenerated (if part of release artifacts)
- [ ] SHA256SUMS file generated for release artifacts

## 8. Public-facing scrub

Per the public-facing-content standard: every comment, doc, test name, changelog entry, release note, and commit message must read as public documentation. **Grep before push:**

- [ ] No plan milestone codes (`M0`, `M1`, etc.)
- [ ] No audit severity codes (`C1`, `H1`, `M1`)
- [ ] No audit hardening codes (`Audit H-##`)
- [ ] No `RAZOR #N` references
- [ ] No `Path A/B` references
- [ ] No `RCA` (use "post-mortem" or "root cause analysis" spelled out)
- [ ] No personal absolute paths (Windows `C:\Users\...` or POSIX `/home/...`)
- [ ] No private-range IPs (`10.x.x.x`, `192.168.x.x`, `172.16-31.x.x`) outside of intentional documentation examples
- [ ] No "dev laptop", "overnight", first-person ("we/our/I/my") in shipped text
- [ ] No test names starting with audit codes

**Sweep command:** `rg -i "(\\bM[0-9]\\b|\\bC[0-9]\\b|\\bH[0-9]\\b|RAZOR|Path [AB]|\\bRCA\\b|\\b192\\.168\\.|/home/|C:\\\\Users)" --glob '!*.bak' --glob '!.git/' --glob '!.github/RELEASE_CHECKLIST.md'`

## 9. Release artifacts

Only run these after every box above is checked.

- [ ] `git tag -s vX.Y.Z -m "release vX.Y.Z"` (signed tag)
- [ ] `git push origin main` (this push is allowed because release is in flight; otherwise pushes need explicit user instruction)
- [ ] `git push origin vX.Y.Z`
- [ ] `twine upload dist/*` (PyPI)
- [ ] `docker push wiztheagent/ironmesh:X.Y.Z` and `:latest`
- [ ] `gh release create vX.Y.Z --title "vX.Y.Z" --notes-file docs/RELEASE_NOTES_vX.Y.Z.md dist/*.whl dist/*.tar.gz SHA256SUMS SBOM*`

## 10. Post-release

- [ ] Verify PyPI listing shows new version + correct metadata
- [ ] Verify Docker Hub shows new tag + `latest` updated
- [ ] Verify GitHub release page renders correctly
- [ ] Manually `pip install ironmesh==X.Y.Z` in a fresh venv and run `ironmesh --version` + `ironmesh demo`
- [ ] Manually `docker pull wiztheagent/ironmesh:X.Y.Z` and run a smoke command
- [ ] Site deployed (manual drag-and-drop to Netlify)
- [ ] Update memory notes (`ironmesh-vX.Y.Z-ship-notes.md`) with: shipped status, digests, any deferrals, marketing-push state

---

## CI enforcement (planned)

The doc-sync section above should be enforceable by CI. A `release-readiness.sh` script that fails the build if it finds the previous version string in current-version positions in any shipped doc would catch this class of bug automatically. Tracked under master plan item 1.1 deliverables.
