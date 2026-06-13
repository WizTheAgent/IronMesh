# Releasing IronMesh

A release is **one tag push.** Pushing a `v*` tag triggers
[`.github/workflows/release.yml`](.github/workflows/release.yml), which runs the
gate, builds the artifacts, and publishes every surface together — PyPI (via
Trusted Publishing, no stored token), Docker Hub, and the GitHub Release — so
they cannot drift apart.

## TL;DR

```bash
scripts/bump-version.sh 0.9.5            # rewrite version strings in one shot
# then: add the CHANGELOG entry + docs/RELEASE_NOTES_v0.9.5.md + the README banner text
bash scripts/release-qc.sh               # must end "FAIL: 0" (includes the doc-sync gate)
# open a PR, let CI go green, merge
git tag -a v0.9.5 -m "IronMesh 0.9.5 — <headline>"
git push origin v0.9.5                   # release.yml does the rest
```

## Step by step

1. **Bump the version.** `scripts/bump-version.sh X.Y.Z` rewrites the version
   strings in `pyproject.toml`, `__init__.py`, `README.md` (banner, `Latest:`,
   Docker tags) and `CITATION.cff`. You type the version once.
2. **Write the parts the script can't:**
   - a `## [X.Y.Z] — <date> — <headline>` section in `CHANGELOG.md`
     (Keep-a-Changelog format — the gate validates the heading chain),
   - `docs/RELEASE_NOTES_vX.Y.Z.md`,
   - the README banner's feature sentence (the script sets the version, not the prose).
3. **Run the gate locally:** `bash scripts/release-qc.sh`. It must end `FAIL: 0`.
   The doc-sync check ([`scripts/doc-sync-check.sh`](scripts/doc-sync-check.sh))
   verifies the version strings agree, the CHANGELOG heading chain is intact, and
   no retired claim has reappeared.
4. **Open a PR.** `main` is protected — CI (tests + `release qc`) must pass before
   merge. This is the gate that stops stale strings or a broken CHANGELOG from
   landing.
5. **Tag and push:**
   ```bash
   git tag -a vX.Y.Z -m "IronMesh X.Y.Z — <headline>"
   git push origin vX.Y.Z
   ```
   `release.yml` then runs the gate again → builds wheel + sdist → publishes to
   PyPI → builds and pushes the Docker image (`:X.Y.Z` and `:latest`) → cuts the
   GitHub Release with the notes and artifacts. If the `pypi` environment has a
   required reviewer, the publish waits for a one-click approval.

## Dry-run

Validate the pipeline without publishing before you tag:
**Actions → release → Run workflow.** A `workflow_dispatch` run executes the gate
and build only — the PyPI, Docker, and GitHub-Release jobs are skipped.

## What keeps the surfaces honest

- **`scripts/doc-sync-check.sh`** (runs in CI on every push and tag) blocks a
  release whose README / `CITATION.cff` / Docker / `Latest:` version strings
  disagree, whose CHANGELOG heading chain is broken, or that resurrects a retired
  claim. **When you correct a false public claim, add its phrasing to that
  script's denylist so it can't come back.**
- **`release-surface-check.yml`** (nightly) compares PyPI, the latest GitHub
  Release, Docker Hub, and ironmesh.org, and opens a "Release surface drift" issue
  on any mismatch.

## Prerequisites (configure once)

- **PyPI Trusted Publishing** for this repo with workflow `release.yml` and
  environment `pypi` — so publishing needs no stored API token.
- Repo secrets **`DOCKERHUB_USERNAME`** and **`DOCKERHUB_TOKEN`** for the image push.
- **Branch protection** on `main` (PR + required checks).

The website (ironmesh.org) is deployed separately; the nightly surface-check flags
it if it falls behind a release.
