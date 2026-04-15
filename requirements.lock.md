# Dependency Lock Generation (Audit L-14)

IronMesh does not commit a frozen `requirements.lock` in the repository
because the dev environments it is installed into vary widely
(Termux, Docker, Raspberry Pi, Windows Python). Instead, the following
procedure produces a reproducible lock for any given deployment.

## Recommended: pip-tools

```bash
pip install pip-tools
pip-compile --resolver=backtracking pyproject.toml -o requirements.lock
```

Commit `requirements.lock` on a per-deployment branch, not on main.

## Quick pin (plain pip)

```bash
pip freeze > requirements.lock
```

The output includes everything in the current virtualenv — review it
before committing and prune unrelated packages.

## Pinned versions (tested combinations as of v0.7.1)

These are the versions the maintainer tests against. CI uses the same:

```
# Core
websockets>=12.0,<17       # tested: 13.x, 15.x, 16.x
pynacl>=1.5.0              # tested: 1.5.0
zeroconf>=0.80.0,<1        # tested: 0.131.x
aiosqlite>=0.19.0          # tested: 0.19–0.22

# Optional (Reticulum transport)
rns>=0.9.0                 # tested: 1.1.4

# Dev (per pyproject.toml)
pytest>=7.0
pytest-asyncio>=0.21.0
pytest-cov>=4.0
ruff>=0.1.0
mypy>=1.0
bandit>=1.7
pip-audit>=2.6
hypothesis>=6.0
```
