# Provenance — `v0_9_4_2/` existing-state fixture

**What this is:** regenerated compatibility evidence. It is on-disk state
written by the published `ironmesh==0.9.4.2` wheel, used to test that current
code reads, migrates and verifies a real 0.9.4.2 node's files.

**What it is not:** the fixture from August 2026. That version was generated
for the 0.9.5 release but its key, database and audit-log files matched the
repository's ignore rules and were never committed; the originals were not
preserved. This regeneration follows the same recorded procedure, but the
identity, peer keys and ciphertext are new (random) material, so it does not
reproduce the August bytes.

## Regeneration record

| Item | Value |
|---|---|
| Date | 2026-10-12 |
| Generator | `tests/fixtures/existing_state/generate_v0942_fixture.py`, unchanged since commit `b750a68c40e6b6f2098d4fedb9263f7775863107` (2026-08-06); sha256 `ed30149660618dd8c245217d9ab9e1c6134e4e316ed1135b299d051b6b893039` |
| Source wheel | `ironmesh-0.9.4.2-py3-none-any.whl`, sha256 `7bb21c614e2b313a2f5543cb7a25941623434fa6ea3f8f453d8c1a3bcadc9848` (matches the digest published on PyPI) |
| Environment | isolated venv, CPython 3.11.9 on Windows: `ironmesh==0.9.4.2`, `aiosqlite==0.22.1`, `cffi==2.1.1`, `ifaddr==0.2.0`, `pycparser==3.11`, `PyNaCl==1.6.2`, `websockets==15.0.1`, `zeroconf==0.151.5` |
| Command | `python generate_v0942_fixture.py --out tests/fixtures/existing_state/v0_9_4_2`, run from outside the repository so the 0.9.4.2 wheel, not the working tree, was imported |

## Generated files

| sha256 | bytes | file |
|---|---|---|
| `f967163acd7f6cbcd67efe579dea26c1e998bcd0a06e2edec8e94ec0d4dbb0fb` | 775 | `audit.log` |
| `cb4226c06e342e2abbd2e0ce63383c4336aef61556b39b6031239ca23d55ff1f` | 69632 | `data.db` |
| `e3cc30c2644e8bc6cc7cab8c6eed96129a440b7e340d81e30841ff9a1527993a` | 701 | `keys.json` |
| `8f3e05ab5a3503f0df020f769dcf1b6e2f3809ccb8dc31503486fbbc467346bd` | 816 | `known_peers.json` |
| `66bb069853cf96d98599e9ff833c5039804958902b49177fa7c9057bb6aacb4c` | 1676 | `manifest.json` |

The `.lock` files the generator also writes are not committed.

## Where the fixture is, and is not, available

- **Repository checkout:** all five files are committed; the 19 tests in
  `tests/test_existing_state_v0942.py` run there.
- **CI and the release gate** set `IRONMESH_REQUIRE_GOLDEN_FIXTURE=1`, which
  turns any missing file into a collection error instead of a skip.
- **sdist:** ships `manifest.json` and `known_peers.json` only. `keys.json` is
  excluded by `MANIFEST.in` and `data.db` / `audit.log` are not packaged, so the
  tests skip there. Running them requires a repository checkout.
- **Wheel and Docker image:** contain no tests at all.

The key file holds a throwaway identity encrypted under a test passphrase that
is published in `manifest.json`; it protects nothing and is kept out of
distributable artifacts anyway.
