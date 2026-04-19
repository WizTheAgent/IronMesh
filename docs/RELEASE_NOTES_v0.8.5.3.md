# IronMesh v0.8.5.3 — Release Notes

## Headline

Patch release on top of v0.8.5.2. Quickstart hardening and onboarding
polish: explicit insecure-flag warnings on startup, a dated deprecation
notice for the pending-trust message gate, two new examples, and a
release checklist that prevents the doc-sync drift that motivated this
release.

No protocol or schema changes. Every v0.8.x peer stays interoperable.
Default behavior is unchanged for existing deployments — the new
warnings only fire when the relevant flags or env vars are set (or
absent in the deprecation case).

## Highlights

### Quickstart hardening

The two opt-in shortcut flags that make a same-machine demo possible
without TLS certs (`--open-discovery` and `--allow-plaintext-ws`) used
to live in the headline 60-second-demo block of the README. A stranger
evaluating IronMesh in 10 minutes could easily copy that command into a
real deployment without realizing it disables default-deny peer
filtering and the wss-first connection attempt.

This release fixes that on three levels:

1. **Runtime.** Setting either flag now logs an explicit `INSECURE`
   warning naming the flag, the security implication, and the
   recommended replacement. A real deployment that accidentally
   inherits the flag will produce a noticeable warning every startup.
2. **Documentation.** The `60-second demo` section now leads with
   pointers to the secure deployment path (`Running two physical
   machines`, which uses `--allowed-peers` and TLS) and to a clearly
   labeled `Advanced / Testing — same-machine localhost demo`
   subsection. The insecure-flag walkthrough still exists in full — it
   just no longer appears in the headline quickstart.
3. **Process.** A new `.github/RELEASE_CHECKLIST.md` documents the
   pre-push doc-sync sweep so this class of drift is caught before
   tag-and-push, not after.

### Pending-trust deprecation notice

The pending-trust message gate (introduced in v0.8.5) is opt-in in the
v0.8.x series. Per the master roadmap, it will become the default in
v0.9. Starting in this release, the daemon emits a `DEPRECATION`
warning on startup whenever the gate is opt-in disabled. The warning
cites:

- The dated commitment (default-on in v0.9)
- How to opt in now (`IRONMESH_REQUIRE_MSG_PROMOTION=true` or
  `--require-message-promotion`)
- The planned escape hatch for legacy behavior in v0.9 and later
  (`--no-message-promotion`, not yet implemented)
- Where the migration doc will live
  (`docs/migration/v0_9_default_deny.md`, written ahead of the v0.9
  ship)

This is a deprecation **notice**, not a behavior change — the gate's
default state is still off in v0.8.x.

### Two new examples

- **`examples/conv_multiturn.py`** — a self-contained `ConvEnvelope`
  walkthrough. Two terminals, two roles (`pinger` / `ponger`), no LLM
  dependency. The reference for: open a conversation, exchange bounded
  turns, recognize end-of-conversation, no orphaned state.
- **`examples/persona_debate.py`** — a persona-vs-persona debate
  orchestrator. Discovers two peers advertising different
  `role:<persona>` capabilities (using the seven bundled persona
  presets in `ironmesh.roles`), seeds a debate motion, relays bounded
  turns. Pair `assistant` vs `devil` for classic debate,
  `security-analyst` vs `ops` for a real-world tradeoff discussion,
  `historian` vs `coder` for perspective contrast.

### Release checklist

`.github/RELEASE_CHECKLIST.md` is the new pre-push checklist. Ten
sections covering code state, version-file sync, doc-sync (the explicit
fix for this release's motivating drift), site updates, tests, the
release-smoke gate, build artifacts, public-facing scrub, the actual
push commands, and post-release verification. Section 3 enumerates
every shipped doc and the exact sweep command for catching stale
current-version claims.

## Upgrade guidance

`pip install --upgrade ironmesh` or `docker pull
wiztheagent/ironmesh:0.8.5.3`. No config changes required. No protocol
changes — your existing peers stay on the mesh.

If you see the new `DEPRECATION` warning on startup and want to silence
it, opt in to the pending-trust gate now:

```bash
export IRONMESH_REQUIRE_MSG_PROMOTION=true
# or pass --require-message-promotion to ironmesh run
```

You will need to opt in eventually — the gate becomes the default in
v0.9.

If you see one of the new `INSECURE` warnings on startup, you almost
certainly want to remove the flag from your deployment config and
either generate a TLS cert (`--allow-plaintext-ws`) or pin your peer
allowlist (`--open-discovery`). Both flags exist for localhost testing
only.

## Verifying the release

| Check | Command |
|---|---|
| PyPI | `pip install ironmesh==0.8.5.3` then `ironmesh --version` |
| Docker | `docker pull wiztheagent/ironmesh:0.8.5.3` then `docker run --rm wiztheagent/ironmesh:0.8.5.3 ironmesh --version` |
| Smoke test | `ironmesh demo` |

## Diff stats

```
README.md                         |  ~70 lines updated
CHANGELOG.md                      |  v0.8.5.3 entry
cli.py                            |  +30 lines (3 startup warnings)
examples/README.md                |  +39 lines (2 new entries)
examples/conv_multiturn.py        |  NEW (~170 lines)
examples/persona_debate.py        |  NEW (~210 lines)
.github/RELEASE_CHECKLIST.md      |  NEW (~115 lines)
docs/RELEASE_NOTES_v0.8.5.3.md    |  NEW (this file)
__init__.py                       |  version bump
pyproject.toml                    |  version bump
```

No production code paths changed. All new code is either documentation,
new example scripts, or additive runtime warnings that only fire when
the corresponding flag/env-var state warrants them.
