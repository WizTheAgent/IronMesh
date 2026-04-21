# IronMesh v0.8.5.6 — Release Notes

## Headline

Trust-binding patch on top of v0.8.5.5. Closes two security gaps
surfaced during external review:

1. **Authenticated-but-over-privileged-after-reconnect.** A peer
   promoted to `trusted` while advertising one capability set used
   to be able to reconnect with a different set and reach the
   trusted code paths with the new privileges. v0.8.5.6 binds the
   capability set to the trust state — changes auto-demote the peer
   to a new `pending-cap-change` state until an operator reviews.
2. **Silent cross-transport replay drops.** A duplicate frame
   arriving via a different transport than the original (e.g.
   WebSocket then Reticulum / LoRa) was deduped silently. v0.8.5.6
   emits a `MSG_REPLAY_CROSS_TRANSPORT` audit event before the drop
   so operators can detect active replay attempts spanning paths.

Plus a release-hardening pass that found and fixed nineteen bugs
— including two critical pre-existing defects (trust store wipe
under MAC mismatch, key-file destruction window during key
generation / rotation) and a high-severity silent-state-corruption
bug under concurrent operator actions on Windows. The full list
(with technical detail for each fix) is in the `### Fixed` section
of `CHANGELOG.md`.

No protocol or schema changes. Every v0.8.x peer stays
interoperable. Existing `known_peers.json` files auto-migrate on
first load.

## Highlights

### Capability-set binding

The trust store gains a `capability_hash` field per pinned peer:
SHA-256 over a canonical serialization of the peer's advertised
capability set. Canonical form is **sorted, deduplicated,
whitespace-normalized, case-sensitive**, and proven stable by
Hypothesis fuzz tests across arbitrary capability-token sequences.

When a peer reconnects:

| Observed | Stored | Action |
|---|---|---|
| baseline (no stored hash) | — | Record observed as baseline. Audit: `PEER_CAP_BASELINE`. Trust state unchanged. |
| matches stored | matches | Normal flow. No action. |
| differs from stored | differs | Demote peer to `pending-cap-change`. Stash observed set as `capability_hash_pending`. Audit: `PEER_CAP_SET_CHANGED` with the added/removed cap diff. Inbound messages queue at the daemon. |

Operator re-promotes via the new surface (CLI / MCP). On accept, the
pending hash becomes the new baseline; trust state goes back to
`trusted`; queued messages drain. Audit: `PEER_CAP_ACCEPTED`.

### Cross-transport replay detection

`DedupCache` now optionally tracks the originating transport per
`(source, msg_id)` pair. When `check_and_add_with_transport(...,
transport="ws")` discovers a duplicate that was originally seen on
`"rns"`, it returns a result dict with `cross_transport=True`. The
mesh router then emits the new `MSG_REPLAY_CROSS_TRANSPORT` audit
event before the drop, with both transport names and the time delta.

The legacy `check_and_add(source, msg_id)` API is unchanged — all
existing callers remain backwards-compatible. Cross-transport
detection only activates when callers explicitly pass `transport`.

Bridge `_handle_message` / `_handle_binary_frame` /
`_handle_json_message` / `_dispatch_message` now thread a
`transport` string through the dispatch chain so the inbound
WebSocket and Reticulum paths each tag their frames correctly.

### Operator surface

**CLI (4 new subcommands):**

```bash
# List peers in pending-cap-change with the cap diff
ironmesh trust list-cap-pending

# Show baseline vs pending capability sets for a single peer
ironmesh trust cap-diff <node_id>

# Re-promote one peer
ironmesh trust cap-promote <node_id>

# Re-promote everyone in pending-cap-change at once
ironmesh trust cap-promote --all
```

**MCP (2 new tools, total grows from 21 to 23):**

- `ironmesh_pending_cap_changes` — for an LLM operator agent to
  review changes before re-promoting
- `ironmesh_cap_promote_peer` — accept and re-promote through the
  running daemon (queued messages drain immediately)

**Programmatic:** `BridgeDaemon.accept_pending_cap_change(node_id)`
for in-process operator code.

### Audit-log additions

Four new HMAC-chained event types in the existing audit log:

- `PEER_CAP_BASELINE` — first observation of a peer's capability
  set; the recorded baseline going forward
- `PEER_CAP_SET_CHANGED` — observed hash differs; peer demoted to
  `pending-cap-change`. Includes added/removed cap diff.
- `PEER_CAP_ACCEPTED` — operator accepted the pending change;
  baseline updated; trust state back to `trusted`
- `MSG_REPLAY_CROSS_TRANSPORT` — duplicate frame caught arriving
  via a different transport than the original. Includes both
  transport names and time delta in milliseconds.

Tail with `jq` for live monitoring:

```bash
tail -F ~/.ironmesh/audit.log \
  | jq 'select(.event | startswith("PEER_CAP_") or .event == "MSG_REPLAY_CROSS_TRANSPORT")'
```

### Design docs

Two new docs land alongside the code:

- **`docs/TRUST_BINDING.md`** — threat model, what v0.8.5.6
  covers, operator surface walkthrough, what's deliberately still
  open.
- **`docs/TRUST_BINDING_WIRE_v0.9.md`** — full design for the
  three wire-protocol extensions queued for v0.9: deterministic
  session ID derived from the handshake transcript, rolling
  transcript hash piggybacked in PING frames with Ed25519
  signatures, and reconnect continuity challenge. Backwards-compat
  strategy (opt-in v0.9, default-on v0.9.1, required v1.0) and
  HELLO extension negotiation syntax documented.

## Release hardening

Before tagging, the release went through a multi-stage audit: a
static review of every change, protocol fuzz of the binary frame
deserializer (5000 random / corrupted inputs), concurrent-operator
stress (2000 threads × 20 peers), SIGKILL chaos across the live
mesh, and an extended idle soak. Nineteen bugs surfaced and were
fixed before tagging.

Severity breakdown: 2 critical, 3 high, 13 medium, 1 low. Most
were pre-existing IronMesh defects that the hardening pass
uncovered; a few were wiring oversights in the new cap-binding
code that shipped fixed in the same release.

Headline fixes:

- **Trust store silently wiped on MAC mismatch** (critical).
  `TrustStore._load()` previously emptied `_peers` when the on-disk
  MAC didn't verify; any subsequent save then overwrote a real file
  with an empty one — wiping every pinned peer. `TrustStore` now
  latches read-only on MAC failure and refuses to save.
- **Key-file destruction window during key generation / rotation**
  (critical). `save_keys()` used non-atomic `open(path, "w")` +
  `json.dump`; a SIGKILL mid-write could leave `keys.json` truncated
  and the daemon's identity unrecoverable. Now fully atomic (tmp +
  `fsync` + rename).
- **Capability-binding was wired in but broken at runtime** (high).
  A stale attribute reference raised `AttributeError` on every
  `CAPABILITY_ANNOUNCE` from a pinned peer, silently disabling the
  entire feature. Fixed by constructing the trust store via a
  helper that matches the pattern used elsewhere in the daemon.
- **Audit-log HMAC chain corruption across processes** (high).
  Multiple processes sharing one audit log could each chain off a
  stale tail and break the chain. A cross-platform sentinel-file
  exclusive lock now wraps every write, plus a chain-tail re-read
  under the lock.
- **Silent state corruption under concurrent operator actions on
  Windows** (high). `TrustStore._save()` had no inter-process lock;
  concurrent callers collided on a shared `<path>.tmp` filename
  (WinError 32) while the mutating methods returned True regardless
  of whether the save reached disk. Fixed with thread + flock
  locks, per-pid + per-thread tmp filenames, and success-bit
  propagation so callers can roll back and report failure honestly.

See the full `### Fixed` section in `CHANGELOG.md` for the complete
list of nineteen fixes plus the two audit-coverage follow-ups.

## Scope note: two wire-protocol extensions land in v0.9

Two further hardening ideas — rolling transcript hash and reconnect
continuity challenge — are designed but deliberately NOT in
v0.8.5.6. Both are wire-protocol changes that require new HELLO
feature-negotiation, new audit event types, and a documented
interop story for older peers. v0.8.5.6 is a patch release with a
"no protocol or schema changes" commitment — a commitment that
lets every v0.8.x peer keep talking to every other v0.8.x peer.
Shipping the wire extensions here would break that contract.

They land in v0.9 with: HELLO feature negotiation, updated
`PROTOCOL_SPEC.md`, fuzz coverage of the negotiation path, and an
opt-in / default-on / required phase-in over v0.9 → v0.9.1 → v1.0
so no peer gets stranded.

The full design (frame format, state machine, migration strategy)
is in `docs/TRUST_BINDING_WIRE_v0.9.md`:

1. **Rolling transcript hash** — both peers maintain a per-session
   rolling hash of frame MACs; periodically signed and exchanged in
   PINGs. Mismatch emits `TRANSCRIPT_HASH_MISMATCH` and optionally
   closes the session. Catches selective-drop and frame-injection
   MITM attacks that a plain-auth-per-frame design misses.
2. **Reconnect continuity challenge** — peer presents
   `last_session_id` + `last_transcript_tip` on reconnect HELLO; the
   server verifies both against its own state. Mismatch demotes the
   peer regardless of prior trust state. Catches identity-key theft
   where the attacker has the key but not the live session state.

## Migration

`known_peers.json` files from v0.8.5.5 and earlier load cleanly.
Entries without a `capability_hash` field treat the next
successful handshake as the baseline observation. No operator
action is required to upgrade.

If you want to pre-flight the new binding before a peer
reconnects, you can also delete the trust file and re-pin from
scratch — but that's a TOFU re-pin in the existing sense and
should only be done deliberately.

## Upgrade guidance

```bash
pip install --upgrade ironmesh
# or
docker pull wiztheagent/ironmesh:0.8.5.6
```

No config changes required. No protocol changes — your existing
peers stay on the mesh. The first reconnect of each pinned peer
records the capability baseline; subsequent reconnects with a
different set trigger the new gate.

## Verifying the release

| Check | Command |
|---|---|
| PyPI | `pip install ironmesh==0.8.5.6 && ironmesh --version` |
| Docker | `docker pull wiztheagent/ironmesh:0.8.5.6` |
| Smoke test | `ironmesh demo` |
| New CLI | `ironmesh trust list-cap-pending --help` |
| MCP tool count | should report 23 (was 21 in v0.8.5.5) |

## Diff stats

```
.github/RELEASE_CHECKLIST.md                  unchanged
CHANGELOG.md                                  v0.8.5.6 entry
CITATION.cff                                  version bump
README.md                                     banner, docker pull, "Latest:",
                                              new "(current)" para, test count
__init__.py                                   version bump
audit.py                                      +4 event type constants
bridge.py                                     +_handle_cap_observation,
                                              +accept_pending_cap_change,
                                              +transport plumbing through
                                              dispatch chain
cli.py                                        +cmd_trust cap-promote /
                                              list-cap-pending / cap-diff;
                                              set-state accepts pending-cap-change
docs/RELEASE_NOTES_v0.8.5.6.md                NEW (this file)
docs/TRUST_BINDING.md                         NEW (~280 lines)
docs/TRUST_BINDING_WIRE_v0.9.md               NEW (~330 lines)
ironmesh_mcp/server.py                        +tool_pending_cap_changes,
                                              +tool_cap_promote_peer,
                                              +2 TOOL_SPECS entries
mesh.py                                       +check_and_add_with_transport,
                                              +cross-transport audit emit in
                                              relay_message; cleanup_expired
                                              handles both bucket shapes
pyproject.toml                                version bump
tests/test_mcp.py                             tool count 21→23,
                                              +test_cap_binding_tools_registered
tests/test_trust_binding.py                   NEW (23 tests, 2 Hypothesis fuzz)
trust.py                                      +canonical_capability_hash,
                                              +observe_capabilities,
                                              +accept_capability_change,
                                              +stash_pending_capability_change,
                                              +list_by_capability_status;
                                              pin_peer / set_trust_state accept
                                              pending-cap-change
```
