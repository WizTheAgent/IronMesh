# Operator runbook

Playbook for the scenarios IronMesh operators actually hit in
production. Each entry is a one-page diagnose-decide-act. Keep a copy
close to the dashboard.

---

## 1. A peer just showed up in PENDING CAP CHANGE

**Symptom:** the dashboard's PENDING CAP CHANGE panel shows a count > 0,
or the feed shows a `CAPCHG` event, or `ironmesh audit tail --event
PEER_CAP_SET_CHANGED --since 1h` prints at least one entry.

**Meaning:** a peer you had already pinned reconnected advertising a
capability set whose canonical hash differs from the one you last
accepted. IronMesh auto-demoted the peer to `pending-cap-change`;
inbound messages are queueing at the daemon until you review.

**Triage (≤ 30 seconds):**

1. Open the panel or run `ironmesh trust cap-diff <node_id>`.
2. Read the `+ added` and `- removed` tokens. Ignore the hashes — they
   reflect the diff and are only there for audit.
3. Decide: is the change legitimate?
   - **Yes** (you just added `--role coder` to the peer's launch
     command, or upgraded its LLM, or added a new tool): click ACCEPT
     in the dashboard, or `ironmesh trust cap-promote <node_id>`.
   - **No** or "not sure": `ironmesh trust cap-reject <node_id>`. The
     peer's old capability set stays pinned; the pending change is
     cleared; the peer returns to `trusted`. If you want to also stop
     accepting messages from that peer entirely, add `--block`.

**Audit trail:** whichever action you take fires a dedicated event
(`PEER_CAP_ACCEPTED`, `PEER_STATE_CHANGED`, or `PEER_BLOCKED`) with an
`actor: "cli"` marker. `ironmesh audit verify` will still be green.

---

## 2. A peer keeps demoting itself every few minutes

**Symptom:** you accept a cap change, the peer is `trusted`, and then
30 seconds to a few minutes later it's back in `pending-cap-change`
with the SAME diff.

**Likely cause:** on the peer side, there's a cap registry that's
persisting an old set alongside the new one. When the peer's daemon
announces, it sends the union. IronMesh's canonical hash catches this
as a change every reconnect.

**Fix on the peer:**

```bash
# On the peer itself
ironmesh keys info                     # confirm you're on the right node
rm ~/.ironmesh/capabilities.json       # clear the persisted local caps
# restart the peer's daemon; it re-announces with ONLY the configured caps
```

**On your side:** a single `cap-promote` after the peer's restart
should stick.

**Prevention:** v0.8.5.6+ uses `set_local()` which replaces rather than
unions. Any peer still exhibiting this is on v0.8.5.5 or older — upgrade
it.

---

## 3. Dashboard shows `PEER_CAP_BINDING_PARTIAL`

**Symptom:** the audit log contains `PEER_CAP_BINDING_PARTIAL` events
and the Prometheus counter
`ironmesh_peer_cap_binding_partial_total > 0`.

**Meaning:** the daemon observed a cap change but either the stash or
the trust-state demote didn't reach disk (disk full, permissions issue,
or — most commonly — the read-only latch tripped because another
process wrote the trust file with a different identity key).

**Triage:**

1. `ironmesh trust cap-status <node_id>` — does it show a pending hash?
   If yes, the stash DID succeed and demote failed; the peer is still
   `trusted` from the gate's perspective.
2. Check the daemon log for `Trust store integrity check FAILED`. If
   present, there's a colliding writer — stop other daemons / CLI
   processes sharing the same trust path, or give them each their own
   `--trust-path`.
3. Check disk: `df -h ~/.ironmesh` / `ironmesh doctor`.

**Recovery:** after resolving the underlying issue, restart the
daemon. The cap-binding logic is idempotent — the next CAPABILITY_ANNOUNCE
will re-evaluate and either fire a clean `PEER_CAP_SET_CHANGED` (which
you can then promote or reject) or return "match" if the peer has
settled on the baseline.

---

## 4. `ironmesh audit verify` reports TAMPER

**Symptom:**

```
$ ironmesh audit verify
TAMPER DETECTED at entry 286 (checked 286)
```

Or in the daemon startup log:

```
WARNING  Audit chain TAMPER detected at entry 286 (of 917 scanned).
         Prior entries remain valid; new writes from this start forward
         will chain cleanly.
```

The daemon now runs `audit.verify()` automatically on startup so
corruption surfaces immediately instead of accumulating silently until
someone runs a manual check.

**First question:** did you run multiple daemons or CLI invocations on
the same host without `--trust-path` / `--audit-path` overrides? The
v0.8.5.6 fix added cross-process locking, but a pre-v0.8.5.6 daemon or
a third-party process with a different HMAC key can still have
corrupted the chain before you upgraded.

**Triage:**

1. `ironmesh audit tail --since 24h --limit 500` — what's around the
   tamper line? The entry at the failure point is the FIRST line that
   doesn't chain cleanly off its predecessor; everything before it is
   intact.
2. `ps -ef | grep -E 'ironmesh|audit.log'` — is another process
   actively writing?

**Recovery options (pick one):**

- **Preserve history for forensics:**
  ```bash
  mv ~/.ironmesh/audit.log ~/.ironmesh/audit.log.tamper-$(date +%s)
  # daemon starts a fresh chain on next write
  ```
  The renamed file stays on disk; you can still read entries before
  the tamper point.
- **Live with it:** the new writes from this point forward will chain
  cleanly. Historical `verify` will keep flagging the tamper line —
  that's correct, it's the truth.

---

## 5. Pending-trust queue is filling up

**Symptom:** dashboard shows a growing count in PENDING TRUST, or
`ironmesh_pending_trust_evicted_total` is climbing.

**Meaning:** new peers are connecting, the message-promotion gate is
enabled, and MSGs from un-promoted peers are queueing. At the cap
(default 100 per peer), the oldest MSG is evicted FIFO.

**Triage:**

1. `ironmesh trust list --show-caps` — confirm the peers are in
   `pending` state, not `blocked`.
2. Decide: promote the peer (`ironmesh trust set-state <node_id>
   trusted`) or reject it (`ironmesh trust revoke <node_id>`).
3. If the queue is legitimately hot and you expect many more MSGs
   before you can review, raise the cap temporarily:
   `--pending-trust-queue-cap 500`. It's per-peer; don't set it to
   millions.

---

## 6. Cross-transport replay event fired

**Symptom:**

```
$ ironmesh audit stats --since 1h
...
      2  MSG_REPLAY_CROSS_TRANSPORT
```

**Meaning:** a frame with the SAME `(source, msg_id)` tuple arrived on
two different transports (e.g. WebSocket and Reticulum / LoRa).
IronMesh's dedup dropped the second one. If the two transports were
BOTH legitimate paths (e.g. a peer reachable via LAN and via LoRa that
had a transient WS failure), this is normal — the mesh is being
resilient. If not, an attacker may be replaying captured traffic
across a different network.

**Triage:**

1. `ironmesh audit tail --event MSG_REPLAY_CROSS_TRANSPORT --since
   6h --json` — get the full event details including
   `original_transport`, `replay_transport`, and
   `time_delta_ms`.
2. If `time_delta_ms` is under a few seconds, it's almost certainly
   a legitimate cross-path delivery. If it's hours or days, that's
   suspicious — investigate the peer.
3. `ironmesh trust cap-status <peer>` to confirm the peer's cap
   hash hasn't drifted too.

---

## 7. `Trust store integrity check FAILED` in the daemon log

**Symptom:**

```
CRITICAL  Trust store integrity check FAILED (peers_in_file=3).
          Refusing to load peers.
ERROR     Refusing to _save(): TrustStore is in MAC-failure read-only mode.
          Mutations will NOT persist.
```

**Meaning:** a second process opened your trust file with a
different HMAC key. The trust store has entered a read-only latch
(v0.8.5.6 fix) to protect the on-disk file from being overwritten
with an empty in-memory copy.

**Most common cause:** integration tests or a second development
daemon running against the default `~/.ironmesh/known_peers.json`
instead of a per-process `--trust-path`.

**Triage:**

1. `ps -ef | grep ironmesh` — what processes are touching the trust
   file right now?
2. Look at each daemon's `~/.ironmesh/keys.json` fingerprint: if two
   daemons have different fingerprints but the same trust path, that's
   your collision.

**Recovery:**

1. Stop the rogue process (the one with the *different* fingerprint
   from the one you want to keep).
2. Restart the surviving daemon. The latch resets on process start;
   the real trust file is still intact on disk.
3. Future: give each daemon its own `--trust-path`, or isolate tests
   by setting `IRONMESH_TRUST_PATH` to a per-test directory (the
   autouse fixture in `tests/conftest.py` does this already for the
   project's own tests).

**Prevention:** the v0.8.5.6 read-only latch is the defense. Never
point two daemons with different identity keys at the same trust
file.

---

## 8. Daemon won't start after key rotation

**Symptom:** `ironmesh run` fails with "identity key decryption
failed" or similar.

**Meaning:** either the passphrase is wrong, or `keys.json` was
written mid-rotation and truncated. The v0.8.5.6 atomic-save fix
closed the truncation window for all NEW rotations; older rotations
can still leave a bad file.

**Recovery:**

1. Check the passphrase: `ironmesh keys info --path
   ~/.ironmesh/keys.json`.
2. If the file is corrupt: restore from the backup you made before the
   rotation (you did make one, right?). If not, you'll need to pin a
   NEW identity on every peer — treat it as a fresh TOFU event.

**Prevention:** always `cp ~/.ironmesh/keys.json ~/.ironmesh/keys.json.bak`
before `ironmesh keys rotate`.

---

## 9. v0.9.4 changes operators care about

### Signed CAPABILITY_ANNOUNCE

From v0.9.4 onward, capability advertisements about a node other than the
delivering peer require an inner Ed25519 signature from the origin (see
`PROTOCOL_SPEC.md` §4.2). Direct-from-peer announces stay unchanged for
backward compatibility.

**Watch for in the dashboard:**

- `capability_announce_bad_signature_total` metric — should sum to ~0 on
  healthy meshes. Any rise = peer attempting relay impersonation OR a
  v0.9.4 sender talking to a pre-v0.9.4 receiver (no harm, but noisy).
- `CAPABILITY_ANNOUNCE_BAD_SIG` audit event — `reason` field tells you
  which path tripped: `missing-sig` (third-party announce arrived unsigned),
  `unknown-origin` (sender claims an origin we have no key for),
  `stale` (announce older than `capability_announce_max_age`), or
  `bad-sig` (signature didn't verify against origin's pinned key).

**Tuning:** `capability_announce_max_age` defaults to 300 s — generous
clock-skew tolerance for NTP-synced fleets, replay window narrow enough
to prevent meaningful misuse of a stolen origin signature.

**TOFU bootstrap path matters for pure-LoRa or fully-disconnected
deployments.** The signed-announce check only authenticates announces against keys we
already have pinned — mesh announces themselves are NOT a
trust-establishing channel. New origin's first announce will be
dropped with `reason="unknown-origin"`. Bootstrap via one of:

- **LAN handshake** (the common case — peers complete the v0.4
  handshake on the same segment and pin each other automatically).
- **`ironmesh trust pin <node-id> <pubkey-b64>`** for out-of-band
  import (Signal, fingerprint card, secure email, paper).
- **A bridged-transport handshake** (Reticulum / LXMF / ACP / A2A
  links go through the same TOFU path as LAN).

If your deployment is pure-LoRa or otherwise fully disconnected, pin
every expected peer's key *before* bringing the mesh online —
otherwise the first batch of announces converges to nothing.

### HELLO X25519 advertisement (Phase 2 of Ed25519/X25519 dual-use split)

v0.9.4 daemons advertise their master-seed X25519 identity public in
HELLO via two optional fields: `x25519_public_b64` and
`x25519_binding_signature_b64`. Receivers that recognize the fields
verify the binding signature under the peer's pinned Ed25519 identity
and, on success, store the advertised X25519 on the peer's PeerState
for subsequent E2E SealedBox encryption.

**Mixed-mesh interop is seamless.** A v0.9.4 receiver ignores both
fields and falls through to the legacy `ed25519_to_curve25519` path —
no operator action needed. A v0.9.4 receiver talking to a v0.9.4
sender doesn't see the advertisement fields and likewise falls back.

**Auto-migration on first start.** When a v0.9.4 daemon loads a legacy
v1/v2 keystore for the first time, it writes the master-seed envelope
forward in place, preserves the Ed25519 seed byte-for-byte (every
TOFU pin in the mesh remains valid), and saves a `.legacy.bak`
alongside the original file. You'll see a one-time WARNING in the log:

```
v0.9.4 Phase 2 auto-migration: legacy keys rewritten to master-seed
envelope (~/.ironmesh/keys.json). Legacy backup at
~/.ironmesh/keys.json.legacy.bak. Ed25519 identity unchanged — every
TOFU pin remains valid.
```

If auto-migration fails (read-only filesystem, disk full, etc.) the
daemon still starts on the legacy keys without the new HELLO
advertisement — a second WARNING fires explaining the situation.
Manual remediation: run `ironmesh keys migrate` once the underlying
condition is fixed.

**Rollback path.** Same as Phase 1 — copy `.legacy.bak` over
`keys.json` to revert to a pre-v0.9.4 daemon. The advertisement is
purely additive in v0.9.4; legacy daemons load the legacy backup
unchanged.

**What to watch:** the existing `peer_blocked` / `peer_state_changed`
metrics catch identity mismatches. A peer whose advertised X25519
fails the binding check is silently ignored at the advertisement
level — the legacy fallback runs and the connection proceeds as if
the peer were v0.9.4. Look for `X25519 binding verification FAILED`
in the log — repeated entries from the same peer indicate either a
buggy implementation or an active attempt to swap the advertised
key without the corresponding Ed25519 secret.

### Master-seed key format (Phase 1 of Ed25519/X25519 dual-use split)

New daemons started fresh in v0.9.4 write `~/.ironmesh/keys.json` in
the **v3 master-seed envelope** — a JSON object tagged
`format: "master-seed-v1"` that carries the same Ed25519 seed as
before plus a 32-byte HKDF-derived X25519 subkey and a 16-byte
`hkdf_salt`. **Wire behaviour is unchanged in v0.9.4** — the X25519
subkey sits on disk but the wire path keeps using
`ed25519_to_curve25519(ed25519_secret)` until Phase 2 (v0.9.4)
switches it over. Phase 1 is a disk-format upgrade only.

**Existing deployments DO NOT auto-migrate.** Legacy v1/v2 key files
continue to load and run identically. Migration is operator-driven:

```bash
ironmesh keys migrate --path ~/.ironmesh/keys.json
# Migrated to master-seed format -> ~/.ironmesh/keys.json
# Legacy backup preserved at:      ~/.ironmesh/keys.json.legacy.bak
# Fingerprint:                     b324ff19...
# Ed25519 identity unchanged — every TOFU pin remains valid.
```

**What survives migration:**
- Ed25519 secret + public (byte-for-byte). Fingerprint unchanged.
- Every TOFU pin recorded on every peer that knows this node.
- The encrypted-at-rest passphrase + Argon2id parameters.

**What's new on disk:**
- 32-byte `x25519_seed` = HKDF-SHA256(`ed25519_secret`, `hkdf_salt`,
  `ironmesh-identity-x25519-v1\x00`).
- 16-byte `hkdf_salt` chosen freshly at migration time.
- `format: "master-seed-v1"` tag for unambiguous detection.

**Rolling back:** the `.legacy.bak` next to your `keys.json` is the
canonical rollback target for one full release cycle (i.e. through
v0.9.4). A v0.9.3 daemon cannot read v3 envelopes; if you need to
revert to v0.9.3, copy `.legacy.bak` back over `keys.json`. Do NOT
delete `.legacy.bak` until you have committed to staying on v0.9.4+.

**Integrity guarantee:** load-time verifies that the on-disk
`x25519_seed` reproduces from HKDF over `ed25519_secret + hkdf_salt`.
A tampered subkey is rejected with a clear `ValueError` even if the
operator's passphrase decrypts the envelope cleanly.

### CVE-2020-10735 mitigation enabled at boot

The daemon now calls `sys.set_int_max_str_digits(4300)` at bridge boot
to cap the cost of parsing pathologically-large integers from untrusted
JSON. On Python 3.11+ this matches the interpreter's default; on 3.10
it activates the PEP 686 backport (or logs a `WARNING` if the
interpreter predates it — upgrade to 3.10.7+ in that case).

### TOFU verification is now fail-closed

A malformed or unreadable peer identity now produces a `WARNING`-level
log line and refuses the connection. Previously the daemon would log at
`debug` and let the peer through. Operators may see a small bump in
`PEER_CONNECT` refusals from buggy peers — investigate any sustained
refusal rate above the noise floor.

## 9.x v0.9.3 changes operators care about

### Trust store now encrypted at rest

`known_peers.json` is rewritten as a SecretBox-encrypted v2 envelope on
the first save after upgrade. The on-disk file no longer contains
plaintext fingerprints, pubkeys, or capability sets. Tools that parse
the file directly need to switch to the CLI surface
(`ironmesh trust list`, `ironmesh trust cap-status`, etc.).

Force the migration immediately:

```bash
ironmesh trust migrate
ironmesh doctor   # Trust-store envelope: v2 (encrypted at rest)
```

Roll back to a v0.9.2 daemon? You need the pre-upgrade trust file from
backup — v0.9.2 cannot read v2 envelopes. See
`docs/migration/v0_9_3_trust_store_encryption.md`.

### Outbound TLS strict mode

If your operator CA / internal Let's Encrypt issues real certs to your
mesh nodes, opt into transport-layer auth:

```bash
ironmesh run ... --strict-tls --pinned-ca /etc/ssl/private-ca.pem
```

Default mesh mode (no flag) keeps `CERT_NONE` — peers authenticate at
the application layer (passphrase HMAC + Ed25519 + TOFU). Use
`--strict-tls` only when the certs are real; otherwise the daemon will
fail to connect.

### Global daemon-wide rate cap

For deployments exposed to potentially-hostile peers:

```bash
ironmesh run ... --max-msgs-per-sec 100
```

Default is off. Burst capacity = `ceil(rate)`. When the cap rejects an
inbound message, `ironmesh_global_msg_rate_limit_total` increments and
a sampled `GLOBAL_RATE_LIMIT_TRIGGERED` audit event fires (≤ one per
ten seconds).

### Out-of-band fingerprint verification

Read a peer's fingerprint to them over the phone, then:

```bash
# What to read aloud (this node):
ironmesh keys fingerprint --format colons

# After they pin you, paste their value here:
ironmesh trust verify <their-node-id> ab:cd:ef:12:34:56:78:90
```

The verifier accepts colons, spaces, and prefix matches of >= 8 hex.

## Useful commands reference

```bash
# v0.9.3 ergonomics
ironmesh trust verify <node_id> <expected-fp>   # OOB pin check
ironmesh trust migrate                          # force trust-store v2 encryption
ironmesh trust export <node_id>                 # JSON dump of one peer
ironmesh trust pin <node_id> <pubkey-b64>       # offline manual pin
ironmesh keys fingerprint --format colons       # this node's FP for OOB share

# Cap-binding
ironmesh trust list --show-caps        # which peers have pinned caps
ironmesh trust cap-status <node_id>    # one-peer deep dive
ironmesh trust cap-diff <node_id>      # just the diff, no status
ironmesh trust list-cap-pending --json # machine-readable pending list
ironmesh trust cap-promote <node_id>   # accept the pending change
ironmesh trust cap-promote --all       # bulk accept (careful!)
ironmesh trust cap-reject <node_id>    # reject, restore baseline
ironmesh trust cap-reject <id> --block # reject + set state=blocked

# Audit
ironmesh audit verify                      # chain integrity
ironmesh audit tail --since 1h             # recent entries (all events)
ironmesh audit tail --event PEER_CAP_SET_CHANGED --since 24h
ironmesh audit stats --since 1h            # event-type histogram
ironmesh audit export --out audit-snap.json  # signed bundle

# Observability
curl http://127.0.0.1:8765/metrics | grep peer_cap   # Prometheus

# Doctor (v0.8.5.x sanity check)
ironmesh doctor

# Peer reachability dry-run (v0.9.4.2)
ironmesh doctor --peer <host>:<port> \
    --passphrase-file ~/.ironmesh/passphrase
```

## Deployment helpers (v0.9.4.2)

Two small wrappers live in `tools/` for the deployment patterns
that have actually hurt operators on the staging mesh:

- **`tools/start-daemon-detached.sh`** — launch a daemon over SSH
  so it survives logout. `nohup ... & disown` does not actually
  survive logout (SIGHUP on terminal close); this wrapper uses
  `setsid` to give the daemon its own session/process group.
  Stdout/stderr land in `~/.ironmesh/daemon.log`.

  ```bash
  ssh peer "bash -s" < tools/start-daemon-detached.sh -- \
      --name peer --port 8765 \
      --passphrase-file ~/.ironmesh/passphrase
  ```

- **`tools/transfer-wheel.sh`** — wheel transfer with remote
  SHA256 verification. `scp` over a flaky network has been
  observed to complete with exit code 0 while transferring a
  truncated file; this wrapper streams via
  `ssh ... 'cat > path'` and re-checks the SHA after copy.

  ```bash
  tools/transfer-wheel.sh dist/ironmesh-0.9.4.2-py3-none-any.whl \
      peer:/tmp/
  ```
