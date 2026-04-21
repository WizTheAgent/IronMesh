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
or — most commonly — the B7 read-only latch tripped because another
process wrote the trust file with a different identity key).

**Triage:**

1. `ironmesh trust cap-status <node_id>` — does it show a pending hash?
   If yes, the stash DID succeed and demote failed; the peer is still
   `trusted` from the gate's perspective.
2. Check the wiz log for `Trust store integrity check FAILED`. If
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

## 7. Daemon won't start after key rotation

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

## Useful commands reference

```bash
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
```
