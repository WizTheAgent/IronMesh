# Node Recovery & Re-Pinning Playbook

This document covers the common operator tasks for dealing with compromised,
lost, or rotated peer identities in an IronMesh deployment.

## Background

IronMesh uses **Trust On First Use (TOFU)** key pinning. The first time a
peer's Ed25519 identity key is seen, it's stored in `trust.json` under the
peer's name. Any subsequent connection claiming the same name but a
different key is **rejected as a potential MITM attack**.

This is deliberately strict. Recovering from a legitimate key change — a
node reinstalled, a key rotated, a compromised node revoked — requires
explicit operator action. That action is documented here.

## Offline pubkey backup (do this before you need it)

Each node's identity lives in `~/.ironmesh/keys.json`. Back
it up to offline media immediately after first deploy:

```bash
cp ~/.ironmesh/keys.json /path/to/offline/keys-$(hostname)-$(date -u +%F).json
```

Restoring from this backup lets a reinstalled node come back with its
original identity — no re-pin required across the mesh.

## When a peer legitimately rotated keys

Every node in the mesh has the old key pinned. The new key will be
rejected on handshake. To accept the new key on a single node:

```bash
# 1. Revoke the old pin
ironmesh trust revoke <peer-name>

# 2. Reconnect — the peer will be re-pinned on next handshake
#    (automatic via mDNS, or force with `trust pin <peer-name> <new-pubkey-b64>`)
```

If many nodes are affected, this has to be done on each. There is no
"broadcast re-pin" — that would reintroduce the MITM hole TOFU closes.

## When a peer is compromised

The revoked-peer list (`trust.json` → `revoked`) is persisted and checked
on every incoming handshake. A revoked peer is rejected even if it
presents a correct ECDH exchange.

```bash
# On every node that had this peer pinned:
ironmesh trust revoke <compromised-peer-name>

# Verify revocation took effect
ironmesh trust list
```

The compromised peer will stop being able to connect. They'll see
`ConnectionError: Peer <name> is revoked` in their logs. Their messages
already in the `pending_messages` queue on other nodes are NOT retroactively
scrubbed — you must manually clear those if needed.

## When a node is reinstalled (legitimate)

Ideal: restore the original keys.json from your offline backup. No re-pin
needed across the mesh.

Fallback (keys lost): follow "When a peer legitimately rotated keys" above.
Every other node must revoke the old pin and accept the new one.

## When the trust store itself is corrupted

Symptom: `Failed to load trust store: ...` on startup; or the MAC check
fails (possible tampering).

1. Stop the daemon.
2. Move the broken store aside: `mv ~/.ironmesh/trust.json ~/.ironmesh/trust.json.broken`
3. Start the daemon. It will create a fresh empty store.
4. **You are now in a first-contact state with every peer.** Existing
   peer keys on other nodes are fine. Your node will TOFU-pin each peer
   on next handshake.

## Offline recovery box

Keep a small offline tool (USB drive, air-gapped machine) with:

- Backup of each node's `keys.json`
- Backup of `trust.json` from a "canonical" node (a node you consider the
  source of truth for pinned peers)
- The `ironmesh trust` CLI binary (static build, or the pip wheel)

With those three, you can rebuild any node's crypto state without
touching the network.

## Don't do this

- **Don't set `--open-discovery` in production.** It disables the TOFU
  gate on mDNS auto-connect and allows any announced peer to establish a
  session. Use `--allowed-peers` with an explicit list.
- **Don't share `keys.json` between nodes.** The private key identifies
  the node; two nodes with the same key will produce duplicate sessions
  and confuse the tie-breaker logic.
- **Don't blindly re-pin on ECDSA_MISMATCH.** That's exactly the signal
  TOFU is designed to raise. Verify out-of-band (call the operator, check
  the new fingerprint matches what they expect) before revoking the old
  pin.
