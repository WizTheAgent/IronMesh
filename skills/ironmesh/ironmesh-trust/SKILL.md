---
name: ironmesh-trust
description: Inspect and manage IronMesh's TOFU trust store — list pinned peers, show revocations, revoke a compromised peer. Revoke has side effects and requires the user's explicit confirmation.
allowed-tools: [Bash]
---

# IronMesh trust store operations

The trust store is the TOFU pin database — first-time peer keys are
recorded, and subsequent connections claiming the same agent name must
present the same Ed25519 identity key.

## Subcommands

### `list`

Show every pinned peer and any revocations. Use to answer "who do we
trust?" before sending sensitive messages.

```bash
ironmesh trust list
```

### `revoke <peer-name>` — destructive

Adds the peer to the revoked set. The daemon will reject future
connections from this peer's identity key even if they present a valid
ECDH exchange. Use when:

- A peer has been compromised (stolen laptop, leaked keys)
- A peer is behaving anomalously (replays, bad signatures)
- A node has been decommissioned and you want to block its return

```bash
# Requires confirmation — the skill prompts the user first
ironmesh trust revoke compromised-peer
```

### `pin <peer-name> <pubkey-b64>`

Manually add a peer pin (for offline-first-contact scenarios like
bootstrapping a new node from air-gapped keys).

```bash
ironmesh trust pin new-peer "mG...base64..."
```

## When to use

- User asks "is X trusted?" → `list`
- After a `TOFU_MISMATCH` event in the audit log → investigate, then
  either revoke the old pin (if legitimately rotated) or revoke the
  incoming peer (if attacker)
- New node deploy → `pin` from the offline key backup

## Recovery playbook

See [docs/REPIN.md](../../../docs/REPIN.md) for the full flow:
compromised peer → revoke everywhere → verify offline → re-pin or
accept TOFU on next contact.

## Safeguards in this skill

- `revoke` without explicit user confirmation → refuses
- `list` is always safe and can be invoked freely
- Never auto-pin without user approval — pinning a malicious key
  would defeat the whole TOFU model
