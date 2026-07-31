# IronMesh RFC: Key Hierarchy & Group Messaging (v0.1 — SKELETON)

**Status:** Draft skeleton — decision not yet made
**Decides:** Group keying model, PQ hybrid placement, revocation semantics — as one coupled system
**Does NOT decide:** PHY/emission controls, routing metrics, reputation systems (see Non-Goals)
**Downstream dependents:** Conformance golden vectors → Rust reference core → tactical profile crypto defaults
**Reviewers:** Planning-Claude (author-assist), Grok (decorrelated review), external auditor (pre-v1.0)

---

## 1. Problem Statement

IronMesh requires forward-secret, post-compromise-secure group messaging over a multi-hop
store-and-forward mesh characterized by DIL conditions: message loss, deep reordering, and
member offline periods ranging from minutes to days. The keying model, the placement of the
post-quantum hybrid, and the revocation mechanism are a single coupled design: the group key
structure determines where a KEM slots in and what revocation can mean. This RFC forces that
decision before any implementation.

**Core constraint that disqualifies naive designs:** Signal-style double ratchets assume
approximately-ordered delivery (a server sequences messages). Vanilla MLS (RFC 9420) assumes a
Delivery Service that imposes a total order on commits. IronMesh has neither a server nor a
sequencer. Any candidate must state explicitly how it replaces or removes the ordering assumption.

## 2. DIL Parameter Table (FILL BEFORE DECIDING — measure on live 3-node mesh + projected tactical topology)

| Parameter | Symbol | Measured / Assumed | Notes |
|---|---|---|---|
| Max partition duration (p95 / worst-case design point) | T_part | ___ (10 min? 72 h?) | THE dominant variable. Answer differs sharply at 10 min vs 3 days |
| Reordering depth (max out-of-order distance, msgs) | D_reorder | ___ | Drives skipped-key window size in ratchet designs |
| Message loss rate per hop / end-to-end | L | ___ | Drives redundancy in commit/epoch distribution |
| Group size range (min / typical / max) | N | ___ (2 / 8 / 64?) | TreeKEM wins at large N; irrelevant at N≤5 |
| Membership churn rate (joins+leaves per epoch) | C | ___ | High churn punishes pairwise re-key designs |
| Fraction of members offline at any given time | F_off | ___ | Offline members can't process commits → epoch divergence handling |
| Revocation latency tolerance (compromise → excluded) | T_rev | ___ | Tactical profile likely demands minutes, not epochs |
| Min device class (RAM / flash / crypto accel) | — | Pi-class? ESP32-class? | Bounds tree state size and PQ key sizes |
| Narrowest transport (payload size, duty cycle) | — | LoRa via RNS: ___ B effective MTU, ___% duty | Bounds commit message size. ML-KEM-768 ct = 1088 B — check fragmentation cost |

## 3. Key Hierarchy (layers this RFC must connect)

1. **Identity keys** — Ed25519 long-term (migration in progress). Signature alg upgrade path → ML-DSA hybrid. Alignment question with IronWeb SIO (FROST-Ed25519, k-of-n recovery, duress keypair) — see §8.
2. **Session/pairwise keys** — X25519-derived, current session rekey. PQ seam: PQXDH-style hybrid initial handshake vs KEM-per-rekey.
3. **Group keys** — THE open decision (§4).
4. **Content/at-rest keys** — out of scope except where group epoch keys feed storage.

## 4. Candidate Models (tradeoff matrix — score against §2 parameters)

### Candidate A — MLS (RFC 9420) with designated committer per mesh cell
TreeKEM group state; solve the no-sequencer problem by electing/designating a committer
(leader) per mesh cell that serializes commits.
- **+** Standardized; hybrid PQ cipher suite path exists (ML-KEM hybrid suites in IETF pipeline); O(log N) commit cost; clean add/remove semantics = clean revocation
- **−** Committer is availability SPOF under partition; leader election in DIL mesh is its own hard problem; MLS state size on constrained devices; commit size × LoRa MTU
- **Open:** behavior when cell partitions and both halves commit (fork healing)

### Candidate B — Decentralized CGKA (DCGKA-family, Weidner et al.)
Continuous group key agreement designed for no central sequencer; causal ordering,
tolerates concurrent updates, built for exactly this async/decentralized setting.
- **+** Assumption-matched to mesh (no DS, concurrent ops, offline members); strong PCS
- **−** Research-grade, no standard, no mature implementations, no PQ story yet — you'd be pioneering; audit cost highest of all candidates
- **Open:** metadata/bandwidth overhead of causal history under high loss

### Candidate C — Sender Keys + pairwise deep-window ratchets (Signal group model, mesh-adapted)
Each sender distributes a symmetric sender key over pairwise ratchets; deep skipped-key
windows (sized to D_reorder, T_part) tolerate reordering/loss.
- **+** Simplest; tolerates async delivery natively; smallest per-message overhead; easy on constrained devices; PQ seam = harden the pairwise layer only (PQXDH-style)
- **−** Weak PCS; revocation = full sender-key redistribution over N pairwise channels (O(N²) messages on churn); skipped-key state growth = DoS surface if window is deep
- **Open:** max safe window size vs memory on min device class

### Candidate D — Epoch-rotated shared group key (baseline / strawman)
Pre-shared or leader-distributed group key, rotated on schedule and on membership change.
- **+** Trivial; works offline indefinitely; fits pre-pinned closed tactical teams
- **−** No FS within epoch; compromise of any member = full epoch exposure; revocation only as good as rotation delivery
- **Role:** floor for comparison + possible degraded-mode fallback, not the answer

### Matrix (fill after §2)

| Criterion (weight) | A: MLS+committer | B: DCGKA | C: SenderKeys+window | D: Epoch key |
|---|---|---|---|---|
| Tolerates T_part = worst case | | | | |
| Tolerates D_reorder without stall | | | | |
| Revocation latency ≤ T_rev | | | | |
| PCS strength | | | | |
| FS granularity | | | | |
| Commit/rekey bytes over LoRa | | | | |
| State size on min device | | | | |
| PQ hybrid seam maturity | | | | |
| Implementation + audit cost | | | | |
| Standardization / interop credibility | | | | |
| Fork/partition healing story | | | | |

**Hybrid options to evaluate:** C-for-small-closed-tactical + A-for-larger-open-meshes is a legitimate outcome, but it doubles conformance surface — price that explicitly.

## 5. Revocation Propagation (design within the chosen model, not after)

- Revocation messages traverse the same lossy store-and-forward fabric they are trying to secure. Define: epoch fencing (messages from revoked member in epochs ≥ E rejected), replay behavior, and what a node does with queued messages from a now-revoked peer.
- Interaction with trust-store tooling and pending-trust gate (tactical profile: pre-pinned only).
- Compromise-response runbook hook: T_rev target from §2 is a hard requirement, not aspiration.
- Duress keypair semantics (SIO): does duress trigger group revocation, silent flag, or both? Cross-layer decision — flag to IronWeb RFC set.

## 6. PQ Hybrid Placement

- **Assumption (normative):** the Reticulum underlay is transparent to a harvest-now-decrypt-later adversary. All PQ guarantees must hold at the IronMesh envelope; classical RNS handshake protects nothing long-term.
- **KEM:** ML-KEM-768 hybrid with X25519 (concatenate-and-KDF per current IETF hybrid practice). Placement depends on §4 winner: MLS → hybrid cipher suite; SenderKeys → PQXDH-style pairwise bootstrap.
- **Signatures:** ML-DSA-65 hybrid with Ed25519 for identity attestations; measure size cost on LoRa (ML-DSA-65 sig ≈ 3.3 KB — likely tactical-profile-only or reserved for low-frequency identity ops, not per-message).
- **Classical-only mode retained** for constrained devices and interop; negotiated, downgrade-protected (transcript-bound).

## 7. Downstream Artifacts (blocked on this RFC)

1. Conformance golden vectors (wire format of the chosen model)
2. Rust reference core (implements chosen model first, Python parity second)
3. Tactical profile crypto defaults (`--profile=tactical`: which model, which suites, window/epoch parameters)
4. External audit scope statement

## 8. Non-Goals & Open Questions

- **Non-goals:** emission/traffic-analysis controls (separate tactical-profile doc), routing metrics, reputation systems (demoted to research question per July 2026 review).
- **Open:** SIO/FROST identity alignment vs IronMesh Ed25519 identities — one identity root or bridged? Multi-device per member (does a member = one leaf or a subtree)? Fork healing after long partitions (A and B differ sharply). Key recovery (k-of-n) interaction with group membership — does recovery = new leaf (revoke old) or restored leaf?
- **Already decided (do not re-derive):** the inner end-to-end source-signature / frame-integrity chokepoint lives in `routing.py`'s `RoutingMixin` (`_verify_inner_source`, wired at the `deserialize_and_decrypt` dispatch point) — group messaging should extend that chokepoint, not build a new one.

## 9. Decision Procedure

1. Fill §2 from live mesh measurements + tactical topology assumptions (Box signs off on worst-case design points).
2. Score §4 matrix; Planning-Claude drafts scores with rationale; Grok independent pass; disagreements resolved by Box against §2 weights.
3. Winner + rationale + rejected-alternatives record ratified into vault; §7 artifacts unblock.
