// Translates between IronMesh node_id and OpenClaw ChannelDirectoryEntry.
// Per the design (D2): contact identity is the IronMesh node_id, NOT
// the Ed25519 fingerprint. Key rotation does not change the contact —
// the contact's pinned fingerprint changes, the contact_id stays.
//
// A single PeerMapper instance is owned by one account's connection
// and folds three sources of truth:
//   1. The persisted state (PluginState.listPeers() — the contacts we
//      knew about across restarts).
//   2. The handshake peer of the current IronMeshClient session — known
//      live, marked online.
//   3. Optional control-frame peer events (PEER_CONNECT/PEER_DISCONNECT)
//      surfaced by the IronMeshClient's typed event API.
//
// `listAll()` returns the union with online flags; `listOnline()`
// returns just the live peers. The mapper does NOT do mDNS discovery
// itself — that's the daemon's job. It only mirrors what the connected
// client tells it.

import type { PluginState, PeerRecord } from "./persistence.js";

export interface DirectoryContact {
  /** IronMesh node_id (32-hex). The stable contact identity. */
  contactId: string;
  /** Display name from the most recent HELLO, if any. */
  displayName?: string;
  /** Whether this peer is currently observed as online. */
  online: boolean;
  /** Trust state from the persisted record. */
  trust: PeerRecord["trust"];
  /** ms since epoch of the most recent inbound or handshake. */
  lastSeenMs?: number;
}

/** Live data the mapper accepts about a peer (from the connection). */
export interface LivePeerObservation {
  nodeId: string;
  agentName?: string;
  fingerprint?: string;
  /** True when newly connected, false when newly disconnected. */
  online: boolean;
  observedAtMs: number;
}

export class PeerMapper {
  private readonly state: PluginState;
  /** node_id -> latest live observation (omitted when offline + not in state). */
  private liveByNodeId: Map<string, LivePeerObservation> = new Map();

  constructor(state: PluginState) {
    this.state = state;
  }

  /**
   * Apply a live observation. If the peer hasn't been seen before, an
   * entry is created in PluginState with trust="pending"; subsequent
   * observations only refresh agent_name + last_seen + the live online
   * flag. The pinned fingerprint is locked on first observation to
   * support TOFU.
   */
  observe(obs: LivePeerObservation): { record: PeerRecord; isNew: boolean } {
    this.liveByNodeId.set(obs.nodeId, obs);
    const before = this.state.getPeer(obs.nodeId);
    const isNew = before === undefined;
    const record = this.state.upsertPeer({
      nodeId: obs.nodeId,
      agentName: obs.agentName,
      lastSeenMs: obs.online ? obs.observedAtMs : before?.lastSeenMs,
      // Only pin fingerprint the FIRST time we see this peer.
      pinnedFingerprint: before?.pinnedFingerprint ?? obs.fingerprint,
      trust: before?.trust ?? "pending",
    });
    return { record, isNew };
  }

  /** Mark a peer as offline; keeps the persisted record around. */
  markOffline(nodeId: string): void {
    const live = this.liveByNodeId.get(nodeId);
    if (live) {
      this.liveByNodeId.set(nodeId, { ...live, online: false });
    }
  }

  /** All known contacts (persisted + live), with current online flag. */
  listAll(): DirectoryContact[] {
    const records = this.state.listPeers();
    return records.map((r) => this._toContact(r));
  }

  /** Only currently-online peers. */
  listOnline(): DirectoryContact[] {
    return this.listAll().filter((c) => c.online);
  }

  resolveByName(name: string): DirectoryContact | undefined {
    return this.listAll().find(
      (c) => c.displayName === name || c.contactId === name,
    );
  }

  resolveById(contactId: string): DirectoryContact | undefined {
    const r = this.state.getPeer(contactId);
    return r ? this._toContact(r) : undefined;
  }

  private _toContact(r: PeerRecord): DirectoryContact {
    const live = this.liveByNodeId.get(r.nodeId);
    return {
      contactId: r.nodeId,
      displayName: live?.agentName ?? r.agentName,
      online: live?.online ?? false,
      trust: r.trust,
      lastSeenMs: r.lastSeenMs,
    };
  }
}
