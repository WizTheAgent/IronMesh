// TOFU pending-trust gate for inbound MSGs.
//
// Sits between the IronMesh connection (which sees every wire MSG) and
// the OpenClaw-facing subscribers. For each inbound message the gate
// looks up the sender's PeerRecord and decides:
//
//   trusted  -> deliver immediately
//   pending  -> queue (cap 100/peer, FIFO eviction) and emit a
//               pendingTrust event so an operator can promote
//   blocked  -> drop, increment a counter
//
// Pending queue is in-memory only — gateway restart drops queued
// messages but the persisted "pending" trust state survives, so the
// peer stays gated until promoted. This is the documented v0.8.5
// limitation.

import type { PeerRecord, PluginState } from "./persistence.js";
import type { ChannelInboundMessage, PluginLogger } from "./types.js";

export type GateAction = "deliver" | "queue" | "drop";

export interface PendingTrustEvent {
  accountId: string;
  nodeId: string;
  agentName?: string;
  fingerprint?: string;
  lastSeenMs?: number;
  queuedMessageCount: number;
}

export interface TrustGateOptions {
  accountId: string;
  state: PluginState;
  logger?: PluginLogger;
  /** Per-peer cap on the pending queue. Default 100. */
  queueCap?: number;
}

const DEFAULT_QUEUE_CAP = 100;

export class TrustGate {
  readonly accountId: string;
  private readonly state: PluginState;
  private readonly logger?: PluginLogger;
  private readonly queueCap: number;
  /** nodeId -> queued inbound messages (oldest first). */
  private readonly pendingQueues: Map<string, ChannelInboundMessage[]> = new Map();
  /** nodeId -> count of messages dropped because the peer is blocked. */
  private readonly blockedDrops: Map<string, number> = new Map();
  private readonly pendingListeners: Set<(evt: PendingTrustEvent) => void> = new Set();

  constructor(opts: TrustGateOptions) {
    this.accountId = opts.accountId;
    this.state = opts.state;
    this.logger = opts.logger;
    this.queueCap = opts.queueCap ?? DEFAULT_QUEUE_CAP;
  }

  /**
   * Decide what to do with an inbound message. Side effects: queues
   * pending messages, increments the blocked counter, emits the
   * pendingTrust event when relevant.
   */
  evaluate(msg: ChannelInboundMessage): GateAction {
    const record = this.state.getPeer(msg.fromId);
    const trust = record?.trust ?? "pending";

    if (trust === "trusted") return "deliver";

    if (trust === "blocked") {
      const next = (this.blockedDrops.get(msg.fromId) ?? 0) + 1;
      this.blockedDrops.set(msg.fromId, next);
      this.logger?.debug?.(
        `[ironmesh-channel] account=${this.accountId} dropped MSG from blocked peer ${msg.fromId.slice(0, 12)} (total=${next})`,
      );
      return "drop";
    }

    // pending
    const queue = this.pendingQueues.get(msg.fromId) ?? [];
    if (queue.length >= this.queueCap) {
      const dropped = queue.shift();
      this.logger?.warn(
        `[ironmesh-channel] account=${this.accountId} pending queue cap (${this.queueCap}) hit for peer ${msg.fromId.slice(0, 12)}; evicted oldest msg ${dropped?.externalId ?? "?"}`,
      );
    }
    queue.push(msg);
    this.pendingQueues.set(msg.fromId, queue);
    this._emitPending(msg.fromId, record, queue.length);
    return "queue";
  }

  /**
   * Promote a peer to trusted. Drains any queued messages to the sink in
   * arrival order. Returns the number of drained messages and whether
   * the peer existed in state.
   */
  promote(
    nodeId: string,
    sink: (msg: ChannelInboundMessage) => void,
  ): { ok: boolean; drained: number } {
    const record = this.state.trust(nodeId);
    if (!record) return { ok: false, drained: 0 };
    const queue = this.pendingQueues.get(nodeId) ?? [];
    this.pendingQueues.delete(nodeId);
    for (const msg of queue) {
      try {
        sink(msg);
      } catch (e) {
        this.logger?.warn(
          `[ironmesh-channel] account=${this.accountId} sink threw while draining promoted peer ${nodeId.slice(0, 12)}: ${e instanceof Error ? e.message : String(e)}`,
        );
      }
    }
    return { ok: true, drained: queue.length };
  }

  /**
   * Block a peer. Drops any currently-queued pending messages and starts
   * incrementing the blocked-drop counter on subsequent inbound.
   */
  block(nodeId: string): { ok: boolean } {
    const record = this.state.block(nodeId);
    if (!record) return { ok: false };
    this.pendingQueues.delete(nodeId);
    return { ok: true };
  }

  /** Peers that have at least one queued message awaiting promotion. */
  listPending(): Array<PeerRecord & { queuedMessageCount: number }> {
    const out: Array<PeerRecord & { queuedMessageCount: number }> = [];
    for (const r of this.state.listPeers()) {
      if (r.trust !== "pending") continue;
      const q = this.pendingQueues.get(r.nodeId);
      if (!q || q.length === 0) continue;
      out.push({ ...r, queuedMessageCount: q.length });
    }
    return out;
  }

  /** Subscribe to pendingTrust events. Returns an unsubscribe fn. */
  onPendingTrust(fn: (evt: PendingTrustEvent) => void): () => void {
    this.pendingListeners.add(fn);
    return () => this.pendingListeners.delete(fn);
  }

  /** @internal — exposed for tests. */
  _queueLength(nodeId: string): number {
    return this.pendingQueues.get(nodeId)?.length ?? 0;
  }

  /** @internal — exposed for tests. */
  _blockedDropCount(nodeId: string): number {
    return this.blockedDrops.get(nodeId) ?? 0;
  }

  private _emitPending(nodeId: string, record: PeerRecord | undefined, queuedMessageCount: number): void {
    const evt: PendingTrustEvent = {
      accountId: this.accountId,
      nodeId,
      agentName: record?.agentName,
      fingerprint: record?.pinnedFingerprint,
      lastSeenMs: record?.lastSeenMs,
      queuedMessageCount,
    };
    for (const fn of this.pendingListeners) {
      try {
        fn(evt);
      } catch (e) {
        this.logger?.warn(
          `[ironmesh-channel] pendingTrust listener threw: ${e instanceof Error ? e.message : String(e)}`,
        );
      }
    }
  }
}
