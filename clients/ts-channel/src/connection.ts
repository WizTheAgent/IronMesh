// Connection lifecycle: a singleton-per-account IronMeshClient that
// the lifecycle/outbound/messaging adapters share. The plugin instance
// holds at most one client per accountId — accounts map 1:1 to mesh
// identities, so reusing the same client across all three adapters
// keeps the wire view consistent.

// Vendored at pack time by scripts/vendor-client.js. Path resolves to
// ./vendor/ironmesh-client/dist/index.js from the package root, both
// in dev (after `npm run prepack` populates vendor) and in published.
import { IronMeshClient } from "../vendor/ironmesh-client/dist/index.js";
import type { PeerMapper } from "./peer-mapper.js";
import type { ChannelInboundMessage, IronMeshChannelAccount, PluginLogger } from "./types.js";

export interface ConnectionEvents {
  inbound: (msg: ChannelInboundMessage) => void;
}

export class IronMeshConnection {
  readonly account: IronMeshChannelAccount;
  readonly client: IronMeshClient;
  readonly peers: PeerMapper;
  private readonly logger?: PluginLogger;
  private readonly inboundListeners: Set<(msg: ChannelInboundMessage) => void> = new Set();
  private connected = false;

  constructor(account: IronMeshChannelAccount, peers: PeerMapper, logger?: PluginLogger) {
    this.account = account;
    this.peers = peers;
    this.logger = logger;
    this.client = new IronMeshClient({
      url: account.url,
      passphrase: account.passphrase,
      name: account.name,
      autoReconnect: true,
    });

    this.client.on("connect", () => {
      this.connected = true;
      const peerNodeId = this.client.peerNodeId;
      this.logger?.info(
        `[ironmesh-channel] account=${account.accountId} connected to ${account.url} (peer=${peerNodeId})`,
      );
      // Record the handshake peer as a live observation. We don't yet
      // know the peer's agent name — the IronMeshClient only surfaces
      // node_id at handshake time. A future client API addition can
      // include the peer's HELLO display name here.
      if (peerNodeId) {
        this.peers.observe({
          nodeId: peerNodeId,
          online: true,
          observedAtMs: Date.now(),
        });
      }
    });
    this.client.on("disconnect", (reason: unknown) => {
      this.connected = false;
      const peerNodeId = this.client.peerNodeId;
      if (peerNodeId) this.peers.markOffline(peerNodeId);
      this.logger?.info(
        `[ironmesh-channel] account=${account.accountId} disconnected: ${String(reason)}`,
      );
    });
    this.client.on("peerConnect", (info: { nodeId: string; agentName?: string }) => {
      this.peers.observe({
        nodeId: info.nodeId,
        agentName: info.agentName,
        online: true,
        observedAtMs: Date.now(),
      });
    });
    this.client.on("peerDisconnect", (info: { nodeId: string }) => {
      this.peers.markOffline(info.nodeId);
    });
    this.client.on("error", (err: { message?: string } | Error) => {
      this.logger?.warn(
        `[ironmesh-channel] account=${account.accountId} error: ${
          err instanceof Error ? err.message : err.message ?? String(err)
        }`,
      );
    });
    this.client.on("message", (msg: { msgType: string; payload: Uint8Array; fromNodeId: string; msgId?: string; timestamp: number }) => {
      // Translate IronMesh inbound MSG into OpenClaw ChannelInboundMessage.
      // Only "MSG" type is surfaced as a chat message; control frames are ignored.
      if (msg.msgType !== "MSG") return;
      const text = new TextDecoder("utf-8", { fatal: false }).decode(msg.payload);
      // Refresh last_seen for the sending peer.
      this.peers.observe({
        nodeId: msg.fromNodeId,
        online: true,
        observedAtMs: msg.timestamp,
      });
      const fromContact = this.peers.resolveById(msg.fromNodeId);
      const inbound: ChannelInboundMessage = {
        channel: "ironmesh",
        accountId: account.accountId,
        fromId: msg.fromNodeId,
        fromName: fromContact?.displayName,
        text,
        externalId: msg.msgId,
        timestamp: msg.timestamp,
      };
      for (const fn of this.inboundListeners) {
        try {
          fn(inbound);
        } catch (e) {
          this.logger?.warn(
            `[ironmesh-channel] inbound listener threw: ${e instanceof Error ? e.message : String(e)}`,
          );
        }
      }
    });
  }

  async start(): Promise<void> {
    if (this.connected) return;
    await this.client.connect();
  }

  async stop(): Promise<void> {
    if (!this.connected) return;
    await this.client.disconnect();
  }

  isConnected(): boolean {
    return this.connected;
  }

  /** Subscribe to inbound messages. Returns an unsubscribe function. */
  onInbound(fn: (msg: ChannelInboundMessage) => void): () => void {
    this.inboundListeners.add(fn);
    return () => this.inboundListeners.delete(fn);
  }
}
