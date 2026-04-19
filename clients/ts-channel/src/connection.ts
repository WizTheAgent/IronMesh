// Connection lifecycle: a singleton-per-account IronMeshClient that
// the lifecycle/outbound/messaging adapters share. The plugin instance
// holds at most one client per accountId — accounts map 1:1 to mesh
// identities, so reusing the same client across all three adapters
// keeps the wire view consistent.

import { IronMeshClient } from "@wiztheagent/ironmesh-client";
import type { ChannelInboundMessage, IronMeshChannelAccount, PluginLogger } from "./types.js";

export interface ConnectionEvents {
  inbound: (msg: ChannelInboundMessage) => void;
}

export class IronMeshConnection {
  readonly account: IronMeshChannelAccount;
  readonly client: IronMeshClient;
  private readonly logger?: PluginLogger;
  private readonly inboundListeners: Set<(msg: ChannelInboundMessage) => void> = new Set();
  private connected = false;

  constructor(account: IronMeshChannelAccount, logger?: PluginLogger) {
    this.account = account;
    this.logger = logger;
    this.client = new IronMeshClient({
      url: account.url,
      passphrase: account.passphrase,
      name: account.name,
      autoReconnect: true,
    });

    this.client.on("connect", () => {
      this.connected = true;
      this.logger?.info(
        `[ironmesh-channel] account=${account.accountId} connected to ${account.url} (peer=${this.client.peerNodeId})`,
      );
    });
    this.client.on("disconnect", (reason) => {
      this.connected = false;
      this.logger?.info(
        `[ironmesh-channel] account=${account.accountId} disconnected: ${reason}`,
      );
    });
    this.client.on("error", (err) => {
      this.logger?.warn(
        `[ironmesh-channel] account=${account.accountId} error: ${err.message}`,
      );
    });
    this.client.on("message", (msg) => {
      // Translate IronMesh inbound MSG into OpenClaw ChannelInboundMessage.
      // Only "MSG" type is surfaced as a chat message; control frames are ignored.
      if (msg.msgType !== "MSG") return;
      const text = new TextDecoder("utf-8", { fatal: false }).decode(msg.payload);
      const inbound: ChannelInboundMessage = {
        channel: "ironmesh",
        accountId: account.accountId,
        fromId: msg.fromNodeId,
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
