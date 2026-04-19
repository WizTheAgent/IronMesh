// IronMesh OpenClaw channel plugin (alpha).
//
// This is the minimum surface OpenClaw needs to load IronMesh as a
// channel: meta + capabilities + lifecycle (connect on start, drop on
// stop) + outbound (send to a peer) + messaging (receive from peers).
//
// Not implemented in alpha: setup wizard, security/allowlist adapter,
// directory adapter (peer-as-contact list), groups, streaming, threading,
// secrets adapter, doctor adapter, status reporter. Those come with the
// v0.9.0 cut.

import { IronMeshConnection } from "./connection.js";
import type {
  ChannelCapabilities,
  ChannelInboundMessage,
  ChannelMeta,
  ChannelOutboundContext,
  ChannelSendResult,
  IronMeshChannelAccount,
  PluginLogger,
} from "./types.js";

const CHANNEL_ID = "ironmesh";

const META: ChannelMeta = {
  id: CHANNEL_ID,
  label: "IronMesh",
  selectionLabel: "IronMesh — local-first encrypted mesh",
  docsPath: "https://ironmesh.org",
  docsLabel: "IronMesh docs",
  blurb:
    "Send and receive messages over the IronMesh peer-to-peer mesh. " +
    "End-to-end encrypted, no cloud, your network only.",
};

const CAPABILITIES: ChannelCapabilities = {
  outbound: true,
  inbound: true,
  directMessages: true,
  groups: false,
  presence: false,
  streaming: false,
};

/**
 * Build an OpenClaw channel-plugin object for IronMesh. Pass a function
 * that resolves the account record from OpenClaw's loaded config — the
 * config schema is left to the caller because OpenClaw's config tree is
 * application-specific.
 *
 * The returned object can be registered with OpenClaw's bundled-channel
 * entry helper (`defineBundledChannelEntry` in @openclaw/plugin-sdk).
 */
export interface IronMeshChannelPluginOptions {
  /** Pull a per-account IronMesh config out of the OpenClaw config tree. */
  resolveAccount: (cfg: unknown, accountId?: string | null) => IronMeshChannelAccount;
  /** Enumerate accountIds present in the config. */
  listAccountIds: (cfg: unknown) => string[];
  /** Optional logger — falls back to console. */
  logger?: PluginLogger;
}

export function ironMeshChannelPlugin(opts: IronMeshChannelPluginOptions) {
  const logger: PluginLogger = opts.logger ?? {
    info: console.log.bind(console),
    warn: console.warn.bind(console),
    error: console.error.bind(console),
    debug: console.debug?.bind(console),
  };

  // accountId -> live connection
  const connections = new Map<string, IronMeshConnection>();
  // accountId -> set of inbound subscribers (OpenClaw runtime)
  const inboundSubscribers = new Map<string, Set<(m: ChannelInboundMessage) => void>>();

  function getOrConnect(account: IronMeshChannelAccount): IronMeshConnection {
    let c = connections.get(account.accountId);
    if (c) return c;
    c = new IronMeshConnection(account, logger);
    connections.set(account.accountId, c);
    // Forward inbound to any subscribers for this account.
    c.onInbound((msg) => {
      const set = inboundSubscribers.get(account.accountId);
      if (!set) return;
      for (const fn of set) {
        try {
          fn(msg);
        } catch (e) {
          logger.warn(
            `[ironmesh-channel] subscriber threw: ${e instanceof Error ? e.message : String(e)}`,
          );
        }
      }
    });
    return c;
  }

  return {
    id: CHANNEL_ID,
    meta: META,
    capabilities: CAPABILITIES,

    /** Per-account config resolution — delegates to the caller. */
    config: {
      listAccountIds: opts.listAccountIds,
      resolveAccount: (cfg: unknown, accountId?: string | null) =>
        opts.resolveAccount(cfg, accountId),
    },

    /** Lifecycle: open the WebSocket on start, close on stop. */
    lifecycle: {
      async start(params: { account: IronMeshChannelAccount }): Promise<void> {
        const c = getOrConnect(params.account);
        await c.start();
      },
      async stop(params: { account: IronMeshChannelAccount }): Promise<void> {
        const c = connections.get(params.account.accountId);
        if (c) await c.stop();
      },
    },

    /** Outbound: send a single MSG to a peer. */
    outbound: {
      async send(
        params: { account: IronMeshChannelAccount; ctx: ChannelOutboundContext },
      ): Promise<ChannelSendResult> {
        const c = getOrConnect(params.account);
        if (!c.isConnected()) {
          try {
            await c.start();
          } catch (e) {
            return {
              ok: false,
              error: `failed to connect: ${e instanceof Error ? e.message : String(e)}`,
            };
          }
        }
        try {
          // The IronMesh client's sendMessage signature is
          // (payload, opts) — peer targeting is implicit (handshake peer
          // in the alpha). For multi-peer routing we need the ironmesh-mesh
          // MCP tools instead — see docs/OPENCLAW_CHANNEL_SETUP.md.
          // For the alpha we ignore params.ctx.to and send to the
          // handshake peer (single-peer-per-account model).
          const { msgId } = await c.client.sendMessage(params.ctx.text, {
            priority: params.ctx.priority,
          });
          return { ok: true, msgId };
        } catch (e) {
          return {
            ok: false,
            error: e instanceof Error ? e.message : String(e),
          };
        }
      },
    },

    /** Messaging: subscribe to inbound. */
    messaging: {
      subscribe(
        params: {
          account: IronMeshChannelAccount;
          onMessage: (msg: ChannelInboundMessage) => void;
        },
      ): { close: () => void } {
        const set =
          inboundSubscribers.get(params.account.accountId) ??
          new Set<(m: ChannelInboundMessage) => void>();
        set.add(params.onMessage);
        inboundSubscribers.set(params.account.accountId, set);
        // Make sure the connection is started so messages will flow.
        const c = getOrConnect(params.account);
        if (!c.isConnected()) {
          c.start().catch((e) =>
            logger.warn(
              `[ironmesh-channel] subscribe-time connect failed: ${e instanceof Error ? e.message : String(e)}`,
            ),
          );
        }
        return {
          close() {
            set.delete(params.onMessage);
          },
        };
      },
    },

    /** Status: thin health check. */
    status: {
      async describe(params: { account: IronMeshChannelAccount }) {
        const c = connections.get(params.account.accountId);
        return {
          channel: CHANNEL_ID,
          accountId: params.account.accountId,
          state: c?.isConnected() ? "linked" : "not linked",
          peerNodeId: c?.client.peerNodeId ?? null,
        };
      },
    },

    /** @internal — exposed for tests so they can drive without OpenClaw. */
    __test__: {
      connections,
      inboundSubscribers,
      getOrConnect,
    },
  };
}

export type IronMeshChannelPlugin = ReturnType<typeof ironMeshChannelPlugin>;
