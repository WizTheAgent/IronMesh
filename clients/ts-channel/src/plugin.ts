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
import { PeerMapper } from "./peer-mapper.js";
import { PluginState } from "./persistence.js";
import { TrustGate, type PendingTrustEvent } from "./trust-gate.js";
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
  /**
   * Where to keep persisted plugin state (one JSON file per account).
   * Defaults to ~/.openclaw/ironmesh-channel/ to live next to other
   * channel state. Tests / non-OpenClaw embedders override this.
   */
  stateDir?: string;
}

export function ironMeshChannelPlugin(opts: IronMeshChannelPluginOptions) {
  const logger: PluginLogger = opts.logger ?? {
    info: console.log.bind(console),
    warn: console.warn.bind(console),
    error: console.error.bind(console),
    debug: console.debug?.bind(console),
  };
  const stateDir =
    opts.stateDir ??
    `${process.env.HOME ?? process.env.USERPROFILE ?? "."}/.openclaw/ironmesh-channel`;

  // accountId -> live connection
  const connections = new Map<string, IronMeshConnection>();
  // accountId -> persisted plugin state
  const stateByAccount = new Map<string, PluginState>();
  // accountId -> set of inbound subscribers (OpenClaw runtime)
  const inboundSubscribers = new Map<string, Set<(m: ChannelInboundMessage) => void>>();
  // accountId -> trust gate (TOFU pending-trust queue)
  const trustGates = new Map<string, TrustGate>();
  // accountId -> set of pendingTrust event listeners
  const pendingTrustListeners = new Map<string, Set<(e: PendingTrustEvent) => void>>();

  async function getOrLoadState(accountId: string): Promise<PluginState> {
    const existing = stateByAccount.get(accountId);
    if (existing) return existing;
    const s = await PluginState.load(accountId, { stateDir });
    stateByAccount.set(accountId, s);
    return s;
  }

  /** Sync version for hot paths — assumes state has already been loaded
   *  (lifecycle.start does that before any other adapter call). */
  function requireState(accountId: string): PluginState {
    const s = stateByAccount.get(accountId);
    if (!s) {
      throw new Error(
        `[ironmesh-channel] state for account=${accountId} not loaded — ` +
          "call lifecycle.start() before any other adapter",
      );
    }
    return s;
  }

  function fanoutToSubscribers(accountId: string, msg: ChannelInboundMessage): void {
    const set = inboundSubscribers.get(accountId);
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
  }

  function getOrCreateTrustGate(accountId: string): TrustGate {
    let g = trustGates.get(accountId);
    if (g) return g;
    const state = requireState(accountId);
    g = new TrustGate({ accountId, state, logger });
    trustGates.set(accountId, g);
    g.onPendingTrust((evt) => {
      const set = pendingTrustListeners.get(accountId);
      if (!set) return;
      for (const fn of set) {
        try {
          fn(evt);
        } catch (e) {
          logger.warn(
            `[ironmesh-channel] pendingTrust listener threw: ${e instanceof Error ? e.message : String(e)}`,
          );
        }
      }
    });
    return g;
  }

  function getOrConnect(account: IronMeshChannelAccount): IronMeshConnection {
    let c = connections.get(account.accountId);
    if (c) return c;
    const state = requireState(account.accountId);
    const peers = new PeerMapper(state);
    c = new IronMeshConnection(account, peers, logger);
    connections.set(account.accountId, c);
    const gate = getOrCreateTrustGate(account.accountId);
    // Forward inbound to subscribers, gated by TOFU trust state.
    c.onInbound((msg) => {
      const action = gate.evaluate(msg);
      if (action !== "deliver") return;
      fanoutToSubscribers(account.accountId, msg);
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

    /** Lifecycle: open the WebSocket on start, close on stop. State is
     *  loaded/persisted around the lifecycle so the adapter is durable
     *  across restart. */
    lifecycle: {
      async start(params: { account: IronMeshChannelAccount }): Promise<void> {
        await getOrLoadState(params.account.accountId);
        const c = getOrConnect(params.account);
        await c.start();
      },
      async stop(params: { account: IronMeshChannelAccount }): Promise<void> {
        const c = connections.get(params.account.accountId);
        if (c) await c.stop();
        const state = stateByAccount.get(params.account.accountId);
        if (state) {
          try {
            await state.save();
          } catch (e) {
            logger.warn(
              `[ironmesh-channel] state save on stop failed: ${e instanceof Error ? e.message : String(e)}`,
            );
          }
        }
      },
    },

    /** Directory: peers seen on the mesh appear as OpenClaw contacts. */
    directory: {
      async self(params: { account: IronMeshChannelAccount }) {
        const c = connections.get(params.account.accountId);
        const myNodeId = c?.client.nodeId;
        if (!myNodeId) return null;
        return {
          kind: "user" as const,
          id: myNodeId,
          name: params.account.name,
          handle: params.account.name,
        };
      },
      async listPeers(params: { account: IronMeshChannelAccount }) {
        const c = connections.get(params.account.accountId);
        if (!c) return [];
        return c.peers.listAll().map((p) => ({
          kind: "user" as const,
          id: p.contactId,
          name: p.displayName ?? p.contactId.slice(0, 12),
          handle: p.displayName,
          raw: { online: p.online, trust: p.trust, lastSeenMs: p.lastSeenMs },
        }));
      },
      async listPeersLive(params: { account: IronMeshChannelAccount }) {
        const c = connections.get(params.account.accountId);
        if (!c) return [];
        return c.peers.listOnline().map((p) => ({
          kind: "user" as const,
          id: p.contactId,
          name: p.displayName ?? p.contactId.slice(0, 12),
          handle: p.displayName,
          raw: { online: true, trust: p.trust, lastSeenMs: p.lastSeenMs },
        }));
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

    /** Trust gate operator API: promote pending peers, block, list. */
    trust: {
      async promote(
        accountId: string,
        nodeId: string,
      ): Promise<{ ok: boolean; drained: number }> {
        const gate = trustGates.get(accountId);
        if (!gate) return { ok: false, drained: 0 };
        const result = gate.promote(nodeId, (m) => fanoutToSubscribers(accountId, m));
        if (result.ok) {
          const state = stateByAccount.get(accountId);
          if (state) {
            try {
              await state.save();
            } catch (e) {
              logger.warn(
                `[ironmesh-channel] state save after promote failed: ${e instanceof Error ? e.message : String(e)}`,
              );
            }
          }
        }
        return result;
      },
      async block(accountId: string, nodeId: string): Promise<{ ok: boolean }> {
        const gate = trustGates.get(accountId);
        if (!gate) return { ok: false };
        const result = gate.block(nodeId);
        if (result.ok) {
          const state = stateByAccount.get(accountId);
          if (state) {
            try {
              await state.save();
            } catch (e) {
              logger.warn(
                `[ironmesh-channel] state save after block failed: ${e instanceof Error ? e.message : String(e)}`,
              );
            }
          }
        }
        return result;
      },
      listPending(accountId: string) {
        const gate = trustGates.get(accountId);
        if (!gate) return [];
        return gate.listPending();
      },
    },

    /** Event subscriptions outside the messaging path (e.g. operator UI). */
    events: {
      onPendingTrust(
        accountId: string,
        fn: (evt: PendingTrustEvent) => void,
      ): { close: () => void } {
        const set =
          pendingTrustListeners.get(accountId) ??
          new Set<(e: PendingTrustEvent) => void>();
        set.add(fn);
        pendingTrustListeners.set(accountId, set);
        return { close: () => set.delete(fn) };
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
      loadState: getOrLoadState,
      stateByAccount,
      trustGates,
      pendingTrustListeners,
    },
  };
}

export type IronMeshChannelPlugin = ReturnType<typeof ironMeshChannelPlugin>;
