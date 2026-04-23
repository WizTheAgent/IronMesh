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
import type {
  ChannelCapabilities,
  ChannelInboundMessage,
  ChannelMeta,
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

  function getOrConnect(account: IronMeshChannelAccount): IronMeshConnection {
    let c = connections.get(account.accountId);
    if (c) return c;
    const state = requireState(account.accountId);
    const peers = new PeerMapper(state);
    c = new IronMeshConnection(account, peers, logger);
    connections.set(account.accountId, c);
    // Inbound is daemon-gated as of v0.8.5 — when the daemon runs with
    // --require-message-promotion, MSGs from pending peers never reach
    // this point. Trust state is owned by the daemon; operators promote
    // via the dashboard or the ironmesh_trust_peer MCP tool.
    c.onInbound((msg) => fanoutToSubscribers(account.accountId, msg));
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

    /** Outbound: OpenClaw 2026.3.x looks for `outbound.sendText` directly
     *  on the channel plugin object (per
     *  `loadOutboundAdapterFromRegistry((entry) => entry.plugin.outbound)`
     *  + `if (!outbound?.sendText) return null` in deliver.js). The `to`
     *  field has been normalized by `messaging.normalizeTarget` — it's
     *  either a 32-hex node_id (lowercase) or an agent name. */
    outbound: {
      sendText: async (params: {
        cfg: unknown;
        accountId?: string | null;
        to: string;
        text: string;
        threadId?: string | number | null;
        replyToId?: string | number | null;
      }): Promise<{ to: string; messageId: string }> => {
        const account = opts.resolveAccount(params.cfg, params.accountId);
        await getOrLoadState(account.accountId);
        const c = getOrConnect(account);
        if (!c.isConnected()) {
          await c.start();
        }
        // The IronMesh client's sendMessage signature is
        // (payload, opts) — peer targeting via opts.toNodeId or toName.
        // The daemon routes via mesh if the target isn't a direct peer.
        const sendOpts: Record<string, unknown> = {};
        if (/^[0-9a-f]{32}$/i.test(params.to)) {
          sendOpts.toNodeId = params.to.toLowerCase();
        } else {
          sendOpts.toName = params.to;
        }
        const { msgId } = await c.client.sendMessage(params.text, sendOpts);
        return { to: params.to, messageId: msgId };
      },
    },

    /** Messaging: subscribe to inbound + target validation/normalization.
     *
     *  IronMesh accepts three target forms:
     *    1. <32-hex node_id>            (preferred — stable across rename)
     *    2. mesh:<32-hex node_id>       (explicit prefix)
     *    3. <agent_name>                (resolved at send time, may be ambiguous)
     */
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

      /** Strip mesh: prefix and lowercase hex; pass through agent names. */
      normalizeTarget: (raw: string): string => {
        const t = raw.trim();
        if (!t) return t;
        const stripped = t.startsWith("mesh:") ? t.slice(5) : t;
        // 32-hex node_id → lowercase canonical form
        if (/^[0-9A-Fa-f]{32}$/.test(stripped)) return stripped.toLowerCase();
        return stripped;
      },

      parseExplicitTarget: ({ raw }: { raw: string }) => {
        const t = raw.trim();
        const stripped = t.startsWith("mesh:") ? t.slice(5) : t;
        const to = /^[0-9A-Fa-f]{32}$/.test(stripped)
          ? stripped.toLowerCase()
          : stripped;
        return { to, chatType: "direct" as const };
      },

      inferTargetChatType: (_args: { to: string }) => "direct" as const,

      targetResolver: {
        looksLikeId: (raw: string): boolean => {
          const t = raw.trim();
          if (!t) return false;
          const stripped = t.startsWith("mesh:") ? t.slice(5) : t;
          // Accept 32-hex node_ids, or any non-empty agent-name token
          // (the daemon ultimately validates against the live peer set).
          return /^[0-9A-Fa-f]{32}$/.test(stripped) || /^[a-zA-Z0-9._-]+$/.test(stripped);
        },
        hint: "<node_id (32-hex)> or mesh:<node_id> or <agent_name>",
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
    },
  };
}

export type IronMeshChannelPlugin = ReturnType<typeof ironMeshChannelPlugin>;
