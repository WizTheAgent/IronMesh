// OpenClaw plugin entry point.
//
// OpenClaw 2026.3.x loads channel plugins via a default-exported
// definition object with a `register(api)` method. This file matches
// that contract; it does NOT use the older `defineBundledChannelEntry`
// helper, which doesn't exist in 2026.3.x.
//
// The contract (from `openclaw/plugin-sdk/plugins/types`):
//
//   export type OpenClawPluginDefinition = {
//     id: string;
//     name?: string;
//     description?: string;
//     configSchema?: OpenClawPluginConfigSchema;
//     register?: (api: OpenClawPluginApi) => void | Promise<void>;
//     activate?: (api: OpenClawPluginApi) => void | Promise<void>;
//   };
//   api.registerChannel(plugin)  — plugin can be a ChannelPlugin
//
// Two config shapes are supported. Single-account (the common case):
//
//   plugins.entries.ironmesh.config = { url, passphrase, name }
//
// Multi-account (advanced):
//
//   channels.ironmesh.<accountId> = { url, passphrase, name }
//
// `api.pluginConfig` carries the first; `api.config` carries the
// second. We accept either; if both are present, the plugin-level
// single-account config wins (because that's the one operators set
// via `openclaw config set plugins.entries.ironmesh.config.X`).

import { ironMeshChannelPlugin } from "./plugin.js";
import {
  listChannelAccountIds,
  resolveChannelAccount,
  ChannelConfigSchema,
  type ChannelAccountConfig,
} from "./config-schema.js";

type OpenClawPluginApi = {
  pluginConfig?: Record<string, unknown>;
  config?: unknown;
  registerChannel: (registration: unknown) => void;
  logger?: {
    info: (msg: string) => void;
    warn: (msg: string) => void;
    error: (msg: string) => void;
    debug?: (msg: string) => void;
  };
};

const PLUGIN_ID = "ironmesh";
const SINGLE_ACCOUNT_ID = "default";

/**
 * If the plugin-level config carries the single-account fields, build
 * an OpenClaw-shaped config tree with a single `default` entry so the
 * existing `resolveChannelAccount` / `listChannelAccountIds` helpers
 * work without branching.
 */
function buildBridgedCfg(api: OpenClawPluginApi): unknown {
  const pc = api.pluginConfig;
  if (
    pc &&
    typeof pc.url === "string" &&
    typeof pc.passphrase === "string" &&
    typeof pc.name === "string"
  ) {
    const account: ChannelAccountConfig = {
      url: pc.url as string,
      passphrase: pc.passphrase as string,
      name: pc.name as string,
    };
    return {
      channels: { [PLUGIN_ID]: { [SINGLE_ACCOUNT_ID]: account } },
    };
  }
  return api.config ?? {};
}

const definition = {
  id: PLUGIN_ID,
  name: "IronMesh",
  description:
    "Send and receive messages over the IronMesh peer-to-peer mesh. " +
    "End-to-end encrypted, no cloud, your network only.",
  configSchema: ChannelConfigSchema,

  register(api: OpenClawPluginApi) {
    const log = api.logger ?? {
      info: (m: string) => console.log(`[ironmesh-channel] ${m}`),
      warn: (m: string) => console.warn(`[ironmesh-channel] ${m}`),
      error: (m: string) => console.error(`[ironmesh-channel] ${m}`),
    };
    log.info(`registering channel plugin id=${PLUGIN_ID}`);

    const plugin = ironMeshChannelPlugin({
      // Wrap the resolvers so they always see a config tree the helpers
      // understand, regardless of whether the operator configured
      // single-account or multi-account.
      listAccountIds: (_cfg) => listChannelAccountIds(buildBridgedCfg(api)),
      resolveAccount: (_cfg, accountId) =>
        resolveChannelAccount(buildBridgedCfg(api), accountId),
      logger: log,
    });

    api.registerChannel(plugin);
    log.info("channel registration complete");
  },
};

export default definition;
