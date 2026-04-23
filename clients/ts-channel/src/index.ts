// Public entry point for @wiztheagent/openclaw-ironmesh.

export { ironMeshChannelPlugin } from "./plugin.js";
export type {
  IronMeshChannelPlugin,
  IronMeshChannelPluginOptions,
} from "./plugin.js";
export type {
  ChannelCapabilities,
  ChannelInboundMessage,
  ChannelMeta,
  ChannelOutboundContext,
  ChannelSendResult,
  IronMeshChannelAccount,
  PluginLogger,
} from "./types.js";

export { PluginState } from "./persistence.js";
export type { PeerRecord, PersistedState, PersistenceOptions } from "./persistence.js";

export { PeerMapper } from "./peer-mapper.js";
export type { DirectoryContact, LivePeerObservation } from "./peer-mapper.js";

export {
  validateChannelConfig,
  resolveChannelAccount,
  listChannelAccountIds,
  ChannelConfigSchema,
} from "./config-schema.js";
export type {
  ChannelAccountConfig,
  ChannelConfigTree,
  ChannelValidationError,
} from "./config-schema.js";

// Default-exported plugin definition consumed by OpenClaw at gateway
// startup via the openclaw.extensions entry path. Re-exported for
// programmatic consumers that want to inspect or wrap it.
export { default as ironMeshPluginDefinition } from "./entry.js";

export const VERSION = "0.2.0";
