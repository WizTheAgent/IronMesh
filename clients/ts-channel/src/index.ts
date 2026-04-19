// Public entry point for @wiztheagent/openclaw-ironmesh-channel.

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

export { defineIronMeshChannelEntry } from "./entry.js";
export type { IronMeshChannelEntryOptions } from "./entry.js";

export const VERSION = "0.1.0";
