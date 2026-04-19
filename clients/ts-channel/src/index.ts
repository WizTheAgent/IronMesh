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

export const VERSION = "0.1.0-alpha.1";
