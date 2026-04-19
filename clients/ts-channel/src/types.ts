// Local type definitions matching the subset of OpenClaw's
// `dist/plugin-sdk/src/channels/plugins/types.plugin.d.ts` that this
// alpha plugin actually implements. We don't import from the openclaw
// package to keep this package installable without a peer dep at
// dev time. OpenClaw checks the contract structurally at load time.

export type ChannelId = string;

/** User-facing metadata used in docs, pickers, and setup surfaces. */
export interface ChannelMeta {
  id: ChannelId;
  label: string;
  selectionLabel: string;
  docsPath: string;
  docsLabel?: string;
  blurb: string;
}

/** What this channel says it can do. Conservative for the alpha. */
export interface ChannelCapabilities {
  /** Can the channel deliver outbound text replies? */
  outbound?: boolean;
  /** Can it surface inbound messages to agents? */
  inbound?: boolean;
  /** Does it support per-recipient targeting (DMs)? */
  directMessages?: boolean;
  /** Group / multi-party rooms (we use mesh broadcast, kept off in alpha). */
  groups?: boolean;
  /** Read-receipts, typing, etc. — none in alpha. */
  presence?: boolean;
  /** Streaming partial replies — none in alpha. */
  streaming?: boolean;
}

/** Resolved per-account state — alpha treats every config as one account. */
export interface IronMeshChannelAccount {
  accountId: string;
  url: string;
  passphrase: string;
  name: string;
}

/** Outbound payload OpenClaw hands us when an agent wants to send. */
export interface ChannelOutboundContext {
  accountId: string;
  /** Target peer agent name OR 32-hex node_id. */
  to: string;
  /** Message body, already templated. */
  text: string;
  /** Optional thread / correlation id from the caller. */
  threadId?: string;
  /** Optional priority hint. */
  priority?: "CRITICAL" | "HIGH" | "NORMAL" | "LOW";
}

/** Result of attempting to send. */
export interface ChannelSendResult {
  ok: boolean;
  msgId?: string;
  error?: string;
}

/** Inbound message OpenClaw expects from us. */
export interface ChannelInboundMessage {
  channel: ChannelId;
  accountId: string;
  /** The peer that sent it (their agent name if known, else node_id). */
  fromId: string;
  fromName?: string;
  /** Plain-text body. */
  text: string;
  /** Original IronMesh msg_id for traceability. */
  externalId?: string;
  /** ms-since-epoch. */
  timestamp: number;
}

/** Subscription handle returned by the messaging adapter. */
export interface InboundSubscription {
  close(): Promise<void> | void;
}

/** A logger compatible with OpenClaw's PluginLogger surface. */
export interface PluginLogger {
  info(msg: string, ...args: unknown[]): void;
  warn(msg: string, ...args: unknown[]): void;
  error(msg: string, ...args: unknown[]): void;
  debug?(msg: string, ...args: unknown[]): void;
}
