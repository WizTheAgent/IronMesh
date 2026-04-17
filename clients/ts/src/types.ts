// Shared types for the IronMesh TS client.

export type Hex = string;

export interface ClientOptions {
  /** ws:// or wss:// URL of the IronMesh daemon's plugin endpoint. */
  url: string;
  /** Mesh-wide passphrase. Required — no plaintext-WS fallback. */
  passphrase: string;
  /** Display name advertised on HELLO (default: "ts-client"). */
  name?: string;
  /** Capabilities to advertise on connect (default: []). */
  capabilities?: string[];
  /** Reconnect on disconnect (default: true). */
  autoReconnect?: boolean;
  /** Initial backoff in ms (default: 500). Doubles up to 30s cap. */
  reconnectInitialDelayMs?: number;
  /** TOFU policy for the daemon's identity key (default: "trust-on-first-use"). */
  tofu?: "trust-on-first-use" | "strict";
  /**
   * Path to a JSON file storing pinned daemon fingerprints. When set, the
   * client refuses to connect to a daemon whose Ed25519 fingerprint
   * doesn't match the pinned value (after first contact).
   */
  pinFile?: string;
}

export interface PeerInfo {
  nodeId: Hex;
  agentName?: string;
  online: boolean;
  rttMs?: number;
}

export type Priority = "CRITICAL" | "HIGH" | "NORMAL" | "LOW";

export interface SendMessageOpts {
  type?: string;
  priority?: Priority;
}

export interface IncomingMessage {
  msgType: string;
  fromNodeId: Hex;
  payload: Uint8Array;
  msgId: string;
  timestamp: number;
}

export type EventListener<T = unknown> = (data: T) => void;

export interface ClientEvents {
  connect: () => void;
  disconnect: (reason: string) => void;
  peerConnect: (peer: PeerInfo) => void;
  peerDisconnect: (peer: PeerInfo) => void;
  message: (msg: IncomingMessage) => void;
  error: (err: Error) => void;
}
