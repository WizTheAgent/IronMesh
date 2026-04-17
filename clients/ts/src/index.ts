// Public entry point for @wiztheagent/ironmesh-client.
//
// This is an alpha-quality scaffold. The connect / send / handshake
// paths throw until the binary frame and handshake are ported from
// protocol.py — see clients/ts/README.md for status.

export { IronMeshClient } from "./client.js";
export type {
  ClientOptions,
  ClientEvents,
  IncomingMessage,
  PeerInfo,
  SendMessageOpts,
  Priority,
  Hex,
  EventListener,
} from "./types.js";

export const VERSION = "0.1.0-alpha.1";
