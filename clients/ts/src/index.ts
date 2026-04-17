// Public entry point for @wiztheagent/ironmesh-client.

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

export {
  generateIdentityKeypair,
  type IdentityKeypair,
  nodeId,
} from "./crypto.js";

export const VERSION = "0.1.0-alpha.2"; // tracks package.json
