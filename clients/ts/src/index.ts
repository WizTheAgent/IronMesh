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

export {
  verifyOrPin,
  clearPin,
  listPins,
  PinMismatchError,
  PinNotFoundError,
  type PinEntry,
  type PinFile,
} from "./pinstore.js";

export const VERSION = "0.2.0"; // tracks package.json
