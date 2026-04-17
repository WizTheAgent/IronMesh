// IronMeshClient — alpha-quality scaffold for the TS client.
//
// Status: structural scaffold only. The connect / handshake / send paths
// throw NotImplemented until the binary frame and ECDH handshake are
// ported from protocol.py. Issue tracking the impl: M2/M3 of the
// OpenClaw integration plan.
//
// Why ship the scaffold first: lets the OpenClaw channel plugin (Path B)
// import a stable type surface and start building UI without waiting on
// the wire-protocol port. The plugin can mock the client during its own
// dev cycles.

import type {
  ClientOptions,
  ClientEvents,
  IncomingMessage,
  PeerInfo,
  SendMessageOpts,
  Hex,
} from "./types.js";

type EventName = keyof ClientEvents;
type Listener<E extends EventName> = ClientEvents[E];

export class IronMeshClient {
  private readonly opts: Required<Omit<ClientOptions, "pinFile" | "tofu" | "capabilities" | "name">> &
    Pick<ClientOptions, "pinFile" | "tofu" | "capabilities" | "name">;
  private listeners: { [E in EventName]?: Set<Listener<E>> } = {};
  private connected = false;

  constructor(options: ClientOptions) {
    if (!options.url) throw new Error("ClientOptions.url is required");
    if (!options.passphrase) throw new Error("ClientOptions.passphrase is required");
    this.opts = {
      url: options.url,
      passphrase: options.passphrase,
      autoReconnect: options.autoReconnect ?? true,
      reconnectInitialDelayMs: options.reconnectInitialDelayMs ?? 500,
      name: options.name,
      capabilities: options.capabilities,
      tofu: options.tofu,
      pinFile: options.pinFile,
    };
  }

  // ------------------------------------------------------------------
  // Connection lifecycle
  // ------------------------------------------------------------------

  /**
   * Open the WebSocket, run the IronMesh passphrase + ECDH handshake,
   * advertise capabilities, then begin streaming events.
   *
   * NOT YET IMPLEMENTED — see handshake.ts / frame.ts (M2 work).
   */
  async connect(): Promise<void> {
    throw new Error(
      "IronMeshClient.connect: not implemented. The handshake + binary " +
        "frame v4 paths still need to be ported from protocol.py. See " +
        "docs/OPENCLAW_CHANNEL_SETUP.md (when written) for the impl order."
    );
  }

  async disconnect(): Promise<void> {
    this.connected = false;
  }

  isConnected(): boolean {
    return this.connected;
  }

  // ------------------------------------------------------------------
  // Messaging
  // ------------------------------------------------------------------

  async sendMessage(
    _target: Hex | string,
    _payload: Uint8Array | string,
    _opts: SendMessageOpts = {}
  ): Promise<{ msgId: string }> {
    throw new Error("IronMeshClient.sendMessage: not implemented (M2)");
  }

  async listPeers(): Promise<PeerInfo[]> {
    throw new Error("IronMeshClient.listPeers: not implemented (M2)");
  }

  // ------------------------------------------------------------------
  // Event API (typed wrappers around an internal map of listener sets)
  // ------------------------------------------------------------------

  on<E extends EventName>(event: E, listener: Listener<E>): this {
    let set = this.listeners[event] as Set<Listener<E>> | undefined;
    if (!set) {
      set = new Set();
      this.listeners[event] = set as Set<Listener<E>> as never;
    }
    set.add(listener);
    return this;
  }

  off<E extends EventName>(event: E, listener: Listener<E>): this {
    const set = this.listeners[event] as Set<Listener<E>> | undefined;
    set?.delete(listener);
    return this;
  }

  // Test seam — mirrors the on() type, lets tests inject events without
  // a real WS round-trip. Will become private once connect() is wired.
  _emit<E extends EventName>(event: E, ...args: Parameters<Listener<E>>): void {
    const set = this.listeners[event] as Set<Listener<E>> | undefined;
    if (!set) return;
    for (const l of set) {
      try {
        // The cast to (...args: any[]) keeps the variadic type checker happy
        // without losing the callsite's parameter typing through Listener<E>.
        (l as (...a: unknown[]) => void)(...args);
      } catch (e) {
        // eslint-disable-next-line no-console
        console.error("ironmesh-client listener threw:", e);
      }
    }
  }
}

export type { ClientOptions, IncomingMessage, PeerInfo, SendMessageOpts };
