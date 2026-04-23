// IronMeshClient — connects to an IronMesh daemon over WebSocket, runs
// the 3-stage passphrase + ECDH + signed-HELLO handshake, then exchanges
// SecretBox-sealed binary frames.
//
// Reference: bridge.py for the server-side state machine, protocol.py
// Frame.serialize_and_encrypt() for the binary frame layout, and
// crypto.py for the encryption primitives.

import { randomUUID } from "node:crypto";
import { Buffer } from "node:buffer";
import WebSocket, { type RawData } from "ws";

import {
  generateIdentityKeypair,
  type IdentityKeypair,
  nodeId as deriveNodeId,
  secretBoxOpen,
  secretBoxSeal,
  signDetached,
  verifyDetached,
} from "./crypto.js";
import {
  decode as decodeFrame,
  encode as encodeFrame,
  FLAG_HIGH_PRIORITY,
  FLAG_CRITICAL_PRIORITY,
} from "./frame.js";
import { performHandshake, type HandshakeResult } from "./handshake.js";
import { verifyOrPin, PinMismatchError, PinNotFoundError } from "./pinstore.js";
import type {
  ClientOptions,
  ClientEvents,
  IncomingMessage,
  PeerInfo,
  Hex,
  SendMessageOpts,
} from "./types.js";

type EventName = keyof ClientEvents;
type Listener<E extends EventName> = ClientEvents[E];

interface InternalState {
  ws: WebSocket | null;
  hsResult: HandshakeResult | null;
  identity: IdentityKeypair;
  sequence: bigint;
}

function priorityFlags(priority: string | undefined): number {
  if (priority === "HIGH") return FLAG_HIGH_PRIORITY;
  if (priority === "CRITICAL") return FLAG_CRITICAL_PRIORITY;
  return 0;
}

export class IronMeshClient {
  private readonly opts: Required<
    Pick<ClientOptions, "url" | "passphrase" | "autoReconnect" | "reconnectInitialDelayMs">
  > &
    Pick<ClientOptions, "name" | "capabilities" | "tofu" | "pinFile">;
  // Typed-but-erased internal storage. The mapped-type record at
  // the public surface (`{ [E in EventName]?: Set<Listener<E>> }`)
  // can't be assigned-into without a cast because TS can't track the
  // per-key Listener type through a write. Using `Set<unknown>` as the
  // storage type and re-narrowing in on/off/_emit retires the
  // `as Set<Listener<E>> as never` double-cast that read like a hack.
  private listeners: Partial<Record<EventName, Set<unknown>>> = {};
  private state: InternalState;
  private connecting = false;
  private intentionallyClosed = false;
  // Exponential backoff state. Capped at 30s with ±20% jitter.
  // Reset to 0 on successful connect.
  private reconnectAttempt = 0;
  // Test seam — vitest tests can stub these to verify backoff math
  // without sleeping. Real callers leave defaults.
  /** @internal */ _now: () => number = Date.now;
  /** @internal */ _setTimeout: (fn: () => void, ms: number) => unknown =
    (fn, ms) => setTimeout(fn, ms);
  /** @internal */ _random: () => number = Math.random;

  constructor(options: ClientOptions, identity?: IdentityKeypair) {
    if (!options.url) throw new Error("ClientOptions.url is required");
    if (!options.passphrase) throw new Error("ClientOptions.passphrase is required");
    this.opts = {
      url: options.url,
      passphrase: options.passphrase,
      autoReconnect: options.autoReconnect ?? true,
      reconnectInitialDelayMs: options.reconnectInitialDelayMs ?? 500,
      name: options.name ?? "ts-client",
      capabilities: options.capabilities,
      tofu: options.tofu,
      pinFile: options.pinFile,
    };
    this.state = {
      ws: null,
      hsResult: null,
      identity: identity ?? generateIdentityKeypair(),
      sequence: 0n,
    };
  }

  /** Our derived node_id (32-hex). Available before any connect. */
  get nodeId(): string {
    return deriveNodeId(this.state.identity.publicKey);
  }

  /** Peer's node_id, set after a successful handshake. */
  get peerNodeId(): string | null {
    return this.state.hsResult?.peerNodeId ?? null;
  }

  isConnected(): boolean {
    return (
      this.state.ws !== null &&
      this.state.ws.readyState === WebSocket.OPEN &&
      this.state.hsResult !== null
    );
  }

  /**
   * Open the WebSocket and run the full handshake. Resolves once the
   * client is ready to send/receive. Rejects on handshake failure.
   */
  async connect(): Promise<void> {
    if (this.isConnected()) return;
    if (this.connecting) {
      throw new Error("connect: already in progress");
    }
    this.connecting = true;
    this.intentionallyClosed = false;
    // Each session has its own sequence space. The daemon's replay
    // guard is per-peer+session; if we carry an old counter across a
    // reconnect, the first frame of the new session will use a seq
    // number that has no meaning to the new session_key. Start fresh.
    this.state.sequence = 0n;
    try {
      const ws = new WebSocket(this.opts.url);
      this.state.ws = ws;

      await new Promise<void>((resolve, reject) => {
        const onOpen = () => {
          ws.removeListener("error", onErr);
          resolve();
        };
        const onErr = (err: Error) => {
          ws.removeListener("open", onOpen);
          reject(err);
        };
        ws.once("open", onOpen);
        ws.once("error", onErr);
      });

      // Buffer text frames during handshake. The daemon only sends text
      // (JSON) until handshake completes; once we hand off to the post-
      // handshake loop, text frames end and binary frames begin.
      const textBuffer: string[] = [];
      const textWaiters: Array<(s: string) => void> = [];
      const errorWaiters: Array<(e: Error) => void> = [];

      const handshakeMessage = (data: RawData) => {
        const text = data.toString("utf8");
        const waiter = textWaiters.shift();
        if (waiter) waiter(text);
        else textBuffer.push(text);
      };
      const handshakeError = (e: Error) => {
        const eWaiter = errorWaiters.shift();
        if (eWaiter) eWaiter(e);
      };
      ws.on("message", handshakeMessage);
      ws.on("error", handshakeError);

      const recv = (): Promise<string> => {
        const queued = textBuffer.shift();
        if (queued !== undefined) return Promise.resolve(queued);
        return new Promise<string>((resolve, reject) => {
          textWaiters.push(resolve);
          errorWaiters.push(reject);
        });
      };
      const send = (text: string): void => {
        ws.send(text);
      };

      const result = await performHandshake({
        passphrase: this.opts.passphrase,
        agentName: this.opts.name ?? "ts-client",
        identity: this.state.identity,
        send,
        recv,
      });

      // TOFU pin enforcement (v0.8.5.5). When `pinFile` is set, verify the
      // peer's identity fingerprint against the stored pin. First contact
      // writes the pin (unless tofu === "strict"). Mismatch refuses the
      // connection — the daemon either rotated keys legitimately (clear
      // the pin) or someone is impersonating it.
      if (this.opts.pinFile) {
        try {
          const tofuMode = this.opts.tofu ?? "trust-on-first-use";
          await verifyOrPin(
            this.opts.pinFile,
            this.opts.url,
            result.peerNodeId,
            tofuMode,
          );
        } catch (err) {
          // Tear down the WebSocket so the user cannot proceed against
          // an unverified peer. Re-throw so connect() rejects.
          try { ws.close(); } catch { /* already closed */ }
          this.state.ws = null;
          if (err instanceof PinMismatchError || err instanceof PinNotFoundError) {
            throw err;
          }
          throw new Error(`pin file check failed: ${(err as Error).message}`);
        }
      }

      this.state.hsResult = result;

      // Detach handshake-only listeners; install the long-lived loop.
      ws.removeListener("message", handshakeMessage);
      this._wireMessageLoop(ws);

      // Wire close/error to event API.
      ws.once("close", (code, reasonBuf) => {
        const reason = `closed (${code}${reasonBuf?.length ? `: ${reasonBuf.toString()}` : ""})`;
        this.state.ws = null;
        this.state.hsResult = null;
        this._emit("disconnect", reason);
        if (!this.intentionallyClosed && this.opts.autoReconnect) {
          this._scheduleReconnect();
        }
      });
      ws.on("error", (err) => this._emit("error", err));

      this._emit("connect");
    } finally {
      this.connecting = false;
    }
  }

  async disconnect(): Promise<void> {
    this.intentionallyClosed = true;
    const ws = this.state.ws;
    if (!ws) return;
    return new Promise<void>((resolve) => {
      ws.once("close", () => resolve());
      ws.close(1000, "client disconnect");
    });
  }

  /**
   * Send a MSG to the connected peer. Returns the locally-generated
   * msg_id. Throws if not connected.
   */
  async sendMessage(
    payload: Uint8Array | string,
    opts: SendMessageOpts = {},
  ): Promise<{ msgId: string }> {
    if (!this.isConnected() || !this.state.ws || !this.state.hsResult) {
      throw new Error("sendMessage: not connected");
    }
    const payloadBytes =
      typeof payload === "string" ? new TextEncoder().encode(payload) : payload;
    const msgId = randomUUID().replace(/-/g, "");
    const msgType = opts.type ?? "MSG";
    this.state.sequence += 1n;

    // Route via the daemon's mesh router if the caller supplied a
    // distinct destination; otherwise the handshake peer is the
    // implicit recipient. The daemon's CAPABILITY_ANNOUNCE-driven
    // routing table handles the relay; we just have to set the
    // `destination` field correctly in the encrypted envelope.
    const destination =
      opts.toNodeId && /^[0-9a-fA-F]{32}$/.test(opts.toNodeId)
        ? opts.toNodeId.toLowerCase()
        : this.state.hsResult.peerNodeId;
    const inner = {
      type: msgType,
      payload: Buffer.from(payloadBytes).toString("base64"),
      msg_id: msgId,
      source: this.state.hsResult.myNodeId,
      source_display: this.opts.name,
      destination,
      // Date.now()/1000 gives ms-precision floats (e.g.
      // 1729203847.123). Python's time.time() can return higher
      // precision (μs). Both serialize identically through JSON, and
      // the daemon's replay-guard windows are seconds-wide, so this
      // is fine — but if you're comparing timestamps for deduplication
      // across implementations, expect the TS side to be coarser.
      timestamp: Date.now() / 1000,
      priority: opts.priority ?? "NORMAL",
      sequence: Number(this.state.sequence),
      retries: 0,
      routing: {} as Record<string, unknown>,
      ttl: 3,
      hops: [] as string[],
    };
    const innerBytes = new TextEncoder().encode(JSON.stringify(inner));
    const encrypted = secretBoxSeal(this.state.hsResult.sessionKey, innerBytes);
    const sig = signDetached(this.state.identity.secretKey, encrypted);
    const wire = encodeFrame({
      flags: priorityFlags(opts.priority),
      sequence: this.state.sequence,
      msgId,
      encrypted,
      signature: sig,
    });
    this.state.ws.send(wire, { binary: true });
    return { msgId };
  }

  /** A trimmed peer view — node_id and agent_name from the handshake. */
  async listPeers(): Promise<PeerInfo[]> {
    if (!this.state.hsResult) return [];
    const r = this.state.hsResult;
    return [
      {
        nodeId: r.peerNodeId as Hex,
        agentName: r.peerAgentName,
        online: this.isConnected(),
      },
    ];
  }

  // ------------------------------------------------------------------
  // Event API
  // ------------------------------------------------------------------

  on<E extends EventName>(event: E, listener: Listener<E>): this {
    let set = this.listeners[event];
    if (!set) {
      set = new Set();
      this.listeners[event] = set;
    }
    set.add(listener as unknown);
    return this;
  }

  off<E extends EventName>(event: E, listener: Listener<E>): this {
    this.listeners[event]?.delete(listener as unknown);
    return this;
  }

  /** @internal — public for tests so synthetic events can be injected. */
  _emit<E extends EventName>(event: E, ...args: Parameters<Listener<E>>): void {
    const set = this.listeners[event];
    if (!set) return;
    for (const l of set) {
      try {
        (l as (...a: unknown[]) => void)(...args);
      } catch (e) {
        // eslint-disable-next-line no-console
        console.error("ironmesh-client listener threw:", e);
      }
    }
  }

  // ------------------------------------------------------------------
  // Internal
  // ------------------------------------------------------------------

  private _wireMessageLoop(ws: WebSocket): void {
    ws.on("message", (data: RawData) => {
      try {
        const buf = Buffer.isBuffer(data)
          ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
          : new Uint8Array(Buffer.from(data as ArrayBuffer));
        this._handleIncoming(buf);
      } catch (e) {
        this._emit("error", e instanceof Error ? e : new Error(String(e)));
      }
    });
  }

  private _handleIncoming(buf: Uint8Array): void {
    if (!this.state.hsResult) return;
    // Try binary first (preferred wire format)
    if (buf[0] === 0xe7 && buf[1] === 0xf6) {
      const frame = decodeFrame(buf);
      // Drop seq=0 frames. The daemon enforces seq > 0 on inbound
      // post-handshake messages (bridge.py:2216-2218); a peer that
      // sends seq=0 is buggy or malicious. The SecretBox AEAD already
      // rejects ciphertext that doesn't decrypt, but seq=0 lets a
      // bug-by-construction frame through to the application layer.
      if (frame.sequence === 0n) {
        this._emit(
          "error",
          new Error("dropped inbound frame with sequence=0"),
        );
        return;
      }
      // Outer signature verification — the daemon signs binary frames
      // with its hop-authentication identity. For 1-hop direct delivery
      // that key is the same as the handshake peer's identity. For
      // mesh-relayed frames, the outer sig is the relayer's identity,
      // not the originator's — so verification against
      // `peerIdentityPublic` will FAIL on every relayed frame even
      // though the frame is legitimate.
      //
      // Treat outer-sig mismatch as a soft warning, not a drop. The
      // SecretBox AEAD tag below provides authenticity for the
      // ciphertext; an inner end-to-end source signature (when present)
      // remains the authoritative trust anchor for the originator.
      if (frame.signature) {
        const ok = verifyDetached(
          this.state.hsResult.peerIdentityPublic,
          frame.encrypted,
          frame.signature,
        );
        if (!ok) {
          this._emit(
            "error",
            new Error(
              "incoming frame outer signature did not match handshake peer's " +
                "identity — this is expected for mesh-relayed frames; " +
                "frame is being dispatched on AEAD authenticity alone",
            ),
          );
        }
      }
      const plaintext = secretBoxOpen(this.state.hsResult.sessionKey, frame.encrypted);
      const inner = JSON.parse(new TextDecoder().decode(plaintext)) as Record<
        string,
        unknown
      >;
      this._dispatchInner(inner, Number(frame.timestamp));
      return;
    }

    // Fallback: legacy JSON envelope (text frame).
    const text = new TextDecoder().decode(buf);
    if (text.startsWith("{")) {
      try {
        const msg = JSON.parse(text) as Record<string, unknown>;
        const enc = msg.encrypted_payload as string | undefined;
        if (enc) {
          const ct = new Uint8Array(Buffer.from(enc, "base64"));
          const plaintext = secretBoxOpen(this.state.hsResult.sessionKey, ct);
          const inner = JSON.parse(new TextDecoder().decode(plaintext)) as Record<
            string,
            unknown
          >;
          this._dispatchInner(inner, Math.floor(Date.now()));
          return;
        }
        // Plain JSON (control message — peer events, etc.)
        this._dispatchControl(msg);
      } catch (e) {
        this._emit("error", e instanceof Error ? e : new Error(String(e)));
      }
    }
  }

  private _dispatchInner(inner: Record<string, unknown>, tsMs: number): void {
    const msgType = String(inner.type ?? "MSG");
    const fromNodeId = String(inner.source ?? "");
    const msgId = String(inner.msg_id ?? "");
    const payloadB64 = (inner.payload as string | undefined) ?? "";
    const payload = payloadB64
      ? new Uint8Array(Buffer.from(payloadB64, "base64"))
      : new Uint8Array(0);
    const event: IncomingMessage = {
      msgType,
      fromNodeId,
      payload,
      msgId,
      timestamp: tsMs,
    };
    this._emit("message", event);
  }

  private _dispatchControl(msg: Record<string, unknown>): void {
    const t = String(msg.type ?? "");
    if (t === "PEER_INFO" || t === "PEER_CONNECT" || t === "PEER_DISCONNECT") {
      const peer: PeerInfo = {
        nodeId: String(msg.peer_id ?? "") as Hex,
        agentName: msg.name as string | undefined,
        online: t !== "PEER_DISCONNECT",
      };
      this._emit(t === "PEER_DISCONNECT" ? "peerDisconnect" : "peerConnect", peer);
    }
  }

  /**
   * Compute the next reconnect delay (ms) given current attempt count.
   * Schedule: initialDelay × 2^attempt, capped at 30 s, with ±20%
   * jitter applied multiplicatively to break thundering-herd patterns
   * across many clients reconnecting to the same daemon.
   * Exposed for tests; not part of the public API.
   * @internal
   */
  _nextBackoffDelayMs(): number {
    const base = this.opts.reconnectInitialDelayMs * Math.pow(2, this.reconnectAttempt);
    const capped = Math.min(base, 30_000);
    const jitter = 1 + (this._random() * 0.4 - 0.2); // [-20%, +20%]
    return Math.max(0, Math.floor(capped * jitter));
  }

  private _scheduleReconnect(): void {
    const delay = this._nextBackoffDelayMs();
    this.reconnectAttempt += 1;
    this._setTimeout(() => {
      if (this.intentionallyClosed) return;
      this.connect()
        .then(() => {
          // Successful reconnect — reset the backoff so the next
          // disconnect starts fresh from the initial delay.
          this.reconnectAttempt = 0;
        })
        .catch((e) => this._emit("error", e));
    }, delay);
  }
}

export type { ClientOptions, IncomingMessage, PeerInfo, SendMessageOpts };
