// C2: outer-signature failure on inbound binary frames must NOT drop
// the frame. Mesh-relayed frames are signed by the relayer's identity,
// not the originator's; verifying against the handshake peer's
// identity will fail in that case. We treat the failure as a soft
// warning and dispatch on AEAD authenticity alone.

import { Buffer } from "node:buffer";
import { beforeEach, describe, expect, it } from "vitest";
import nacl from "tweetnacl";

import { IronMeshClient } from "../src/index.js";
import {
  generateEphemeralKeypair,
  generateIdentityKeypair,
  ecdh,
  secretBoxSeal,
  signDetached,
} from "../src/crypto.js";
import { encode as encodeFrame } from "../src/frame.js";

/**
 * Build a fully-formed binary frame as if it came from a relay (signed
 * with `relayerIdentity`, not the handshake-peer's identity), then push
 * it through the client's incoming-frame handler via the test seam.
 */
function craftRelayFrame(
  sessionKey: Uint8Array,
  payload: object,
  relayerIdentity: { secretKey: Uint8Array },
  sequence: bigint,
): Uint8Array {
  const inner = new TextEncoder().encode(JSON.stringify(payload));
  const ct = secretBoxSeal(sessionKey, inner);
  const sig = signDetached(relayerIdentity.secretKey, ct);
  return encodeFrame({
    msgId: "relay-test",
    encrypted: ct,
    signature: sig,
    sequence,
  });
}

describe("C2: relayed frame outer-sig", () => {
  let client: IronMeshClient;
  let sessionKey: Uint8Array;
  let handshakePeerIdentity: { publicKey: Uint8Array; secretKey: Uint8Array };
  let relayerIdentity: { publicKey: Uint8Array; secretKey: Uint8Array };

  beforeEach(() => {
    // Build a client and force-inject a synthetic handshake result so
    // we can drive _handleIncoming directly without a real WebSocket.
    client = new IronMeshClient({
      url: "ws://test",
      passphrase: "x",
      autoReconnect: false,
    });

    // Two distinct identities — handshake peer vs upstream relayer
    handshakePeerIdentity = generateIdentityKeypair();
    relayerIdentity = generateIdentityKeypair();

    // Synthesize a session key from a one-shot ECDH
    const myEph = generateEphemeralKeypair();
    const peerEph = generateEphemeralKeypair();
    sessionKey = ecdh(myEph.secretKey, peerEph.publicKey);

    // Reach into private state — same shape performHandshake produces
    // and that _handleIncoming consumes (client.ts:91, 318).
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (client as any).state.hsResult = {
      sessionKey,
      myNodeId: "0".repeat(32),
      peerNodeId: "1".repeat(32),
      peerAgentName: "test-peer",
      protocolVersion: "ironmesh/0.6",
      peerIdentityPublic: handshakePeerIdentity.publicKey,
      serverNonce: new Uint8Array(32),
    };
  });

  it("dispatches a relayed frame and emits a warning instead of dropping", async () => {
    const messages: { msgType: string; body: string }[] = [];
    const errors: string[] = [];
    client.on("message", (m) => {
      messages.push({
        msgType: m.msgType,
        body: new TextDecoder().decode(m.payload),
      });
    });
    client.on("error", (e) => errors.push(e.message));

    const frame = craftRelayFrame(
      sessionKey,
      {
        type: "MSG",
        payload: Buffer.from("hello-via-relay").toString("base64"),
        msg_id: "x",
        source: "0".repeat(32),
        sequence: 1,
      },
      relayerIdentity, // signed by an identity the client doesn't know
      1n,
    );

    // Drive the private path
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (client as any)._handleIncoming(frame);

    expect(messages.length).toBe(1);
    expect(messages[0].msgType).toBe("MSG");
    expect(messages[0].body).toBe("hello-via-relay");
    expect(errors.length).toBe(1);
    expect(errors[0]).toMatch(/outer signature did not match/);
    expect(errors[0]).toMatch(/AEAD/);
  });

  it("drops a frame whose sequence is 0 with a warning", () => {
    const messages: { msgType: string }[] = [];
    const errors: string[] = [];
    client.on("message", (m) => messages.push({ msgType: m.msgType }));
    client.on("error", (e) => errors.push(e.message));

    const frame = craftRelayFrame(
      sessionKey,
      {
        type: "MSG",
        payload: Buffer.from("seq-zero").toString("base64"),
        msg_id: "x",
        source: "1".repeat(32),
        sequence: 0,
      },
      handshakePeerIdentity,
      0n, // <-- the protocol violation
    );

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (client as any)._handleIncoming(frame);

    expect(messages.length).toBe(0);
    expect(errors.find((e) => /sequence=0/.test(e))).toBeDefined();
  });

  it("dispatches a 1-hop frame (sig matches handshake peer) without warning", async () => {
    const messages: { msgType: string; body: string }[] = [];
    const errors: string[] = [];
    client.on("message", (m) => {
      messages.push({
        msgType: m.msgType,
        body: new TextDecoder().decode(m.payload),
      });
    });
    client.on("error", (e) => errors.push(e.message));

    const frame = craftRelayFrame(
      sessionKey,
      {
        type: "MSG",
        payload: Buffer.from("hello-direct").toString("base64"),
        msg_id: "x",
        source: "1".repeat(32),
        sequence: 2,
      },
      handshakePeerIdentity, // signed by the handshake peer (1-hop case)
      2n,
    );

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (client as any)._handleIncoming(frame);

    expect(messages.length).toBe(1);
    expect(messages[0].body).toBe("hello-direct");
    expect(errors.length).toBe(0);
  });
});

// Use _ to acknowledge nacl is referenced at import (used by helpers above)
void nacl;
