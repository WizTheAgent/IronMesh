// IronMesh handshake — TypeScript port of the 3-stage protocol that
// `bridge.py` runs over each WebSocket connection.
//
//   Stage 1: PASSPHRASE_CHALLENGE
//     Server →  { type: "PASSPHRASE_CHALLENGE", nonce: <32-hex> }
//     Client →  { type: "PASSPHRASE_RESPONSE",  proof: HMAC-SHA256(passphrase, nonce) }
//     Server →  { type: "PASSPHRASE_VERIFIED",  server_proof: HMAC-SHA256(passphrase, nonce_reversed) }
//                — or PASSPHRASE_REJECTED on mismatch.
//
//   Stage 2: HELLO (mutual)
//     Each side sends a signed HELLO with ephemeral X25519 pub, ed25519 identity,
//     name, protocol version, and channel_binding (= server's nonce hex).
//     `signature` is base64(NaCl-attached-sign(secret, canonical-json(body))).
//     The server reconstructs the canonical body and validates the signature;
//     do likewise for the peer's HELLO before deriving the session key.
//
//   Stage 3: ECDH (implicit)
//     Both sides compute session_key = X25519(my_eph_priv, peer_eph_pub).
//     All subsequent frames use SecretBox(session_key, nonce || plaintext).
//
// Reference: bridge.py around line 1500-1700 for the server-side dance,
// clients/go/ironmesh/handshake.go for a working detached-signature port
// (we use attached-form signatures here to match the Python verifier
// exactly; the Go client's detached form happens to work because the
// server is lenient, but matching attached is correct).

import {
  type IdentityKeypair,
  canonicalJson,
  ecdh,
  generateEphemeralKeypair,
  nodeId,
  passphraseProof,
  signAttached,
  verifyAttached,
  verifyPassphraseProof,
} from "./crypto.js";

const PROTOCOL_VERSION = "ironmesh/0.6";

export interface HandshakeOptions {
  passphrase: string;
  agentName: string;
  identity: IdentityKeypair;
  /** Send a JSON-stringified frame to the peer. */
  send: (text: string) => Promise<void> | void;
  /** Read the next text frame from the peer. */
  recv: () => Promise<string>;
  /** Optional capability strings to advertise on HELLO (post-stage-2). */
  capabilities?: string[];
}

export interface HandshakeResult {
  /** 32-byte ECDH shared secret — use as SecretBox key for all subsequent frames. */
  sessionKey: Uint8Array;
  /** Our node_id (32 hex chars). */
  myNodeId: string;
  /** Peer's node_id (32 hex chars). */
  peerNodeId: string;
  /** Peer's agent_name from their HELLO. */
  peerAgentName: string;
  /** Negotiated protocol version string. */
  protocolVersion: string;
  /** Raw peer Ed25519 public key (32 bytes) — for TOFU pinning. */
  peerIdentityPublic: Uint8Array;
  /** The server's nonce (32 bytes) — used as channel_binding. */
  serverNonce: Uint8Array;
}

function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex string must be even-length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function fromBase64(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}

export class HandshakeError extends Error {
  constructor(
    message: string,
    readonly stage: 1 | 2 | 3,
    readonly cause?: unknown,
  ) {
    super(message);
    this.name = "HandshakeError";
  }
}

export async function performHandshake(opts: HandshakeOptions): Promise<HandshakeResult> {
  // --- Stage 1: passphrase challenge ---
  let challengeRaw: string;
  try {
    challengeRaw = await opts.recv();
  } catch (e) {
    throw new HandshakeError("failed to read PASSPHRASE_CHALLENGE", 1, e);
  }

  let challenge: { type: string; nonce?: string };
  try {
    challenge = JSON.parse(challengeRaw);
  } catch (e) {
    throw new HandshakeError("malformed PASSPHRASE_CHALLENGE JSON", 1, e);
  }
  if (challenge.type !== "PASSPHRASE_CHALLENGE" || !challenge.nonce) {
    throw new HandshakeError(`expected PASSPHRASE_CHALLENGE, got ${challenge.type}`, 1);
  }

  const serverNonce = fromHex(challenge.nonce);
  const proof = passphraseProof(opts.passphrase, serverNonce);
  // Note: BOTH directions reuse the type string "PASSPHRASE_CHALLENGE".
  // The server's outgoing message has a `nonce`; the client's response
  // has a `proof`. Server side switches on which field is present.
  // (The Go client sends "PASSPHRASE_RESPONSE" but the daemon strictly
  // requires "PASSPHRASE_CHALLENGE" — see bridge.py line 1531. The Go
  // client only "works" because of unrelated lenience elsewhere.)
  await opts.send(
    JSON.stringify({ type: "PASSPHRASE_CHALLENGE", proof }),
  );

  let verifiedRaw: string;
  try {
    verifiedRaw = await opts.recv();
  } catch (e) {
    throw new HandshakeError("failed to read PASSPHRASE_VERIFIED", 1, e);
  }
  let verified: { type: string; server_proof?: string };
  try {
    verified = JSON.parse(verifiedRaw);
  } catch (e) {
    throw new HandshakeError("malformed PASSPHRASE_VERIFIED JSON", 1, e);
  }
  if (verified.type === "PASSPHRASE_REJECTED") {
    throw new HandshakeError("passphrase rejected by server", 1);
  }
  if (verified.type !== "PASSPHRASE_VERIFIED") {
    throw new HandshakeError(`expected PASSPHRASE_VERIFIED, got ${verified.type}`, 1);
  }

  // Mutual auth: server proves it knows the passphrase by HMACing a reversed nonce.
  const reversed = new Uint8Array(serverNonce.length);
  for (let i = 0; i < serverNonce.length; i++) {
    reversed[i] = serverNonce[serverNonce.length - 1 - i];
  }
  if (!verified.server_proof || !verifyPassphraseProof(verified.server_proof, opts.passphrase, reversed)) {
    throw new HandshakeError("server passphrase proof failed (mutual auth)", 1);
  }

  // --- Stage 2: HELLO exchange ---
  const eph = generateEphemeralKeypair();
  const myNodeId = nodeId(opts.identity.publicKey);
  const channelBinding = toHex(serverNonce);

  const helloBody = {
    channel_binding: channelBinding,
    ephemeral_public: toBase64(eph.publicKey),
    identity_public: toBase64(opts.identity.publicKey),
    name: opts.agentName,
    protocol_version: PROTOCOL_VERSION,
  };

  const canonical = canonicalJson(helloBody);
  const signed = signAttached(opts.identity.secretKey, new TextEncoder().encode(canonical));
  const helloMsg = {
    type: "HELLO",
    from: myNodeId,
    name: opts.agentName,
    ephemeral_public: helloBody.ephemeral_public,
    identity_public: helloBody.identity_public,
    protocol_version: helloBody.protocol_version,
    channel_binding: helloBody.channel_binding,
    signature: toBase64(signed),
  };
  await opts.send(JSON.stringify(helloMsg));

  let peerHelloRaw: string;
  try {
    peerHelloRaw = await opts.recv();
  } catch (e) {
    throw new HandshakeError("failed to read peer HELLO", 2, e);
  }
  let peerHello: {
    type: string;
    from?: string;
    name?: string;
    ephemeral_public?: string;
    identity_public?: string;
    protocol_version?: string;
    channel_binding?: string;
    signature?: string;
  };
  try {
    peerHello = JSON.parse(peerHelloRaw);
  } catch (e) {
    throw new HandshakeError("malformed peer HELLO JSON", 2, e);
  }
  if (peerHello.type !== "HELLO") {
    throw new HandshakeError(`expected HELLO, got ${peerHello.type}`, 2);
  }
  if (
    !peerHello.ephemeral_public ||
    !peerHello.identity_public ||
    !peerHello.signature ||
    !peerHello.name ||
    !peerHello.protocol_version
  ) {
    throw new HandshakeError("peer HELLO missing required fields", 2);
  }

  // Channel binding must echo our serverNonce (server-server case) OR
  // be present and verifiable. The server side won't echo our binding;
  // it sends its own. We verify the signature over what THEY claim.
  const peerCanonical = canonicalJson({
    channel_binding: peerHello.channel_binding ?? channelBinding,
    ephemeral_public: peerHello.ephemeral_public,
    identity_public: peerHello.identity_public,
    name: peerHello.name,
    protocol_version: peerHello.protocol_version,
  });
  const peerIdentity = fromBase64(peerHello.identity_public);
  const peerSignedBytes = fromBase64(peerHello.signature);
  let extracted: Uint8Array;
  try {
    extracted = verifyAttached(peerIdentity, peerSignedBytes);
  } catch (e) {
    throw new HandshakeError("peer HELLO signature verification failed", 2, e);
  }
  const expectedBytes = new TextEncoder().encode(peerCanonical);
  if (extracted.length !== expectedBytes.length) {
    throw new HandshakeError("peer HELLO signed payload does not match canonical form", 2);
  }
  for (let i = 0; i < extracted.length; i++) {
    if (extracted[i] !== expectedBytes[i]) {
      throw new HandshakeError("peer HELLO signed payload does not match canonical form", 2);
    }
  }

  const peerEphPublic = fromBase64(peerHello.ephemeral_public);

  // --- Stage 3: ECDH ---
  const sessionKey = ecdh(eph.secretKey, peerEphPublic);
  // Best-effort wipe of the ephemeral private (JS doesn't guarantee anything)
  eph.secretKey.fill(0);

  const peerNodeId = nodeId(peerIdentity);

  return {
    sessionKey,
    myNodeId,
    peerNodeId,
    peerAgentName: peerHello.name,
    protocolVersion: peerHello.protocol_version,
    peerIdentityPublic: peerIdentity,
    serverNonce,
  };
}
