// IronMesh handshake — TS port (TODO).
//
// Reference implementation: ../../crypto.py + ../../protocol.py.
//
// Three-stage protocol (must match protocol.py exactly to interop with
// existing daemons — golden-vector tests in tests/vectors/ are the
// regression net):
//
//   Stage 1: PASSPHRASE_CHALLENGE
//     - Server sends nonce (16 random bytes)
//     - Client computes proof = HMAC-SHA256(passphrase, nonce)
//     - Client replies AUTH_PROOF { proof }
//     - Server verifies via timing-safe compare
//
//   Stage 2: ECDH key exchange
//     - Both sides generate Curve25519 ephemeral keypair
//     - Exchange ECDH_PUB { pub_key }
//     - Both derive session_key = scalarMult(my_priv, their_pub)
//     - All subsequent frames are encrypted with NaCl secretbox + nonce++
//
//   Stage 3: HELLO + identity
//     - Each side sends signed HELLO { node_id, ed25519_pub, agent_name,
//       capabilities, signature }
//     - Signature verified against ed25519_pub
//     - First contact: pin to known_peers (TOFU). Subsequent: verify match.
//
// Implement in this order: HMAC proof first (smallest crypto surface,
// catches passphrase bugs early), then ECDH (use tweetnacl.box.keyPair +
// scalarMult), then signed HELLO (tweetnacl.sign).
//
// Wire formats: frame.ts (binary frame v4 — see protocol.py's FrameV4
// for the canonical layout).

export interface HandshakeResult {
  sessionKey: Uint8Array;
  daemonNodeId: string;
  daemonAgentName: string;
  daemonCapabilities: string[];
}

export async function performHandshake(_passphrase: string): Promise<HandshakeResult> {
  throw new Error("handshake.performHandshake: not implemented (M2)");
}
