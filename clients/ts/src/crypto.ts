// Crypto primitives — TypeScript port of the relevant pieces of crypto.py
// and keys.py. Backed by tweetnacl-js (Curve25519 + Ed25519 + SecretBox)
// and Node's built-in `crypto` for HMAC-SHA256.

import { createHash, createHmac, randomBytes } from "node:crypto";
import nacl from "tweetnacl";

export interface IdentityKeypair {
  /** 32 bytes — Ed25519 public key */
  publicKey: Uint8Array;
  /** 64 bytes — Ed25519 secret key (seed||pub, NaCl format) */
  secretKey: Uint8Array;
}

export interface EphemeralKeypair {
  /** 32 bytes — Curve25519 public */
  publicKey: Uint8Array;
  /** 32 bytes — Curve25519 secret */
  secretKey: Uint8Array;
}

/** Generate a fresh Ed25519 identity keypair. */
export function generateIdentityKeypair(): IdentityKeypair {
  const kp = nacl.sign.keyPair();
  return { publicKey: kp.publicKey, secretKey: kp.secretKey };
}

/** Generate a fresh Curve25519 ephemeral keypair for ECDH. */
export function generateEphemeralKeypair(): EphemeralKeypair {
  const kp = nacl.box.keyPair();
  return { publicKey: kp.publicKey, secretKey: kp.secretKey };
}

/**
 * NaCl shared-key derivation — matches Python's
 * `Box(my_private, their_public).shared_key()`. Internally this is X25519
 * scalarmult followed by HSalsa20 with a zero nonce (NaCl's
 * `crypto_box_beforenm`). Raw `nacl.scalarMult` does only the first step
 * and produces a DIFFERENT key — we need the after-HSalsa20 form so the
 * Python daemon's SecretBox decrypts our ciphertext.
 */
export function ecdh(myPrivate: Uint8Array, peerPublic: Uint8Array): Uint8Array {
  if (myPrivate.length !== 32) throw new Error("ecdh: myPrivate must be 32 bytes");
  if (peerPublic.length !== 32) throw new Error("ecdh: peerPublic must be 32 bytes");
  return nacl.box.before(peerPublic, myPrivate);
}

/**
 * IronMesh node_id: SHA-256(ed25519_public)[:16] as 32 lowercase hex chars.
 * Matches keys.py.
 */
export function nodeId(ed25519Public: Uint8Array): string {
  if (ed25519Public.length !== 32) {
    throw new Error("nodeId: input must be 32 bytes");
  }
  const h = createHash("sha256").update(ed25519Public).digest();
  return h.subarray(0, 16).toString("hex");
}

/** HMAC-SHA256(passphrase, nonce) — passphrase challenge proof. */
export function passphraseProof(passphrase: string, nonce: Uint8Array): string {
  return createHmac("sha256", passphrase).update(nonce).digest("hex");
}

/** Constant-time equality on hex-encoded HMAC outputs. */
export function verifyPassphraseProof(
  proof: string,
  passphrase: string,
  nonce: Uint8Array,
): boolean {
  const expected = passphraseProof(passphrase, nonce);
  if (proof.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= proof.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * NaCl attached-signature form: 64-byte sig followed by message.
 * Matches Python's nacl.signing.SigningKey.sign() and is what the
 * IronMesh server expects in the HELLO `signature` field.
 */
export function signAttached(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  if (secretKey.length !== 64) {
    throw new Error("signAttached: Ed25519 secret key must be 64 bytes");
  }
  return nacl.sign(message, secretKey);
}

/**
 * Detached 64-byte Ed25519 signature. Useful for binary frames where
 * the signed payload travels separately.
 */
export function signDetached(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  if (secretKey.length !== 64) {
    throw new Error("signDetached: Ed25519 secret key must be 64 bytes");
  }
  return nacl.sign.detached(message, secretKey);
}

export function verifyDetached(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== 32) return false;
  if (signature.length !== 64) return false;
  return nacl.sign.detached.verify(message, signature, publicKey);
}

/**
 * Verify an attached-form signed message. Returns the original message
 * bytes on success, throws on bad signature. Mirrors Python's
 * VerifyKey.verify(signed_bytes).
 */
export function verifyAttached(
  publicKey: Uint8Array,
  signedMessage: Uint8Array,
): Uint8Array {
  if (publicKey.length !== 32) {
    throw new Error("verifyAttached: public key must be 32 bytes");
  }
  const opened = nacl.sign.open(signedMessage, publicKey);
  if (!opened) throw new Error("verifyAttached: bad signature");
  return opened;
}

/**
 * SecretBox seal — XSalsa20-Poly1305. Returns nonce(24) || ciphertext.
 * Matches Python's nacl.secret.SecretBox(key).encrypt(plaintext).
 */
export function secretBoxSeal(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
  if (key.length !== 32) throw new Error("secretBoxSeal: key must be 32 bytes");
  const nonce = randomBytes(24);
  const ct = nacl.secretbox(plaintext, nonce, key);
  const out = new Uint8Array(nonce.length + ct.length);
  out.set(nonce, 0);
  out.set(ct, nonce.length);
  return out;
}

/** SecretBox open — input is nonce(24) || ciphertext, output is plaintext. */
export function secretBoxOpen(key: Uint8Array, box: Uint8Array): Uint8Array {
  if (key.length !== 32) throw new Error("secretBoxOpen: key must be 32 bytes");
  if (box.length < 24) throw new Error("secretBoxOpen: input too short for nonce");
  const nonce = box.subarray(0, 24);
  const ct = box.subarray(24);
  const pt = nacl.secretbox.open(ct, nonce, key);
  if (!pt) throw new Error("secretBoxOpen: authentication failure");
  return pt;
}

/**
 * Canonical JSON: keys sorted, no whitespace, ASCII-only. Matches
 * Python's `json.dumps(obj, separators=(",", ":"), sort_keys=True)`
 * — which defaults to `ensure_ascii=True` and escapes every non-ASCII
 * char as `\uXXXX`. JS `JSON.stringify` outputs raw UTF-8 by default,
 * so an agent name with `é` or an emoji would produce a different
 * byte string than Python and the HELLO signature verification would
 * fail. This wrapper post-processes string output to escape any
 * codepoint ≥ 0x80 in JSON's standard `\uXXXX` form (surrogate pairs
 * are preserved as the UTF-16 code units `JSON.stringify` already
 * produces, matching Python's behavior on the BMP). Used for the
 * channel-binding-bound HELLO signature.
 *
 * Handles flat objects with string/number/boolean/null values — which
 * is exactly the HELLO body shape.
 */
export function canonicalJson(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const k of keys) {
    parts.push(escapeAscii(JSON.stringify(k)) + ":" + escapeAscii(JSON.stringify(obj[k])));
  }
  return "{" + parts.join(",") + "}";
}

function escapeAscii(s: string): string {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 0x80) {
      out += s[i];
    } else {
      out += "\\u" + code.toString(16).padStart(4, "0");
    }
  }
  return out;
}

export { randomBytes };
