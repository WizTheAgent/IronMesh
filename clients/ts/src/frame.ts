// Binary frame v4 — TypeScript port of protocol.py's Frame class.
//
// Wire layout (network/big-endian):
//   [magic:2][version:1][flags:1][seq:8][timestamp:8][msg_id_hash:8][payload_len:4][payload:N][?signature:64]
//
// Reference: ../../protocol.py Frame class. Cross-implementation parity is
// enforced by the golden-vector tests in tests/vectors.test.ts — both
// Python and TypeScript MUST encode/decode identical bytes for the same
// inputs.

import { createHash } from "node:crypto";

export const MAGIC = new Uint8Array([0xe7, 0xf6]);
export const VERSION: 4 = 4;
export const HEADER_SIZE = 32;

export const FLAG_HIGH_PRIORITY = 0x01;
export const FLAG_CRITICAL_PRIORITY = 0x02;
export const FLAG_ENCRYPTED = 0x04;
export const FLAG_SIGNED = 0x08;

export interface FrameHeader {
  flags: number;
  sequence: bigint;
  timestamp: bigint; // milliseconds since epoch
  msgIdHash: Uint8Array; // 8 bytes
}

export interface DecodedFrame extends FrameHeader {
  version: number;
  encrypted: Uint8Array;
  signature?: Uint8Array; // 64 bytes if FLAG_SIGNED set
}

export class FrameError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FrameError";
  }
}

function writeBigUint64BE(buf: Uint8Array, offset: number, value: bigint): void {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  view.setBigUint64(offset, value, false);
}

function writeUint32BE(buf: Uint8Array, offset: number, value: number): void {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  view.setUint32(offset, value, false);
}

function readBigUint64BE(buf: Uint8Array, offset: number): bigint {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  return view.getBigUint64(offset, false);
}

function readUint32BE(buf: Uint8Array, offset: number): number {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  return view.getUint32(offset, false);
}

/**
 * Compute the 8-byte SHA-256 prefix of a msg_id string. This is what
 * goes into the frame header — the full msg_id lives inside the
 * encrypted payload's JSON envelope.
 */
export function msgIdHash(msgId: string): Uint8Array {
  const full = createHash("sha256").update(msgId, "utf8").digest();
  return new Uint8Array(full.buffer, full.byteOffset, 8);
}

export interface EncodeOptions {
  flags?: number;
  sequence?: bigint;
  msgId: string;
  encrypted: Uint8Array;
  /** Optional 64-byte detached Ed25519 signature over `encrypted`. */
  signature?: Uint8Array;
  /** Override timestamp (ms). Defaults to Date.now(). Useful for tests. */
  timestampMs?: bigint;
}

/**
 * Build a binary wire frame. Always sets FLAG_ENCRYPTED on output (the
 * payload IS the SecretBox ciphertext). FLAG_SIGNED is set automatically
 * if `signature` is provided.
 */
export function encode(opts: EncodeOptions): Uint8Array {
  let flags = (opts.flags ?? 0) | FLAG_ENCRYPTED;
  if (opts.signature) {
    if (opts.signature.length !== 64) {
      throw new FrameError(`signature must be 64 bytes, got ${opts.signature.length}`);
    }
    flags |= FLAG_SIGNED;
  }

  const sequence = opts.sequence ?? 0n;
  const timestamp = opts.timestampMs ?? BigInt(Date.now());
  const idHash = msgIdHash(opts.msgId);
  const sigLen = opts.signature ? 64 : 0;
  const total = HEADER_SIZE + opts.encrypted.length + sigLen;
  const out = new Uint8Array(total);

  // Header
  out[0] = MAGIC[0];
  out[1] = MAGIC[1];
  out[2] = VERSION;
  out[3] = flags;
  writeBigUint64BE(out, 4, sequence);
  writeBigUint64BE(out, 12, timestamp);
  out.set(idHash, 20);
  writeUint32BE(out, 28, opts.encrypted.length);
  // Payload
  out.set(opts.encrypted, HEADER_SIZE);
  // Signature
  if (opts.signature) {
    out.set(opts.signature, HEADER_SIZE + opts.encrypted.length);
  }
  return out;
}

/**
 * Parse a binary wire frame. Does NOT decrypt — the caller still has to
 * SecretBox-open `decoded.encrypted` with the negotiated session key.
 */
export function decode(buf: Uint8Array): DecodedFrame {
  if (buf.length < HEADER_SIZE) {
    throw new FrameError(`frame too short: ${buf.length} bytes (need ≥${HEADER_SIZE})`);
  }
  if (buf[0] !== MAGIC[0] || buf[1] !== MAGIC[1]) {
    throw new FrameError(`invalid magic: ${buf[0].toString(16)} ${buf[1].toString(16)}`);
  }
  const version = buf[2];
  if (version !== 3 && version !== 4) {
    throw new FrameError(`unsupported version: ${version}`);
  }
  const flags = buf[3];
  const sequence = readBigUint64BE(buf, 4);
  const timestamp = readBigUint64BE(buf, 12);
  const msgHash = buf.slice(20, 28);
  const encLen = readUint32BE(buf, 28);

  if (buf.length < HEADER_SIZE + encLen) {
    throw new FrameError(`truncated: need ${HEADER_SIZE + encLen}, have ${buf.length}`);
  }
  const encrypted = buf.slice(HEADER_SIZE, HEADER_SIZE + encLen);

  let signature: Uint8Array | undefined;
  if (flags & FLAG_SIGNED) {
    const sigStart = HEADER_SIZE + encLen;
    if (buf.length < sigStart + 64) {
      throw new FrameError("signed frame missing 64-byte signature");
    }
    signature = buf.slice(sigStart, sigStart + 64);
  }

  return {
    version,
    flags,
    sequence,
    timestamp,
    msgIdHash: msgHash,
    encrypted,
    signature,
  };
}
