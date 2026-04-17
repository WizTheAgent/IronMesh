// Binary frame v4 — TS port (TODO).
//
// Canonical layout: see Frame / FrameV4 in ../../protocol.py. Whatever
// is implemented here MUST round-trip identically with the Python side
// — that's enforced by the cross-implementation golden vector tests
// planned for tests/vectors/ (see clients/ts/README.md status).
//
// Layout (network byte order):
//   [version:1] [type:1] [flags:1] [nonce:24] [ciphertext_len:4] [ciphertext:N]
//
// MessageType enum: see MessageType in protocol.py — keep numeric values
// pinned (HELLO=0x01, MSG=0x10, etc.). Adding a new type bumps the
// frame version (currently 4).

export type FrameVersion = 4;

export interface FrameHeader {
  version: FrameVersion;
  type: number;
  flags: number;
  nonce: Uint8Array;
}

export interface DecodedFrame extends FrameHeader {
  payload: Uint8Array;
}

export function encode(_header: FrameHeader, _payload: Uint8Array): Uint8Array {
  throw new Error("frame.encode: not implemented (M2)");
}

export function decode(_buf: Uint8Array): DecodedFrame {
  throw new Error("frame.decode: not implemented (M2)");
}
