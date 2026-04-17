import { describe, expect, it } from "vitest";
import {
  decode,
  encode,
  FLAG_ENCRYPTED,
  FLAG_HIGH_PRIORITY,
  FLAG_SIGNED,
  FrameError,
  HEADER_SIZE,
  MAGIC,
  msgIdHash,
  VERSION,
} from "../src/frame.js";

describe("frame v4 encode/decode", () => {
  it("encodes magic + version + flags correctly", () => {
    const payload = new Uint8Array([1, 2, 3, 4]);
    const wire = encode({ msgId: "abc", encrypted: payload });
    expect(wire[0]).toBe(MAGIC[0]);
    expect(wire[1]).toBe(MAGIC[1]);
    expect(wire[2]).toBe(VERSION);
    // FLAG_ENCRYPTED is forced on
    expect(wire[3] & FLAG_ENCRYPTED).toBe(FLAG_ENCRYPTED);
  });

  it("round-trips an unsigned encrypted frame", () => {
    const payload = new Uint8Array(64).map((_, i) => i);
    const ts = 1700000000000n;
    const wire = encode({
      msgId: "msg-001",
      encrypted: payload,
      sequence: 42n,
      timestampMs: ts,
    });
    const decoded = decode(wire);
    expect(decoded.version).toBe(VERSION);
    expect(decoded.flags & FLAG_ENCRYPTED).toBe(FLAG_ENCRYPTED);
    expect(decoded.flags & FLAG_SIGNED).toBe(0);
    expect(decoded.sequence).toBe(42n);
    expect(decoded.timestamp).toBe(ts);
    expect(decoded.encrypted).toEqual(payload);
    expect(decoded.signature).toBeUndefined();
  });

  it("round-trips a signed encrypted frame", () => {
    const payload = new Uint8Array([10, 20, 30]);
    const sig = new Uint8Array(64).fill(0xab);
    const wire = encode({
      msgId: "signed-1",
      encrypted: payload,
      signature: sig,
    });
    const decoded = decode(wire);
    expect(decoded.flags & FLAG_SIGNED).toBe(FLAG_SIGNED);
    expect(decoded.signature).toEqual(sig);
    expect(decoded.encrypted).toEqual(payload);
  });

  it("preserves caller-provided priority flag", () => {
    const wire = encode({
      msgId: "x",
      encrypted: new Uint8Array(0),
      flags: FLAG_HIGH_PRIORITY,
    });
    expect(wire[3] & FLAG_HIGH_PRIORITY).toBe(FLAG_HIGH_PRIORITY);
  });

  it("rejects a frame shorter than the header", () => {
    expect(() => decode(new Uint8Array(HEADER_SIZE - 1))).toThrow(FrameError);
  });

  it("rejects bad magic", () => {
    const wire = encode({ msgId: "x", encrypted: new Uint8Array(0) });
    wire[0] = 0x00;
    expect(() => decode(wire)).toThrow(/invalid magic/);
  });

  it("rejects unsupported version", () => {
    const wire = encode({ msgId: "x", encrypted: new Uint8Array(0) });
    wire[2] = 99;
    expect(() => decode(wire)).toThrow(/unsupported version/);
  });

  it("rejects truncated payload", () => {
    const wire = encode({ msgId: "x", encrypted: new Uint8Array(100) });
    const truncated = wire.slice(0, HEADER_SIZE + 50);
    expect(() => decode(truncated)).toThrow(/truncated/);
  });

  it("rejects signature length != 64", () => {
    expect(() =>
      encode({
        msgId: "x",
        encrypted: new Uint8Array(0),
        signature: new Uint8Array(63),
      }),
    ).toThrow(/64 bytes/);
  });

  it("msg_id hash matches Python's SHA256(msg_id)[:8]", () => {
    // Python: hashlib.sha256(b"hello").digest()[:8].hex()
    // -> 2cf24dba5fb0a30e
    const h = msgIdHash("hello");
    expect(Buffer.from(h).toString("hex")).toBe("2cf24dba5fb0a30e");
  });
});
