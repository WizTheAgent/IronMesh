import { describe, expect, it } from "vitest";
import {
  canonicalJson,
  ecdh,
  generateEphemeralKeypair,
  generateIdentityKeypair,
  nodeId,
  passphraseProof,
  secretBoxOpen,
  secretBoxSeal,
  signAttached,
  signDetached,
  verifyAttached,
  verifyDetached,
  verifyPassphraseProof,
} from "../src/crypto.js";

describe("nodeId", () => {
  it("matches Python: hashlib.sha256(pub)[:16].hex()", () => {
    // Python repro:
    //   import hashlib; hashlib.sha256(b"\x00"*32).hexdigest()[:32]
    //   -> '66687aadf862bd776c8fc18b8e9f8e20'
    const id = nodeId(new Uint8Array(32));
    expect(id).toBe("66687aadf862bd776c8fc18b8e9f8e20");
  });

  it("returns 32 lowercase hex chars for any 32-byte input", () => {
    const id = nodeId(new Uint8Array(32).fill(0xab));
    expect(id).toMatch(/^[0-9a-f]{32}$/);
  });
});

describe("passphraseProof", () => {
  it("matches Python: hmac.new(pw, nonce, sha256).hexdigest()", () => {
    // Python repro:
    //   import hmac, hashlib
    //   hmac.new(b"secret", b"\x00"*16, hashlib.sha256).hexdigest()
    //   -> 'b59552af05f12492a77b3e0257ef8de842a9c9d1099fa955349928f48baf1ace'
    const p = passphraseProof("secret", new Uint8Array(16));
    expect(p).toBe("b59552af05f12492a77b3e0257ef8de842a9c9d1099fa955349928f48baf1ace");
  });

  it("verifyPassphraseProof returns true for matching", () => {
    const nonce = new Uint8Array(16).fill(0xee);
    const proof = passphraseProof("hunter2", nonce);
    expect(verifyPassphraseProof(proof, "hunter2", nonce)).toBe(true);
    expect(verifyPassphraseProof(proof, "wrong", nonce)).toBe(false);
  });
});

describe("ECDH", () => {
  it("two parties derive the same shared secret", () => {
    const a = generateEphemeralKeypair();
    const b = generateEphemeralKeypair();
    const ab = ecdh(a.secretKey, b.publicKey);
    const ba = ecdh(b.secretKey, a.publicKey);
    expect(ab).toEqual(ba);
    expect(ab.length).toBe(32);
  });
});

describe("SecretBox", () => {
  it("seal/open round-trips", () => {
    const key = new Uint8Array(32).fill(0x42);
    const pt = new TextEncoder().encode("hello world");
    const ct = secretBoxSeal(key, pt);
    const back = secretBoxOpen(key, ct);
    expect(back).toEqual(pt);
  });

  it("open with wrong key fails", () => {
    const k1 = new Uint8Array(32).fill(0x42);
    const k2 = new Uint8Array(32).fill(0x43);
    const ct = secretBoxSeal(k1, new TextEncoder().encode("x"));
    expect(() => secretBoxOpen(k2, ct)).toThrow(/authentication failure/);
  });

  it("includes a 24-byte nonce prefix", () => {
    const key = new Uint8Array(32);
    const ct = secretBoxSeal(key, new Uint8Array(0));
    expect(ct.length).toBeGreaterThanOrEqual(24);
  });
});

describe("Ed25519 sign/verify", () => {
  it("attached round-trips through verifyAttached", () => {
    const id = generateIdentityKeypair();
    const msg = new TextEncoder().encode("hello");
    const signed = signAttached(id.secretKey, msg);
    const back = verifyAttached(id.publicKey, signed);
    expect(back).toEqual(msg);
  });

  it("detached round-trips through verifyDetached", () => {
    const id = generateIdentityKeypair();
    const msg = new TextEncoder().encode("hello");
    const sig = signDetached(id.secretKey, msg);
    expect(sig.length).toBe(64);
    expect(verifyDetached(id.publicKey, msg, sig)).toBe(true);
    expect(verifyDetached(id.publicKey, new TextEncoder().encode("changed"), sig)).toBe(false);
  });

  it("verifyAttached throws on bad signature", () => {
    const id = generateIdentityKeypair();
    const msg = new TextEncoder().encode("hello");
    const signed = signAttached(id.secretKey, msg);
    signed[5] ^= 0xff;
    expect(() => verifyAttached(id.publicKey, signed)).toThrow(/bad signature/);
  });
});

describe("canonicalJson", () => {
  it("matches Python json.dumps(separators=(',',':'),sort_keys=True) for flat objects", () => {
    expect(canonicalJson({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
    expect(canonicalJson({ name: "alice", port: 8765, ok: true })).toBe(
      '{"name":"alice","ok":true,"port":8765}',
    );
    expect(canonicalJson({ x: null })).toBe('{"x":null}');
  });

  it("matches a real HELLO body shape", () => {
    const body = {
      channel_binding: "deadbeef",
      ephemeral_public: "AAAA",
      identity_public: "BBBB",
      name: "alice",
      protocol_version: "ironmesh/0.6",
    };
    expect(canonicalJson(body)).toBe(
      '{"channel_binding":"deadbeef","ephemeral_public":"AAAA","identity_public":"BBBB","name":"alice","protocol_version":"ironmesh/0.6"}',
    );
  });

  it("escapes non-ASCII to match Python's ensure_ascii=True default", () => {
    // Python repro:
    //   json.dumps({"name": "Zoë"}, separators=(",", ":"), sort_keys=True)
    //   -> '{"name": "Zo\\u00eb"}' — actually no space; verified:
    //   '{"name":"Zo\\u00eb"}'
    expect(canonicalJson({ name: "Zoë" })).toBe('{"name":"Zo\\u00eb"}');
    // Emoji (BMP-adjacent — uses surrogate pair in UTF-16, both halves
    // escape in Python; JSON.stringify produces the same surrogate pair
    // so escaping each half matches).
    //   json.dumps({"x": "🔐"}, separators=(",",":"), sort_keys=True)
    //   -> '{"x":"\\ud83d\\udd10"}'
    expect(canonicalJson({ x: "🔐" })).toBe('{"x":"\\ud83d\\udd10"}');
  });
});
