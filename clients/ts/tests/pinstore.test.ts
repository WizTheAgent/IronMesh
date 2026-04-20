// pinstore TOFU enforcement — verifies the v0.8.5.5 graduation from
// "pin file recognized but not enforced" to actual enforcement.

import { promises as fs } from "node:fs";
import { mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, it, expect, beforeEach } from "vitest";

import {
  verifyOrPin,
  clearPin,
  listPins,
  PinMismatchError,
  PinNotFoundError,
} from "../src/pinstore.js";

let tmpDir: string;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "ironmesh-pin-test-"));
});

describe("pinstore — first contact", () => {
  it("writes the pin on first observation when tofu='trust-on-first-use'", async () => {
    const path = join(tmpDir, "pins.json");
    const result = await verifyOrPin(
      path,
      "ws://daemon.example.com:8765",
      "abc123def456",
      "trust-on-first-use",
    );
    expect(result).toBe("first-contact");

    const pins = await listPins(path);
    expect(pins["ws://daemon.example.com:8765"]?.fingerprint).toBe(
      "abc123def456",
    );
    expect(pins["ws://daemon.example.com:8765"]?.firstSeen).toMatch(
      /^\d{4}-\d{2}-\d{2}T/,
    );
  });

  it("refuses first contact under tofu='strict'", async () => {
    const path = join(tmpDir, "pins.json");
    await expect(
      verifyOrPin(
        path,
        "ws://daemon.example.com:8765",
        "abc123",
        "strict",
      ),
    ).rejects.toBeInstanceOf(PinNotFoundError);
  });
});

describe("pinstore — repeat connect", () => {
  it("returns 'matched' when fingerprint matches the pin", async () => {
    const path = join(tmpDir, "pins.json");
    await verifyOrPin(path, "ws://x:8765", "fp1");
    const second = await verifyOrPin(path, "ws://x:8765", "fp1");
    expect(second).toBe("matched");
  });

  it("throws PinMismatchError when the fingerprint changes", async () => {
    const path = join(tmpDir, "pins.json");
    await verifyOrPin(path, "ws://x:8765", "fp-original");
    await expect(
      verifyOrPin(path, "ws://x:8765", "fp-different"),
    ).rejects.toBeInstanceOf(PinMismatchError);
  });

  it("PinMismatchError surfaces both fingerprints in the message", async () => {
    const path = join(tmpDir, "pins.json");
    await verifyOrPin(path, "ws://x:8765", "AAAA");
    try {
      await verifyOrPin(path, "ws://x:8765", "BBBB");
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(PinMismatchError);
      expect((err as Error).message).toContain("AAAA");
      expect((err as Error).message).toContain("BBBB");
    }
  });
});

describe("pinstore — clear", () => {
  it("clearPin returns true when removing an existing pin", async () => {
    const path = join(tmpDir, "pins.json");
    await verifyOrPin(path, "ws://x:8765", "fp");
    expect(await clearPin(path, "ws://x:8765")).toBe(true);
    expect(await listPins(path)).toEqual({});
  });

  it("clearPin returns false when no pin exists", async () => {
    const path = join(tmpDir, "pins.json");
    expect(await clearPin(path, "ws://nonexistent:1234")).toBe(false);
  });

  it("after clearing, first-contact succeeds again", async () => {
    const path = join(tmpDir, "pins.json");
    await verifyOrPin(path, "ws://x:8765", "old-fp");
    await clearPin(path, "ws://x:8765");
    const result = await verifyOrPin(path, "ws://x:8765", "new-fp");
    expect(result).toBe("first-contact");
  });
});

describe("pinstore — file format", () => {
  it("writes a v1 JSON file with chmod 600", async () => {
    const path = join(tmpDir, "pins.json");
    await verifyOrPin(path, "ws://x:8765", "fp", undefined, "alice");

    const raw = await fs.readFile(path, "utf-8");
    const parsed = JSON.parse(raw);
    expect(parsed.version).toBe(1);
    expect(parsed.pins["ws://x:8765"].fingerprint).toBe("fp");
    expect(parsed.pins["ws://x:8765"].agentName).toBe("alice");

    // chmod 600 verification — POSIX only; on Windows the bits we
    // care about (group/other read) are not enforced the same way,
    // so the assertion is best-effort and conditional.
    if (process.platform !== "win32") {
      const stat = await fs.stat(path);
      expect(stat.mode & 0o777).toBe(0o600);
    }
  });

  it("ignores a missing pin file (treats as empty)", async () => {
    const path = join(tmpDir, "absent.json");
    const result = await verifyOrPin(path, "ws://x:8765", "fp");
    expect(result).toBe("first-contact");
  });
});
