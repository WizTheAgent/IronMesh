import { describe, expect, it } from "vitest";
import { IronMeshClient, VERSION, generateIdentityKeypair, nodeId } from "../src/index.js";

describe("IronMeshClient", () => {
  describe("constructor validation", () => {
    it("requires a url", () => {
      expect(() => new IronMeshClient({ url: "", passphrase: "x" })).toThrow(
        /url is required/,
      );
    });

    it("requires a passphrase", () => {
      expect(
        () => new IronMeshClient({ url: "ws://localhost:8765", passphrase: "" }),
      ).toThrow(/passphrase is required/);
    });

    it("accepts minimal valid options", () => {
      const c = new IronMeshClient({
        url: "ws://localhost:8765",
        passphrase: "test-passphrase",
      });
      expect(c).toBeInstanceOf(IronMeshClient);
      expect(c.isConnected()).toBe(false);
    });

    it("derives a stable node_id from a fresh identity", () => {
      const c = new IronMeshClient({ url: "ws://x", passphrase: "p" });
      expect(c.nodeId).toMatch(/^[0-9a-f]{32}$/);
    });

    it("uses a caller-provided identity when given", () => {
      const id = generateIdentityKeypair();
      const c = new IronMeshClient({ url: "ws://x", passphrase: "p" }, id);
      expect(c.nodeId).toBe(nodeId(id.publicKey));
    });
  });

  describe("event API", () => {
    it("registers and fires listeners via the test seam", () => {
      const c = new IronMeshClient({ url: "ws://x", passphrase: "p" });
      const seen: string[] = [];
      c.on("disconnect", (reason) => seen.push(reason));
      c._emit("disconnect", "test");
      expect(seen).toEqual(["test"]);
    });

    it("supports off() to unregister", () => {
      const c = new IronMeshClient({ url: "ws://x", passphrase: "p" });
      const seen: string[] = [];
      const fn = (r: string) => seen.push(r);
      c.on("disconnect", fn);
      c.off("disconnect", fn);
      c._emit("disconnect", "test");
      expect(seen).toEqual([]);
    });

    it("does not throw when emitting an event with no listeners", () => {
      const c = new IronMeshClient({ url: "ws://x", passphrase: "p" });
      expect(() => c._emit("connect")).not.toThrow();
    });
  });

  describe("pre-connect surface", () => {
    it("isConnected() is false before connect", () => {
      const c = new IronMeshClient({ url: "ws://x", passphrase: "p" });
      expect(c.isConnected()).toBe(false);
    });

    it("peerNodeId is null before handshake", () => {
      const c = new IronMeshClient({ url: "ws://x", passphrase: "p" });
      expect(c.peerNodeId).toBe(null);
    });

    it("sendMessage() throws when not connected", async () => {
      const c = new IronMeshClient({ url: "ws://x", passphrase: "p" });
      await expect(c.sendMessage("hi")).rejects.toThrow(/not connected/);
    });

    it("listPeers() returns [] before handshake", async () => {
      const c = new IronMeshClient({ url: "ws://x", passphrase: "p" });
      await expect(c.listPeers()).resolves.toEqual([]);
    });
  });
});

describe("module exports", () => {
  it("exposes a VERSION constant matching package.json semver", () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });
});
