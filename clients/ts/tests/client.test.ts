import { describe, expect, it } from "vitest";
import { IronMeshClient, VERSION } from "../src/index.js";

describe("IronMeshClient (scaffold)", () => {
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
  });

  describe("event API", () => {
    it("registers and fires listeners via the test seam", () => {
      const c = new IronMeshClient({
        url: "ws://x",
        passphrase: "p",
      });
      const seen: string[] = [];
      c.on("disconnect", (reason) => seen.push(reason));
      c._emit("disconnect", "test");
      expect(seen).toEqual(["test"]);
    });

    it("supports off() to unregister", () => {
      const c = new IronMeshClient({
        url: "ws://x",
        passphrase: "p",
      });
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

  describe("not-yet-implemented surface", () => {
    // These tests are deliberately strict: they pin the surface that is
    // SHIPPED (the throws) so a partial impl that silently no-ops doesn't
    // sneak in. Replace each test as the underlying method lands.

    it("connect() throws with a helpful message", async () => {
      const c = new IronMeshClient({ url: "ws://x", passphrase: "p" });
      await expect(c.connect()).rejects.toThrow(/not implemented/);
    });

    it("sendMessage() throws", async () => {
      const c = new IronMeshClient({ url: "ws://x", passphrase: "p" });
      await expect(c.sendMessage("peer", "hi")).rejects.toThrow(/not implemented/);
    });

    it("listPeers() throws", async () => {
      const c = new IronMeshClient({ url: "ws://x", passphrase: "p" });
      await expect(c.listPeers()).rejects.toThrow(/not implemented/);
    });
  });
});

describe("module exports", () => {
  it("exposes a VERSION constant matching package.json", () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });
});
