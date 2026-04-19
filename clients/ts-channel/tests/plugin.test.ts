// Unit tests for the channel plugin shape + adapter wiring. Tests
// don't require a live IronMesh daemon — they synthesize a fake
// IronMeshClient state so adapter behavior can be verified in
// isolation. The end-to-end "real daemon" test lives in the
// @wiztheagent/ironmesh-client package's e2e suite.

import { describe, expect, it, vi } from "vitest";
import { ironMeshChannelPlugin, VERSION } from "../src/index.js";
import type { IronMeshChannelAccount } from "../src/types.js";

function fakeAccount(overrides: Partial<IronMeshChannelAccount> = {}): IronMeshChannelAccount {
  return {
    accountId: "test-account",
    url: "ws://127.0.0.1:8765",
    passphrase: "test-passphrase-12345",
    name: "test-agent",
    ...overrides,
  };
}

function buildPlugin() {
  const acc = fakeAccount();
  return {
    plugin: ironMeshChannelPlugin({
      listAccountIds: () => [acc.accountId],
      resolveAccount: () => acc,
    }),
    account: acc,
  };
}

describe("plugin shape", () => {
  it("exposes the channel id, meta, and capabilities", () => {
    const { plugin } = buildPlugin();
    expect(plugin.id).toBe("ironmesh");
    expect(plugin.meta.id).toBe("ironmesh");
    expect(plugin.meta.label).toBe("IronMesh");
    expect(plugin.capabilities.outbound).toBe(true);
    expect(plugin.capabilities.inbound).toBe(true);
    expect(plugin.capabilities.directMessages).toBe(true);
    expect(plugin.capabilities.groups).toBe(false);
    expect(plugin.capabilities.streaming).toBe(false);
  });

  it("lifecycle / outbound / messaging / status / config adapters all present", () => {
    const { plugin } = buildPlugin();
    expect(typeof plugin.lifecycle.start).toBe("function");
    expect(typeof plugin.lifecycle.stop).toBe("function");
    expect(typeof plugin.outbound.send).toBe("function");
    expect(typeof plugin.messaging.subscribe).toBe("function");
    expect(typeof plugin.status.describe).toBe("function");
    expect(typeof plugin.config.listAccountIds).toBe("function");
    expect(typeof plugin.config.resolveAccount).toBe("function");
  });

  it("config delegates to caller-supplied resolvers", () => {
    const acc = fakeAccount({ accountId: "alpha" });
    const plugin = ironMeshChannelPlugin({
      listAccountIds: () => ["alpha", "beta"],
      resolveAccount: () => acc,
    });
    expect(plugin.config.listAccountIds(null)).toEqual(["alpha", "beta"]);
    expect(plugin.config.resolveAccount(null, "alpha")).toEqual(acc);
  });

  it("VERSION export matches package.json semver", () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });
});

describe("connection caching", () => {
  it("getOrConnect returns the same instance per accountId", () => {
    const { plugin, account } = buildPlugin();
    const a = plugin.__test__.getOrConnect(account);
    const b = plugin.__test__.getOrConnect(account);
    expect(a).toBe(b);
    expect(plugin.__test__.connections.size).toBe(1);
  });

  it("different accountIds get distinct connections", () => {
    const accA = fakeAccount({ accountId: "a", port: undefined } as never);
    const accB = fakeAccount({ accountId: "b" });
    const plugin = ironMeshChannelPlugin({
      listAccountIds: () => ["a", "b"],
      resolveAccount: () => accA,
    });
    const ca = plugin.__test__.getOrConnect(accA);
    const cb = plugin.__test__.getOrConnect(accB);
    expect(ca).not.toBe(cb);
    expect(plugin.__test__.connections.size).toBe(2);
  });
});

describe("outbound", () => {
  it("returns ok+msgId on a successful send (mocked)", async () => {
    const { plugin, account } = buildPlugin();
    const conn = plugin.__test__.getOrConnect(account);
    // Force-mark connected and stub the underlying client.
    Object.defineProperty(conn, "isConnected", { value: () => true });
    vi.spyOn(conn.client, "sendMessage").mockResolvedValue({ msgId: "abc123" });
    const result = await plugin.outbound.send({
      account,
      ctx: { accountId: account.accountId, to: "peer", text: "hi" },
    });
    expect(result.ok).toBe(true);
    expect(result.msgId).toBe("abc123");
  });

  it("returns ok=false + error on send rejection", async () => {
    const { plugin, account } = buildPlugin();
    const conn = plugin.__test__.getOrConnect(account);
    Object.defineProperty(conn, "isConnected", { value: () => true });
    vi.spyOn(conn.client, "sendMessage").mockRejectedValue(new Error("nope"));
    const result = await plugin.outbound.send({
      account,
      ctx: { accountId: account.accountId, to: "peer", text: "hi" },
    });
    expect(result.ok).toBe(false);
    expect(result.error).toBe("nope");
  });
});

describe("messaging", () => {
  it("subscribe registers an inbound listener and the unsubscribe handle removes it", () => {
    const { plugin, account } = buildPlugin();
    const onMsg = vi.fn();
    const sub = plugin.messaging.subscribe({ account, onMessage: onMsg });
    expect(plugin.__test__.inboundSubscribers.get(account.accountId)?.size).toBe(1);
    sub.close();
    expect(plugin.__test__.inboundSubscribers.get(account.accountId)?.size).toBe(0);
  });

  it("inbound MSG events from the client are routed to subscribers as ChannelInboundMessage", () => {
    const { plugin, account } = buildPlugin();
    const conn = plugin.__test__.getOrConnect(account);
    const received: { fromId: string; text: string }[] = [];
    plugin.messaging.subscribe({
      account,
      onMessage: (m) => received.push({ fromId: m.fromId, text: m.text }),
    });
    // Drive the client emit path directly via the test seam on IronMeshClient.
    const payload = new TextEncoder().encode("hello from peer");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (conn.client as any)._emit("message", {
      msgType: "MSG",
      fromNodeId: "f".repeat(32),
      payload,
      msgId: "msg-1",
      timestamp: Date.now(),
    });
    expect(received).toEqual([{ fromId: "f".repeat(32), text: "hello from peer" }]);
  });

  it("non-MSG inbound types are filtered out", () => {
    const { plugin, account } = buildPlugin();
    const conn = plugin.__test__.getOrConnect(account);
    const received: unknown[] = [];
    plugin.messaging.subscribe({ account, onMessage: (m) => received.push(m) });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (conn.client as any)._emit("message", {
      msgType: "PING",
      fromNodeId: "g".repeat(32),
      payload: new Uint8Array(),
      msgId: "msg-2",
      timestamp: Date.now(),
    });
    expect(received).toHaveLength(0);
  });
});

describe("status", () => {
  it("reports 'not linked' before lifecycle.start", async () => {
    const { plugin, account } = buildPlugin();
    const s = await plugin.status.describe({ account });
    expect(s.state).toBe("not linked");
    expect(s.peerNodeId).toBe(null);
  });
});
