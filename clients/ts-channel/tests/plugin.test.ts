import { describe, expect, it, vi } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

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

function tempStateDir(): string {
  return mkdtempSync(join(tmpdir(), "ts-channel-test-"));
}

function buildPlugin(stateDir: string = tempStateDir()) {
  const acc = fakeAccount();
  return {
    plugin: ironMeshChannelPlugin({
      listAccountIds: () => [acc.accountId],
      resolveAccount: () => acc,
      stateDir,
    }),
    account: acc,
    stateDir,
  };
}

describe("plugin shape", () => {
  it("exposes id, meta, capabilities, and all advertised adapters", () => {
    const { plugin } = buildPlugin();
    expect(plugin.id).toBe("ironmesh");
    expect(plugin.meta.id).toBe("ironmesh");
    expect(plugin.capabilities.outbound).toBe(true);
    expect(plugin.capabilities.directMessages).toBe(true);
    expect(plugin.capabilities.groups).toBe(false);
    expect(typeof plugin.lifecycle.start).toBe("function");
    expect(typeof plugin.lifecycle.stop).toBe("function");
    expect(typeof plugin.outbound.send).toBe("function");
    expect(typeof plugin.messaging.subscribe).toBe("function");
    expect(typeof plugin.status.describe).toBe("function");
    expect(typeof plugin.directory.self).toBe("function");
    expect(typeof plugin.directory.listPeers).toBe("function");
    expect(typeof plugin.directory.listPeersLive).toBe("function");
    expect(typeof plugin.config.listAccountIds).toBe("function");
    expect(typeof plugin.config.resolveAccount).toBe("function");
  });

  it("config delegates to caller-supplied resolvers", () => {
    const acc = fakeAccount({ accountId: "alpha" });
    const plugin = ironMeshChannelPlugin({
      listAccountIds: () => ["alpha", "beta"],
      resolveAccount: () => acc,
      stateDir: tempStateDir(),
    });
    expect(plugin.config.listAccountIds(null)).toEqual(["alpha", "beta"]);
    expect(plugin.config.resolveAccount(null, "alpha")).toEqual(acc);
  });

  it("VERSION export tracks the package", () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });
});

describe("connection caching", () => {
  it("requires lifecycle.start before any other adapter (state-load gate)", () => {
    const { plugin, account } = buildPlugin();
    expect(() => plugin.__test__.getOrConnect(account)).toThrow(/state .* not loaded/);
  });

  it("getOrConnect returns the same instance per accountId once started", async () => {
    const { plugin, account } = buildPlugin();
    // Trigger state load via the public lifecycle.
    await plugin.__test__.loadState(account.accountId);
    const a = plugin.__test__.getOrConnect(account);
    const b = plugin.__test__.getOrConnect(account);
    expect(a).toBe(b);
    expect(plugin.__test__.connections.size).toBe(1);
    await a.stop();
  });
});

describe("outbound", () => {
  it("returns ok+msgId on a successful send (mocked client)", async () => {
    const { plugin, account } = buildPlugin();
    await plugin.__test__.loadState(account.accountId);
    const conn = plugin.__test__.getOrConnect(account);
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
    await plugin.__test__.loadState(account.accountId);
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
  it("subscribe registers an inbound listener and unsubscribe removes it", async () => {
    const { plugin, account } = buildPlugin();
    await plugin.__test__.loadState(account.accountId);
    const onMsg = vi.fn();
    const sub = plugin.messaging.subscribe({ account, onMessage: onMsg });
    expect(plugin.__test__.inboundSubscribers.get(account.accountId)?.size).toBe(1);
    sub.close();
    expect(plugin.__test__.inboundSubscribers.get(account.accountId)?.size).toBe(0);
  });

  it("inbound MSG events become ChannelInboundMessage AND refresh peer-mapper", async () => {
    const { plugin, account } = buildPlugin();
    await plugin.__test__.loadState(account.accountId);
    const conn = plugin.__test__.getOrConnect(account);
    const received: { fromId: string; text: string; fromName?: string }[] = [];
    plugin.messaging.subscribe({
      account,
      onMessage: (m) => received.push({ fromId: m.fromId, text: m.text, fromName: m.fromName }),
    });
    const payload = new TextEncoder().encode("hello from peer");
    const peerNodeId = "f".repeat(32);
    // Pre-seed the peer with a name. As of v0.8.5 the daemon owns trust
    // gating — anything that reaches the TS plugin is already trusted.
    conn.peers.observe({ nodeId: peerNodeId, agentName: "alice", online: true, observedAtMs: Date.now() });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (conn.client as any)._emit("message", {
      msgType: "MSG",
      fromNodeId: peerNodeId,
      payload,
      msgId: "msg-1",
      timestamp: Date.now(),
    });
    expect(received).toEqual([{ fromId: peerNodeId, text: "hello from peer", fromName: "alice" }]);
    // Inbound observation should refresh last_seen on the existing record.
    const rec = conn.peers.resolveById(peerNodeId);
    expect(rec?.lastSeenMs).toBeTypeOf("number");
  });

  it("non-MSG inbound types are filtered out", async () => {
    const { plugin, account } = buildPlugin();
    await plugin.__test__.loadState(account.accountId);
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

describe("directory adapter", () => {
  it("listPeers returns persisted contacts even when offline", async () => {
    const { plugin, account } = buildPlugin();
    await plugin.__test__.loadState(account.accountId);
    const conn = plugin.__test__.getOrConnect(account);
    // Seed two known peers, one currently online, one historical.
    conn.peers.observe({ nodeId: "1".repeat(32), agentName: "alice", online: true, observedAtMs: Date.now() });
    conn.peers.observe({ nodeId: "2".repeat(32), agentName: "bob",   online: false, observedAtMs: Date.now() - 60000 });
    const list = await plugin.directory.listPeers({ account });
    const ids = list.map((e) => e.id).sort();
    expect(ids).toEqual(["1".repeat(32), "2".repeat(32)]);
    const alice = list.find((e) => e.id === "1".repeat(32));
    expect(alice?.name).toBe("alice");
    expect((alice?.raw as { online: boolean }).online).toBe(true);
  });

  it("listPeersLive returns only currently-online peers", async () => {
    const { plugin, account } = buildPlugin();
    await plugin.__test__.loadState(account.accountId);
    const conn = plugin.__test__.getOrConnect(account);
    conn.peers.observe({ nodeId: "1".repeat(32), agentName: "alice", online: true, observedAtMs: Date.now() });
    conn.peers.observe({ nodeId: "2".repeat(32), agentName: "bob",   online: false, observedAtMs: Date.now() });
    const live = await plugin.directory.listPeersLive({ account });
    expect(live).toHaveLength(1);
    expect(live[0].id).toBe("1".repeat(32));
  });

  it("self returns the account's own identity (after connect)", async () => {
    const { plugin, account } = buildPlugin();
    await plugin.__test__.loadState(account.accountId);
    const conn = plugin.__test__.getOrConnect(account);
    const self = await plugin.directory.self({ account });
    // Pre-handshake the underlying client still derives its node_id
    // from the identity keypair, so self() resolves immediately.
    expect(self?.kind).toBe("user");
    expect(self?.id).toBe(conn.client.nodeId);
    expect(self?.name).toBe(account.name);
  });

  it("self returns null when connection has not been established", async () => {
    const { plugin, account } = buildPlugin();
    await plugin.__test__.loadState(account.accountId);
    // Don't connect — self should bail.
    const self = await plugin.directory.self({ account });
    expect(self).toBe(null);
  });
});

describe("status reporter", () => {
  it("reports 'not linked' before lifecycle.start", async () => {
    const { plugin, account } = buildPlugin();
    const s = await plugin.status.describe({ account });
    expect(s.state).toBe("not linked");
    expect(s.peerNodeId).toBe(null);
  });
});
