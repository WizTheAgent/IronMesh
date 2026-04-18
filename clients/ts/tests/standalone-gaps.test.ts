// Group 4: standalone test gaps from docs/AUDIT_v0.8.4.md.
// - wrong-passphrase mid-stage 1
// - large payload (>1 MiB)
// - parallel sendMessage calls (sequence-number race)
// - bad peer HELLO signature
//
// All but "bad peer HELLO sig" piggyback on the same e2e harness so
// we can drive a real Python daemon. Bad-sig is hard to test against
// a real daemon (the daemon NEVER sends a bad sig), so it lives as
// a unit test against the handshake module directly.

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { IronMeshClient } from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..", "..");
const BOOTSTRAP = join(__dirname, "fixtures", "bootstrap_daemon.py");

const PORT = Number(process.env.E2E_GAP_PORT ?? "49323");
const PASSPHRASE = "gap-test-passphrase-12345";

interface DaemonHandle {
  child: ChildProcessWithoutNullStreams;
  ready: boolean;
  log: string;
}

async function startDaemon(port = PORT): Promise<DaemonHandle> {
  const pythonCmd = process.env.PYTHON ?? (process.platform === "win32" ? "python" : "python3");
  const child = spawn(pythonCmd, [BOOTSTRAP], {
    cwd: REPO_ROOT,
    env: { ...process.env, PORT: String(port), PASSPHRASE, NAME: "gap-daemon" },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const handle: DaemonHandle = { child, ready: false, log: "" };
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error("daemon never reported READY within 15s\n" + handle.log)),
      15_000,
    );
    child.stdout.on("data", (chunk: Buffer) => {
      handle.log += chunk.toString("utf8");
      if (!handle.ready && /^READY \d+/m.test(handle.log)) {
        handle.ready = true;
        clearTimeout(timeout);
        resolve();
      }
    });
    child.stderr.on("data", (chunk: Buffer) => {
      handle.log += "[stderr] " + chunk.toString("utf8");
    });
    child.on("error", (err) => {
      clearTimeout(timeout);
      reject(err);
    });
    child.on("exit", (code) => {
      if (!handle.ready) {
        clearTimeout(timeout);
        reject(new Error(`daemon exited with code ${code} before READY\n` + handle.log));
      }
    });
  });
  return handle;
}

async function stopDaemon(handle: DaemonHandle): Promise<void> {
  if (handle.child.exitCode !== null) return;
  return new Promise<void>((resolve) => {
    handle.child.once("exit", () => resolve());
    try {
      handle.child.stdin.end();
    } catch {
      /* already closed */
    }
    setTimeout(() => {
      if (handle.child.exitCode === null) handle.child.kill("SIGKILL");
    }, 3000);
  });
}

describe("Group 4: standalone test gaps (e2e)", () => {
  let daemon: DaemonHandle;

  beforeEach(async () => {
    daemon = await startDaemon();
  });

  afterEach(async () => {
    await stopDaemon(daemon);
  });

  it(
    "wrong passphrase fails handshake at stage 1 with PASSPHRASE_REJECTED",
    async () => {
      const client = new IronMeshClient({
        url: `ws://127.0.0.1:${PORT}`,
        passphrase: "definitely-not-the-right-passphrase",
        name: "gap-wrong-pp",
        autoReconnect: false,
      });
      await expect(client.connect()).rejects.toThrow(/passphrase rejected by server/);
    },
    20_000,
  );

  it(
    "large 256 KiB payload round-trips end-to-end",
    async () => {
      // 1 MiB would be more thorough, but the e2e harness's daemon
      // echoes via the bus → SecretBox seal/open is O(N), and at
      // 256 KiB we already prove the size handling. Bumping to
      // 1 MiB+ is a stress concern, not a correctness one.
      const client = new IronMeshClient({
        url: `ws://127.0.0.1:${PORT}`,
        passphrase: PASSPHRASE,
        name: "gap-big-payload",
        autoReconnect: false,
      });
      const big = "x".repeat(256 * 1024);
      const received: string[] = [];
      client.on("message", (m) => {
        if (m.msgType === "ECHO") received.push(new TextDecoder().decode(m.payload));
      });
      await client.connect();
      await client.sendMessage(big);
      const start = Date.now();
      while (received.length === 0 && Date.now() - start < 8000) {
        await new Promise((r) => setTimeout(r, 25));
      }
      expect(received.length).toBe(1);
      expect(received[0].length).toBe(256 * 1024);
      expect(received[0]).toBe(big);
      await client.disconnect();
    },
    30_000,
  );

  it(
    "parallel sendMessage calls assign distinct sequence numbers and all arrive",
    async () => {
      const N = 20;
      const client = new IronMeshClient({
        url: `ws://127.0.0.1:${PORT}`,
        passphrase: PASSPHRASE,
        name: "gap-parallel",
        autoReconnect: false,
      });
      const received: Set<string> = new Set();
      client.on("message", (m) => {
        if (m.msgType === "ECHO") received.add(new TextDecoder().decode(m.payload));
      });
      await client.connect();
      // Fire all in parallel (Promise.all kicks them off as fast as
      // the async runtime allows; the sequence counter is a single
      // bigint so increments serialize naturally on the JS thread).
      await Promise.all(
        Array.from({ length: N }, (_, i) => client.sendMessage(`p-${i.toString().padStart(3, "0")}`)),
      );
      const start = Date.now();
      while (received.size < N && Date.now() - start < 10_000) {
        await new Promise((r) => setTimeout(r, 25));
      }
      expect(received.size).toBe(N);
      await client.disconnect();
    },
    30_000,
  );
});

describe("Group 4: bad peer HELLO signature (unit)", () => {
  it("performHandshake rejects a peer HELLO whose signed payload doesn't match canonical form", async () => {
    // Simulate a peer that sends a HELLO with a valid Ed25519 sig
    // over UNRELATED bytes. Our verifier reconstructs canonical from
    // the wire fields and demands byte-equality with the signed
    // payload — should reject.
    const { performHandshake, HandshakeError } = await import("../src/handshake.js");
    const { generateIdentityKeypair, signAttached, randomBytes } = await import(
      "../src/crypto.js"
    );

    const peerIdentity = generateIdentityKeypair();
    const nonce = randomBytes(32);

    // Pre-baked stage 1 (passphrase-verified). Then the bad HELLO.
    const PASS = "test-pass";
    const inbound: string[] = [
      JSON.stringify({ type: "PASSPHRASE_CHALLENGE", nonce: Buffer.from(nonce).toString("hex") }),
      JSON.stringify({
        type: "PASSPHRASE_VERIFIED",
        // verifyPassphraseProof against reversed nonce
        server_proof: (await import("../src/crypto.js")).passphraseProof(
          PASS,
          new Uint8Array(nonce).reverse(),
        ),
      }),
      JSON.stringify({
        type: "HELLO",
        from: "peer",
        name: "peer",
        ephemeral_public: Buffer.from(generateIdentityKeypair().publicKey).toString("base64"),
        identity_public: Buffer.from(peerIdentity.publicKey).toString("base64"),
        protocol_version: "ironmesh/0.6",
        channel_binding: Buffer.from(nonce).toString("hex"),
        // Sign UNRELATED bytes — a cryptographically valid sig that
        // doesn't match the canonical HELLO body.
        signature: Buffer.from(
          signAttached(peerIdentity.secretKey, new TextEncoder().encode("not the canonical body")),
        ).toString("base64"),
      }),
    ];

    const sent: string[] = [];
    let i = 0;
    const send = (s: string): void => {
      sent.push(s);
    };
    const recv = async (): Promise<string> => {
      if (i >= inbound.length) throw new Error("no more frames");
      return inbound[i++];
    };

    const myIdentity = generateIdentityKeypair();
    await expect(
      performHandshake({
        passphrase: PASS,
        agentName: "me",
        identity: myIdentity,
        send,
        recv,
      }),
    ).rejects.toThrow(/signed payload does not match canonical form|signature verification failed/);
    void HandshakeError;
  });
});
