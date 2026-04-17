// End-to-end test: spin up a real Python BridgeDaemon, connect from
// the TS client, run the full handshake + send a MSG + receive its
// echo. Skipped automatically if Python or the in-tree daemon module
// can't be located.

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { IronMeshClient } from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..", "..");
const BOOTSTRAP = join(__dirname, "fixtures", "bootstrap_daemon.py");

const PORT = Number(process.env.E2E_PORT ?? "49321");
const PASSPHRASE = "e2e-overnight-passphrase-12345";

interface DaemonHandle {
  child: ChildProcessWithoutNullStreams;
  ready: boolean;
  log: string;
}

async function startDaemon(): Promise<DaemonHandle> {
  const pythonCmd = process.env.PYTHON ?? (process.platform === "win32" ? "python" : "python3");
  const child = spawn(
    pythonCmd,
    [BOOTSTRAP],
    {
      cwd: REPO_ROOT,
      env: { ...process.env, PORT: String(PORT), PASSPHRASE, NAME: "e2e-daemon" },
      stdio: ["pipe", "pipe", "pipe"],
    },
  );

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
      // already closed
    }
    setTimeout(() => {
      if (handle.child.exitCode === null) handle.child.kill("SIGKILL");
    }, 3000);
  });
}

describe("e2e: TS client ↔ Python daemon", () => {
  let daemon: DaemonHandle;

  beforeEach(async () => {
    daemon = await startDaemon();
  });

  afterEach(async () => {
    await stopDaemon(daemon);
  });

  it(
    "handshake succeeds and a MSG round-trips",
    async () => {
      const client = new IronMeshClient({
        url: `ws://127.0.0.1:${PORT}`,
        passphrase: PASSPHRASE,
        name: "ts-e2e",
        autoReconnect: false,
      });

      const received: { type: string; body: string }[] = [];
      client.on("message", (msg) => {
        received.push({
          type: msg.msgType,
          body: new TextDecoder().decode(msg.payload),
        });
      });

      await client.connect();
      expect(client.isConnected()).toBe(true);
      expect(client.peerNodeId).toMatch(/^[0-9a-f]{32}$/);

      await client.sendMessage("hello-from-ts", { priority: "NORMAL" });

      // Wait up to 5 s for the echo
      const start = Date.now();
      while (received.length === 0 && Date.now() - start < 5000) {
        await new Promise((r) => setTimeout(r, 50));
      }

      if (received.length === 0) {
        // eslint-disable-next-line no-console
        console.log("daemon log so far:\n" + daemon.log);
      }
      expect(received.length).toBeGreaterThan(0);
      // The daemon's echo handler returns the same payload bytes with type ECHO
      const echo = received.find((m) => m.type === "ECHO");
      expect(echo).toBeDefined();
      expect(echo!.body).toBe("hello-from-ts");

      await client.disconnect();
    },
    30_000,
  );
});
