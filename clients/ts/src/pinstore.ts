// pinstore.ts — TOFU pin file persistence for the IronMesh TS client.
//
// File format (JSON, deliberately tiny so it can be reviewed by hand):
//
//   {
//     "version": 1,
//     "pins": {
//       "<peer-key>": {
//         "fingerprint": "<32-hex-or-64-hex>",
//         "firstSeen": "<ISO 8601 timestamp>",
//         "agentName": "<optional human label>"
//       }
//     }
//   }
//
// "<peer-key>" is normally the WebSocket URL the client connects to —
// that's what disambiguates two daemons on the same host. Caller can
// override with an explicit identifier if connecting to multiple
// daemons through one URL pattern (e.g. behind a load balancer).
//
// Atomic writes: write to <path>.tmp, fsync, then os.rename.
// (Same pattern as the Python TrustStore in v0.8.5.2.)

import { promises as fs } from "node:fs";
import { dirname } from "node:path";

export interface PinEntry {
  fingerprint: string;
  firstSeen: string;
  agentName?: string;
}

export interface PinFile {
  version: 1;
  pins: Record<string, PinEntry>;
}

export class PinMismatchError extends Error {
  constructor(
    public readonly peerKey: string,
    public readonly pinned: string,
    public readonly observed: string,
  ) {
    super(
      `TOFU pin mismatch for ${peerKey}: pinned ${pinned}, ` +
        `observed ${observed}. Refusing to connect — either the daemon ` +
        `legitimately rotated its identity (clear the pin manually) or ` +
        `someone is impersonating it.`,
    );
    this.name = "PinMismatchError";
  }
}

export class PinNotFoundError extends Error {
  constructor(public readonly peerKey: string) {
    super(
      `Strict TOFU mode: no pin found for ${peerKey} and tofu='strict' ` +
        `forbids first-contact trust. Pin the daemon first via a ` +
        `trust-on-first-use connection, then switch to strict.`,
    );
    this.name = "PinNotFoundError";
  }
}

async function load(path: string): Promise<PinFile> {
  try {
    const raw = await fs.readFile(path, "utf-8");
    const parsed = JSON.parse(raw) as Partial<PinFile>;
    if (parsed.version !== 1 || typeof parsed.pins !== "object") {
      throw new Error(`pin file ${path} has invalid shape`);
    }
    return { version: 1, pins: parsed.pins as Record<string, PinEntry> };
  } catch (err: unknown) {
    if (
      err instanceof Error &&
      "code" in err &&
      (err as NodeJS.ErrnoException).code === "ENOENT"
    ) {
      return { version: 1, pins: {} };
    }
    throw err;
  }
}

async function save(path: string, pf: PinFile): Promise<void> {
  await fs.mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.tmp`;
  const data = JSON.stringify(pf, null, 2);
  // open + write + fsync + rename — survives SIGKILL / power loss mid-write
  const fh = await fs.open(tmp, "w", 0o600);
  try {
    await fh.writeFile(data);
    await fh.sync();
  } finally {
    await fh.close();
  }
  await fs.rename(tmp, path);
  // chmod 600 again — some filesystems ignore the open() mode argument
  try {
    await fs.chmod(path, 0o600);
  } catch {
    // Non-POSIX filesystems may reject chmod; not fatal.
  }
}

/**
 * Verify or pin the observed fingerprint for `peerKey`.
 *
 * Behavior:
 *   - If a pin exists and matches: return "matched" (no write).
 *   - If a pin exists and does NOT match: throw PinMismatchError.
 *   - If no pin exists and `tofu` is "trust-on-first-use" (default):
 *     write the new pin, return "first-contact".
 *   - If no pin exists and `tofu` is "strict": throw PinNotFoundError.
 *
 * Either result indicates the connection is allowed to proceed; the
 * thrown errors must be propagated to the caller and surface as a
 * connect failure.
 */
export async function verifyOrPin(
  pinFilePath: string,
  peerKey: string,
  fingerprint: string,
  tofu: "trust-on-first-use" | "strict" = "trust-on-first-use",
  agentName?: string,
): Promise<"matched" | "first-contact"> {
  const pf = await load(pinFilePath);
  const existing = pf.pins[peerKey];
  if (existing) {
    if (existing.fingerprint === fingerprint) {
      return "matched";
    }
    throw new PinMismatchError(peerKey, existing.fingerprint, fingerprint);
  }
  if (tofu === "strict") {
    throw new PinNotFoundError(peerKey);
  }
  pf.pins[peerKey] = {
    fingerprint,
    firstSeen: new Date().toISOString(),
    ...(agentName ? { agentName } : {}),
  };
  await save(pinFilePath, pf);
  return "first-contact";
}

/**
 * Manually clear a pin (e.g. after a deliberate daemon identity
 * rotation). Returns true if a pin was removed, false if no pin was
 * present.
 */
export async function clearPin(
  pinFilePath: string,
  peerKey: string,
): Promise<boolean> {
  const pf = await load(pinFilePath);
  if (!(peerKey in pf.pins)) {
    return false;
  }
  delete pf.pins[peerKey];
  await save(pinFilePath, pf);
  return true;
}

/** Read-only access to the current pin set, for diagnostics. */
export async function listPins(
  pinFilePath: string,
): Promise<Record<string, PinEntry>> {
  const pf = await load(pinFilePath);
  return pf.pins;
}
