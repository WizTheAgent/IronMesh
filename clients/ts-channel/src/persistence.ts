// Disk-backed plugin state. Survives gateway restart; per-account JSON
// file layout so multiple accounts on the same host don't stomp on each
// other. Single shape today (last-seen + TOFU pin); evolves additively.

import { readFile, writeFile, mkdir, rename } from "node:fs/promises";
import { dirname, join } from "node:path";

/** Per-peer state remembered across restarts. */
export interface PeerRecord {
  /** 32-hex IronMesh node_id. The contact identity per design. */
  nodeId: string;
  /** Last advertised agent name (display only, may change). */
  agentName?: string;
  /** ms since epoch of the most recent inbound or handshake. */
  lastSeenMs?: number;
  /** Identity-key fingerprint pinned on first sight (TOFU). */
  pinnedFingerprint?: string;
  /** Trust state — `pending` until operator approves, `trusted` after. */
  trust: "pending" | "trusted" | "blocked";
}

/** On-disk file shape. Versioned so we can migrate later if needed. */
export interface PersistedState {
  version: 1;
  accountId: string;
  /** node_id -> PeerRecord */
  peers: Record<string, PeerRecord>;
}

export interface PersistenceOptions {
  /** Directory to keep per-account state files in (created if missing). */
  stateDir: string;
}

/**
 * One in-memory state object per account, with manual save() to flush
 * to disk. Atomic writes via tmp + rename so a crash mid-save can never
 * leave a half-written JSON.
 */
export class PluginState {
  readonly accountId: string;
  readonly stateFile: string;
  private state: PersistedState;
  private dirty = false;

  private constructor(accountId: string, stateFile: string, state: PersistedState) {
    this.accountId = accountId;
    this.stateFile = stateFile;
    this.state = state;
  }

  /**
   * Load (or initialize) state for an account. Missing file → fresh
   * empty state. Corrupt file → throws so the operator notices instead
   * of silently losing trust pins.
   */
  static async load(accountId: string, opts: PersistenceOptions): Promise<PluginState> {
    const file = join(opts.stateDir, `${safeFilename(accountId)}.json`);
    let state: PersistedState;
    try {
      const raw = await readFile(file, "utf8");
      const parsed = JSON.parse(raw) as PersistedState;
      if (parsed.version !== 1) {
        throw new Error(`unsupported state version ${parsed.version} in ${file}`);
      }
      if (parsed.accountId !== accountId) {
        throw new Error(
          `state file ${file} is for account ${parsed.accountId}, not ${accountId}`,
        );
      }
      state = parsed;
    } catch (e) {
      if (isNotFound(e)) {
        state = { version: 1, accountId, peers: {} };
      } else {
        throw e;
      }
    }
    return new PluginState(accountId, file, state);
  }

  /** Snapshot of all known peers — safe to iterate. */
  listPeers(): PeerRecord[] {
    return Object.values(this.state.peers).map((p) => ({ ...p }));
  }

  getPeer(nodeId: string): PeerRecord | undefined {
    const r = this.state.peers[nodeId];
    return r ? { ...r } : undefined;
  }

  /**
   * Insert or update a peer. Existing fields are merged; the trust state
   * is only mutated when explicitly provided (so a `last_seen` touch
   * can't silently flip a pending peer to trusted).
   */
  upsertPeer(record: Partial<PeerRecord> & { nodeId: string }): PeerRecord {
    const existing = this.state.peers[record.nodeId];
    const merged: PeerRecord = {
      nodeId: record.nodeId,
      agentName: record.agentName ?? existing?.agentName,
      lastSeenMs: record.lastSeenMs ?? existing?.lastSeenMs,
      pinnedFingerprint:
        record.pinnedFingerprint ?? existing?.pinnedFingerprint,
      trust: record.trust ?? existing?.trust ?? "pending",
    };
    this.state.peers[record.nodeId] = merged;
    this.dirty = true;
    return { ...merged };
  }

  /** Mark a peer as trusted (operator-approved). */
  trust(nodeId: string): PeerRecord | undefined {
    const r = this.state.peers[nodeId];
    if (!r) return undefined;
    r.trust = "trusted";
    this.dirty = true;
    return { ...r };
  }

  block(nodeId: string): PeerRecord | undefined {
    const r = this.state.peers[nodeId];
    if (!r) return undefined;
    r.trust = "blocked";
    this.dirty = true;
    return { ...r };
  }

  /** Atomic write — tmp file + rename. No-op if nothing changed since load/save. */
  async save(): Promise<void> {
    if (!this.dirty) return;
    await mkdir(dirname(this.stateFile), { recursive: true });
    const tmp = `${this.stateFile}.tmp`;
    const body = JSON.stringify(this.state, null, 2);
    await writeFile(tmp, body, "utf8");
    await rename(tmp, this.stateFile);
    this.dirty = false;
  }

  /** @internal — for tests. */
  _isDirty(): boolean {
    return this.dirty;
  }
}

function safeFilename(s: string): string {
  return s.replace(/[^A-Za-z0-9_.-]/g, "_");
}

function isNotFound(e: unknown): boolean {
  return (
    typeof e === "object" &&
    e !== null &&
    "code" in e &&
    (e as { code?: string }).code === "ENOENT"
  );
}
