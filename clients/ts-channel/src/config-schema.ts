// JSON-schema-shaped descriptor for the channel's openclaw.json block.
//
// Operators put a section like this in their OpenClaw config tree:
//
//   "channels": {
//     "ironmesh": {
//       "default": {
//         "url": "ws://127.0.0.1:8765",
//         "passphrase": "my-mesh-passphrase",
//         "name": "my-agent"
//       }
//     }
//   }
//
// We export a small validator (not a full JSON Schema engine — we want
// zero runtime deps) plus a structural description that OpenClaw's
// setup tooling can show in `openclaw mcp set` and friends.

import type { IronMeshChannelAccount } from "./types.js";

/** Per-account record in the openclaw.json `channels.ironmesh` map. */
export interface ChannelAccountConfig {
  /** WebSocket URL of the IronMesh daemon, e.g. ws://127.0.0.1:8765. */
  url: string;
  /** Mesh-wide shared passphrase. Minimum 12 characters per the daemon. */
  passphrase: string;
  /** Agent name advertised on HELLO. */
  name: string;
}

/** OpenClaw config tree shape this channel reads. */
export interface ChannelConfigTree {
  channels?: {
    ironmesh?: Record<string, ChannelAccountConfig>;
  };
}

export interface ChannelValidationError {
  /** Dotted path to the offending field, e.g. `channels.ironmesh.default.url`. */
  path: string;
  /** Human-readable description. */
  message: string;
}

/**
 * Validate the IronMesh section of an OpenClaw config tree. Returns an
 * empty array on success, or a list of structured errors. Caller is
 * free to surface them in setup wizards or fail-closed at startup.
 */
export function validateChannelConfig(cfg: unknown): ChannelValidationError[] {
  const errors: ChannelValidationError[] = [];
  if (cfg == null || typeof cfg !== "object") {
    errors.push({ path: "(root)", message: "config must be an object" });
    return errors;
  }
  const root = cfg as Record<string, unknown>;
  const channels = root.channels;
  if (channels == null) return errors; // No IronMesh section is fine.
  if (typeof channels !== "object") {
    errors.push({ path: "channels", message: "must be an object" });
    return errors;
  }
  const ironmesh = (channels as Record<string, unknown>).ironmesh;
  if (ironmesh == null) return errors;
  if (typeof ironmesh !== "object") {
    errors.push({ path: "channels.ironmesh", message: "must be an object mapping accountId to account record" });
    return errors;
  }
  for (const [accountId, raw] of Object.entries(ironmesh as Record<string, unknown>)) {
    const base = `channels.ironmesh.${accountId}`;
    if (raw == null || typeof raw !== "object") {
      errors.push({ path: base, message: "must be an object" });
      continue;
    }
    const acc = raw as Record<string, unknown>;
    for (const k of ["url", "passphrase", "name"] as const) {
      if (typeof acc[k] !== "string" || (acc[k] as string).length === 0) {
        errors.push({ path: `${base}.${k}`, message: `required string field "${k}"` });
      }
    }
    if (typeof acc.url === "string" && !/^wss?:\/\//.test(acc.url)) {
      errors.push({ path: `${base}.url`, message: "must start with ws:// or wss://" });
    }
    if (typeof acc.passphrase === "string" && (acc.passphrase as string).length < 12) {
      errors.push({
        path: `${base}.passphrase`,
        message: "minimum 12 characters (the daemon enforces this)",
      });
    }
  }
  return errors;
}

/**
 * Read the per-account record for ``accountId`` (or the only one when
 * there's exactly one). Throws on a config that fails validation —
 * easier to fail at startup than mid-message.
 */
export function resolveChannelAccount(
  cfg: unknown,
  accountId?: string | null,
): IronMeshChannelAccount {
  const errs = validateChannelConfig(cfg);
  if (errs.length) {
    const summary = errs.map((e) => `${e.path}: ${e.message}`).join("; ");
    throw new Error(`[ironmesh-channel] invalid config: ${summary}`);
  }
  const map =
    ((cfg as ChannelConfigTree | null | undefined)?.channels?.ironmesh) ?? {};
  const ids = Object.keys(map);
  if (ids.length === 0) {
    throw new Error("[ironmesh-channel] no accounts configured under channels.ironmesh");
  }
  const wantId = accountId ?? (ids.length === 1 ? ids[0] : "default");
  const acc = map[wantId];
  if (!acc) {
    throw new Error(
      `[ironmesh-channel] no account "${wantId}" — known: ${ids.join(", ")}`,
    );
  }
  return {
    accountId: wantId,
    url: acc.url,
    passphrase: acc.passphrase,
    name: acc.name,
  };
}

/**
 * Enumerate accountIds present in the config. Returns an empty array
 * when no IronMesh section is configured.
 */
export function listChannelAccountIds(cfg: unknown): string[] {
  const map =
    ((cfg as ChannelConfigTree | null | undefined)?.channels?.ironmesh) ?? {};
  return Object.keys(map);
}

/**
 * Structural descriptor — when the OpenClaw plugin SDK exposes a JSON
 * Schema host, this can be the body. Kept as a data export so it's
 * inspectable from outside without instantiating the plugin.
 */
export const ChannelConfigSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    channels: {
      type: "object",
      properties: {
        ironmesh: {
          type: "object",
          additionalProperties: {
            type: "object",
            required: ["url", "passphrase", "name"],
            properties: {
              url: {
                type: "string",
                pattern: "^wss?://",
                description: "WebSocket URL of the IronMesh daemon",
              },
              passphrase: {
                type: "string",
                minLength: 12,
                description: "Mesh-wide shared passphrase (minimum 12 chars)",
              },
              name: {
                type: "string",
                minLength: 1,
                description: "Agent name advertised on HELLO",
              },
            },
            additionalProperties: false,
          },
        },
      },
    },
  },
} as const;
