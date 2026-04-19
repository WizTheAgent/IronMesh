// Bundled entry point for OpenClaw to load this package as a channel
// plugin without the operator writing any glue code.
//
// Usage from an OpenClaw plugin loader:
//
//   import { defineIronMeshChannelEntry }
//     from "@wiztheagent/openclaw-ironmesh-channel/entry";
//
//   // top-level await (Node 18+ ESM) or inside an async function
//   export default await defineIronMeshChannelEntry();
//
// To override defaults (e.g. a non-standard config tree shape):
//
//   await defineIronMeshChannelEntry({
//     listAccountIds: (cfg) => Object.keys(cfg?.myCustomChannelMap ?? {}),
//     resolveAccount: (cfg, id) => cfg.myCustomChannelMap[id ?? "default"],
//   });
//
// The OpenClaw plugin SDK is a peer dependency — we dynamic-import its
// `defineBundledChannelEntry` helper at call time. When OpenClaw isn't
// installed (e.g. unit tests, library consumers), the call rejects
// with a descriptive error so the operator sees the missing peer dep.

import { ironMeshChannelPlugin } from "./plugin.js";
import {
  listChannelAccountIds,
  resolveChannelAccount,
  ChannelConfigSchema,
} from "./config-schema.js";
import type { IronMeshChannelPluginOptions } from "./plugin.js";

/**
 * Options accepted by ``defineIronMeshChannelEntry``. All fields are
 * optional — sensible defaults wire the package into the standard
 * ``channels.ironmesh.<accountId>`` config layout. Override
 * ``listAccountIds`` / ``resolveAccount`` if your OpenClaw config
 * tree puts the IronMesh section somewhere unusual.
 */
export interface IronMeshChannelEntryOptions
  extends Partial<IronMeshChannelPluginOptions> {}

/**
 * Build the bundled channel entry that OpenClaw expects. Returns
 * whatever ``defineBundledChannelEntry`` returns from the plugin SDK
 * (its exact shape is OpenClaw's; we don't re-declare it here).
 *
 * On a host without the ``openclaw`` package installed, this throws a
 * descriptive error so the operator sees the missing peer dep instead
 * of a confusing ``ERR_MODULE_NOT_FOUND``.
 */
export async function defineIronMeshChannelEntry(
  opts: IronMeshChannelEntryOptions = {},
): Promise<unknown> {
  let define: ((spec: unknown) => unknown) | undefined;
  try {
    // openclaw is an optional peer dep — install it in the host project.
    // The dynamic specifier prevents tsc from requiring resolution at
    // build time when the dep isn't present.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const sdk: any = await import(
      /* @vite-ignore */ /* webpackIgnore: true */ "openclaw" as string
    );
    define = (sdk.defineBundledChannelEntry ??
      sdk.default?.defineBundledChannelEntry) as
      | ((spec: unknown) => unknown)
      | undefined;
  } catch (e) {
    throw new Error(
      "[ironmesh-channel] failed to load the openclaw plugin SDK — " +
        "install `openclaw` as a peer dependency in the host project. " +
        `(underlying: ${e instanceof Error ? e.message : String(e)})`,
    );
  }
  if (typeof define !== "function") {
    throw new Error(
      "[ironmesh-channel] openclaw is installed but does not export " +
        "defineBundledChannelEntry — required minimum: openclaw >= 2026.3",
    );
  }

  const plugin = ironMeshChannelPlugin({
    listAccountIds: opts.listAccountIds ?? listChannelAccountIds,
    resolveAccount: opts.resolveAccount ?? resolveChannelAccount,
    logger: opts.logger,
    stateDir: opts.stateDir,
  });

  return define({
    plugin,
    configSchema: ChannelConfigSchema,
  });
}
