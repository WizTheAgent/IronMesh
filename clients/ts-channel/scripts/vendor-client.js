// Vendor the sibling ironmesh-client into ./vendor/ before pack.
// Avoids both file: dependency resolution (broken across pack boundaries)
// and bundledDependencies (which keeps file: paths and triggers npm install
// failures at OpenClaw-side install time).
//
// The plugin imports re-route from "@wiztheagent/ironmesh-client" to
// "./vendor/ironmesh-client" via a tsconfig path alias at build time.

import { existsSync, rmSync, mkdirSync, cpSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = dirname(here);
const sibling = join(pkgRoot, "..", "ts");
const dst = join(pkgRoot, "vendor", "ironmesh-client");

if (!existsSync(join(sibling, "dist", "index.js"))) {
  console.error("[vendor-client] sibling ../ts is not built — run `npm run build` in clients/ts first");
  process.exit(1);
}

rmSync(dst, { recursive: true, force: true });
mkdirSync(dst, { recursive: true });

cpSync(join(sibling, "dist"), join(dst, "dist"), { recursive: true });
cpSync(join(sibling, "package.json"), join(dst, "package.json"));

const pkg = JSON.parse(readFileSync(join(sibling, "package.json"), "utf-8"));
console.log(`[vendor-client] vendored @wiztheagent/ironmesh-client@${pkg.version} into ./vendor/ironmesh-client`);
