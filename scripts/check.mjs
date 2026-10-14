import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { join } from "node:path";

const roots = ["src", "test", "scripts"];
const skip = new Set(["node_modules", "fixtures"]);

function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (skip.has(entry.name)) continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(path);
    else if (entry.name.endsWith(".mjs")) yield path;
  }
}

let failed = 0;
let checked = 0;
for (const root of roots) {
  for (const file of walk(root)) {
    checked += 1;
    const result = spawnSync(process.execPath, ["--check", file], { stdio: "inherit" });
    if (result.status !== 0) failed += 1;
  }
}

console.log(`checked ${checked} files, ${failed} failed`);
process.exitCode = failed === 0 ? 0 : 1;
