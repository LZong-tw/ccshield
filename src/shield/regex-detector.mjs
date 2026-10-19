import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const DEFAULT_REGEX_WORKER_SOURCE = fileURLToPath(new URL("../../detectors/regex/privacy-worker.mjs", import.meta.url));

const defaultIo = { chmod, lstat, mkdir, open, readFile, rename, unlink };

// launchd's PATH cannot resolve `#!/usr/bin/env node`, so the stored copy
// names the node binary that runs the daemon. The digest covers the rewritten
// bytes, which is what the daemon will actually execute.
export async function prepareRegexWorker({ storeRoot, sourcePath = DEFAULT_REGEX_WORKER_SOURCE, nodePath = process.execPath, io = defaultIo } = {}) {
  if (typeof storeRoot !== "string" || !isAbsolute(storeRoot) || resolve(storeRoot) !== storeRoot) throw new Error("shield regex detector requires the asset store");
  if (typeof nodePath !== "string" || !isAbsolute(nodePath) || /\s/.test(nodePath)) throw new Error("shield regex detector needs an absolute node path");
  const source = (await io.readFile(sourcePath)).toString("utf8");
  const version = /^const VERSION = "([A-Za-z0-9._-]{1,128})";$/m.exec(source)?.[1];
  if (!version || !source.startsWith("#!")) throw new Error("shield regex detector source is invalid");
  const bytes = Buffer.from(`#!${nodePath}${source.slice(source.indexOf("\n"))}`, "utf8");
  const command = join(storeRoot, "regex", version, "privacy-worker.mjs");
  return Object.freeze({
    version,
    worker: Object.freeze({ command, args: Object.freeze([]), sha256: createHash("sha256").update(bytes).digest("hex") }),
    bytes,
  });
}

export async function installRegexWorker(prepared, { io = defaultIo } = {}) {
  const path = prepared.worker.command;
  const dir = dirname(path);
  await io.mkdir(dir, { recursive: true, mode: 0o755 });
  const entry = await io.lstat(dir);
  if (entry.isSymbolicLink() || !entry.isDirectory()) throw new Error("shield regex detector directory must be a real directory");
  if (typeof process.getuid === "function" && entry.uid !== process.getuid()) throw new Error("shield regex detector directory has unexpected owner");
  const temporaryPath = `${path}.tmp-${process.pid}-${Date.now()}`;
  try {
    const handle = await io.open(temporaryPath, "wx", 0o600);
    try { await handle.writeFile(prepared.bytes); await handle.chmod(0o755); }
    finally { await handle.close(); }
    await io.rename(temporaryPath, path);
  } catch (error) {
    await io.unlink(temporaryPath).catch(() => {});
    throw error;
  }
  const written = await io.readFile(path);
  if (createHash("sha256").update(written).digest("hex") !== prepared.worker.sha256) throw new Error("shield regex detector digest mismatch after install");
}
