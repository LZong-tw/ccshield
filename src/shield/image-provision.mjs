import { createHash } from "node:crypto";
import { chmod, copyFile, lstat, mkdir, mkdtemp, readFile, realpath, rename, rm, unlink } from "node:fs/promises";
import { isAbsolute, join } from "node:path";

import { IMAGE_WORKER_SOURCE, compileImageWorker } from "../../shield-image/compile.mjs";
import { attestImageWorker, createImageWorker } from "../../shield-image/worker.mjs";
import { readShieldImageProvision, shieldAssetStore, writeShieldImageProvision } from "./paths.mjs";

const REQUIRED_LANGUAGES = ["en-US", "zh-Hant"];
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

// Preview by default. A write builds in a private staging directory, probes the
// staged binary, and only then installs it and replaces the pin, so any failure
// leaves the previous pin and its binary as they were.
export async function provisionImageWorker({
  paths, sourcePath = IMAGE_WORKER_SOURCE, write = false, compile = compileImageWorker, probeTimeoutMs = 120_000,
} = {}) {
  if (typeof sourcePath !== "string" || !isAbsolute(sourcePath)) throw new Error("shield image worker source must be an absolute path");
  const sourceSha256 = sha256(await readFile(sourcePath));
  const version = `image-${sourceSha256.slice(0, 12)}`;
  const store = shieldAssetStore(paths);
  const target = store.imageWorker(sourceSha256);
  const plan = { version, path: target.binary, source: { path: sourcePath, sha256: sourceSha256 } };
  const current = await readShieldImageProvision({ paths }).catch(() => null);
  const upToDate = current !== null && current.path === target.binary && current.source.path === sourcePath
    && current.source.sha256 === sourceSha256 && await attestImageWorker(current.path, current.sha256).then(() => true, () => false);

  if (!write) return { action: "preview", upToDate, ...plan };
  if (upToDate) return { action: "unchanged", ...current };

  await mkdir(store.stagingDir, { recursive: true, mode: 0o700 });
  const staging = await realpath(await mkdtemp(join(store.stagingDir, "image-")));
  try {
    const built = await compile({ sourcePath, outDir: staging, version });
    // Pinned after linking: the linker's ad-hoc signature is part of the bytes.
    const digest = sha256(await readFile(built));
    await chmod(built, 0o500);
    await probeStaged(built, digest, version, probeTimeoutMs);
    await install(built, target, digest);
    const state = await writeShieldImageProvision({ paths, state: { ...plan, sha256: digest } });
    const rebuilt = current?.source.sha256 === sourceSha256 && current.sha256 !== digest;
    return { action: "installed", ...state, ...(rebuilt ? { note: "binary digest changed, source unchanged" } : {}) };
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
}

async function probeStaged(path, digest, version, timeoutMs) {
  const worker = createImageWorker({ path, sha256: digest, probeTimeoutMs: timeoutMs });
  try {
    const probe = await worker.probe();
    if (probe.worker !== version) throw new Error(`shield image worker reports ${probe.worker}, expected ${version}`);
    const missing = REQUIRED_LANGUAGES.filter((language) => !probe.languages.includes(language));
    if (missing.length > 0) throw new Error(`shield image worker lacks Vision languages: ${missing.join(", ")}`);
  } finally {
    worker.close();
  }
}

async function install(built, target, digest) {
  await mkdir(target.dir, { recursive: true, mode: 0o700 });
  const entry = await lstat(target.dir);
  if (entry.isSymbolicLink() || !entry.isDirectory()) throw new Error("shield image worker directory must be a real directory");
  if (typeof process.getuid === "function" && entry.uid !== process.getuid()) throw new Error("shield image worker directory has unexpected owner");
  await chmod(target.dir, 0o700);
  const temporary = `${target.binary}.tmp-${process.pid}-${Date.now()}`;
  try {
    await copyFile(built, temporary);
    await chmod(temporary, 0o500);
    await rename(temporary, target.binary);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
  await attestImageWorker(target.binary, digest).catch(() => { throw new Error("shield image worker digest changed during install"); });
}
