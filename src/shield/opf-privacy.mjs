import { createHash } from "node:crypto";
import { chmod, copyFile, mkdir, readFile, readdir, realpath, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { buildOpfWorkerArgs } from "./opf-args.mjs";
import { PRIVACY_PROTOCOL } from "./protocol.mjs";
import { MANIFEST_FORMAT_VERSION, provisionPrivacyRecord } from "./provision.mjs";

export const DEFAULT_OPF_SOURCE_DIR = fileURLToPath(new URL("../../detectors/opf/", import.meta.url));
const WORKER_NAME = "privacy-opf-worker.mjs";
// The CPU-only worker needs the widest scan bound the protocol allows.
const SCAN_TIMEOUT_MS = 60_000;

// Turns a verified OPF bundle into the manifest `ccshield privacy` accepts and
// provisions it through the same path, so the daemon swaps off regex on its
// next refresh. The manifest sits in the bundle it describes.
export async function provisionOpfPrivacy({ paths, pins, bundle, sourceDir = DEFAULT_OPF_SOURCE_DIR, provision = provisionPrivacyRecord } = {}) {
  const workerPath = await stageOpfWorker({ bundleDir: bundle.dir, sourceDir });
  const manifest = await opfPrivacyManifest({ pins, bundle, workerPath });
  const manifestPath = join(bundle.dir, "privacy-manifest.json");
  const temporary = `${manifestPath}.${process.pid}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    await rename(temporary, manifestPath);
  } finally {
    await rm(temporary, { force: true });
  }
  return provision({ paths, privacyBundlePath: manifestPath });
}

// The worker loads its adapter and Python helpers from its own directory and
// must be executable, but the package ships them 0644 in a nested layout. The
// job copies them flat into the bundle, so the provisioned worker lives in the
// asset store next to the files it serves.
export async function stageOpfWorker({ bundleDir, sourceDir = DEFAULT_OPF_SOURCE_DIR }) {
  const target = join(bundleDir, "worker");
  const staging = `${target}.tmp-${process.pid}`;
  const helpers = (await readdir(join(sourceDir, "python"))).filter((name) => name.endsWith(".py"));
  await rm(staging, { recursive: true, force: true });
  try {
    await mkdir(staging, { mode: 0o700 });
    await copyFile(join(sourceDir, WORKER_NAME), join(staging, WORKER_NAME));
    await chmod(join(staging, WORKER_NAME), 0o755);
    await copyFile(join(sourceDir, "opf-adapter.mjs"), join(staging, "opf-adapter.mjs"));
    await chmod(join(staging, "opf-adapter.mjs"), 0o644);
    for (const name of helpers) {
      await copyFile(join(sourceDir, "python", name), join(staging, name));
      await chmod(join(staging, name), 0o644);
    }
    await chmod(staging, 0o755);
    await rm(target, { recursive: true, force: true });
    await rename(staging, target);
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
  return join(target, WORKER_NAME);
}

export async function opfPrivacyManifest({ pins, bundle, workerPath }) {
  const command = await realpath(workerPath);
  const workerBytes = await readFile(command);
  // The version is read from the same bytes the digest pins; the self-test then
  // has to hear the running worker report it.
  const version = /^const VERSION = "([A-Za-z0-9._-]{1,128})";$/m.exec(workerBytes.toString("utf8"))?.[1];
  if (!version) throw new Error("shield OPF worker declares no version");
  const adapterPath = resolve(dirname(command), "opf-adapter.mjs");
  const references = {
    checkpoint: { path: join(bundle.checkpoint, "original"), sha256: pins.checkpoint.treeSha256, version: pins.checkpoint.revision },
    source: { path: join(bundle.src, "opf"), sha256: pins.code.treeSha256, version: pins.code.commit },
    adapter: { path: adapterPath, sha256: sha256(await readFile(adapterPath)) },
    tokenizer: { path: join(bundle.tokenizer, pins.tokenizer.cacheName), sha256: pins.tokenizer.sha256, version: pins.tokenizer.encoding },
  };
  const args = buildOpfWorkerArgs({ ...references, python: join(bundle.venv, "bin", "python"), scanTimeoutMs: SCAN_TIMEOUT_MS });
  return {
    formatVersion: MANIFEST_FORMAT_VERSION,
    protocol: PRIVACY_PROTOCOL,
    version,
    worker: { command, args, sha256: sha256(workerBytes) },
    ...references,
  };
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
