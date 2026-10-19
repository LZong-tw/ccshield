import { createHash } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, resolve } from "node:path";

import { runPrivacyWorkerSelfTest } from "./privacy.mjs";
import { verifyShieldCheckpoint } from "./checkpoint.mjs";
import { ASSETS_FORMAT_VERSION, readShieldAssetsProvision, shieldAssetStore, writeShieldAssetsProvision } from "./paths.mjs";
import { installRegexWorker, prepareRegexWorker } from "./regex-detector.mjs";
import { isValidOpfWorkerArgs } from "./opf-args.mjs";
import { PRIVACY_PROTOCOL } from "./protocol.mjs";

const MANIFEST_FORMAT_VERSION = 1;
const O200K_CACHE_KEY = "fb374d419588a4632f3f557e76b4b70aebbca790";
const defaultIo = { lstat, readFile, realpath };

export async function provisionShieldAssets({
  bundlePath, gitleaksPath, gitleaksRulesPath, privacyBundlePath, write = false, paths, io = defaultIo, writeState,
  runPrivacySelfTest: selfTest = runPrivacyWorkerSelfTest,
  storeRoot = paths ? shieldAssetStore(paths).root : undefined, regexWorkerSource, nodePath, installRegex = installRegexWorker,
} = {}) {
  const bundle = await validateAsset({ path: bundlePath, executable: false, label: "policy bundle", io });
  const gitleaks = await validateAsset({ path: gitleaksPath, executable: true, label: "gitleaks", io });
  const gitleaksRules = await validateAsset({ path: gitleaksRulesPath, executable: false, label: "gitleaks rules", io });
  // Without an OPF bundle the store records privacy as absent and the daemon
  // runs on the regex worker until the pinned download verifies one.
  const privacy = privacyBundlePath == null ? null : await provisionPrivacy(privacyBundlePath, io);
  const regex = await prepareRegexWorker({ storeRoot, sourcePath: regexWorkerSource, nodePath });
  const state = Object.freeze({
    version: ASSETS_FORMAT_VERSION,
    bundle: Object.freeze({ version: policyVersion(bundle.bytes), sha256: bundle.sha256, path: bundle.path }),
    gitleaks: Object.freeze({
      sha256: gitleaks.sha256,
      path: gitleaks.path,
      // Derived, not declared: nothing cross-checks this version, so a
      // hand-typed one could only ever go stale against the file it names.
      rules: Object.freeze({ path: gitleaksRules.path, sha256: gitleaksRules.sha256, version: `rules-${gitleaksRules.sha256.slice(0, 12)}` }),
    }),
    privacy: privacy ?? Object.freeze({ state: "absent" }),
    regex: Object.freeze({ version: regex.version, worker: regex.worker }),
  });
  if (privacy) {
    const result = await selfTest(state);
    if (!result || result.version !== state.privacy.version) throw new Error("shield privacy worker self-test failed");
  }
  if (write) {
    const writer = writeState ?? (paths ? async (value) => writeShieldAssetsProvision({ paths, state: keepInstallRecord(value, await readShieldAssetsProvision({ paths }).catch(() => null)) }) : null);
    if (typeof writer !== "function") throw new Error("shield asset provision writer is required");
    // The file lands before the record that names it, so a reader never sees
    // a regex reference without its worker.
    await installRegex(regex);
    await writer(state);
  }
  return state;
}

// `ccshield install --write` owns the opf block and the Gitleaks origin; a
// re-provision keeps them, the origin only while it still names the same binary.
export function keepInstallRecord(state, current) {
  if (!current) return state;
  const sameGitleaks = current.gitleaks.origin && current.gitleaks.path === state.gitleaks.path && current.gitleaks.sha256 === state.gitleaks.sha256;
  return {
    ...state,
    ...(sameGitleaks ? { gitleaks: { origin: current.gitleaks.origin, version: current.gitleaks.version, ...state.gitleaks } } : {}),
    ...(current.opf ? { opf: current.opf } : {}),
  };
}

async function provisionPrivacy(privacyBundlePath, io) {
  const privacyBundle = await validateAsset({ path: privacyBundlePath, executable: false, label: "privacy bundle", io });
  const manifest = parsePrivacyManifest(privacyBundle.bytes);
  const worker = await validateAsset({ path: manifest.worker.command, executable: true, label: "privacy worker", expectedDigest: manifest.worker.sha256, io });
  const checkpoint = manifest.checkpoint ? await verifyShieldCheckpoint(manifest.checkpoint) : null;
  const source = manifest.source ? await verifyShieldCheckpoint(manifest.source, { label: "source" }) : null;
  const adapter = manifest.adapter ? await validateAsset({ path: manifest.adapter.path, executable: false, label: "privacy adapter", expectedDigest: manifest.adapter.sha256, io }) : null;
  const tokenizer = manifest.tokenizer ? await validateAsset({ path: manifest.tokenizer.path, executable: false, label: "privacy tokenizer", expectedDigest: manifest.tokenizer.sha256, io }) : null;
  // A bundle handed to provision lives outside the asset store, so its OPF
  // files are adopted; only the pinned downloader records "downloaded".
  return Object.freeze({
    state: "verified",
    ...(checkpoint ? { origin: "adopted" } : {}),
    version: manifest.version,
    sha256: privacyBundle.sha256,
    path: privacyBundle.path,
    worker: Object.freeze({ command: worker.path, args: Object.freeze([...manifest.worker.args]), sha256: worker.sha256 }),
    ...(checkpoint ? {
      checkpoint,
      source,
      adapter: Object.freeze({ path: adapter.path, sha256: adapter.sha256 }),
      tokenizer: Object.freeze({ path: tokenizer.path, sha256: tokenizer.sha256, version: manifest.tokenizer.version }),
    } : {}),
  });
}

async function validateAsset({ path, executable, label, expectedDigest, io }) {
  if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path) throw new Error(`shield ${label} path must be canonical and absolute`);
  let entry;
  let canonicalPath;
  let bytes;
  try { [entry, canonicalPath, bytes] = await Promise.all([io.lstat(path), io.realpath(path), io.readFile(path)]); }
  catch { throw new Error(`shield ${label} validation failed`); }
  if (canonicalPath !== path) throw new Error(`shield ${label} path is not canonical`);
  if (entry.isSymbolicLink?.()) throw new Error(`shield ${label} must not be a symlink`);
  if (!entry.isFile?.()) throw new Error(`shield ${label} must be a regular file`);
  if (typeof process.getuid === "function" && entry.uid !== process.getuid()) throw new Error(`shield ${label} has unexpected owner`);
  if ((entry.mode & 0o022) !== 0) throw new Error(`shield ${label} must not be group or world writable`);
  if (executable && (entry.mode & 0o100) === 0) throw new Error(`shield ${label} is not executable`);
  const content = Buffer.from(bytes);
  const sha256 = createHash("sha256").update(content).digest("hex");
  if (expectedDigest !== undefined && sha256 !== expectedDigest) throw new Error(`shield ${label} digest mismatch`);
  return Object.freeze({ path, sha256, bytes: content });
}

function policyVersion(bytes) {
  let parsed;
  try { parsed = JSON.parse(bytes.toString("utf8")); } catch { throw new Error("shield policy bundle manifest is invalid"); }
  const version = parsed?.manifest?.version;
  if (!safeIdentifier(version)) throw new Error("shield policy bundle manifest is invalid");
  return version;
}

function parsePrivacyManifest(bytes) {
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); } catch { throw new Error("shield privacy bundle manifest is invalid"); }
  if (!isPlainObject(value) || !(exactKeys(value, ["formatVersion", "protocol", "version", "worker"])
    || exactKeys(value, ["adapter", "checkpoint", "formatVersion", "protocol", "source", "tokenizer", "version", "worker"]))
    || value.formatVersion !== MANIFEST_FORMAT_VERSION || value.protocol !== PRIVACY_PROTOCOL || !safeIdentifier(value.version)
    || !isPlainObject(value.worker) || !exactKeys(value.worker, ["args", "command", "sha256"])
    || typeof value.worker.command !== "string" || !isAbsolute(value.worker.command) || resolve(value.worker.command) !== value.worker.command
    || !Array.isArray(value.worker.args) || !value.worker.args.every((argument) => typeof argument === "string" && argument.length > 0 && argument.length <= 256)
    || !/^[a-f0-9]{64}$/.test(value.worker.sha256 ?? "")) {
    throw new Error("shield privacy bundle manifest is invalid");
  }
  if (value.checkpoint !== undefined && (!isPlainObject(value.adapter)
    || !exactKeys(value.adapter, ["path", "sha256"])
    || value.adapter.path !== resolve(dirname(value.worker.command), "opf-adapter.mjs")
    || !/^[a-f0-9]{64}$/.test(value.adapter.sha256 ?? "")
    || !isPlainObject(value.tokenizer) || !exactKeys(value.tokenizer, ["path", "sha256", "version"])
    || !isAbsolute(value.tokenizer.path) || resolve(value.tokenizer.path) !== value.tokenizer.path
    || basename(value.tokenizer.path) !== O200K_CACHE_KEY || value.tokenizer.version !== "o200k_base"
    || !/^[a-f0-9]{64}$/.test(value.tokenizer.sha256 ?? "")
    || !isValidOpfWorkerArgs(value.worker.args, value))) {
    throw new Error("shield privacy bundle manifest is invalid");
  }
  return Object.freeze({
    version: value.version,
    worker: Object.freeze({ command: value.worker.command, args: Object.freeze([...value.worker.args]), sha256: value.worker.sha256 }),
    ...(value.checkpoint ? { checkpoint: value.checkpoint, source: value.source, adapter: value.adapter, tokenizer: value.tokenizer } : {}),
  });
}

function safeIdentifier(value) { return typeof value === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(value); }
function isPlainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exactKeys(value, expected) { const keys = Object.keys(value).sort(); return keys.length === expected.length && keys.every((key, index) => key === expected[index]); }
