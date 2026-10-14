import { createHash } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, resolve } from "node:path";

import { runPrivacyWorkerSelfTest } from "./privacy.mjs";
import { verifyShieldCheckpoint } from "./checkpoint.mjs";
import { writeShieldAssetsProvision } from "./paths.mjs";

const FORMAT_VERSION = 1;
const O200K_CACHE_KEY = "fb374d419588a4632f3f557e76b4b70aebbca790";
const defaultIo = { lstat, readFile, realpath };

export async function provisionShieldAssets({ bundlePath, gitleaksPath, gitleaksRulesPath, privacyBundlePath, write = false, paths, io = defaultIo, writeState, runPrivacySelfTest: selfTest = runPrivacyWorkerSelfTest } = {}) {
  const bundle = await validateAsset({ path: bundlePath, executable: false, label: "policy bundle", io });
  const gitleaks = await validateAsset({ path: gitleaksPath, executable: true, label: "gitleaks", io });
  const gitleaksRules = await validateAsset({ path: gitleaksRulesPath, executable: false, label: "gitleaks rules", io });
  const privacyBundle = await validateAsset({ path: privacyBundlePath, executable: false, label: "privacy bundle", io });
  const manifest = parsePrivacyManifest(privacyBundle.bytes);
  const worker = await validateAsset({ path: manifest.worker.command, executable: true, label: "privacy worker", expectedDigest: manifest.worker.sha256, io });
  const checkpoint = manifest.checkpoint ? await verifyShieldCheckpoint(manifest.checkpoint) : null;
  const source = manifest.source ? await verifyShieldCheckpoint(manifest.source, { label: "source" }) : null;
  const adapter = manifest.adapter ? await validateAsset({ path: manifest.adapter.path, executable: false, label: "privacy adapter", expectedDigest: manifest.adapter.sha256, io }) : null;
  const tokenizer = manifest.tokenizer ? await validateAsset({ path: manifest.tokenizer.path, executable: false, label: "privacy tokenizer", expectedDigest: manifest.tokenizer.sha256, io }) : null;
  const state = Object.freeze({
    version: FORMAT_VERSION,
    bundle: Object.freeze({ version: policyVersion(bundle.bytes), sha256: bundle.sha256, path: bundle.path }),
    gitleaks: Object.freeze({
      sha256: gitleaks.sha256,
      path: gitleaks.path,
      // Derived, not declared: nothing cross-checks this version, so a
      // hand-typed one could only ever go stale against the file it names.
      rules: Object.freeze({ path: gitleaksRules.path, sha256: gitleaksRules.sha256, version: `rules-${gitleaksRules.sha256.slice(0, 12)}` }),
    }),
    privacy: Object.freeze({
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
    }),
  });
  const result = await selfTest(state);
  if (!result || result.version !== state.privacy.version) throw new Error("shield privacy worker self-test failed");
  if (write) {
    const writer = writeState ?? (paths ? (value) => writeShieldAssetsProvision({ paths, state: value }) : null);
    if (typeof writer !== "function") throw new Error("shield asset provision writer is required");
    await writer(state);
  }
  return state;
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
    || value.formatVersion !== FORMAT_VERSION || value.protocol !== "airkit-privacy-ndjson-v1" || !safeIdentifier(value.version)
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
    || !validOpfArguments(value.worker.args, value))) {
    throw new Error("shield privacy bundle manifest is invalid");
  }
  return Object.freeze({
    version: value.version,
    worker: Object.freeze({ command: value.worker.command, args: Object.freeze([...value.worker.args]), sha256: value.worker.sha256 }),
    ...(value.checkpoint ? { checkpoint: value.checkpoint, source: value.source, adapter: value.adapter, tokenizer: value.tokenizer } : {}),
  });
}

function validOpfArguments(args, manifest) {
  return args.length === 22 && isAbsolute(args[1]) && resolve(args[1]) === args[1]
    && args[0] === "--python"
    && args[2] === "--checkpoint" && args[3] === manifest.checkpoint?.path
    && args[4] === "--checkpoint-sha256" && args[5] === manifest.checkpoint?.sha256
    && args[6] === "--checkpoint-version" && args[7] === manifest.checkpoint?.version
    && args[8] === "--opf-source" && args[9] === manifest.source?.path
    && args[10] === "--opf-source-sha256" && args[11] === manifest.source?.sha256
    && args[12] === "--adapter-sha256" && args[13] === manifest.adapter?.sha256
    && args[14] === "--tokenizer" && args[15] === manifest.tokenizer?.path
    && args[16] === "--tokenizer-sha256" && args[17] === manifest.tokenizer?.sha256
    && args[18] === "--startup-timeout-ms" && args[19] === "30000"
    && args[20] === "--scan-timeout-ms" && ["2000", "10000", "25000", "60000"].includes(args[21]);
}

function safeIdentifier(value) { return typeof value === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(value); }
function isPlainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exactKeys(value, expected) { const keys = Object.keys(value).sort(); return keys.length === expected.length && keys.every((key, index) => key === expected[index]); }
