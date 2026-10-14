import { createHash, createPrivateKey, createPublicKey, KeyObject, verify } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";

import { invalidateShieldPolicyBinding, writeShieldPolicyProvision } from "./paths.mjs";

export const SHIELD_POLICY_FORMAT_VERSION = 1;
export const SHIELD_OPA_WASM_SDK_VERSION = "1.8.0";
export const SUPPORTED_OPA_ABIS = new Set(["1"]);

export function validateShieldPolicyBundle(bundle, { publicKey } = {}) {
  if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) throw new TypeError("shield policy bundle is required");
  const manifest = parseManifest(bundle.manifest);
  const wasm = assertWasm(bundle.wasm);
  const trustedKey = assertEd25519PublicKey(publicKey);
  const signature = decodeSignature(bundle.signature);

  assertManifest(manifest);
  if (!verify(null, Buffer.from(canonicalJson(manifest)), trustedKey, signature)) {
    throw new Error("shield policy manifest signature is invalid");
  }
  const actualDigest = createHash("sha256").update(wasm).digest("hex");
  if (actualDigest !== manifest.wasmSha256) throw new Error("shield policy Wasm digest mismatch");

  return Object.freeze({ manifest: freezeManifest(manifest), wasm });
}

export function assertEd25519PublicKey(value) {
  let key;
  if (value instanceof KeyObject) {
    if (value.type !== "public") throw new Error("shield policy trust root must be an Ed25519 public key");
    key = value;
  } else if (typeof value === "string" || Buffer.isBuffer(value)) {
    try {
      createPrivateKey(value);
      throw new Error("shield policy trust root must be an Ed25519 public key");
    } catch (error) {
      if (/trust root must be an Ed25519 public key/.test(error.message)) throw error;
    }
    try {
      key = createPublicKey(value);
    } catch {
      throw new Error("shield policy trust root must be an Ed25519 public key");
    }
  } else {
    throw new Error("shield policy trust root must be an Ed25519 public key");
  }
  if (key.asymmetricKeyType !== "ed25519") throw new Error("shield policy trust root must be an Ed25519 public key");
  return key;
}

export async function readShieldPolicyProvision({ paths, io = { lstat, readFile } } = {}) {
  if (!paths?.policyBundlePath || !paths?.policyPublicKeyPath) throw new TypeError("shield policy provision paths are required");
  const [bundleText, publicKey] = await Promise.all([
    readPrivatePolicyFile(paths.policyBundlePath, io),
    readPrivatePolicyFile(paths.policyPublicKeyPath, io),
  ]);
  let stored;
  try {
    stored = JSON.parse(bundleText);
  } catch {
    throw new Error("shield policy bundle is invalid JSON");
  }
  if (!stored || typeof stored !== "object" || Array.isArray(stored) || Object.keys(stored).length !== 3 || !Object.hasOwn(stored, "manifest") || !Object.hasOwn(stored, "signature") || !Object.hasOwn(stored, "wasm")) {
    throw new Error("shield policy bundle is malformed");
  }
  return Object.freeze({
    bundle: Object.freeze({ manifest: stored.manifest, signature: stored.signature, wasm: decodeArtifact(stored.wasm) }),
    publicKey,
  });
}

export async function installShieldPolicyProvision({ bundlePath, publicKeyPath, write = false, paths, io = { lstat, readFile }, stateIo, loadPolicy } = {}) {
  if (typeof bundlePath !== "string" || !isAbsolute(bundlePath) || resolve(bundlePath) !== bundlePath
    || typeof publicKeyPath !== "string" || !isAbsolute(publicKeyPath) || resolve(publicKeyPath) !== publicKeyPath) {
    throw new Error("shield policy source paths must be canonical and absolute");
  }
  const [bundleText, publicKey] = await Promise.all([readPrivatePolicyFile(bundlePath, io), readPrivatePolicyFile(publicKeyPath, io)]);
  let stored;
  try { stored = JSON.parse(bundleText); } catch { throw new Error("shield policy bundle is invalid JSON"); }
  if (!stored || typeof stored !== "object" || Array.isArray(stored) || Object.keys(stored).length !== 3 || !Object.hasOwn(stored, "manifest") || !Object.hasOwn(stored, "signature") || !Object.hasOwn(stored, "wasm")) {
    throw new Error("shield policy bundle is malformed");
  }
  const bundle = Object.freeze({ manifest: stored.manifest, signature: stored.signature, wasm: decodeArtifact(stored.wasm) });
  if (typeof loadPolicy !== "function") throw new TypeError("shield policy installer requires a loader");
  const policy = await loadPolicy({ bundle, publicKey });
  if (write) {
    await invalidateShieldPolicyBinding({ paths, io: stateIo });
    await writeShieldPolicyProvision({ paths, bundleText, publicKey, io: stateIo });
  }
  return Object.freeze({ version: policy.version, detectorVersions: policy.detectorVersions, write });
}

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function parseManifest(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("shield policy manifest is malformed");
  return value;
}

function assertManifest(manifest) {
  assertExactKeys(manifest, ["formatVersion", "version", "opaAbi", "opaWasmSdkVersion", "wasmSha256", "detectorVersions", "selfTest"], "shield policy manifest");
  if (manifest.formatVersion !== SHIELD_POLICY_FORMAT_VERSION) throw new Error("shield policy manifest format is unsupported");
  assertSafeIdentifier(manifest.version, "shield policy version");
  if (typeof manifest.opaAbi !== "string" || !SUPPORTED_OPA_ABIS.has(manifest.opaAbi)) throw new Error("shield policy OPA ABI is unsupported");
  if (manifest.opaWasmSdkVersion !== SHIELD_OPA_WASM_SDK_VERSION) throw new Error("shield policy OPA/Wasm runtime version is unsupported");
  if (typeof manifest.wasmSha256 !== "string" || !/^[a-f0-9]{64}$/.test(manifest.wasmSha256)) throw new Error("shield policy Wasm digest is invalid");
  assertDetectorVersions(manifest.detectorVersions);
  assertSelfTest(manifest.selfTest);
}

function assertSelfTest(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("shield policy self-test is required");
  assertExactKeys(value, ["input", "expected"], "shield policy self-test");
  if (!value.input || typeof value.input !== "object" || Array.isArray(value.input)) throw new Error("shield policy self-test input is invalid");
  if (!value.expected || typeof value.expected !== "object" || Array.isArray(value.expected)) throw new Error("shield policy self-test expected decision is invalid");
}

function assertDetectorVersions(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("shield policy detector versions are required");
  const names = Object.keys(value).sort();
  if (names.length !== 2 || names[0] !== "gitleaks" || names[1] !== "privacy") {
    throw new Error("shield policy detector versions must include Gitleaks and Privacy");
  }
  for (const [name, version] of Object.entries(value)) {
    assertSafeIdentifier(name, "shield policy detector name");
    assertSafeIdentifier(version, "shield policy detector version");
  }
}

function assertWasm(value) {
  if (!(value instanceof Uint8Array) || value.byteLength === 0) throw new Error("shield policy compiled Wasm artifact is required");
  return Buffer.from(value);
}

function decodeSignature(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) throw new Error("shield policy manifest signature is required");
  const signature = Buffer.from(value, "base64");
  if (signature.length === 0) throw new Error("shield policy manifest signature is required");
  return signature;
}

function decodeArtifact(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) throw new Error("shield policy Wasm artifact is invalid");
  const wasm = Buffer.from(value, "base64");
  if (wasm.length === 0) throw new Error("shield policy Wasm artifact is invalid");
  return wasm;
}

async function readPrivatePolicyFile(path, io) {
  const entry = await io.lstat(path);
  if (entry.isSymbolicLink() || !entry.isFile() || (entry.mode & 0o077) !== 0) throw new Error("shield policy provision file is not private regular state");
  if (typeof process.getuid === "function" && entry.uid !== process.getuid()) throw new Error("shield policy provision file has unexpected owner");
  return io.readFile(path, "utf8");
}

function assertSafeIdentifier(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(value)) throw new Error(`${label} is invalid`);
  return value;
}

function assertExactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== [...expected].sort()[index])) {
    throw new Error(`${label} contains unsupported fields`);
  }
}

function freezeManifest(manifest) {
  return Object.freeze({
    formatVersion: manifest.formatVersion,
    version: manifest.version,
    opaAbi: manifest.opaAbi,
    opaWasmSdkVersion: manifest.opaWasmSdkVersion,
    wasmSha256: manifest.wasmSha256,
    detectorVersions: Object.freeze({ ...manifest.detectorVersions }),
    selfTest: Object.freeze({ input: Object.freeze({ ...manifest.selfTest.input }), expected: Object.freeze({ ...manifest.selfTest.expected }) }),
  });
}
