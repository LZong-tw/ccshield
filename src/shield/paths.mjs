import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";

const SHIELD_LABEL = "com.airkit.shield";
const defaultIo = { chmod, constants, lstat, mkdir, open, readFile, rename, unlink };
const canonicalShieldPaths = new WeakSet();

export function shieldPaths({ env = process.env, homeDir = homeFromEnv(env), uid = env.AIRKIT_GUI_UID ?? env.UID ?? process.getuid?.(), lane = "subscription", rootDir, configPath, identityPath, socketPath, launchAgentPath } = {}) {
  assertLane(lane);
  const home = absolutePath(homeDir, "homeDir");
  const canonicalRoot = join(home, ".local", "state", "airkit-shield", lane);
  const root = absolutePath(rootDir ?? env.AIRKIT_SHIELD_ROOT_DIR ?? canonicalRoot, "rootDir");
  if (resolve(root) !== resolve(canonicalRoot)) throw new Error("rootDir must be the canonical AirKit Shield state directory");
  const serviceLabel = `${SHIELD_LABEL}.${lane}`;
  const paths = {
    lane,
    serviceLabel,
    rootDir: root,
    configPath: childPath(configPath ?? join(root, "config.json"), root, "configPath"),
    identityPath: childPath(identityPath ?? join(root, "identity.json"), root, "identityPath"),
    policyStatePath: childPath(join(root, "policy-state.json"), root, "policyStatePath"),
    policyBundlePath: childPath(join(root, "policy-bundle.json"), root, "policyBundlePath"),
    policyPublicKeyPath: childPath(join(root, "policy-public.pem"), root, "policyPublicKeyPath"),
    assetsProvisionPath: childPath(join(root, "assets-provision.json"), root, "assetsProvisionPath"),
    socketPath: childPath(socketPath ?? join(root, "shield.sock"), root, "socketPath"),
    launchAgentPath: launchAgentPath ?? join(home, "Library", "LaunchAgents", `${serviceLabel}.plist`),
    launchdDomain: `gui/${numericUid(uid)}`,
  };
  paths.launchAgentPath = absolutePath(paths.launchAgentPath, "launchAgentPath");
  if (resolve(dirname(paths.launchAgentPath)) !== resolve(home, "Library", "LaunchAgents")) {
    throw new Error("launchAgentPath must be under homeDir/Library/LaunchAgents");
  }
  paths.launchdTarget = `${paths.launchdDomain}/${serviceLabel}`;
  Object.freeze(paths);
  canonicalShieldPaths.add(paths);
  return paths;
}

export function shieldPathsForConfigPath({ env = process.env, configPath } = {}) {
  for (const lane of ["subscription", "managed"]) {
    const paths = shieldPaths({ env, lane });
    if (configPath === paths.configPath) return paths;
  }
  throw new Error("shield daemon config path must be a canonical lane-specific private configuration path");
}

export async function readShieldIdentity({ paths, io = defaultIo } = {}) {
  if (!paths?.identityPath) throw new TypeError("shield identity paths are required");
  let contents;
  try {
    contents = await io.readFile(paths.identityPath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  let identity;
  try {
    identity = JSON.parse(contents);
  } catch {
    throw new Error("shield identity is invalid JSON");
  }
  return assertShieldIdentity(identity);
}

export async function readShieldPolicyState({ paths, io = defaultIo } = {}) {
  if (!paths?.policyStatePath) throw new TypeError("shield policy state paths are required");
  assertCanonicalPolicyStatePath(paths);
  let contents;
  try {
    await assertPrivateRegularFile(paths.policyStatePath, io);
    contents = await io.readFile(paths.policyStatePath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  let state;
  try {
    state = JSON.parse(contents);
  } catch {
    throw new Error("shield policy state is invalid JSON");
  }
  return assertShieldPolicyState(state);
}

export function assertShieldIdentity(identity) {
  let url;
  try { url = new URL(identity?.origin ?? ""); } catch { url = null; }
  if (!url || url.protocol !== "http:" || url.hostname !== "127.0.0.1" || !Number.isInteger(Number(url.port)) || Number(url.port) < 1 || Number(url.port) > 65535) {
    throw new Error("shield identity origin must be a loopback HTTP endpoint");
  }
  if (typeof identity.capability !== "string" || identity.capability.length < 32) {
    throw new Error("shield identity capability is missing or invalid");
  }
  if (!(Number.isInteger(identity.version) || (typeof identity.version === "string" && identity.version.length > 0))) {
    throw new Error("shield identity version is missing or invalid");
  }
  if (!Number.isInteger(identity.pid) || identity.pid < 1) throw new Error("shield identity pid is missing or invalid");
  if (identity.lane !== "subscription" && identity.lane !== "managed") {
    throw new Error("shield identity lane must be subscription or managed");
  }
  if (identity.targetClass !== identity.lane) throw new Error("shield identity targetClass must match its lane");
  if (typeof identity.generation !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(identity.generation)) {
    throw new Error("shield identity generation is missing or invalid");
  }
  if (typeof identity.policyVersion !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(identity.policyVersion)) {
    throw new Error("shield identity policy version is missing or invalid");
  }
  const detectorVersions = assertDetectorVersions(identity.detectorVersions, "shield identity");
  return {
    origin: url.origin,
    capability: identity.capability,
    version: identity.version,
    pid: identity.pid,
    lane: identity.lane,
    generation: identity.generation,
    targetClass: identity.targetClass,
    policyVersion: identity.policyVersion,
    detectorVersions,
  };
}

export function assertShieldPolicyState(state) {
  if (!state || typeof state !== "object" || Array.isArray(state)) throw new Error("shield policy state is invalid");
  const keys = Object.keys(state).sort();
  if (keys.length !== 2 || keys[0] !== "detectorVersions" || keys[1] !== "version") {
    throw new Error("shield policy state contains unsupported fields");
  }
  if (typeof state.version !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(state.version)) {
    throw new Error("shield policy state version is invalid");
  }
  const detectorVersions = assertDetectorVersions(state.detectorVersions, "shield policy state");
  return Object.freeze({ version: state.version, detectorVersions });
}

export async function writeShieldIdentity({ paths, identity, io = defaultIo } = {}) {
  if (!paths?.rootDir || !paths.identityPath) throw new TypeError("shield identity paths are required");
  const validated = assertShieldIdentity(identity);
  await writePrivateShieldState({ paths, path: paths.identityPath, value: validated, io });
  return validated;
}

export async function writeShieldConfig({ paths, config, io = defaultIo } = {}) {
  if (!paths?.rootDir || !paths.configPath) throw new TypeError("shield configuration paths are required");
  if (!config || typeof config !== "object" || Array.isArray(config)) throw new TypeError("shield configuration must be an object");
  await writePrivateShieldState({ paths, path: paths.configPath, value: config, io });
}

export async function writeShieldPolicyState({ paths, state, io = defaultIo } = {}) {
  if (!paths?.rootDir || !paths.policyStatePath) throw new TypeError("shield policy state paths are required");
  const validated = assertShieldPolicyState(state);
  await writePrivateShieldState({ paths, path: paths.policyStatePath, value: validated, io });
  return validated;
}

export async function invalidateShieldPolicyBinding({ paths, io = defaultIo } = {}) {
  if (!paths?.rootDir || !paths.identityPath || !paths.policyStatePath) throw new TypeError("shield policy binding paths are required");
  assertWritablePaths(paths);
  // unlink has no `force` option — only rm does — so an absent binding threw
  // ENOENT and made the first policy install on a fresh lane impossible.
  const clear = async (path) => {
    try { await io.unlink(path, { force: true }); }
    catch (error) { if (error?.code !== "ENOENT") throw error; }
  };
  await Promise.all([clear(paths.identityPath), clear(paths.policyStatePath)]);
}

export async function writeShieldPolicyProvision({ paths, bundleText, publicKey, io = defaultIo } = {}) {
  if (!paths?.rootDir || !paths.policyBundlePath || !paths.policyPublicKeyPath) throw new TypeError("shield policy provision paths are required");
  if (typeof bundleText !== "string" || bundleText.length < 1 || typeof publicKey !== "string" || publicKey.length < 1) {
    throw new TypeError("shield policy provision is invalid");
  }
  await writePrivateShieldState({ paths, path: paths.policyPublicKeyPath, value: publicKey, io, raw: true });
  await writePrivateShieldState({ paths, path: paths.policyBundlePath, value: bundleText, io, raw: true });
}

export async function readShieldAssetsProvision({ paths, io = defaultIo } = {}) {
  if (!paths?.assetsProvisionPath) throw new TypeError("shield asset provision paths are required");
  assertCanonicalAssetsProvisionPath(paths);
  let contents;
  try {
    await assertPrivateRegularFile(paths.assetsProvisionPath, io);
    contents = await io.readFile(paths.assetsProvisionPath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  let state;
  try { state = JSON.parse(contents); } catch { throw new Error("shield asset provision is invalid JSON"); }
  return assertShieldAssetsProvision(state);
}

export async function writeShieldAssetsProvision({ paths, state, io = defaultIo } = {}) {
  if (!paths?.rootDir || !paths.assetsProvisionPath) throw new TypeError("shield asset provision paths are required");
  const validated = assertShieldAssetsProvision(state);
  await writePrivateShieldState({ paths, path: paths.assetsProvisionPath, value: validated, io });
  return validated;
}

async function writePrivateShieldState({ paths, path, value, io, raw = false }) {
  assertWritablePaths(paths);
  const [homeDir, localDir, stateDir, rootDir] = stateComponents(paths.rootDir);
  const ownerUid = process.getuid?.();
  await ensureDirectory(homeDir, io, ownerUid, false);
  await ensureDirectory(localDir, io, ownerUid, true);
  await ensureDirectory(stateDir, io, ownerUid, true);
  await ensureDirectory(rootDir, io, ownerUid, true);
  await assertDirectory(rootDir, io, ownerUid);
  const rootHandle = await openPrivateRoot(rootDir, io, ownerUid);
  try {
    await rootHandle.chmod(0o700);
    await assertDirectory(rootDir, io, ownerUid);
    const temporaryPath = `${path}.tmp-${process.pid}-${Date.now()}`;
    try {
      const fileHandle = await openExclusiveFile(temporaryPath, io);
      try { await fileHandle.writeFile(raw ? value : `${JSON.stringify(value)}\n`); await fileHandle.chmod(0o600); }
      finally { await fileHandle.close(); }
      await assertDirectory(rootDir, io, ownerUid);
      await io.rename(temporaryPath, path);
    } catch (error) {
      await io.unlink(temporaryPath, { force: true }).catch(() => {});
      throw error;
    }
  } finally {
    await rootHandle.close();
  }
}

async function openPrivateRoot(rootDir, io, ownerUid) {
  const flags = io.constants?.O_RDONLY | io.constants?.O_DIRECTORY | io.constants?.O_NOFOLLOW;
  const handle = await io.open(rootDir, flags);
  const entry = await handle.stat();
  if (entry.isSymbolicLink() || !entry.isDirectory()) { await handle.close(); throw new Error("shield state root must be a real directory"); }
  if (Number.isInteger(ownerUid) && entry.uid !== ownerUid) { await handle.close(); throw new Error("shield state path has unexpected owner"); }
  return handle;
}

async function openExclusiveFile(path, io) {
  const flags = io.constants?.O_WRONLY | io.constants?.O_CREAT | io.constants?.O_EXCL | io.constants?.O_NOFOLLOW;
  return io.open(path, flags, 0o600);
}

function assertWritablePaths(paths) {
  if (!canonicalShieldPaths.has(paths)) {
    throw new Error("shield paths must be a canonical object returned by shieldPaths");
  }
  if ((paths.lane !== "subscription" && paths.lane !== "managed") || paths.serviceLabel !== `${SHIELD_LABEL}.${paths.lane}` || paths.configPath !== join(paths.rootDir, "config.json") || paths.identityPath !== join(paths.rootDir, "identity.json") || paths.policyStatePath !== join(paths.rootDir, "policy-state.json") || paths.policyBundlePath !== join(paths.rootDir, "policy-bundle.json") || paths.policyPublicKeyPath !== join(paths.rootDir, "policy-public.pem") || paths.assetsProvisionPath !== join(paths.rootDir, "assets-provision.json") || paths.socketPath !== join(paths.rootDir, "shield.sock")) {
    throw new Error("shield paths must use the canonical AirKit Shield state layout");
  }
}

function assertLane(lane) {
  if (lane !== "subscription" && lane !== "managed") throw new Error("shield lane must be subscription or managed");
}

function assertCanonicalPolicyStatePath(paths) {
  if (!canonicalShieldPaths.has(paths) || paths.policyStatePath !== join(paths.rootDir, "policy-state.json")) {
    throw new Error("shield policy state paths must use the canonical AirKit Shield state layout");
  }
}

function assertCanonicalAssetsProvisionPath(paths) {
  if (!canonicalShieldPaths.has(paths) || paths.assetsProvisionPath !== join(paths.rootDir, "assets-provision.json")) {
    throw new Error("shield asset provision paths must use the canonical AirKit Shield state layout");
  }
}

export function assertShieldAssetsProvision(state) {
  if (!isPlainObject(state) || !exactKeys(state, ["bundle", "gitleaks", "privacy", "version"]) || state.version !== 1
    || !isPlainObject(state.bundle) || !exactKeys(state.bundle, ["path", "sha256", "version"])
    || !isPlainObject(state.gitleaks) || !exactKeys(state.gitleaks, ["path", "rules", "sha256"])
    || !isPlainObject(state.gitleaks.rules) || !exactKeys(state.gitleaks.rules, ["path", "sha256", "version"])
    || !isPlainObject(state.privacy) || !(exactKeys(state.privacy, ["path", "sha256", "version", "worker"])
      || exactKeys(state.privacy, ["adapter", "checkpoint", "path", "sha256", "source", "tokenizer", "version", "worker"]))
    || !isPlainObject(state.privacy.worker) || !exactKeys(state.privacy.worker, ["args", "command", "sha256"])) {
    throw new Error("shield asset provision is invalid");
  }
  assertAssetReference(state.bundle, "shield policy bundle");
  assertAssetReference(state.gitleaks, "shield gitleaks");
  assertAssetReference(state.gitleaks.rules, "shield gitleaks rules");
  assertAssetReference(state.privacy, "shield privacy bundle");
  if (!safePath(state.privacy.worker.command) || !/^[a-f0-9]{64}$/.test(state.privacy.worker.sha256)
    || !Array.isArray(state.privacy.worker.args) || !state.privacy.worker.args.every((argument) => typeof argument === "string" && argument.length > 0 && argument.length <= 256)) {
    throw new Error("shield privacy worker reference is invalid");
  }
  if (state.privacy.checkpoint && (!isPlainObject(state.privacy.checkpoint)
    || !exactKeys(state.privacy.checkpoint, ["path", "sha256", "version"])
    || !safePath(state.privacy.checkpoint.path)
    || !/^[a-f0-9]{64}$/.test(state.privacy.checkpoint.sha256)
    || !safeIdentifier(state.privacy.checkpoint.version)
    || !isPlainObject(state.privacy.source) || !exactKeys(state.privacy.source, ["path", "sha256", "version"])
    || !safePath(state.privacy.source.path) || !/^[a-f0-9]{64}$/.test(state.privacy.source.sha256)
    || !safeIdentifier(state.privacy.source.version)
    || !isPlainObject(state.privacy.adapter) || !exactKeys(state.privacy.adapter, ["path", "sha256"])
    || state.privacy.adapter.path !== resolve(dirname(state.privacy.worker.command), "opf-adapter.mjs")
    || !/^[a-f0-9]{64}$/.test(state.privacy.adapter.sha256)
    || !isPlainObject(state.privacy.tokenizer) || !exactKeys(state.privacy.tokenizer, ["path", "sha256", "version"])
    || !safePath(state.privacy.tokenizer.path)
    || state.privacy.tokenizer.path.split("/").at(-1) !== "fb374d419588a4632f3f557e76b4b70aebbca790"
    || state.privacy.tokenizer.version !== "o200k_base"
    || !/^[a-f0-9]{64}$/.test(state.privacy.tokenizer.sha256))) {
    throw new Error("shield privacy checkpoint reference is invalid");
  }
  return Object.freeze({
    version: state.version,
    bundle: Object.freeze({ version: state.bundle.version, sha256: state.bundle.sha256, path: state.bundle.path }),
    gitleaks: Object.freeze({
      sha256: state.gitleaks.sha256,
      path: state.gitleaks.path,
      rules: Object.freeze({ path: state.gitleaks.rules.path, sha256: state.gitleaks.rules.sha256, version: state.gitleaks.rules.version }),
    }),
    privacy: Object.freeze({
      version: state.privacy.version,
      sha256: state.privacy.sha256,
      path: state.privacy.path,
      worker: Object.freeze({ command: state.privacy.worker.command, args: Object.freeze([...state.privacy.worker.args]), sha256: state.privacy.worker.sha256 }),
      ...(state.privacy.checkpoint ? {
        checkpoint: Object.freeze({ ...state.privacy.checkpoint }),
        source: Object.freeze({ ...state.privacy.source }),
        adapter: Object.freeze({ ...state.privacy.adapter }),
        tokenizer: Object.freeze({ ...state.privacy.tokenizer }),
      } : {}),
    }),
  });
}

function assertAssetReference(value, label) {
  if (!safeIdentifier(value.version ?? "reference") || !safePath(value.path) || !/^[a-f0-9]{64}$/.test(value.sha256)) {
    throw new Error(`${label} reference is invalid`);
  }
}

function safeIdentifier(value) { return typeof value === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(value); }
function safePath(value) { return typeof value === "string" && isAbsolute(value) && resolve(value) === value; }
function isPlainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exactKeys(value, expected) { const keys = Object.keys(value).sort(); return keys.length === expected.length && keys.every((key, index) => key === expected[index]); }

async function assertPrivateRegularFile(path, io) {
  const entry = await io.lstat(path);
  if (entry.isSymbolicLink()) throw new Error("shield policy state must not be a symlink");
  if (!entry.isFile()) throw new Error("shield policy state must be a regular file");
  if ((entry.mode & 0o077) !== 0) throw new Error("shield policy state must be private");
  const ownerUid = process.getuid?.();
  if (Number.isInteger(ownerUid) && entry.uid !== ownerUid) throw new Error("shield policy state has unexpected owner");
}

async function ensureDirectory(path, io, ownerUid, privateMode) {
  try {
    await assertDirectory(path, io, ownerUid);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    await io.mkdir(path, { mode: privateMode ? 0o700 : 0o755 });
    await assertDirectory(path, io, ownerUid);
    if (privateMode) await io.chmod(path, 0o700);
  }
}

async function assertDirectory(path, io, ownerUid) {
  const entry = await io.lstat(path);
  if (entry.isSymbolicLink()) throw new Error("shield state path must not be a symlink");
  if (!entry.isDirectory()) throw new Error("shield state path must be a directory");
  if (Number.isInteger(ownerUid) && entry.uid !== ownerUid) throw new Error("shield state path has unexpected owner");
}

function stateComponents(rootDir) {
  const stateDir = dirname(rootDir);
  const localDir = dirname(stateDir);
  return [dirname(localDir), localDir, stateDir, rootDir];
}

function childPath(value, root, label) {
  const path = absolutePath(value, label);
  if (relative(root, path).startsWith("..")) throw new Error(`${label} must be under rootDir`);
  return path;
}

function absolutePath(value, label) {
  if (typeof value !== "string" || !isAbsolute(value)) throw new Error(`${label} must be an absolute path`);
  return value;
}

function numericUid(value) {
  if (!/^\d+$/.test(String(value ?? ""))) throw new Error("uid must be a numeric macOS user id");
  return String(value);
}

function assertDetectorVersions(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} detector versions are invalid`);
  const result = {};
  for (const [name, version] of Object.entries(value)) {
    if (!/^[A-Za-z0-9._-]{1,128}$/.test(name) || typeof version !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(version)) {
      throw new Error(`${label} detector versions are invalid`);
    }
    result[name] = version;
  }
  return Object.freeze(result);
}

function homeFromEnv(env) { return typeof env?.HOME === "string" && env.HOME.length > 0 ? env.HOME : homedir(); }
