import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";

import { readEnv } from "../compat-env.mjs";
import { withFileLock } from "./file-lock.mjs";

const SHIELD_LABEL = "com.ccshield";
const defaultIo = { chmod, constants, lstat, mkdir, open, readFile, rename, unlink };
const canonicalShieldPaths = new WeakSet();

export function shieldPaths({ env = process.env, homeDir = homeFromEnv(env), uid = readEnv(env, "CCSHIELD_GUI_UID") ?? env.UID ?? process.getuid?.(), lane = "subscription", platform = process.platform, rootDir, configPath, identityPath, socketPath, launchAgentPath, serviceUnitPath } = {}) {
  assertLane(lane);
  const home = absolutePath(homeDir, "homeDir");
  const linux = platform === "linux";
  const dataHome = linux ? xdgDir(env, "XDG_DATA_HOME", join(home, ".local", "share")) : join(home, ".local", "share");
  const canonicalRoot = join(dataHome, "ccshield", lane);
  const root = absolutePath(rootDir ?? readEnv(env, "CCSHIELD_ROOT_DIR") ?? canonicalRoot, "rootDir");
  if (resolve(root) !== resolve(canonicalRoot)) throw new Error("rootDir must be the canonical ccshield state directory");
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
    auditDatabasePath: childPath(join(root, "audit.sqlite"), root, "auditDatabasePath"),
    windowCachePath: childPath(join(root, "opf-window-cache"), root, "windowCachePath"),
    platform: linux ? "linux" : "darwin",
  };
  if (linux) {
    const unitDir = join(xdgDir(env, "XDG_CONFIG_HOME", join(home, ".config")), "systemd", "user");
    paths.serviceUnitPath = absolutePath(serviceUnitPath ?? join(unitDir, `ccshield-${lane}.service`), "serviceUnitPath");
    if (resolve(dirname(paths.serviceUnitPath)) !== resolve(unitDir)) throw new Error("serviceUnitPath must be under the systemd user unit directory");
    Object.freeze(paths);
    canonicalShieldPaths.add(paths);
    return paths;
  }
  paths.launchAgentPath = launchAgentPath ?? join(home, "Library", "LaunchAgents", `${serviceLabel}.plist`);
  paths.launchdDomain = `gui/${numericUid(uid)}`;
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
    contents = await readPrivateRegularFile(paths.identityPath, "shield identity", io);
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
    contents = await readPrivateRegularFile(paths.policyStatePath, "shield policy state", io);
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
  const validated = {
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
  if (Object.hasOwn(identity, "media")) validated.media = assertMediaCoverage(identity.media);
  return validated;
}

// What the running daemon does with media it cannot inspect. A daemon from
// before the media check writes no `media`, and readers treat that as unscanned.
const MEDIA_COVERAGE_STATES = Object.freeze({ documents: ["unscanned", "blocked"], images: ["unscanned"] });

function assertMediaCoverage(media) {
  if (!media || typeof media !== "object" || Array.isArray(media)
    || Object.keys(media).length !== 2
    || !Object.entries(MEDIA_COVERAGE_STATES).every(([kind, allowed]) => allowed.includes(media[kind]))) {
    throw new Error("shield identity media coverage is invalid");
  }
  return { documents: media.documents, images: media.images };
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
    contents = await readPrivateRegularFile(paths.assetsProvisionPath, "shield asset provision", io);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  let state;
  try { state = JSON.parse(contents); } catch { throw new Error("shield asset provision is invalid JSON"); }
  return assertShieldAssetsProvision(state, { storeRoot: shieldAssetStore(paths).root });
}

export async function writeShieldAssetsProvision({ paths, state, io = defaultIo } = {}) {
  if (!paths?.rootDir || !paths.assetsProvisionPath) throw new TypeError("shield asset provision paths are required");
  const validated = assertShieldAssetsProvision(state, { storeRoot: shieldAssetStore(paths).root });
  await writePrivateShieldState({ paths, path: paths.assetsProvisionPath, value: validated, io });
  return validated;
}

// Every writer of the asset record goes through here. The background OPF job
// and a manual provision each own different blocks, so the read-merge-write
// runs under a per-record lock and neither can drop the other's change.
// `update` gets the current record (or null) and returns the next one, or
// undefined to leave it alone; it must stay cheap, since it runs locked. A full
// re-provision passes `replaceInvalid`, so an unreadable record reads as none.
export async function updateShieldAssetsProvision({ paths, update, replaceInvalid = false, io = defaultIo, lock = withFileLock } = {}) {
  if (!paths?.rootDir || !paths.assetsProvisionPath) throw new TypeError("shield asset provision paths are required");
  if (typeof update !== "function") throw new TypeError("shield asset provision update is required");
  await ensureStateRoot(paths, io);
  return lock(`${paths.assetsProvisionPath}.lock`, async () => {
    const read = readShieldAssetsProvision({ paths, io });
    const next = await update(await (replaceInvalid ? read.catch(() => null) : read));
    return next === undefined ? null : writeShieldAssetsProvision({ paths, state: next, io });
  });
}

async function ensureStateRoot(paths, io) {
  assertWritablePaths(paths);
  const [homeDir, localDir, stateDir, rootDir] = stateComponents(paths.rootDir);
  const ownerUid = process.getuid?.();
  await ensureDirectory(homeDir, io, ownerUid, false);
  await ensureDirectory(localDir, io, ownerUid, true);
  await ensureDirectory(stateDir, io, ownerUid, true);
  await ensureDirectory(rootDir, io, ownerUid, true);
  await assertDirectory(rootDir, io, ownerUid);
  return { rootDir, ownerUid };
}

async function writePrivateShieldState({ paths, path, value, io, raw = false }) {
  const { rootDir, ownerUid } = await ensureStateRoot(paths, io);
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
  if ((paths.lane !== "subscription" && paths.lane !== "managed") || paths.serviceLabel !== `${SHIELD_LABEL}.${paths.lane}` || paths.configPath !== join(paths.rootDir, "config.json") || paths.identityPath !== join(paths.rootDir, "identity.json") || paths.policyStatePath !== join(paths.rootDir, "policy-state.json") || paths.policyBundlePath !== join(paths.rootDir, "policy-bundle.json") || paths.policyPublicKeyPath !== join(paths.rootDir, "policy-public.pem") || paths.assetsProvisionPath !== join(paths.rootDir, "assets-provision.json") || paths.socketPath !== join(paths.rootDir, "shield.sock") || paths.auditDatabasePath !== join(paths.rootDir, "audit.sqlite")) {
    throw new Error("shield paths must use the canonical ccshield state layout");
  }
}

function assertLane(lane) {
  if (lane !== "subscription" && lane !== "managed") throw new Error("shield lane must be subscription or managed");
}

// The OPF disk tier is per lane; only a shieldPaths() object may name it.
export function laneWindowCachePath(paths) {
  if (!canonicalShieldPaths.has(paths) || paths.windowCachePath !== join(paths.rootDir, "opf-window-cache")) {
    throw new Error("shield window cache paths must use the canonical ccshield state layout");
  }
  return paths.windowCachePath;
}

function assertCanonicalPolicyStatePath(paths) {
  if (!canonicalShieldPaths.has(paths) || paths.policyStatePath !== join(paths.rootDir, "policy-state.json")) {
    throw new Error("shield policy state paths must use the canonical ccshield state layout");
  }
}

function assertCanonicalAssetsProvisionPath(paths) {
  if (!canonicalShieldPaths.has(paths) || paths.assetsProvisionPath !== join(paths.rootDir, "assets-provision.json")) {
    throw new Error("shield asset provision paths must use the canonical ccshield state layout");
  }
}

export const ASSETS_FORMAT_VERSION = 3;
const PRIVACY_ORIGINS = new Set(["downloaded", "adopted"]);
const GITLEAKS_ORIGINS = new Set(["downloaded", "override"]);
const OPF_INSTALL_STATES = new Set(["verified", "failed", "unsupported"]);

// Lane-independent detector assets. Downloads land in staging and move into
// opf/<codeCommit>-<hfRev>/ only after their digests check out.
export function shieldAssetStore(paths) {
  if (!canonicalShieldPaths.has(paths)) throw new Error("shield asset store requires canonical ccshield paths");
  const root = join(dirname(paths.rootDir), "assets");
  const opfRoot = childPath(join(root, "opf"), root, "opfRoot");
  return Object.freeze({
    root,
    opfRoot,
    stagingDir: childPath(join(root, "staging"), root, "stagingDir"),
    opfBundle(codeCommit, hfRevision) {
      if (!/^[a-f0-9]{40}$/.test(codeCommit ?? "") || !/^[a-f0-9]{40}$/.test(hfRevision ?? "")) throw new Error("shield OPF bundle revisions must be 40-hex commits");
      const dir = childPath(join(opfRoot, `${codeCommit}-${hfRevision}`), opfRoot, "opfBundle");
      return Object.freeze(Object.fromEntries([["dir", dir], ...["src", "checkpoint", "venv", "tokenizer"]
        .map((name) => [name, childPath(join(dir, name), dir, name)])]));
    },
    gitleaks(version) {
      if (!/^\d+\.\d+\.\d+$/.test(version ?? "")) throw new Error("shield Gitleaks version must be a plain semver");
      const dir = childPath(join(root, "gitleaks", version), root, "gitleaksDir");
      return Object.freeze({ dir, binary: join(dir, "gitleaks") });
    },
  });
}

// privacy.state is absent | preparing | verified | failed. OPF references are
// required only when verified. A version-1 file predates the field: a shape the
// old check accepted is read as verified (OPF there counts as adopted); any
// other version-1 privacy block is failed with reason legacy-schema.
// Version 3 adds what `ccshield install --write` did: the Gitleaks origin and
// version, and an optional opf block. Versions 1 and 2 still read unchanged.
export function assertShieldAssetsProvision(state, { storeRoot } = {}) {
  const v3 = state?.version === ASSETS_FORMAT_VERSION;
  const keys = state?.version === 1 ? ["bundle", "gitleaks", "privacy", "version"] : ["bundle", "gitleaks", "privacy", "regex", "version"];
  // `source` is optional: where a store copy was adopted from, so doctor can
  // tell when an upgrade replaced the original and the copy went stale.
  const withSource = (base, value) => (isPlainObject(value) && "source" in value ? [...base, "source"].sort() : base);
  const gitleaksKeys = withSource(v3 && isPlainObject(state.gitleaks) && "origin" in state.gitleaks
    ? ["origin", "path", "rules", "sha256", "version"]
    : ["path", "rules", "sha256"], state?.gitleaks);
  if (!isPlainObject(state) || !exactKeys(state, v3 && "opf" in state ? [...keys, "opf"].sort() : keys)
    || (state.version !== 1 && state.version !== 2 && !v3)
    || !isPlainObject(state.bundle) || !exactKeys(state.bundle, ["path", "sha256", "version"])
    || !isPlainObject(state.gitleaks) || !exactKeys(state.gitleaks, gitleaksKeys)
    || (state.gitleaks.origin !== undefined && !GITLEAKS_ORIGINS.has(state.gitleaks.origin))
    || !isPlainObject(state.gitleaks.rules) || !exactKeys(state.gitleaks.rules, withSource(["path", "sha256", "version"], state.gitleaks.rules))
    || (state.gitleaks.source !== undefined && !safePath(state.gitleaks.source))
    || (state.gitleaks.rules.source !== undefined && !safePath(state.gitleaks.rules.source))) {
    throw new Error("shield asset provision is invalid");
  }
  assertAssetReference(state.bundle, "shield policy bundle");
  assertAssetReference(state.gitleaks, "shield gitleaks");
  assertAssetReference(state.gitleaks.rules, "shield gitleaks rules");
  return Object.freeze({
    version: ASSETS_FORMAT_VERSION,
    bundle: Object.freeze({ version: state.bundle.version, sha256: state.bundle.sha256, path: state.bundle.path }),
    gitleaks: Object.freeze({
      ...(state.gitleaks.origin ? { origin: state.gitleaks.origin, version: state.gitleaks.version } : {}),
      sha256: state.gitleaks.sha256,
      path: state.gitleaks.path,
      ...(state.gitleaks.source ? { source: state.gitleaks.source } : {}),
      rules: Object.freeze({
        path: state.gitleaks.rules.path, sha256: state.gitleaks.rules.sha256, version: state.gitleaks.rules.version,
        ...(state.gitleaks.rules.source ? { source: state.gitleaks.rules.source } : {}),
      }),
    }),
    privacy: state.version === 1 ? legacyPrivacyAssets(state.privacy) : privacyAssets(state.privacy, storeRoot),
    regex: state.version === 1 ? null : regexAssets(state.regex, storeRoot),
    ...(v3 && "opf" in state ? { opf: opfInstallAssets(state.opf, storeRoot) } : {}),
  });
}

// state is verified (with the bundle directory), failed or unsupported (with
// a reason); platform is the detected key or "none".
function opfInstallAssets(value, storeRoot) {
  const keys = value?.state === "verified" ? ["bundle", "platform", "state"] : ["platform", "reason", "state"];
  if (!isPlainObject(value) || !OPF_INSTALL_STATES.has(value.state) || !exactKeys(value, keys)
    || !safeIdentifier(value.platform)
    || (value.state === "verified" ? !safePath(value.bundle) : !safeReason(value.reason))) {
    throw new Error("shield OPF install record is invalid");
  }
  if (value.state === "verified" && typeof storeRoot === "string" && !isInside(value.bundle, join(storeRoot, "opf"))) {
    throw new Error("shield OPF install record must stay inside the asset store");
  }
  return Object.freeze(value.state === "verified"
    ? { state: value.state, platform: value.platform, bundle: value.bundle }
    : { state: value.state, platform: value.platform, reason: value.reason });
}

function safeReason(value) { return typeof value === "string" && value.length > 0 && value.length <= 500 && !/[\u0000-\u001f\u007f]/.test(value); }

// The regex detector is copied into the store at install time, so the daemon
// runs a pinned file rather than whatever the package currently ships.
function regexAssets(value, storeRoot) {
  if (!isPlainObject(value) || !exactKeys(value, ["version", "worker"]) || !safeIdentifier(value.version)
    || !isPlainObject(value.worker) || !exactKeys(value.worker, ["args", "command", "sha256"])
    || !safePath(value.worker.command) || !Array.isArray(value.worker.args) || value.worker.args.length !== 0
    || !/^[a-f0-9]{64}$/.test(value.worker.sha256 ?? "")) {
    throw new Error("shield regex detector reference is invalid");
  }
  if (typeof storeRoot === "string" && value.worker.command !== join(storeRoot, "regex", value.version, "privacy-worker.mjs")) {
    throw new Error("shield regex detector must stay inside the asset store");
  }
  return Object.freeze({
    version: value.version,
    worker: Object.freeze({ command: value.worker.command, args: Object.freeze([]), sha256: value.worker.sha256 }),
  });
}

function legacyPrivacyAssets(value) {
  try {
    return verifiedPrivacyAssets(value, isPlainObject(value) && value.checkpoint ? "adopted" : undefined);
  } catch {
    return Object.freeze({ state: "failed", reason: "legacy-schema" });
  }
}

function privacyAssets(value, storeRoot) {
  if (!isPlainObject(value)) throw new Error("shield asset provision is invalid");
  if ((value.state === "absent" || value.state === "preparing") && exactKeys(value, ["state"])) return Object.freeze({ state: value.state });
  if (value.state === "failed" && exactKeys(value, ["reason", "state"]) && safeIdentifier(value.reason)) {
    return Object.freeze({ state: "failed", reason: value.reason });
  }
  if (value.state !== "verified") throw new Error("shield asset provision is invalid");
  const { state: _state, origin, ...fields } = value;
  if (fields.checkpoint ? !PRIVACY_ORIGINS.has(origin) : origin !== undefined) throw new Error("shield privacy origin is invalid");
  const verified = verifiedPrivacyAssets(fields, origin);
  if (origin === "downloaded") {
    if (typeof storeRoot !== "string" || !isAbsolute(storeRoot)) throw new Error("shield downloaded privacy assets require the asset store");
    const opfRoot = join(storeRoot, "opf");
    for (const path of [verified.checkpoint.path, verified.source.path, verified.tokenizer.path, verified.worker.args[1]]) {
      if (!isInside(path, opfRoot)) throw new Error("shield downloaded privacy assets must stay inside the asset store");
    }
  }
  return verified;
}

function verifiedPrivacyAssets(privacy, origin) {
  if (!isPlainObject(privacy) || !(exactKeys(privacy, ["path", "sha256", "version", "worker"])
      || exactKeys(privacy, ["adapter", "checkpoint", "path", "sha256", "source", "tokenizer", "version", "worker"]))
    || !isPlainObject(privacy.worker) || !exactKeys(privacy.worker, ["args", "command", "sha256"])) {
    throw new Error("shield asset provision is invalid");
  }
  assertAssetReference(privacy, "shield privacy bundle");
  if (!safePath(privacy.worker.command) || !/^[a-f0-9]{64}$/.test(privacy.worker.sha256)
    || !Array.isArray(privacy.worker.args) || !privacy.worker.args.every((argument) => typeof argument === "string" && argument.length > 0 && argument.length <= 256)) {
    throw new Error("shield privacy worker reference is invalid");
  }
  if (privacy.checkpoint && (!isPlainObject(privacy.checkpoint)
    || !exactKeys(privacy.checkpoint, ["path", "sha256", "version"])
    || !safePath(privacy.checkpoint.path)
    || !/^[a-f0-9]{64}$/.test(privacy.checkpoint.sha256)
    || !safeIdentifier(privacy.checkpoint.version)
    || !isPlainObject(privacy.source) || !exactKeys(privacy.source, ["path", "sha256", "version"])
    || !safePath(privacy.source.path) || !/^[a-f0-9]{64}$/.test(privacy.source.sha256)
    || !safeIdentifier(privacy.source.version)
    || !isPlainObject(privacy.adapter) || !exactKeys(privacy.adapter, ["path", "sha256"])
    || privacy.adapter.path !== resolve(dirname(privacy.worker.command), "opf-adapter.mjs")
    || !/^[a-f0-9]{64}$/.test(privacy.adapter.sha256)
    || !isPlainObject(privacy.tokenizer) || !exactKeys(privacy.tokenizer, ["path", "sha256", "version"])
    || !safePath(privacy.tokenizer.path)
    || privacy.tokenizer.path.split("/").at(-1) !== "fb374d419588a4632f3f557e76b4b70aebbca790"
    || privacy.tokenizer.version !== "o200k_base"
    || !/^[a-f0-9]{64}$/.test(privacy.tokenizer.sha256))) {
    throw new Error("shield privacy checkpoint reference is invalid");
  }
  return Object.freeze({
    state: "verified",
    ...(origin ? { origin } : {}),
    version: privacy.version,
    sha256: privacy.sha256,
    path: privacy.path,
    worker: Object.freeze({ command: privacy.worker.command, args: Object.freeze([...privacy.worker.args]), sha256: privacy.worker.sha256 }),
    ...(privacy.checkpoint ? {
      checkpoint: Object.freeze({ ...privacy.checkpoint }),
      source: Object.freeze({ ...privacy.source }),
      adapter: Object.freeze({ ...privacy.adapter }),
      tokenizer: Object.freeze({ ...privacy.tokenizer }),
    } : {}),
  });
}

function isInside(path, root) {
  const offset = relative(root, path);
  return safePath(path) && offset !== "" && !offset.startsWith("..") && !isAbsolute(offset);
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

// Checks run on the opened descriptor, not the path, so a swap between check and read
// cannot hand us a different file. O_NOFOLLOW refuses a symlinked final component and
// O_NONBLOCK keeps a planted FIFO from hanging the open; the trailing lstat confirms the
// path still names the inode we read.
async function readPrivateRegularFile(path, label, io) {
  const flags = io.constants.O_RDONLY | io.constants.O_NOFOLLOW | io.constants.O_NONBLOCK;
  let handle;
  try {
    handle = await io.open(path, flags);
  } catch (error) {
    if (error?.code === "ELOOP") throw new Error(`${label} must not be a symlink`);
    throw error;
  }
  try {
    const entry = await handle.stat();
    if (!entry.isFile()) throw new Error(`${label} must be a regular file`);
    if ((entry.mode & 0o077) !== 0) throw new Error(`${label} must be private`);
    const ownerUid = process.getuid?.();
    if (Number.isInteger(ownerUid) && entry.uid !== ownerUid) throw new Error(`${label} has unexpected owner`);
    const contents = await handle.readFile({ encoding: "utf8" });
    const current = await io.lstat(path);
    if (current.dev !== entry.dev || current.ino !== entry.ino) throw new Error(`${label} was replaced while being read`);
    return contents;
  } finally {
    await handle.close();
  }
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

// XDG base directories must be absolute; a relative value is ignored, as the spec requires.
function xdgDir(env, name, fallback) {
  const value = env?.[name];
  return typeof value === "string" && isAbsolute(value) ? value : fallback;
}

function homeFromEnv(env) { return typeof env?.HOME === "string" && env.HOME.length > 0 ? env.HOME : homedir(); }
