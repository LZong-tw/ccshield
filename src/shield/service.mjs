import { execFile, spawn } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, resolve } from "node:path";
import { tmpdir } from "node:os";
import { mkdtemp, rm } from "node:fs/promises";
import { createInterface } from "node:readline/promises";
import { promisify } from "node:util";
import { describePlistDrift } from "../launchd-plist.mjs";
import { describeUnitDrift, renderUnit, unitLabel } from "../systemd-unit.mjs";
import { envNamesFor } from "../compat-env.mjs";

import { readShieldIdentity, readShieldPolicyState, shieldPaths, writeShieldConfig } from "./paths.mjs";
import { classifyShieldRequest } from "./classify.mjs";
import { createApprovalBroker } from "./approval.mjs";
import { approvalChannelRegistration, createApprovalChannel } from "./approval-channel.mjs";

const execFileAsync = promisify(execFile);
export const SHIELD_SERVICE_LABEL = "com.ccshield";
const SUBSCRIPTION_TARGET_ORIGIN = "https://api.anthropic.com";
const UNKNOWN_REMOTE_HASH = "0".repeat(64);

const defaultIo = { chmod, constants, lstat, mkdir, open, readFile, rename, unlink, writeFile };

// Each platform's service manager sits behind one backend; the exported functions below only pick it.
const backendFor = (paths) => (paths?.platform === "linux" ? systemdBackend : launchdBackend);

export function planShieldService(options = {}) {
  return backendFor(options.paths).plan(options);
}

export async function installShieldService(options = {}) {
  return backendFor(options.paths).install(options);
}

export async function startShieldService(options = {}) {
  return backendFor(options.paths).start(options);
}

export async function stopShieldService(options = {}) {
  return backendFor(options.paths).stop(options);
}

export async function uninstallShieldService(options = {}) {
  return backendFor(options.paths).uninstall(options);
}

export async function inspectShieldService(options = {}) {
  return backendFor(options.paths).inspect(options);
}

function planLaunchdService({ paths, nodePath, daemonPath } = {}) {
  assertShieldPaths(paths);
  for (const [name, value] of Object.entries({ nodePath, daemonPath })) {
    if (typeof value !== "string" || !isAbsolute(value)) throw new Error(`${name} must be an absolute path`);
  }
  const plist = {
    Label: paths.serviceLabel,
    ProgramArguments: [nodePath, daemonPath, "--config", paths.configPath],
    EnvironmentVariables: {},
    RunAtLoad: true,
    KeepAlive: true,
    ProcessType: "Standard",
  };
  const plistXml = renderPlist(plist);
  return {
    label: paths.serviceLabel,
    plistPath: paths.launchAgentPath,
    domain: paths.launchdDomain,
    target: paths.launchdTarget,
    plist,
    plistXml,
    operations: [
      { op: "mkdir", path: dirname(paths.launchAgentPath), mode: 0o700 },
      { op: "writeFileAtomic", path: paths.launchAgentPath, mode: 0o600, content: plistXml },
      { op: "bootstrap", domain: paths.launchdDomain, path: paths.launchAgentPath },
      { op: "kickstart", target: paths.launchdTarget, kill: true },
    ],
  };
}

async function installLaunchdService({ write = false, io = defaultIo, runLaunchctl = defaultLaunchctl, ...options } = {}) {
  const plan = planLaunchdService(options);
  if (!write) return plan;
  const config = createShieldConfig(options.config);
  await writeShieldConfig({ paths: options.paths, config, io });
  await io.mkdir(dirname(plan.plistPath), { recursive: true, mode: 0o700 });
  const temporaryPath = `${plan.plistPath}.tmp-${process.pid}`;
  await io.writeFile(temporaryPath, plan.plistXml, { mode: 0o600 });
  await io.chmod(temporaryPath, 0o600);
  await io.rename(temporaryPath, plan.plistPath);
  await launch(runLaunchctl, ["bootstrap", plan.domain, plan.plistPath], true);
  await launch(runLaunchctl, ["kickstart", "-k", plan.target], false);
  return { ...plan, written: true };
}

export function createShieldConfig(config = {}) {
  const lane = config.lane ?? "subscription";
  assertLane(lane);
  const targetOrigin = config.targetOrigin ?? (lane === "subscription" ? SUBSCRIPTION_TARGET_ORIGIN : undefined);
  const launcherContext = config.launcherContext ?? defaultShieldLauncherContext(lane);
  const validated = {
    capability: config.capability ?? randomUUID().replaceAll("-", ""),
    controlCapability: config.controlCapability ?? randomUUID().replaceAll("-", ""),
    lane,
    generation: config.generation ?? randomUUID(),
    targetClass: config.targetClass ?? lane,
  };
  if (lane === "subscription") validated.targetOrigin = normalizeShieldTargetOrigin(targetOrigin, "shield configuration target");
  if (lane === "managed" && targetOrigin !== undefined) throw new Error("shield managed configuration must not persist a target origin");
  if (validated.targetClass !== lane) throw new Error("shield configuration targetClass must match its lane");
  if (lane === "subscription" && validated.targetOrigin !== SUBSCRIPTION_TARGET_ORIGIN) {
    throw new Error("shield subscription configuration must target api.anthropic.com");
  }
  if (typeof validated.capability !== "string" || validated.capability.length < 32) throw new Error("shield configuration capability is missing or invalid");
  if (typeof validated.controlCapability !== "string" || validated.controlCapability.length < 32 || validated.controlCapability === validated.capability) {
    throw new Error("shield configuration control capability is missing or invalid");
  }
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(validated.generation)) throw new Error("shield configuration generation is missing or invalid");
  assertLauncherContext(launcherContext);
  if (config.launcherContext !== undefined) validated.launcherContext = launcherContext;
  if (config.gitleaks !== undefined) validated.gitleaks = config.gitleaks;
  return validated;
}

async function startLaunchdService(options = {}) {
  const { io = defaultIo, runLaunchctl = defaultLaunchctl, ...rest } = options;
  const plan = planLaunchdService(rest);
  let missing = false;
  try {
    await io.readFile(plan.plistPath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") missing = true;
    else throw error;
  }
  if (missing) {
    throw new Error("shield service is not installed; run 'ccshield install --write' before start");
  }
  await ensurePathDrift(plan, io);
  await launch(runLaunchctl, ["bootstrap", plan.domain, plan.plistPath], true);
  await launch(runLaunchctl, ["kickstart", "-k", plan.target], false);
  return { ...plan, started: true };
}

async function stopLaunchdService({ paths, runLaunchctl = defaultLaunchctl } = {}) {
  assertShieldPaths(paths);
  await launch(runLaunchctl, ["bootout", paths.launchdTarget], true);
  return { label: SHIELD_SERVICE_LABEL, stopped: true };
}

// Removes only the lane's LaunchAgent so a retired lane stops coming back at login.
// Pins, policy and config stay, so a later install needs no re-provisioning.
async function uninstallLaunchdService({ paths, write = false, io = defaultIo, runLaunchctl = defaultLaunchctl, uid = process.getuid?.() } = {}) {
  assertShieldPaths(paths);
  // Bootout must reach the domain the job actually runs in, or unlink would leave it loaded until logout.
  if (write && uid !== undefined && paths.launchdDomain !== `gui/${uid}`) throw new Error(`shield launchd domain ${paths.launchdDomain} is not this user's gui/${uid}`);
  let stat;
  try {
    stat = await io.lstat(paths.launchAgentPath);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    // A plist deleted by hand can leave its KeepAlive job loaded; unload it too.
    if (write) await launch(runLaunchctl, ["bootout", paths.launchdTarget], true);
    return { label: paths.serviceLabel, installed: false, removed: false };
  }
  if (!stat.isFile() || (uid !== undefined && stat.uid !== uid)) throw new Error(`shield launch plist is not a regular file owned by this user: ${paths.launchAgentPath}`);
  const plist = await io.readFile(paths.launchAgentPath, "utf8");
  const label = plist.match(/<key>Label<\/key>\s*<string>([^<]*)<\/string>/)?.[1];
  if (label !== paths.serviceLabel) throw new Error(`shield launch plist does not belong to ${paths.serviceLabel}: ${paths.launchAgentPath}`);
  if (!write) return { label: paths.serviceLabel, installed: true, removed: false, operations: [{ op: "bootout", target: paths.launchdTarget }, { op: "unlink", path: paths.launchAgentPath }] };
  await launch(runLaunchctl, ["bootout", paths.launchdTarget], true);
  await io.unlink(paths.launchAgentPath);
  return { label: paths.serviceLabel, installed: true, removed: true };
}

export async function transitionShieldPolicy({ paths, installPolicy, io = defaultIo, runLaunchctl = defaultLaunchctl, runSystemctl = defaultSystemctl, inspectService = inspectShieldService, stopService = stopShieldService, startService = startShieldService, isProcessAlive = defaultIsProcessAlive, probeShield = defaultProbeShield, ensureReady = ensureShieldReady, recordShieldPolicyTransition = null } = {}) {
  if (typeof installPolicy !== "function") throw new TypeError("shield policy transition installer is required");
  if (recordShieldPolicyTransition !== null && typeof recordShieldPolicyTransition !== "function") {
    throw new TypeError("shield policy transition recorder is invalid");
  }
  const previous = await readShieldIdentity({ paths, io });
  const service = await inspectService({ paths, io, runLaunchctl, runSystemctl });
  if (service.active) {
    if (!previous || service.pid !== previous.pid) throw new Error("shield policy transition cannot quiesce an unbound active daemon");
    await stopService({ paths, runLaunchctl, runSystemctl });
    const stopped = await inspectService({ paths, io, runLaunchctl, runSystemctl });
    if (stopped.active) throw new Error("shield policy transition could not stop the prior daemon");
    if (await isProcessAlive(previous.pid)) throw new Error("shield policy transition could not stop the prior daemon");
    if (await probeShield(previous.origin, previous.capability, previous.wire)) throw new Error("shield policy transition prior proxy remains reachable");
  } else if (previous) {
    if (await isProcessAlive(previous.pid)) throw new Error("shield policy transition cannot quiesce a live stale daemon");
    if (await probeShield(previous.origin, previous.capability, previous.wire)) throw new Error("shield policy transition prior proxy remains reachable");
  }
  const installed = await installPolicy();
  const recordTransition = async (config = null) => {
    if (recordShieldPolicyTransition === null) return;
    await recordShieldPolicyTransition({
      requestId: `policy-${randomUUID().replaceAll("-", "")}`,
      lane: config?.lane ?? paths.lane,
      destinationClass: config?.targetClass ?? paths.lane,
      bundleVersion: installed.version,
      detectorVersions: installed.detectorVersions,
      action: "transition",
      reasonCodes: ["policy_replaced"],
      transformCount: 0,
      override: false,
      elapsedMs: 0,
    });
  };
  if (!service.active) {
    await recordTransition();
    return installed;
  }
  await startService({ paths, io, runLaunchctl, runSystemctl });
  const config = await readShieldConfig({ paths, io });
  const ready = await ensureReady({
    lane: config.lane,
    expectedTargetOrigin: config.targetOrigin,
    paths,
    io,
    inspectService,
    isProcessAlive,
    probeShield,
  });
  if (ready.policyVersion !== installed.version || !sameDetectorVersions(ready.detectorVersions, installed.detectorVersions)) {
    throw new Error("shield policy transition fresh daemon binding mismatch");
  }
  await recordTransition(config);
  return installed;
}

async function inspectLaunchdService({ paths, io = defaultIo, runLaunchctl = defaultLaunchctl } = {}) {
  assertShieldPaths(paths);
  const installed = await io.readFile(paths.launchAgentPath, "utf8").then(() => true, () => false);
  const printed = await launch(runLaunchctl, ["print", paths.launchdTarget], true);
  const state = /^\s*state = (\S+)\s*$/m.exec(printed.stdout ?? "")?.[1] ?? null;
  const pidValue = /^\s*pid = (\d+)\s*$/m.exec(printed.stdout ?? "")?.[1];
  const pid = pidValue === undefined ? null : Number(pidValue);
  const active = printed.ok && state === "running" && Number.isInteger(pid) && pid > 0;
  return { label: paths.serviceLabel, installed, loaded: printed.ok, active, pid, state, stale: installed && !active };
}

export async function readShieldConfig({ paths, io = defaultIo } = {}) {
  assertShieldPaths(paths);
  let config;
  try {
    config = JSON.parse(await io.readFile(paths.configPath, "utf8"));
  } catch {
    throw new Error("shield configuration is missing or invalid");
  }
  assertLane(config?.lane);
  if (typeof config.capability !== "string" || config.capability.length < 32) throw new Error("shield configuration capability is missing or invalid");
  if (typeof config.controlCapability !== "string" || config.controlCapability.length < 32 || config.controlCapability === config.capability) {
    throw new Error("shield configuration control capability is missing or invalid");
  }
  const targetOrigin = config.lane === "subscription"
    ? normalizeShieldTargetOrigin(config.targetOrigin, "shield configuration target")
    : undefined;
  if (config.lane === "managed" && Object.hasOwn(config, "targetOrigin")) throw new Error("shield managed configuration must not persist a target origin");
  if (typeof config.generation !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(config.generation)) {
    throw new Error("shield configuration generation is missing or invalid");
  }
  if (config.targetClass !== undefined && config.targetClass !== config.lane) {
    throw new Error("shield configuration targetClass must match its lane");
  }
  const result = {
    capability: config.capability,
    controlCapability: config.controlCapability,
    lane: config.lane,
    generation: config.generation,
    targetClass: config.lane,
  };
  if (targetOrigin !== undefined) result.targetOrigin = targetOrigin;
  if (config.launcherContext !== undefined) {
    assertLauncherContext(config.launcherContext);
    result.launcherContext = config.launcherContext;
  }
  if (config.gitleaks !== undefined) result.gitleaks = config.gitleaks;
  if (config.auditRetentionDays !== undefined) {
    if (!Number.isInteger(config.auditRetentionDays) || config.auditRetentionDays < 1 || config.auditRetentionDays > 3650) {
      throw new Error("shield configuration auditRetentionDays must be a whole number of days between 1 and 3650");
    }
    result.auditRetentionDays = config.auditRetentionDays;
  }
  return result;
}

export async function ensureShieldReady({ lane, expectedTargetOrigin, env = process.env, paths = shieldPaths({ env, lane }), io = defaultIo, inspectService = inspectShieldService, isProcessAlive = defaultIsProcessAlive, probeShield = defaultProbeShield } = {}) {
  assertLane(lane);
  const identity = await readShieldIdentity({ paths, io });
  if (!identity || !(await isProcessAlive(identity.pid))) {
    throw new Error("shield identity is stale; start the shield service and try again");
  }
  const service = await inspectService({ paths, io });
  if (!service.loaded || !service.active) throw new Error("shield identity is stale; shield service is not actively running");
  if (service.pid !== identity.pid) throw new Error("shield service PID mismatch; restart the shield service and try again");
  const config = await readShieldConfig({ paths, io });
  if (config.lane !== lane || identity.lane !== lane || identity.targetClass !== lane) {
    throw new Error("shield lane mismatch; start the service configured for the requested lane");
  }
  const expectedOrigin = lane === "subscription" ? SUBSCRIPTION_TARGET_ORIGIN : undefined;
  if (expectedOrigin !== undefined && config.targetOrigin !== expectedOrigin) {
    throw new Error("shield target origin mismatch; restart the service with the expected fixed target");
  }
  if (config.generation !== identity.generation) throw new Error("shield configuration generation mismatch; restart the shield service");
  if (config.capability !== identity.capability) throw new Error("shield capability generation mismatch; restart the shield service");
  const policyState = await readShieldPolicyState({ paths, io });
  if (!policyState) throw new Error("shield policy state is missing; install a valid policy before launch");
  assertCompleteDetectorVersions(identity.detectorVersions);
  assertCompleteDetectorVersions(policyState.detectorVersions);
  if (identity.policyVersion !== policyState.version) throw new Error("shield policy version mismatch; restart the shield service");
  if (!sameDetectorVersions(identity.detectorVersions, policyState.detectorVersions)) {
    throw new Error("shield detector version mismatch; restart the shield service");
  }
  if (!(await probeShield(identity.origin, identity.capability, identity.wire))) {
    throw new Error("shield listener readiness probe failed; restart the shield service");
  }
  return {
    origin: identity.origin,
    capability: identity.capability,
    lane,
    targetClass: identity.targetClass,
    policyVersion: identity.policyVersion,
    detectorVersions: identity.detectorVersions,
    ...(identity.wire === undefined ? {} : { wire: identity.wire }),
  };
}

// Header and path names for the daemon behind `ready`. Old daemons only know the
// airkit spellings; remove the wire-1 branch once no supported daemon lacks wire 2.
export function shieldWireNames(ready) {
  return (ready?.wire ?? 1) >= 2
    ? { capability: "x-ccshield-capability", control: "x-ccshield-control", launch: "x-ccshield-launch", prefix: "/_ccshield/" }
    : { capability: "x-airkit-shield", control: "x-airkit-shield-control", launch: "x-airkit-shield-launch", prefix: "/_airkit/shield/" };
}

export async function launchShieldChild({ command, args = [], ready, env = process.env, spawnChild = spawn, approvalBroker, allowUnscannedImages = false, createApprovalChannel: createChannel = createLauncherApprovalChannel, registerApprovalChannel: registerChannel = registerShieldApprovalChannel, unregisterApprovalChannel: unregisterChannel = unregisterShieldApprovalChannel, registerImageOverride = registerShieldImageOverride, unregisterImageOverride = unregisterShieldImageOverride } = {}) {
  if (typeof command !== "string" || command.length === 0 || command.includes("\0")) throw new Error("shield launch command is required");
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== "string" || arg.includes("\0"))) throw new Error("shield launch arguments must be strings");
  assertNoShieldEndpointOverride(args, ready?.origin);
  await assertNoPersistedShieldEndpointOverride(ready?.origin, env);
  const launchId = createShieldLaunchId();
  const channel = await openShieldApprovalChannel({ approvalBroker, createApprovalChannel: createChannel });
  let registered = false;
  let overridden = false;
  try {
    if (channel !== null) {
      await registerChannel({ ready, channel, launchId });
      registered = true;
    }
    // The override lives in the daemon's memory under this launch id only, so
    // the next launch (or a daemon restart) is fail-closed again.
    if (allowUnscannedImages) {
      await registerImageOverride({ ready, launchId });
      overridden = true;
    }
    const child = spawnChild(command, args, {
      env: buildShieldChildEnv(ready, env, launchId),
      shell: false,
      stdio: "inherit",
    });
    return await new Promise((resolvePromise, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolvePromise({ code, signal }));
    });
  } finally {
    if (overridden) await unregisterImageOverride({ ready, launchId }).catch(() => {});
    if (registered) await unregisterChannel({ ready, launchId }).catch(() => {});
    await channel?.close?.();
  }
}

export function createShieldLaunchId() {
  return randomBytes(16).toString("hex");
}

function assertShieldLaunchId(launchId) {
  if (typeof launchId !== "string" || !/^[a-f0-9]{32}$/.test(launchId)) throw new Error("shield launch id is invalid");
}

export async function openShieldApprovalChannel({ approvalBroker, createApprovalChannel: createChannel = createLauncherApprovalChannel } = {}) {
  return await createChannel({ broker: approvalBroker ?? createApprovalBroker({ tty: defaultApprovalTty() }) });
}

export async function registerShieldApprovalChannel({ ready, channel, launchId, paths, io, fetchImpl = fetch } = {}) {
  if (!ready?.origin || !ready?.capability || channel === null || channel === undefined) throw new Error("shield approval registration requires a fresh ready identity");
  assertShieldLaunchId(launchId);
  const registration = { ...approvalChannelRegistration(channel), launchId };
  const config = await readShieldConfig({ paths: paths ?? shieldPaths({ lane: ready.lane }), io });
  let response;
  try {
    response = await fetchImpl(`${ready.origin}${shieldWireNames(ready).prefix}approval-channel`, {
      method: "POST",
      headers: { [shieldWireNames(ready).control]: config.controlCapability, "content-type": "application/json" },
      body: JSON.stringify(registration),
    });
  } catch {
    throw new Error("shield approval registration failed");
  }
  if (response?.status !== 204) throw new Error("shield approval registration failed");
}

export async function unregisterShieldApprovalChannel({ ready, launchId, paths, io, fetchImpl = fetch } = {}) {
  if (!ready?.origin) return;
  assertShieldLaunchId(launchId);
  const config = await readShieldConfig({ paths: paths ?? shieldPaths({ lane: ready.lane }), io });
  const response = await fetchImpl(`${ready.origin}${shieldWireNames(ready).prefix}approval-channel`, {
    method: "DELETE",
    headers: { [shieldWireNames(ready).control]: config.controlCapability, "content-type": "application/json" },
    body: JSON.stringify({ launchId }),
  }).catch(() => null);
  if (response?.status !== 204) throw new Error("shield approval unregister failed");
}

export async function registerShieldImageOverride({ ready, launchId, paths, io, fetchImpl = fetch } = {}) {
  if (!(await postImageOverride({ method: "POST", ready, launchId, paths, io, fetchImpl }))) throw new Error("shield image override registration failed");
}

export async function unregisterShieldImageOverride({ ready, launchId, paths, io, fetchImpl = fetch } = {}) {
  if (!(await postImageOverride({ method: "DELETE", ready, launchId, paths, io, fetchImpl }))) throw new Error("shield image override unregister failed");
}

async function postImageOverride({ method, ready, launchId, paths, io, fetchImpl }) {
  if (!ready?.origin) return false;
  assertShieldLaunchId(launchId);
  const config = await readShieldConfig({ paths: paths ?? shieldPaths({ lane: ready.lane }), io });
  const response = await fetchImpl(`${ready.origin}${shieldWireNames(ready).prefix}image-override`, {
    method,
    headers: { [shieldWireNames(ready).control]: config.controlCapability, "content-type": "application/json" },
    body: JSON.stringify({ launchId }),
  }).catch(() => null);
  return response?.status === 204;
}

export async function createShieldDestinationLease({ ready, targetOrigin, launcherContext, paths, io, fetchImpl = fetch } = {}) {
  if ((ready?.lane !== "managed" && ready?.lane !== "subscription") || !ready.origin || !targetOrigin) throw new Error("shield destination lease requires a fresh lane identity");
  if (launcherContext !== undefined) classifyShieldRequest({ body: Buffer.alloc(0), launcherContext });
  const config = await readShieldConfig({ paths: paths ?? shieldPaths({ lane: ready.lane }), io });
  const capability = randomUUID().replaceAll("-", "");
  const response = await fetchImpl(`${ready.origin}${shieldWireNames(ready).prefix}destination-lease`, {
    method: "POST",
    headers: { [shieldWireNames(ready).control]: config.controlCapability, "content-type": "application/json" },
    body: JSON.stringify({ capability, targetOrigin, expiresAt: Date.now() + 30_000, ...(launcherContext === undefined ? {} : { launcherContext }) }),
  }).catch(() => null);
  if (response?.status !== 204) throw new Error("shield managed destination lease registration failed");
  return Object.freeze({ ...ready, capability });
}

export async function revokeShieldDestinationLease({ ready, paths, io, fetchImpl = fetch } = {}) {
  if ((ready?.lane !== "managed" && ready?.lane !== "subscription") || !ready.origin || !ready.capability) return;
  const config = await readShieldConfig({ paths: paths ?? shieldPaths({ lane: ready.lane }), io });
  const response = await fetchImpl(`${ready.origin}${shieldWireNames(ready).prefix}destination-lease`, {
    method: "DELETE",
    headers: { [shieldWireNames(ready).control]: config.controlCapability, "content-type": "application/json" },
    body: JSON.stringify({ capability: ready.capability }),
  }).catch(() => null);
  if (response?.status !== 204) throw new Error("shield managed destination lease revocation failed");
}

export async function renewShieldDestinationLease({ ready, targetOrigin, paths, io, fetchImpl = fetch } = {}) {
  if ((ready?.lane !== "managed" && ready?.lane !== "subscription") || !ready.origin || !ready.capability || !targetOrigin) return false;
  const config = await readShieldConfig({ paths: paths ?? shieldPaths({ lane: ready.lane }), io });
  const response = await fetchImpl(`${ready.origin}${shieldWireNames(ready).prefix}destination-lease`, {
    method: "POST",
    headers: { [shieldWireNames(ready).control]: config.controlCapability, "content-type": "application/json" },
    body: JSON.stringify({ capability: ready.capability, targetOrigin, expiresAt: Date.now() + 30_000, renew: true }),
  }).catch(() => null);
  return response?.status === 204;
}

export function buildShieldChildEnv(ready, env = process.env, launchId) {
  if (!ready?.origin || !ready?.capability || ready.targetClass !== ready.lane || (ready.lane !== "subscription" && ready.lane !== "managed")) {
    throw new Error("shield launch requires a fresh lane-bound loopback identity");
  }
  if (/[\r\n]/.test(ready.capability)) {
    throw new Error("shield capability cannot be represented as an HTTP header");
  }
  if (launchId !== undefined) assertShieldLaunchId(launchId);
  const keptHeaders = String(env.ANTHROPIC_CUSTOM_HEADERS ?? "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "" && !/^x-(?:airkit-shield|ccshield)(?:-|:)/i.test(line));
  const names = shieldWireNames(ready);
  const childEnv = {
    ...env,
    ANTHROPIC_API_BASE_URL: ready.origin,
    ANTHROPIC_BASE_URL: ready.origin,
    CLAUDE_AGENT_API_BASE_URL: ready.origin,
    ANTHROPIC_CUSTOM_HEADERS: [
      ...keptHeaders,
      `${names.capability}: ${ready.capability}`,
      ...(launchId === undefined ? [] : [`${names.launch}: ${launchId}`]),
    ].join("\n"),
  };
  for (const name of ["CCSHIELD_CONTROL_CAPABILITY", "CCSHIELD_APPROVAL_CAPABILITY", "CCSHIELD_APPROVAL_SOCKET", "CCSHIELD_CAPABILITY"]) {
    for (const key of envNamesFor(name)) delete childEnv[key];
  }
  return childEnv;
}

function assertNoShieldEndpointOverride(args, shieldOrigin) {
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--settings-file" || arg.startsWith("--settings-file=")) {
      throw new Error("Shield launch settings file cannot override the Shield transport");
    }
    const raw = arg === "--settings"
      ? args[index + 1]
      : arg.startsWith("--settings=")
        ? arg.slice("--settings=".length)
        : null;
    if (raw === null) continue;
    let settings;
    try { settings = JSON.parse(raw); } catch { throw new Error("Shield launch settings must be valid JSON"); }
    assertNoShieldEndpointSettings(settings, shieldOrigin);
  }
}

export async function assertNoPersistedShieldEndpointOverride(shieldOrigin, env) {
  const settingsPath = resolve(env?.CLAUDE_CONFIG_DIR ?? resolve(env?.HOME ?? tmpdir(), ".claude"), "settings.json");
  let raw;
  try { raw = await readFile(settingsPath, "utf8"); } catch { return; }
  let settings;
  try { settings = JSON.parse(raw); } catch { throw new Error("Shield launch settings must be valid JSON"); }
  assertNoShieldEndpointSettings(settings, shieldOrigin);
}

function assertNoShieldEndpointSettings(settings, shieldOrigin) {
  const configured = settings?.env;
  if (!configured || typeof configured !== "object" || Array.isArray(configured)) return;
  for (const key of ["ANTHROPIC_API_BASE_URL", "ANTHROPIC_BASE_URL", "CLAUDE_AGENT_API_BASE_URL"]) {
    if (Object.hasOwn(configured, key) && configured[key] !== shieldOrigin) {
      throw new Error(`Shield launch settings cannot override ${key}`);
    }
  }
}

async function createLauncherApprovalChannel({ broker }) {
  if (!isInteractiveApprovalTty()) return null;
  const directory = await mkdtemp(resolve(tmpdir(), "ccshield-approval-"));
  const channel = await createApprovalChannel({ broker, directory });
  return Object.freeze({ ...channel, close: async () => { await channel.close(); await rm(directory, { recursive: true, force: true }); } });
}

function defaultApprovalTty() {
  if (!isInteractiveApprovalTty()) return null;
  return Object.freeze({
    interactive: true,
    write: (value) => process.stdout.write(value),
    async prompt() {
      const reader = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
      try { return await reader.question(""); } finally { reader.close(); }
    },
  });
}

function isInteractiveApprovalTty() { return process.stdin?.isTTY === true && process.stdout?.isTTY === true; }

function assertLane(lane) {
  if (lane !== "subscription" && lane !== "managed") throw new Error("shield lane must be subscription or managed");
}

export function defaultShieldLauncherContext(lane) {
  return {
    repository: { remoteHash: UNKNOWN_REMOTE_HASH, trustClass: "unknown" },
    pathClasses: ["unknown"],
    destinationClass: lane,
    interactive: false,
  };
}

function assertLauncherContext(context) {
  classifyShieldRequest({ body: Buffer.alloc(0), launcherContext: context });
}

function normalizeShieldTargetOrigin(value, label) {
  let target;
  try {
    target = new URL(value);
  } catch {
    target = null;
  }
  if (
    target === null
    || (target.protocol !== "http:" && target.protocol !== "https:")
    || target.username !== ""
    || target.password !== ""
    || target.pathname !== "/"
    || target.search !== ""
    || target.hash !== ""
  ) {
    throw new Error(`${label} origin is missing or invalid`);
  }
  return target.origin;
}

function assertShieldPaths(paths) {
  if (paths?.platform === "linux") {
    if (typeof paths.serviceUnitPath !== "string" || !isAbsolute(paths.serviceUnitPath) || basename(paths.serviceUnitPath) !== `ccshield-${paths.lane}.service`) {
      throw new Error("paths.serviceUnitPath must be the absolute lane-specific shield unit path");
    }
    assertShieldStateLayout(paths);
    return;
  }
  if (!paths?.rootDir || !paths.lane || !paths.serviceLabel || !paths.configPath || !paths.identityPath || !paths.policyStatePath || !paths.launchAgentPath || !paths.launchdDomain || !paths.launchdTarget) {
    throw new TypeError("shield service paths are required");
  }
  if (!/^gui\/\d+$/.test(paths.launchdDomain) || paths.launchdTarget !== `${paths.launchdDomain}/${paths.serviceLabel}`) {
    throw new Error("paths.launchdTarget must target the lane-specific shield service");
  }
  if (!isAbsolute(paths.launchAgentPath) || basename(paths.launchAgentPath) !== `${paths.serviceLabel}.plist`) {
    throw new Error("paths.launchAgentPath must be the absolute lane-specific shield plist path");
  }
  assertShieldStateLayout(paths);
}

function assertShieldStateLayout(paths) {
  if (!paths.rootDir || !paths.lane || !paths.serviceLabel || !paths.configPath || !paths.identityPath || !paths.policyStatePath) {
    throw new TypeError("shield service paths are required");
  }
  if ((paths.lane !== "subscription" && paths.lane !== "managed") || paths.serviceLabel !== `${SHIELD_SERVICE_LABEL}.${paths.lane}` || !isAbsolute(paths.rootDir) || paths.configPath !== resolve(paths.rootDir, "config.json") || paths.identityPath !== resolve(paths.rootDir, "identity.json") || paths.policyStatePath !== resolve(paths.rootDir, "policy-state.json")) {
    throw new Error("shield service paths must use the canonical shield state layout");
  }
}

function sameDetectorVersions(actual, expected) {
  const actualEntries = Object.entries(actual).sort(([left], [right]) => left.localeCompare(right));
  const expectedEntries = Object.entries(expected).sort(([left], [right]) => left.localeCompare(right));
  return actualEntries.length === expectedEntries.length
    && actualEntries.every(([name, version], index) => name === expectedEntries[index][0] && version === expectedEntries[index][1]);
}

function assertCompleteDetectorVersions(value) {
  const size = value && typeof value === "object" ? Object.keys(value).length : 0;
  if ((size !== 2 && !(size === 3 && typeof value.image === "string"))
    || typeof value.gitleaks !== "string" || typeof value.privacy !== "string") {
    throw new Error("shield detector binding must include Gitleaks and Privacy");
  }
}

const launchdBackend = {
  plan: planLaunchdService,
  install: installLaunchdService,
  start: startLaunchdService,
  stop: stopLaunchdService,
  uninstall: uninstallLaunchdService,
  inspect: inspectLaunchdService,
};

function planSystemdService({ paths, nodePath, daemonPath } = {}) {
  assertShieldPaths(paths);
  for (const [name, value] of Object.entries({ nodePath, daemonPath })) {
    if (typeof value !== "string" || !isAbsolute(value)) throw new Error(`${name} must be an absolute path`);
  }
  // rootDir is <XDG_DATA_HOME>/ccshield/<lane>; pinning it keeps the daemon on the root the CLI chose.
  const unit = renderUnit({ nodePath, daemonPath, configPath: paths.configPath, label: paths.serviceLabel, dataHome: dirname(dirname(paths.rootDir)) });
  const unitName = basename(paths.serviceUnitPath);
  return {
    label: paths.serviceLabel,
    unitPath: paths.serviceUnitPath,
    unitName,
    unit,
    operations: [
      { op: "mkdir", path: dirname(paths.serviceUnitPath), mode: 0o700 },
      { op: "writeFileAtomic", path: paths.serviceUnitPath, mode: 0o600, content: unit },
      { op: "daemon-reload" },
      { op: "enable", unit: unitName },
      { op: "restart", unit: unitName },
    ],
  };
}

async function installSystemdService({ write = false, io = defaultIo, runSystemctl = defaultSystemctl, ...options } = {}) {
  const plan = planSystemdService(options);
  if (!write) return plan;
  const config = createShieldConfig(options.config);
  await writeShieldConfig({ paths: options.paths, config, io });
  await io.mkdir(dirname(plan.unitPath), { recursive: true, mode: 0o700 });
  const temporaryPath = `${plan.unitPath}.tmp-${process.pid}`;
  await io.writeFile(temporaryPath, plan.unit, { mode: 0o600 });
  await io.chmod(temporaryPath, 0o600);
  await io.rename(temporaryPath, plan.unitPath);
  await systemctl(runSystemctl, ["daemon-reload"]);
  try {
    await systemctl(runSystemctl, ["enable", plan.unitName]);
  } catch (error) {
    if (!UNKNOWN_UNIT.test(error.message)) throw error;
    throw new Error(`${error.message}; the systemd user manager does not search ${dirname(plan.unitPath)} (is XDG_CONFIG_HOME set in the shell but not in the manager's environment?)`);
  }
  // restart, not start: a running daemon keeps the old config's capability and generation, as kickstart -k avoids on macOS.
  await systemctl(runSystemctl, ["restart", plan.unitName]);
  return { ...plan, written: true };
}

async function startSystemdService({ io = defaultIo, runSystemctl = defaultSystemctl, ...rest } = {}) {
  const plan = planSystemdService(rest);
  let existing;
  try {
    existing = await io.readFile(plan.unitPath, "utf8");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    throw new Error("shield service is not installed; run 'ccshield install --write' before start");
  }
  if (existing !== plan.unit) throw new Error(`shield service unit path drift detected: ${plan.unitPath} (${describeUnitDrift(existing, plan.unit)}); run the install command from the checkout that should own this unit`);
  await systemctl(runSystemctl, ["daemon-reload"]);
  await systemctl(runSystemctl, ["restart", plan.unitName]);
  return { ...plan, started: true };
}

async function stopSystemdService({ paths, runSystemctl = defaultSystemctl } = {}) {
  assertShieldPaths(paths);
  await systemctl(runSystemctl, ["stop", basename(paths.serviceUnitPath)], UNKNOWN_UNIT);
  return { label: SHIELD_SERVICE_LABEL, stopped: true };
}

// Removes only the lane's unit; pins, policy and config stay, as with the LaunchAgent.
async function uninstallSystemdService({ paths, write = false, io = defaultIo, runSystemctl = defaultSystemctl, uid = process.getuid?.() } = {}) {
  assertShieldPaths(paths);
  const unitName = basename(paths.serviceUnitPath);
  let stat;
  try {
    stat = await io.lstat(paths.serviceUnitPath);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    // A unit file deleted by hand can leave its service running until the manager reloads.
    if (write) await systemctl(runSystemctl, ["stop", unitName], UNKNOWN_UNIT);
    return { label: paths.serviceLabel, installed: false, removed: false };
  }
  if (!stat.isFile() || (uid !== undefined && stat.uid !== uid)) throw new Error(`shield service unit is not a regular file owned by this user: ${paths.serviceUnitPath}`);
  const unit = await io.readFile(paths.serviceUnitPath, "utf8");
  if (unitLabel(unit) !== paths.serviceLabel) throw new Error(`shield service unit does not belong to ${paths.serviceLabel}: ${paths.serviceUnitPath}`);
  if (!write) return { label: paths.serviceLabel, installed: true, removed: false, operations: [{ op: "disable", unit: unitName, now: true }, { op: "unlink", path: paths.serviceUnitPath }, { op: "daemon-reload" }] };
  await systemctl(runSystemctl, ["disable", "--now", unitName]);
  await io.unlink(paths.serviceUnitPath);
  await systemctl(runSystemctl, ["daemon-reload"]);
  return { label: paths.serviceLabel, installed: true, removed: true };
}

// `systemctl show` succeeds even for a unit it has never heard of, so loaded comes from LoadState, not the exit code.
async function inspectSystemdService({ paths, io = defaultIo, runSystemctl = defaultSystemctl } = {}) {
  assertShieldPaths(paths);
  const installed = await io.readFile(paths.serviceUnitPath, "utf8").then(() => true, () => false);
  const shown = await systemctl(runSystemctl, ["show", "-p", "ActiveState,MainPID,LoadState", basename(paths.serviceUnitPath)], /.*/s);
  const property = (name) => new RegExp(`^${name}=(.*)$`, "m").exec(shown.stdout ?? "")?.[1]?.trim();
  const state = shown.ok ? (property("ActiveState") ?? null) : null;
  const pidValue = property("MainPID");
  const pid = shown.ok && /^\d+$/.test(pidValue ?? "") && Number(pidValue) > 0 ? Number(pidValue) : null;
  const loaded = shown.ok && property("LoadState") === "loaded";
  const active = loaded && state === "active" && pid !== null;
  return { label: paths.serviceLabel, installed, loaded, active, pid, state, stale: installed && !active };
}

const systemdBackend = {
  plan: planSystemdService,
  install: installSystemdService,
  start: startSystemdService,
  stop: stopSystemdService,
  uninstall: uninstallSystemdService,
  inspect: inspectSystemdService,
};

const UNKNOWN_UNIT = /not loaded|not found|does not exist/i;

async function systemctl(runSystemctl, args, tolerated = null) {
  const result = await runSystemctl(["--user", ...args]);
  if (result?.ok === false && !(tolerated && tolerated.test(result.stderr ?? ""))) {
    throw new Error(`systemctl --user ${args[0]} failed: ${result.stderr ?? "unknown error"}`);
  }
  return { ok: result?.ok !== false, ...result };
}

async function defaultSystemctl(args) {
  try {
    const result = await execFileAsync("systemctl", args);
    return { ok: true, status: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    return { ok: false, status: error.code, stderr: error.stderr ?? error.message };
  }
}

async function ensurePathDrift(plan, io) {
  const existing = await io.readFile(plan.plistPath, "utf8");
  if (existing !== plan.plistXml) throw new Error(`shield launch plist path drift detected: ${plan.plistPath} (${describePlistDrift(existing, plan.plistXml)}); run the install command from the checkout that should own this job`);
}

// launchctl reports an already-bootstrapped service as "Bootstrap failed: 5:
// Input/output error" rather than saying so, which made `shield start` fail on
// every service `install --write` had already loaded. Tolerating it is safe
// because the kickstart that follows is not tolerated: a service that genuinely
// failed to bootstrap still raises there.
const TOLERATED_LAUNCHCTL_FAILURES = /already (loaded|bootstrapped)|could not find service|no such process|Bootstrap failed: 5:/i;

async function launch(runLaunchctl, args, tolerateFailure) {
  const result = await runLaunchctl(args);
  if (result?.ok === false && !(tolerateFailure && TOLERATED_LAUNCHCTL_FAILURES.test(result.stderr ?? ""))) {
    throw new Error(`launchctl ${args[0]} failed: ${result.stderr ?? "unknown error"}`);
  }
  return { ok: result?.ok !== false, ...result };
}

async function defaultLaunchctl(args) {
  try {
    const result = await execFileAsync("launchctl", args);
    return { ok: true, status: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    return { ok: false, status: error.code, stderr: error.stderr ?? error.message };
  }
}

async function defaultProbeShield(origin, capability, wire) {
  const names = shieldWireNames({ wire });
  try {
    const response = await fetch(new URL(`${names.prefix}ready`, origin), {
      headers: { [names.capability]: capability },
      redirect: "manual",
      signal: AbortSignal.timeout(1_000),
    });
    await response.body?.cancel();
    return response.status === 204;
  } catch {
    return false;
  }
}

async function defaultIsProcessAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code === "EPERM";
  }
}

function renderPlist(value) {
  const body = Object.entries(value).map(([key, item]) => `${indent(1)}<key>${escapeXml(key)}</key>\n${renderValue(item, 1)}`).join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n${body}\n</dict>\n</plist>\n`;
}

function renderValue(value, level) {
  if (Array.isArray(value)) return `<array>\n${value.map((entry) => `${indent(level + 1)}${renderValue(entry, level + 1)}`).join("\n")}\n${indent(level)}</array>`;
  if (value && typeof value === "object") return `<dict>\n${Object.entries(value).map(([key, entry]) => `${indent(level + 1)}<key>${escapeXml(key)}</key>\n${indent(level + 1)}${renderValue(entry, level + 1)}`).join("\n")}\n${indent(level)}</dict>`;
  if (typeof value === "boolean") return value ? "<true/>" : "<false/>";
  return `<string>${escapeXml(String(value))}</string>`;
}

const indent = (level) => "  ".repeat(level);
const escapeXml = (text) => text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&apos;");
