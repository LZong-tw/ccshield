import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";

import { installPlugin } from "../plugin/install.mjs";
import { detectAirkitInstall } from "../plugin/migrate.mjs";

import { GITLEAKS_COMMAND_PROFILE } from "./gitleaks.mjs";
import { doctorDetectorAssets, ensureOpfJob, fetchDetectorAssets, runOpfJobForLane } from "./detectors.mjs";
import { readShieldAssetsProvision, readShieldIdentity, readShieldPolicyState, shieldPaths } from "./paths.mjs";
import { provisionImageWorker } from "./image-provision.mjs";
import { provisionShieldAssets } from "./provision.mjs";
import { installShieldPolicyProvision, readShieldPolicyProvision } from "./policy-bundle.mjs";
import { readShieldOperationalStatus } from "./operational-status.mjs";
import { hasBackgroundClaudeHost, scheduleBackgroundHostRelease } from "./background-host.mjs";
import { ANTHROPIC_ORIGIN, startPxpipeHop } from "./pxpipe-hop.mjs";
import {
  ensureShieldReady,
  createShieldDestinationLease,
  inspectShieldService,
  installShieldService,
  launchShieldChild,
  startShieldService,
  stopShieldService,
  uninstallShieldService,
  transitionShieldPolicy,
  renewShieldDestinationLease,
  revokeShieldDestinationLease,
} from "./service.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..");
const EXIT_CODES = Object.freeze({ healthy: 0, preview: 0, degraded: 1, stopped: 2, blocked: 3 });
const SENSITIVE_KEYS = new Set(["capability", "origin", "path", "target", "targetClass", "targetOrigin"]);

export async function runShieldCli(argv = [], dependencies = {}) {
  const stdout = dependencies.stdout ?? process.stdout;
  const [command = "help", ...rest] = argv;
  if (command === "__opf-job") {
    const { lane } = parseLaneCommand(rest, "ccshield __opf-job");
    const job = await (dependencies.runOpfJobForLane ?? runOpfJobForLane)({ paths: shieldPaths({ env: dependencies.env ?? process.env, lane }) });
    return job.state === "verified" ? 0 : 1;
  }
  if (["help", "-h", "--help"].includes(command)) {
    stdout.write(renderShieldHelp());
    return 0;
  }
  if (command === "plugin" || command === "migrate") {
    const result = command === "plugin" ? await runPluginCommand(rest) : await detectAirkitInstall({ home: (dependencies.env ?? process.env).HOME ?? homedir() });
    stdout.write(renderShieldResult(command, result));
    return result.exitCode;
  }
  const shield = dependencies.shield ?? await createDefaultShieldDependencies(dependencies);
  const handler = SHIELD_COMMANDS[command];
  if (!handler) throw new Error(`unknown ccshield command: ${argv.join(" ") || "(none)"}`);
  const result = await handler(rest, shield);
  stdout.write(renderShieldResult(command, result));
  if (Number.isInteger(result?.exitCode)) return result.exitCode;
  return EXIT_CODES[result?.state] ?? EXIT_CODES.blocked;
}

const SHIELD_COMMANDS = Object.freeze({
  install: (argv, shield) => shield.install(parseInstall(argv)),
  uninstall: (argv, shield) => shield.uninstall(parseInstall(argv, "ccshield uninstall")),
  start: (argv, shield) => shield.start(parseLaneCommand(argv, "ccshield start")),
  stop: (argv, shield) => shield.stop(parseLaneCommand(argv, "ccshield stop")),
  status: (argv, shield) => shield.status(parseLaneCommand(argv, "ccshield status")),
  doctor: (argv, shield) => shield.doctor(parseLaneCommand(argv, "ccshield doctor")),
  policy: (argv, shield) => argv[0] === "status" ? shield.policyStatus(parseLaneCommand(argv.slice(1), "ccshield policy status")) : shield.policyInstall(parsePolicyInstall(argv)),
  privacy: (argv, shield) => shield.privacyProvision(parsePrivacyProvision(argv)),
  image: (argv, shield) => shield.imageProvision(parseImageProvision(argv)),
  launch: (argv, shield) => {
    const launch = parseLaunch(argv);
    if (launch.lane === "managed") throw new Error("managed Shield launch requires AirKit lease lifecycle");
    return shield.launch(launch);
  },
});

async function createDefaultShieldDependencies(dependencies) {
  const env = dependencies.env ?? process.env;
  const paths = dependencies.paths ?? shieldPaths({ env });
  const nodePath = dependencies.nodePath ?? process.execPath;
  const daemonPath = dependencies.daemonPath ?? resolve(repoRoot, "src", "shieldd.mjs");
  const readAssets = dependencies.readShieldAssetsProvision ?? readShieldAssetsProvision;
  const fetchDetectors = dependencies.fetchDetectorAssets ?? fetchDetectorAssets;
  const doctorDetectors = dependencies.doctorDetectorAssets ?? doctorDetectorAssets;
  const readPolicyProvision = dependencies.readShieldPolicyProvision ?? readShieldPolicyProvision;
  const installService = dependencies.installShieldService ?? installShieldService;
  const provisionAssets = dependencies.provisionShieldAssets ?? provisionShieldAssets;
  const provisionImage = dependencies.provisionImageWorker ?? provisionImageWorker;
  const installPolicy = dependencies.installShieldPolicyProvision ?? installShieldPolicyProvision;
  const ensureReady = dependencies.ensureShieldReady ?? ensureShieldReady;
  const readOperational = dependencies.readShieldOperationalStatus ?? readShieldOperationalStatus;
  const readStatus = dependencies.shieldStatus ?? shieldStatus;
  const readAuditHealth = dependencies.readAuditHealth ?? (async (options) => (await import("../store.mjs")).readAuditHealth(options));
  const inspectKey = dependencies.inspectMasterKey ?? (async () => (await import("../keys.mjs")).inspectMasterKey({ env }));
  const createLease = dependencies.createShieldDestinationLease ?? createShieldDestinationLease;
  const renewLease = dependencies.renewShieldDestinationLease ?? renewShieldDestinationLease;
  const revokeLease = dependencies.revokeShieldDestinationLease ?? revokeShieldDestinationLease;
  const launchChild = dependencies.launchShieldChild ?? launchShieldChild;
  const createDecisionRecorder = dependencies.createDecisionRecorder ?? (async ({ paths: lanePaths }) => {
    const { createDefaultDecisionRecorder } = await import("../shieldd.mjs");
    return createDefaultDecisionRecorder({ env, paths: lanePaths });
  });
  const common = { paths, nodePath, daemonPath, env, ...(dependencies.io ? { io: dependencies.io } : {}), ...(dependencies.runLaunchctl ? { runLaunchctl: dependencies.runLaunchctl } : {}) };
  return {
    async install({ write, lane, gitleaksPath }) {
      const lanePaths = shieldPaths({ env, lane });
      const provisioned = await readAssets({ paths: lanePaths, io: dependencies.io });
      if (!provisioned) throw new Error("shield assets are missing; run ccshield privacy provision with Gitleaks before install");
      const detectors = await fetchDetectors({ paths: lanePaths, gitleaksPath, write, background: write });
      // A write records the installed Gitleaks, which the service then runs.
      const assets = write ? await readAssets({ paths: lanePaths, io: dependencies.io }) : provisioned;
      const { loadShieldPolicy } = dependencies.loadShieldPolicy ? { loadShieldPolicy: dependencies.loadShieldPolicy } : await import("./policy.mjs");
      const provision = await readPolicyProvision({ paths: lanePaths, io: dependencies.io });
      await loadShieldPolicy(provision);
      const config = {
        lane,
        gitleaks: {
          executable: assets.gitleaks.path,
          sha256: assets.gitleaks.sha256,
          ruleBundle: {
            path: assets.gitleaks.rules.path,
            sha256: assets.gitleaks.rules.sha256,
            version: assets.gitleaks.rules.version,
            commandProfile: { versionArgs: [...GITLEAKS_COMMAND_PROFILE.versionArgs], scanArgs: [...GITLEAKS_COMMAND_PROFILE.scanArgs] },
          },
        },
      };
      const service = await installService({ ...common, paths: lanePaths, config, write });
      return { state: write ? "degraded" : "preview", exitCode: write ? 1 : 0, write, lane, detectors, service: { label: service.label, planned: true } };
    },
    async uninstall({ write, lane }) {
      const service = await uninstallShieldService({ ...common, paths: shieldPaths({ env, lane }), write });
      return { state: write || !service.installed ? "stopped" : "preview", exitCode: 0, write, lane, service };
    },
    async start({ lane }) {
      await startShieldService({ ...common, paths: shieldPaths({ env, lane }) });
      return { state: "degraded", started: true };
    },
    async stop({ lane }) {
      await stopShieldService({ ...common, paths: shieldPaths({ env, lane }) });
      return { state: "stopped", stopped: true };
    },
    async status({ lane }) {
      return await shieldStatus({ paths: shieldPaths({ env, lane }), io: dependencies.io, runLaunchctl: dependencies.runLaunchctl });
    },
    async doctor({ lane }) {
      const lanePaths = shieldPaths({ env, lane });
      const status = await readStatus({ paths: lanePaths, io: dependencies.io, runLaunchctl: dependencies.runLaunchctl });
      const operational = await readOperational({ env, audit: await readAuditHealth({ paths: lanePaths }) });
      const selected = operational.lanes?.find((entry) => entry.lane === lane);
      const key = await inspectKey();
      const detectors = await doctorDetectors({ paths: lanePaths, assets: await readAssets({ paths: lanePaths, io: dependencies.io }) });
      return {
        ...status,
        state: status.state === "healthy" && selected?.state !== "protected" ? "degraded" : status.state,
        operational,
        masterKey: { source: key.source, ...(key.warning ? { warning: key.warning } : {}) },
        detectors,
        checked: true,
      };
    },
    async privacyProvision({ bundlePath, gitleaksPath, gitleaksRulesPath, policyBundlePath, lane = "subscription", write }) {
      const lanePaths = shieldPaths({ env, lane });
      await provisionAssets({
        bundlePath: policyBundlePath ?? lanePaths.policyBundlePath,
        gitleaksPath,
        gitleaksRulesPath,
        privacyBundlePath: bundlePath,
        write,
        paths: lanePaths,
        nodePath,
      });
      return { state: write ? "degraded" : "preview", write, provisioned: write };
    },
    async imageProvision({ sourcePath, lane, write }) {
      const result = await provisionImage({ paths: shieldPaths({ env, lane }), write, ...(sourcePath ? { sourcePath } : {}) });
      return { ...result, state: write ? "degraded" : "preview", write };
    },
    async policyInstall({ bundlePath, publicKeyPath, lane = "subscription", write }) {
      const lanePaths = shieldPaths({ env, lane });
      const { loadShieldPolicy } = await import("./policy.mjs");
      const preview = await installPolicy({ bundlePath, publicKeyPath, paths: lanePaths, loadPolicy: loadShieldPolicy });
      if (!write) return { state: "preview", version: preview.version, detectorVersions: preview.detectorVersions, write: false, restarted: false };
      const recorder = await createDecisionRecorder({ paths: lanePaths });
      if (typeof recorder?.recordShieldPolicyTransition !== "function") {
        throw new Error("shield policy transition audit recorder is unavailable");
      }
      let result;
      try {
        result = await transitionShieldPolicy({
          ...common,
          paths: lanePaths,
          installPolicy: () => installPolicy({ bundlePath, publicKeyPath, write: true, paths: lanePaths, loadPolicy: loadShieldPolicy }),
          recordShieldPolicyTransition: recorder.recordShieldPolicyTransition,
        });
      } finally {
        await recorder.close?.();
      }
      return { state: "degraded", version: result.version, detectorVersions: result.detectorVersions, write: true };
    },
    async policyStatus({ lane }) {
      const state = await readShieldPolicyState({ paths: shieldPaths({ env, lane }), io: dependencies.io });
      return state ? { state: "healthy", version: state.version, detectorVersions: state.detectorVersions } : { state: "stopped", installed: false };
    },
    async launch({ lane, targetOrigin: fixedTarget, pxpipe = false, allowUnscannedImages = false, command, args }) {
      const lanePaths = shieldPaths({ env, lane });
      if (allowUnscannedImages) (dependencies.stderr ?? process.stderr).write("ccshield: 圖片掃描已停用（僅本次啟動）；圖片不經 OCR 掃描或遮罩即送出，文字仍會掃描、遮罩或攔截。\n");
      let ready = await ensureReady({ lane, env, paths: lanePaths, io: dependencies.io, inspectService: dependencies.inspectService, isProcessAlive: dependencies.isProcessAlive, probeShield: dependencies.probeShield });
      await (dependencies.ensureOpfJob ?? ensureOpfJob)({ paths: lanePaths }).catch(() => null);
      // pxpipe sits behind Shield, so it only sees redacted traffic. It lives
      // exactly as long as the lease that points Shield at it.
      const hop = pxpipe ? await (dependencies.startPxpipeHop ?? startPxpipeHop)({ upstream: ANTHROPIC_ORIGIN, env }) : null;
      const targetOrigin = hop?.origin ?? fixedTarget;
      if (targetOrigin) {
        try { ready = await createLease({ ready, targetOrigin, paths: lanePaths, io: dependencies.io }); }
        catch (error) { await hop?.close(); throw error; }
      }
      let leaseTimer = null;
      const stopLeaseTimer = () => {
        if (leaseTimer !== null) {
          (dependencies.shieldLeaseClearInterval ?? clearInterval)(leaseTimer);
          leaseTimer = null;
        }
      };
      if (targetOrigin) {
        const schedule = dependencies.shieldLeaseSetInterval ?? setInterval;
        leaseTimer = schedule(() => {
          void renewLease({ ready, targetOrigin, paths: lanePaths, io: dependencies.io }).catch(() => {});
        }, 15_000);
        leaseTimer.unref?.();
      }
      let outcome;
      let leaseRetained = false;
      let leaseReleased = false;
      const releaseLease = async () => {
        if (leaseReleased) return;
        leaseReleased = true;
        stopLeaseTimer();
        await revokeLease({ ready, paths: lanePaths, io: dependencies.io }).catch(() => {});
        await hop?.close();
      };
      try {
        outcome = await launchChild({ command, args, ready, env, allowUnscannedImages, spawnChild: dependencies.spawnChild });
        if (targetOrigin && await hasBackgroundClaudeHost(ready.origin, dependencies.backgroundHostDetector)) {
          leaseRetained = scheduleBackgroundHostRelease(ready.origin, {
            detector: dependencies.backgroundHostDetector,
            graceMs: dependencies.backgroundMiddlewareGraceMs,
            setTimeoutFn: dependencies.backgroundSetTimeout,
            onReleased: releaseLease,
          });
        }
      }
      finally {
        if (targetOrigin && !leaseRetained) await releaseLease();
      }
      return { state: outcome.code === 0 ? "healthy" : "degraded", launched: true, exitCode: outcome.code ?? 1 };
    },
  };
}

async function shieldStatus({ paths, io, runLaunchctl }) {
  const service = await inspectShieldService({ paths, io, runLaunchctl });
  try {
    const identity = await readShieldIdentity({ paths, io });
    if (!identity) return { state: service.active ? "degraded" : "stopped", service, identity: { present: false } };
    return { state: service.active && service.pid === identity.pid ? "healthy" : "degraded", service, identity: { present: true } };
  } catch {
    return { state: "blocked", service, identity: { present: false, valid: false } };
  }
}

function parseLaunch(argv) {
  const laneIndex = argv.indexOf("--lane");
  const boundary = argv.indexOf("--");
  const lane = laneIndex >= 0 ? argv[laneIndex + 1] : undefined;
  const targetIndex = argv.indexOf("--target");
  const targetOrigin = targetIndex >= 0 ? argv[targetIndex + 1] : undefined;
  const beforeBoundary = argv.slice(0, boundary);
  const pxpipe = beforeBoundary.includes("--pxpipe");
  const allowUnscannedImages = beforeBoundary.includes("--allow-unscanned-images");
  const repeated = ["--pxpipe", "--allow-unscanned-images"].some((flag) => beforeBoundary.filter((value) => value === flag).length > 1);
  const validTarget = targetIndex < 0 || (targetIndex + 1 < boundary && isLoopbackTarget(targetOrigin));
  if (laneIndex < 0 || !lane || boundary < 0 || boundary === argv.length - 1 || (lane !== "subscription" && lane !== "managed") || !validTarget || repeated || beforeBoundary.some((value) => !["--lane", lane, "--target", targetOrigin, "--pxpipe", "--allow-unscanned-images"].includes(value))) {
    throw new Error("usage: ccshield launch --lane subscription|managed [--target http://127.0.0.1:port | --pxpipe] [--allow-unscanned-images] -- command [args...]");
  }
  if (lane === "managed" && (targetOrigin || pxpipe)) throw new Error("managed Shield launch requires AirKit lease lifecycle");
  if (pxpipe && targetOrigin) throw new Error("shield launch accepts --target or --pxpipe, not both");
  return { lane, targetOrigin, pxpipe, allowUnscannedImages, command: argv[boundary + 1], args: argv.slice(boundary + 2) };
}

function isLoopbackTarget(value) { try { const url = new URL(value); return url.protocol === "http:" && url.hostname === "127.0.0.1" && Number.isInteger(Number(url.port)) && Number(url.port) > 0 && url.pathname === "/" && !url.search && !url.hash; } catch { return false; } }

function parseInstall(argv, command = "ccshield install") {
  const acceptsGitleaksPath = command === "ccshield install";
  let write = false;
  let lane = null;
  let gitleaksPath = null;
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--write" && !write) { write = true; continue; }
    if (argv[index] === "--lane" && lane === null && (argv[index + 1] === "subscription" || argv[index + 1] === "managed")) {
      lane = argv[index + 1]; index += 1; continue;
    }
    if (acceptsGitleaksPath && argv[index] === "--gitleaks-path" && gitleaksPath === null && isAbsolute(argv[index + 1] ?? "")) {
      gitleaksPath = argv[index + 1]; index += 1; continue;
    }
    throw new Error(`usage: ${command} [--lane subscription|managed]${acceptsGitleaksPath ? " [--gitleaks-path /absolute/gitleaks]" : ""} [--write]`);
  }
  return { write, lane: lane ?? "subscription", ...(gitleaksPath ? { gitleaksPath } : {}) };
}

function parseLaneCommand(argv, command) {
  if (argv.length === 0) return { lane: "subscription" };
  if (argv.length === 2 && argv[0] === "--lane" && ["subscription", "managed"].includes(argv[1])) return { lane: argv[1] };
  throw new Error(`usage: ${command} [--lane subscription|managed]`);
}

const PRIVACY_PROVISION_USAGE = "usage: ccshield privacy provision --gitleaks /absolute/gitleaks --gitleaks-rules /absolute/gitleaks-rules.toml [--bundle /absolute/privacy-manifest] [--policy-bundle /absolute/policy-bundle] [--write]";

function parsePrivacyProvision(argv) {
  if (argv[0] !== "provision") throw new Error(PRIVACY_PROVISION_USAGE);
  const write = argv.includes("--write");
  const names = ["--bundle", "--gitleaks", "--gitleaks-rules", "--lane", "--policy-bundle"];
  const values = Object.fromEntries(names.map((name) => [name, null]));
  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--write") continue;
    if (!names.includes(token) || values[token] !== null || typeof argv[index + 1] !== "string" || argv[index + 1].startsWith("--")) {
      throw new Error(PRIVACY_PROVISION_USAGE);
    }
    values[token] = argv[index + 1];
    index += 1;
  }
  if (!values["--gitleaks"] || !values["--gitleaks-rules"] || (values["--lane"] !== null && !["subscription", "managed"].includes(values["--lane"]))) throw new Error(PRIVACY_PROVISION_USAGE);
  return { ...(values["--bundle"] === null ? {} : { bundlePath: values["--bundle"] }), gitleaksPath: values["--gitleaks"], gitleaksRulesPath: values["--gitleaks-rules"], ...(values["--policy-bundle"] === null ? {} : { policyBundlePath: values["--policy-bundle"] }), lane: values["--lane"] ?? "subscription", write };
}

const IMAGE_PROVISION_USAGE = "usage: ccshield image provision [--image-source /absolute/image-worker.swift] [--lane subscription|managed] [--write]";

function parseImageProvision(argv) {
  if (argv[0] !== "provision") throw new Error(IMAGE_PROVISION_USAGE);
  const values = { "--image-source": null, "--lane": null };
  let write = false;
  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--write" && !write) { write = true; continue; }
    const value = argv[index + 1];
    if (!(token in values) || values[token] !== null || typeof value !== "string" || value.startsWith("--")) throw new Error(IMAGE_PROVISION_USAGE);
    values[token] = value;
    index += 1;
  }
  const source = values["--image-source"];
  if ((source !== null && !isAbsolute(source)) || (values["--lane"] !== null && !["subscription", "managed"].includes(values["--lane"]))) throw new Error(IMAGE_PROVISION_USAGE);
  return { ...(source === null ? {} : { sourcePath: source }), lane: values["--lane"] ?? "subscription", write };
}

function parsePolicyInstall(argv) {
  if (argv[0] !== "install") throw new Error("usage: ccshield policy install --bundle /absolute/policy-bundle --public-key /absolute/policy-public-key [--write]");
  const write = argv.includes("--write");
  const names = ["--bundle", "--public-key", "--lane"];
  const values = Object.fromEntries(names.map((name) => [name, null]));
  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--write") continue;
    if (!names.includes(token) || values[token] !== null || typeof argv[index + 1] !== "string" || argv[index + 1].startsWith("--")) {
      throw new Error("usage: ccshield policy install --bundle /absolute/policy-bundle --public-key /absolute/policy-public-key [--write]");
    }
    values[token] = argv[index + 1];
    index += 1;
  }
  if (!values["--bundle"] || !values["--public-key"] || (values["--lane"] !== null && !["subscription", "managed"].includes(values["--lane"]))) throw new Error("usage: ccshield policy install --bundle /absolute/policy-bundle --public-key /absolute/policy-public-key [--write]");
  return { bundlePath: values["--bundle"], publicKeyPath: values["--public-key"], lane: values["--lane"] ?? "subscription", write };
}

async function runPluginCommand(argv) {
  const [sub, ...rest] = argv;
  const options = { pluginRoot: repoRoot, write: false };
  for (let index = 0; index < rest.length; index += 1) {
    if (rest[index] === "--write") options.write = true;
    else if (rest[index] === "--plugin-root" && rest[index + 1]) options.pluginRoot = rest[++index];
    else throw new Error("usage: ccshield plugin install [--plugin-root /absolute/dir] [--write]");
  }
  if (sub !== "install") throw new Error("usage: ccshield plugin install [--plugin-root /absolute/dir] [--write]");
  return installPlugin(options);
}

function renderShieldHelp() {
  return `Commands:\n  ccshield install [--lane subscription|managed] [--gitleaks-path /absolute/gitleaks] [--write]\n  ccshield uninstall [--lane subscription|managed] [--write]\n  ccshield start [--lane subscription|managed]\n  ccshield stop [--lane subscription|managed]\n  ccshield status [--lane subscription|managed]\n  ccshield doctor [--lane subscription|managed]\n  ccshield policy <status [--lane subscription|managed]|install --bundle /absolute/policy-bundle --public-key /absolute/policy-public-key [--lane subscription|managed] [--write]>\n  ccshield privacy provision --gitleaks /absolute/gitleaks --gitleaks-rules /absolute/gitleaks-rules.toml [--bundle /absolute/privacy-manifest] [--policy-bundle /absolute/policy-bundle] [--lane subscription|managed] [--write]\n  ccshield image provision [--image-source /absolute/image-worker.swift] [--lane subscription|managed] [--write]\n  ccshield launch --lane subscription|managed [--target http://127.0.0.1:port] [--allow-unscanned-images] -- command [args...]\n  ccshield plugin install [--plugin-root /absolute/dir] [--write]\n  ccshield migrate\n`;
}

function renderShieldResult(command, result = {}) {
  const lines = flatten(sanitize({ command, ...result }));
  return `${lines.length ? lines.join("\n") : `${command}: ok`}\n`;
}

function sanitize(value, key = "", parentKey = "") {
  if (SENSITIVE_KEYS.has(key) || ((key === "args" || key === "command") && parentKey === "worker")) return undefined;
  if (Array.isArray(value)) return value.map((entry) => sanitize(entry, key, parentKey));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).flatMap(([entryKey, entry]) => (SENSITIVE_KEYS.has(entryKey) || ((entryKey === "args" || entryKey === "command") && key === "worker")) ? [] : [[entryKey, sanitize(entry, entryKey, key)]]));
  }
  return value;
}

function flatten(value, prefix = "") {
  if (value && typeof value === "object") {
    return Object.entries(value).flatMap(([key, entry]) => flatten(entry, `${prefix}${key}.`));
  }
  return [`${prefix.slice(0, -1)}: ${String(value)}`];
}
