#!/usr/bin/env node

import { execFile } from "node:child_process";
import { stat, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { readShieldAssetsProvision, shieldPathsForConfigPath, writeShieldIdentity, writeShieldPolicyState } from "./shield/paths.mjs";
import { classifyShieldRequest } from "./shield/classify.mjs";
import { createGitleaksScanner } from "./shield/gitleaks.mjs";
import { readShieldPolicyProvision } from "./shield/policy-bundle.mjs";
import { loadShieldPolicy } from "./shield/policy.mjs";
import { createPrivacyFilter, isVerifiedRedaction } from "./shield/privacy.mjs";
import { createShieldFailure as shieldFailure, startShieldProxy } from "./shield/proxy.mjs";
import { createDecisionCache } from "./shield/decision-cache.mjs";
import { defaultShieldLauncherContext, readShieldConfig } from "./shield/service.mjs";
import { createShieldDecisionRecorder } from "./shield/audit.mjs";
import { createMasterKeyProvider } from "./audit/keychain.mjs";
import { resolveAuditPaths } from "./audit/paths.mjs";
import { createEncryptedSpool } from "./audit/spool.mjs";
import { createAuditClient } from "./audit/transport.mjs";

const execFileAsync = promisify(execFile);

async function main() {
  const configPath = parseConfigPath(process.argv.slice(2));
  const paths = shieldPathsForConfigPath({ env: process.env, configPath });
  await assertPrivateConfig(configPath);
  const config = await readShieldConfig({ paths });
  const { shield } = await startShieldDaemon({ config, paths });
  const stop = async () => {
    await shield.close();
    process.exitCode = 0;
  };
  process.once("SIGINT", () => { void stop(); });
  process.once("SIGTERM", () => { void stop(); });
  await new Promise(() => {});
}

export async function startShieldDaemon({
  config,
  paths,
  pid = process.pid,
  readPolicyBundle = readShieldPolicyProvision,
  readAssetsProvision = readShieldAssetsProvision,
  loadPolicy = loadShieldPolicy,
  createScanner = createGitleaksScanner,
  createPrivacy = createPrivacyFilter,
  createDecisionRecorder = createDefaultDecisionRecorder,
  createCache = createDecisionCache,
  writePolicyState = writeShieldPolicyState,
  startProxy = startShieldProxy,
  writeIdentity = writeShieldIdentity,
} = {}) {
  if (!config || !paths) throw new TypeError("shield daemon configuration and paths are required");
  const destinationClass = resolveDestinationClass(config);
  const provision = await readPolicyBundle({ paths });
  const policy = await loadPolicy({ bundle: provision.bundle, publicKey: provision.publicKey });
  const assets = await readAssetsProvision({ paths });
  if (!assets) throw new Error("shield asset provision is missing");
  if (!config.gitleaks) throw new Error("shield gitleaks provision is missing");
  assertGitleaksAsset(config.gitleaks, assets.gitleaks);
  const scanner = await createScanner(config.gitleaks);
  if (scanner?.version !== policy.detectorVersions.gitleaks) throw new Error("shield gitleaks version does not match policy metadata");
  let privacy;
  let shield;
  const close = async () => {
    try { await shield?.close(); }
    finally { await privacy?.close?.(); }
  };
  try {
    privacy = await createPrivacy({ provision: assets });
    if (privacy?.version !== policy.detectorVersions.privacy) throw new Error("shield privacy version does not match policy metadata");
    const recorder = await createDecisionRecorder({ config, paths, policy, assets });
    if (typeof recorder?.recordShieldDecision !== "function") throw new Error("shield audit recorder is unavailable");
    const decide = async ({ body, launcherContext: requestLauncherContext = null }) => {
      const launcherContext = {
        ...(requestLauncherContext ?? config.launcherContext ?? defaultShieldLauncherContext(destinationClass)),
        destinationClass,
      };
      const facts = classifyShieldRequest({ body, launcherContext });
      let secretScan;
      let confirmedSecret;
      try {
        secretScan = await scanner.scan(body);
        confirmedSecret = secretScan.findings.length > 0;
      } catch { throw shieldFailure("secret_scan", "scanner_unavailable", "shield secret scanner unavailable"); }
      let privacyScan;
      try {
        privacyScan = confirmedSecret ? { status: "ok", findings: [] } : await privacy.scan(body);
      } catch { throw shieldFailure("privacy_scan", "privacy_unavailable", "shield privacy worker unavailable"); }
      if (privacyScan?.status !== "ok") throw shieldFailure("privacy_scan", privacyScan?.reason, "shield privacy worker unavailable");
      let piiFindings;
      try { piiFindings = canonicalPrivacyFindings(privacyScan.findings); }
      catch { throw shieldFailure("privacy_scan", "findings_invalid", "shield privacy findings are invalid"); }
      let decision;
      try {
        decision = await policy.evaluate({
          lane: config.lane,
          destinationClass,
          interactive: facts.interactive,
          repositoryClass: facts.repositoryClass,
          pathClasses: facts.pathClasses,
          secretFindings: secretScan.findings,
          piiFindings,
        });
      } catch { throw shieldFailure("policy", "policy_unavailable", "shield policy unavailable"); }
      if (confirmedSecret && decision.action !== "block") throw shieldFailure("policy", "secret_block_invalid", "shield confirmed secret must be blocked");
      if (decision.action === "redact" && !isVerifiedRedaction({ original: body, result: privacyScan })) {
        throw shieldFailure("redaction", "redaction_invalid", "shield privacy redaction is invalid");
      }
      return {
        ...decision,
        lane: config.lane,
        destinationClass,
        bundleVersion: policy.version,
        detectorVersions: { ...policy.detectorVersions },
        ...(decision.action === "redact" ? { redactedBody: privacyScan.redactedBody, transformCount: privacyScan.redactions.reduce((total, item) => total + item.count, 0) } : {}),
      };
    };

    await writePolicyState({ paths, state: { version: policy.version, detectorVersions: policy.detectorVersions } });
    shield = await startProxy({
      capability: config.capability,
      controlCapability: config.controlCapability,
      targetOrigin: config.targetOrigin,
      allowDestinationLeases: true,
      decide,
      // Policy activation restarts this daemon after identity quiescence. This
      // cache is process-local, so no terminal decision survives that boundary.
      decisionCache: createCache(),
      decisionContext: { lane: config.lane, destinationClass, policyVersion: policy.version, detectorVersions: policy.detectorVersions },
      recordShieldDecision: recorder.recordShieldDecision,
      isReady: async () => Boolean(await recorder.isReady?.() ?? true) && Boolean(await privacy.isReady?.()),
      scanStats: privacy.recentScans ? () => privacy.recentScans() : null,
    });
    await writeIdentity({
      paths,
      identity: {
        origin: shield.origin,
        capability: config.capability,
        version: 1,
        pid,
        lane: config.lane,
        generation: config.generation,
        targetClass: config.targetClass,
        policyVersion: policy.version,
        detectorVersions: policy.detectorVersions,
      },
    });
  } catch (error) {
    await close().catch(() => {});
    throw error;
  }
  return Object.freeze({ shield: Object.freeze({ ...shield, close }), policy, scanner, privacy });
}

export async function createDefaultDecisionRecorder({ env = process.env, auditPaths = resolveAuditPaths({ env }), readCapability = readFile, masterKeyProvider, createClient = createAuditClient, createSpool = createEncryptedSpool } = {}) {
  const capabilityPath = env.AIRKIT_AUDIT_CAPABILITY_FILE ?? join(auditPaths.rootDir, "capability");
  const capability = (await readCapability(capabilityPath, "utf8")).trim();
  if (!/^[A-Za-z0-9._-]{32,512}$/.test(capability)) throw new Error("shield audit capability is unavailable");
  const provider = masterKeyProvider ?? createRuntimeMasterKeyProvider(env);
  const masterKey = await provider.get();
  const spool = createSpool({ paths: auditPaths, masterKey });
  const state = await spool.stats();
  if (state?.atCapacity === true) throw new Error("shield audit spool is at capacity");
  const client = createClient({ socketPath: env.AIRKIT_AUDIT_SOCKET_PATH ?? auditPaths.socketPath, capability, timeoutMs: 750 });
  return createShieldDecisionRecorder({ client, spool, masterKey });
}

function createRuntimeMasterKeyProvider(env) {
  const repoRoot = resolve(fileURLToPath(new URL(".", import.meta.url)), "..");
  const keychainHelperPath = env.AIRKIT_AUDIT_KEYCHAIN_HELPER ?? join(repoRoot, "native", "airkit-audit-keychain.swift");
  return createMasterKeyProvider({
    env,
    keychainHelperPath,
    runSecurity: (request) => runCommand(env.AIRKIT_SECURITY_PATH ?? "security", request),
    runKeychainHelper: (request) => runCommand(env.AIRKIT_SWIFT_PATH ?? "swift", request),
  });
}

async function runCommand(command, request) {
  try {
    const result = await execFileAsync(command, request?.args ?? [], { input: request?.input, timeout: 10_000, maxBuffer: 4 * 1024 });
    return { status: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    return { status: typeof error?.code === "number" ? error.code : 1, stdout: error?.stdout ?? "", stderr: error?.stderr ?? "" };
  }
}

function assertGitleaksAsset(gitleaks, asset) {
  if (!asset || gitleaks.executable !== asset.path || gitleaks.sha256 !== asset.sha256) {
    throw new Error("shield gitleaks asset provision does not match configuration");
  }
  // The rules decide what counts as a secret, so a config naming rules that
  // were never provisioned is the same class of failure as an unpinned binary.
  const bundle = gitleaks.ruleBundle;
  if (!asset.rules || !bundle || bundle.path !== asset.rules.path || bundle.sha256 !== asset.rules.sha256 || bundle.version !== asset.rules.version) {
    throw new Error("shield gitleaks rule bundle does not match asset provision");
  }
}

function canonicalPrivacyFindings(findings) {
  if (!Array.isArray(findings) || findings.length > 128) throw new Error("shield privacy findings are invalid");
  const totals = new Map();
  for (const finding of findings) {
    if (!finding || typeof finding !== "object" || Array.isArray(finding)
      || Object.keys(finding).length !== 2 || typeof finding.label !== "string"
      || !/^[A-Za-z0-9._-]{1,128}$/.test(finding.label)
      || !Number.isInteger(finding.count) || finding.count < 1 || finding.count > 1_000_000) {
      throw new Error("shield privacy findings are invalid");
    }
    const count = (totals.get(finding.label) ?? 0) + finding.count;
    if (count > 1_000_000) throw new Error("shield privacy findings are invalid");
    totals.set(finding.label, count);
  }
  return [...totals].sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0)).map(([category, count]) => Object.freeze({ category, count }));
}

function resolveDestinationClass(config) {
  if (config?.lane !== "subscription" && config?.lane !== "managed") {
    throw new Error("shield configuration lane is invalid");
  }
  if (config.targetClass !== undefined && config.targetClass !== config.lane) {
    throw new Error("shield configuration targetClass must match its lane");
  }
  return config.lane;
}

function parseConfigPath(argv) {
  if (argv.length !== 2 || argv[0] !== "--config" || !argv[1]) throw new Error("usage: airkit-shieldd --config <private-config-path>");
  return argv[1];
}

async function assertPrivateConfig(path) {
  const entry = await stat(path);
  if (!entry.isFile() || (entry.mode & 0o077) !== 0) throw new Error("shield daemon configuration must be a private regular file");
  if (typeof process.getuid === "function" && entry.uid !== process.getuid()) throw new Error("shield daemon configuration has unexpected owner");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch(() => {
    process.stderr.write("AIRKIT_SHIELDD code=AIRKIT_SHIELDD_BOOT_FAILED\n", () => process.exit(1));
  });
}
