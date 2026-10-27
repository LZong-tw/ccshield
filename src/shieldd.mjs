#!/usr/bin/env node

import "./quiet-sqlite.mjs";

import { stat } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { readShieldAssetsProvision, readShieldImageProvision, shieldPathsForConfigPath, writeShieldIdentity, writeShieldPolicyState } from "./shield/paths.mjs";
import { classifyShieldRequest } from "./shield/classify.mjs";
import { createGitleaksScanner } from "./shield/gitleaks.mjs";
import { readShieldPolicyProvision } from "./shield/policy-bundle.mjs";
import { loadShieldPolicy } from "./shield/policy.mjs";
import { openPrivacyDetector } from "./shield/privacy-detector.mjs";
import { createPrivacyFilter, isVerifiedRedaction } from "./shield/privacy.mjs";
import { createShieldFailure as shieldFailure, startShieldProxy } from "./shield/proxy.mjs";
import { extractMedia, MEDIA_COVERAGE, mediaOutcomeFor, patchImages } from "./shield/media.mjs";
import { createImageInspector } from "../shield-image/inspector.mjs";
import { checkImageReadiness } from "../shield-image/readiness.mjs";
import { createImageWorker } from "../shield-image/worker.mjs";
import { createDecisionCache } from "./shield/decision-cache.mjs";
import { defaultShieldLauncherContext, readShieldConfig } from "./shield/service.mjs";
import { createShieldDecisionRecorder } from "./shield/audit.mjs";
import { getMasterKey } from "./keys.mjs";
import { openShieldStore } from "./store.mjs";

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
  readImageProvision = readShieldImageProvision,
  loadPolicy = loadShieldPolicy,
  createScanner = createGitleaksScanner,
  createPrivacy = createPrivacyFilter,
  createDecisionRecorder = createDefaultDecisionRecorder,
  createCache = createDecisionCache,
  writePolicyState = writeShieldPolicyState,
  startProxy = startShieldProxy,
  writeIdentity = writeShieldIdentity,
  createImageScanner = createDefaultImageScanner,
} = {}) {
  if (!config || !paths) throw new TypeError("shield daemon configuration and paths are required");
  const destinationClass = resolveDestinationClass(config);
  const provision = await readPolicyBundle({ paths });
  const policy = await loadPolicy({ bundle: provision.bundle, publicKey: provision.publicKey });
  // Once an image worker is pinned, only a bundle that names that exact image
  // version may boot, so a 2-key bundle cannot silently drop image scanning.
  const image = await readImageProvision({ paths });
  if (image && policy.detectorVersions.image !== image.version) throw new Error("shield image detector version does not match the provisioned worker");
  const assets = await readAssetsProvision({ paths });
  if (!assets) throw new Error("shield asset provision is missing");
  if (!config.gitleaks) throw new Error("shield gitleaks provision is missing");
  assertGitleaksAsset(config.gitleaks, assets.gitleaks);
  const scanner = await createScanner(config.gitleaks);
  if (scanner?.version !== policy.detectorVersions.gitleaks) throw new Error("shield gitleaks version does not match policy metadata");
  let privacy;
  let shield;
  let recorder;
  let images = null;
  const close = async () => {
    try { await shield?.close(); }
    finally {
      try { await privacy?.close?.(); }
      finally {
        try { await images?.close?.(); }
        finally { await recorder?.close?.(); }
      }
    }
  };
  try {
    privacy = await openPrivacyDetector({
      paths,
      assets,
      policy,
      readAssets: readAssetsProvision,
      createPrivacy,
      onOpfFailure: () => process.stderr.write("ccshieldd: OPF is unusable; staying on the regex detector\n"),
    });
    recorder = await createDecisionRecorder({ config, paths, policy, assets });
    if (typeof recorder?.recordShieldDecision !== "function") throw new Error("shield audit recorder is unavailable");
    // Without a provisioned worker, images stay unscanned (Q1). With one, an
    // image request fails closed until the readiness check has passed.
    if (image) {
      images = await createImageScanner({
        image,
        scanSecrets: (body) => scanner.scan(body),
        scanPrivacy: (body) => privacy.scan(body, { version: privacy.detectorVersions().privacy }),
        context: () => ({ policyVersion: policy.version, detectorVersions: { ...policy.detectorVersions } }),
      });
    }
    const decide = async ({ body, signal, launcherContext: requestLauncherContext = null, detectorVersions: keyedVersions }) => {
      privacy.refresh();
      const detectorVersions = keyedVersions ?? privacy.detectorVersions();
      const launcherContext = {
        ...(requestLauncherContext ?? config.launcherContext ?? defaultShieldLauncherContext(destinationClass)),
        destinationClass,
      };
      // Shield sees the original request, before pxpipe renders anything to images.
      let media;
      try {
        media = extractMedia(body);
      } catch {
        throw shieldFailure("media_scan", "media_scan_failed", "shield media scan failed");
      }
      const hasMedia = media.imageCount > 0 || media.documentCount > 0 || media.reasonCodes.length > 0;
      const mediaFacts = hasMedia
        ? { noCache: true, imageCount: media.imageCount, documentCount: media.documentCount, mediaOutcome: mediaOutcomeFor(media.reasonCodes) ?? "none" }
        : {};
      const shape = (decision) => ({
        ...decision,
        ...mediaFacts,
        lane: config.lane,
        destinationClass,
        bundleVersion: policy.version,
        detectorVersions: { ...detectorVersions },
      });
      // Documents and unscannable images stop here, before any scanner sees them. Base64 images are
      // forwarded unscanned in this phase; the text pipeline below still covers the rest of the body.
      if (media.reasonCodes.length > 0) return shape({ action: "block", reasonCodes: media.reasonCodes, transformCount: 0 });
      // Masked images are spliced in first, so the text scanners and any text
      // redaction work on exactly the body that will leave.
      let scanBody = body;
      let imageSecrets = 0;
      let imagePii = [];
      let imageTransforms = 0;
      if (images && media.images.length > 0) {
        if (!images.isReady()) throw shieldFailure("image_scan", "image_unavailable", "shield image worker is not ready");
        let results;
        try {
          results = await images.inspect(media.images.map(({ bytes, lastTurn }) => ({ bytes, lastTurn })));
        } catch (error) {
          if (error?.code === "too_many_images") return shape({ action: "block", reasonCodes: ["media_image_limit_blocked"], transformCount: 0 });
          throw shieldFailure("image_scan", IMAGE_FAILURES.has(error?.code) ? error.code : "image_scan_unavailable", "shield image scan unavailable");
        }
        imageSecrets = results.filter((result) => result.status === "secret").length;
        if (imageSecrets === 0) {
          try { scanBody = patchImages(body, results.map((result, index) => ({ image: media.images[index], bytes: result.bytes }))); }
          catch { throw shieldFailure("image_scan", "image_splice_invalid", "shield image splice failed"); }
          imagePii = results.flatMap((result) => result.piiFindings);
          imageTransforms = results.reduce((total, result) => total + Math.max(1, result.maskCount), 0);
        }
      }
      const facts = classifyShieldRequest({ body: scanBody, launcherContext });
      let secretScan;
      let confirmedSecret;
      try {
        secretScan = await scanner.scan(scanBody);
        secretScan = { findings: withImageSecrets(secretScan.findings, imageSecrets) };
        confirmedSecret = secretScan.findings.length > 0;
      } catch { throw shieldFailure("secret_scan", "scanner_unavailable", "shield secret scanner unavailable"); }
      let privacyScan;
      try {
        privacyScan = confirmedSecret ? { status: "ok", findings: [] } : await privacy.scan(scanBody, { signal, version: detectorVersions.privacy });
      } catch { throw shieldFailure("privacy_scan", "privacy_unavailable", "shield privacy worker unavailable"); }
      if (privacyScan?.status !== "ok") throw shieldFailure("privacy_scan", privacyScan?.reason, "shield privacy worker unavailable", privacyScan ?? {});
      let piiFindings;
      try { piiFindings = canonicalPrivacyFindings([...privacyScan.findings, ...imagePii]); }
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
      const textRedacted = privacyScan.findings.length > 0;
      if (decision.action === "redact" && (textRedacted || imageTransforms === 0) && !isVerifiedRedaction({ original: scanBody, result: privacyScan })) {
        throw shieldFailure("redaction", "redaction_invalid", "shield privacy redaction is invalid");
      }
      if (imageTransforms === 0) {
        return shape({
          ...decision,
          ...(decision.action === "redact" ? { redactedBody: privacyScan.redactedBody, transformCount: privacyScan.redactions.reduce((total, item) => total + item.count, 0) } : {}),
        });
      }
      // Normalized images always leave as transformed bytes, so an allow
      // becomes a redaction and an approval forwards the spliced body.
      if (decision.action === "block") return shape({ ...decision, transformCount: 0 });
      const textTransforms = decision.action === "redact" && textRedacted ? privacyScan.redactions.reduce((total, item) => total + item.count, 0) : 0;
      return shape({
        ...decision,
        action: decision.action === "allow" ? "redact" : decision.action,
        redactedBody: textTransforms > 0 ? privacyScan.redactedBody : scanBody,
        transformCount: textTransforms + imageTransforms,
      });
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
      decisionContext: () => {
        privacy.refresh();
        return { lane: config.lane, destinationClass, policyVersion: policy.version, detectorVersions: privacy.detectorVersions() };
      },
      recordShieldDecision: recorder.recordShieldDecision,
      isReady: async () => Boolean(await recorder.isReady?.() ?? true) && Boolean(await privacy.isReady?.()),
      scanStats: () => privacy.recentScans(),
      scanTotals: () => privacy.scanTotals(),
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
        media: { ...MEDIA_COVERAGE },
      },
    });
  } catch (error) {
    await close().catch(() => {});
    throw error;
  }
  return Object.freeze({ shield: Object.freeze({ ...shield, close }), policy, scanner, privacy });
}

const RETENTION_SWEEP_MS = 60 * 60 * 1000;

export async function createDefaultDecisionRecorder({ config = {}, paths, env = process.env, masterKeyProvider, openStore = openShieldStore } = {}) {
  if (!paths?.auditDatabasePath) throw new TypeError("shield audit store path is required");
  const provider = masterKeyProvider ?? { get: async () => (await getMasterKey({ env })).key };
  const masterKey = await provider.get();
  const store = openStore({
    databasePath: paths.auditDatabasePath,
    masterKey,
    ...(config.auditRetentionDays === undefined ? {} : { retentionDays: config.auditRetentionDays }),
  });
  // The store purges at open; this keeps a long-lived daemon inside the window too.
  const sweep = setInterval(() => { try { store.purgeExpiredEvidence(); } catch { /* the next write reports a broken store */ } }, RETENTION_SWEEP_MS);
  sweep.unref();
  const recorder = createShieldDecisionRecorder({ store });
  return Object.freeze({
    ...recorder,
    close: async () => {
      clearInterval(sweep);
      store.close();
    },
  });
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

const IMAGE_FAILURES = new Set(["image_unavailable", "image_timeout", "image_queue_full", "image_scan_unavailable", "image_splice_invalid"]);

function withImageSecrets(findings, count) {
  if (count === 0) return findings;
  return [...findings, { category: "image-ocr-secret", count }].sort((left, right) => (left.category < right.category ? -1 : left.category > right.category ? 1 : 0));
}

const IMAGE_TIMEOUT_MS = 60_000;

async function createDefaultImageScanner({ image, scanSecrets, scanPrivacy, context }) {
  const worker = createImageWorker({ path: image.path, sha256: image.sha256 });
  const inspector = createImageInspector({ worker, scanSecrets, scanPrivacy, context, timeoutMs: IMAGE_TIMEOUT_MS });
  let state = { ready: false, reason: "pending" };
  // The first Vision request takes ~30 s; readiness runs in the background and
  // only image requests wait on it.
  void checkImageReadiness({ worker }).then((result) => {
    state = result;
    if (!result.ready) process.stderr.write(`ccshieldd: image worker is not ready (${result.reason}); image requests stay unavailable\n`);
  });
  return Object.freeze({ isReady: () => state.ready, readiness: () => ({ ...state }), inspect: (images) => inspector.inspect(images), close: () => worker.close() });
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
  if (argv.length !== 2 || argv[0] !== "--config" || !argv[1]) throw new Error("usage: shieldd --config <private-config-path>");
  return argv[1];
}

async function assertPrivateConfig(path) {
  const entry = await stat(path);
  if (!entry.isFile() || (entry.mode & 0o077) !== 0) throw new Error("shield daemon configuration must be a private regular file");
  if (typeof process.getuid === "function" && entry.uid !== process.getuid()) throw new Error("shield daemon configuration has unexpected owner");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch(() => {
    process.stderr.write("CCSHIELDD code=CCSHIELDD_BOOT_FAILED\n", () => process.exit(1));
  });
}
