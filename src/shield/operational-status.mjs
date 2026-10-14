import { readShieldAssetsProvision, readShieldIdentity, readShieldPolicyState, shieldPaths } from "./paths.mjs";
import { ensureShieldReady, inspectShieldService } from "./service.mjs";
import { shieldLauncherDescriptors } from "./launchers.mjs";

const LANES = Object.freeze(["subscription", "managed"]);
const HEALTH = new Set(["healthy", "unavailable"]);
// What the proxy can inspect, independent of lane health. Base64 images and documents under the body
// limit are forwarded without OCR or text extraction, so the gap is reported rather than implied away.
const CONTENT_COVERAGE = Object.freeze({ text: "scanned", images: "unscanned", documents: "unscanned" });

export async function readShieldOperationalStatus({
  env = process.env,
  audit = "unavailable",
  shieldPaths: resolvePaths = shieldPaths,
  inspectService = inspectShieldService,
  readIdentity = readShieldIdentity,
  readPolicy = readShieldPolicyState,
  readAssets = readShieldAssetsProvision,
  ensureReady = ensureShieldReady,
  launcherDescriptors = shieldLauncherDescriptors,
} = {}) {
  const auditState = HEALTH.has(audit) ? audit : "unavailable";
  const lanes = await Promise.all(LANES.map(async (lane) => {
    let paths;
    try {
      paths = resolvePaths({ env, lane });
    } catch {
      return unavailableLane(lane, auditState);
    }
    return readLaneStatus({ lane, audit: auditState, paths, inspectService, readIdentity, readPolicy, readAssets, ensureReady });
  }));
  const descriptors = safeLauncherDescriptors(launcherDescriptors({
    subscriptionShield: env?.AIRKIT_SHIELD_SUBSCRIPTION === "1",
  }));
  return {
    state: lanes.some((lane) => lane.state === "protected") ? "protected" : "unavailable",
    lanes,
    content_coverage: { ...CONTENT_COVERAGE },
    declared_coverage: descriptors.filter((descriptor) => descriptor.coverage === "protected").map(({ coverage: _coverage, ...descriptor }) => descriptor),
    declared_bypasses: descriptors.filter((descriptor) => descriptor.coverage === "bypass").map(({ coverage: _coverage, launcher, bypassReason }) => ({ launcher, reason: bypassReason })),
  };
}

async function readLaneStatus({ lane, audit, paths, inspectService, readIdentity, readPolicy, readAssets, ensureReady }) {
  const [serviceResult, identityResult, policyResult, assetsResult] = await Promise.allSettled([
    inspectService({ paths }),
    readIdentity({ paths }),
    readPolicy({ paths }),
    readAssets({ paths }),
  ]);
  const service = serviceResult.status === "fulfilled" ? serviceResult.value : null;
  const identity = identityResult.status === "fulfilled" ? identityResult.value : null;
  const policy = policyResult.status === "fulfilled" ? policyResult.value : null;
  const assets = assetsResult.status === "fulfilled" ? assetsResult.value : null;
  const serviceState = classifyService(service, identity, serviceResult.status === "rejected" || identityResult.status === "rejected");
  const policyState = classifyPolicy(policy, identity, policyResult.status === "rejected");
  const privacyState = classifyPrivacy(assets, identity, policy, assetsResult.status === "rejected");
  const provisioned = serviceState === "healthy" && policyState === "healthy" && privacyState === "healthy";
  let runtimeReady = false;
  if (provisioned) {
    try { runtimeReady = Boolean(await ensureReady({ lane, paths })); } catch {}
  }
  const protectedLane = provisioned && runtimeReady;
  const result = {
    lane,
    state: protectedLane ? "protected" : "unavailable",
    service: provisioned && !runtimeReady ? "degraded" : serviceState,
    policy: policyState,
    privacy: privacyState,
    audit,
  };
  if (policyState === "healthy") {
    result.policy_version = policy.version;
    result.gitleaks_version = policy.detectorVersions.gitleaks;
    result.privacy_version = policy.detectorVersions.privacy;
  }
  return result;
}

function unavailableLane(lane, audit) {
  return { lane, state: "unavailable", service: "unavailable", policy: "unavailable", privacy: "unavailable", audit };
}

function classifyService(service, identity, hadError) {
  if (hadError) return "unavailable";
  if (!service?.installed) return "stopped";
  if (!service.active) return service.loaded ? "degraded" : "stopped";
  return Number.isInteger(identity?.pid) && service.pid === identity.pid ? "healthy" : "degraded";
}

function classifyPolicy(policy, identity, hadError) {
  if (hadError) return "unavailable";
  if (!policy || !identity) return "missing";
  return policy.version === identity.policyVersion && sameDetectors(policy.detectorVersions, identity.detectorVersions) ? "healthy" : "degraded";
}

function classifyPrivacy(assets, identity, policy, hadError) {
  if (hadError) return "unavailable";
  if (!assets || !identity || !policy) return "missing";
  return assets.privacy?.version === policy.detectorVersions?.privacy
    && sameDetectors(policy.detectorVersions, identity.detectorVersions)
    ? "healthy"
    : "degraded";
}

function sameDetectors(left, right) {
  return left?.gitleaks === right?.gitleaks && left?.privacy === right?.privacy;
}

function safeLauncherDescriptors(value) {
  if (!Array.isArray(value)) return [];
  return value.flatMap((descriptor) => {
    if (!descriptor || typeof descriptor !== "object" || Array.isArray(descriptor)) return [];
    if (descriptor.coverage === "protected"
      && isId(descriptor.launcher)
      && Array.isArray(descriptor.lanes) && descriptor.lanes.every((lane) => LANES.includes(lane))
      && Array.isArray(descriptor.hopChain) && descriptor.hopChain.every(isId)) {
      return [{ coverage: "protected", launcher: descriptor.launcher, lanes: [...descriptor.lanes], hop_chain: [...descriptor.hopChain] }];
    }
    if (descriptor.coverage === "bypass" && isId(descriptor.launcher) && isId(descriptor.bypassReason)) {
      return [{ coverage: "bypass", launcher: descriptor.launcher, bypassReason: descriptor.bypassReason }];
    }
    return [];
  });
}

function isId(value) {
  return typeof value === "string" && /^[A-Za-z0-9._*-]{1,128}$/.test(value);
}
