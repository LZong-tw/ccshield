import assert from "node:assert/strict";
import test from "node:test";

import { readShieldOperationalStatus } from "../src/shield/operational-status.mjs";

const detectors = Object.freeze({ gitleaks: "8.24.3", privacy: "privacy-1" });

test("operational Shield status reports each lane from verified local state and declared launcher dispositions", async () => {
  const result = await readShieldOperationalStatus({
    audit: "healthy",
    shieldPaths: ({ lane }) => ({ lane }),
    inspectService: async ({ paths }) => paths.lane === "subscription"
      ? { installed: true, loaded: true, active: true, pid: 42, stale: false }
      : { installed: true, loaded: true, active: false, pid: null, stale: true },
    readIdentity: async ({ paths }) => paths.lane === "subscription"
      ? { pid: 42, lane: "subscription", policyVersion: "policy-1", detectorVersions: detectors }
      : null,
    readPolicy: async ({ paths }) => paths.lane === "subscription"
      ? { version: "policy-1", detectorVersions: detectors }
      : null,
    readAssets: async ({ paths }) => paths.lane === "subscription"
      ? { privacy: { version: "privacy-1" }, gitleaks: { path: "/not-rendered", sha256: "a".repeat(64) } }
      : null,
    ensureReady: async () => true,
    launcherDescriptors: () => [
      { coverage: "protected", launcher: "airclaude", lanes: ["managed"], hopChain: ["airclaude", "shield", "managed"] },
      { coverage: "bypass", launcher: "claude", bypassReason: "direct_client" },
    ],
  });

  assert.deepEqual(result, {
    state: "protected",
    lanes: [
      {
        lane: "subscription",
        state: "protected",
        service: "healthy",
        policy: "healthy",
        privacy: "healthy",
        audit: "healthy",
        policy_version: "policy-1",
        gitleaks_version: "8.24.3",
        privacy_version: "privacy-1",
        content_coverage: { text: "scanned", images: "unscanned", documents: "unscanned" },
      },
      {
        lane: "managed",
        state: "unavailable",
        service: "degraded",
        policy: "missing",
        privacy: "missing",
        audit: "healthy",
        content_coverage: { text: "n/a", images: "n/a", documents: "n/a" },
      },
    ],
    declared_coverage: [{ launcher: "airclaude", lanes: ["managed"], hop_chain: ["airclaude", "shield", "managed"] }],
    declared_bypasses: [{ launcher: "claude", reason: "direct_client" }],
  });
});

test("operational Shield status reads document coverage from the running daemon identity", async () => {
  const media = { documents: "blocked", images: "unscanned" };
  const status = (options) => readShieldOperationalStatus({
    shieldPaths: ({ lane }) => ({ lane }),
    inspectService: async ({ paths }) => paths.lane === "subscription"
      ? { installed: true, loaded: true, active: true, pid: options.pid ?? 42 }
      : { installed: false, loaded: false, active: false },
    readIdentity: async ({ paths }) => paths.lane === "subscription"
      ? { pid: 42, policyVersion: "policy-1", detectorVersions: detectors, ...options.identity }
      : { pid: 7, policyVersion: "policy-1", detectorVersions: detectors, media },
    readPolicy: async () => ({ version: "policy-1", detectorVersions: detectors }),
    readAssets: async () => ({ privacy: { version: "privacy-1" } }),
    ensureReady: async () => true,
    launcherDescriptors: () => [],
  });

  const running = await status({ identity: { media } });
  assert.deepEqual(running.lanes[0].content_coverage, { text: "scanned", images: "unscanned", documents: "blocked" });
  assert.deepEqual(running.lanes[1].content_coverage, { text: "n/a", images: "n/a", documents: "n/a" });

  const beforeRestart = await status({ identity: {} });
  assert.equal(beforeRestart.lanes[0].content_coverage.documents, "unscanned");

  const staleIdentity = await status({ pid: 99, identity: { media } });
  assert.equal(staleIdentity.lanes[0].content_coverage.documents, "unscanned");
});

test("operational Shield status does not claim protection when the live readiness probe fails", async () => {
  const result = await readShieldOperationalStatus({
    shieldPaths: ({ lane }) => ({ lane }),
    inspectService: async ({ paths }) => paths.lane === "subscription"
      ? { installed: true, loaded: true, active: true, pid: 42 }
      : { installed: false, loaded: false, active: false },
    readIdentity: async ({ paths }) => paths.lane === "subscription"
      ? { pid: 42, policyVersion: "policy-1", detectorVersions: detectors }
      : null,
    readPolicy: async ({ paths }) => paths.lane === "subscription"
      ? { version: "policy-1", detectorVersions: detectors }
      : null,
    readAssets: async ({ paths }) => paths.lane === "subscription"
      ? { privacy: { version: "privacy-1" } }
      : null,
    ensureReady: async () => { throw new Error("private readiness detail"); },
    launcherDescriptors: () => [],
  });
  assert.equal(result.state, "unavailable");
  assert.equal(result.lanes[0].state, "unavailable");
  assert.equal(result.lanes[0].service, "degraded");
  assert.doesNotMatch(JSON.stringify(result), /private readiness detail/);
});

test("operational Shield status reports the Headroom subscription route as protected only when enabled", async () => {
  let descriptorOptions;
  await readShieldOperationalStatus({
    env: { CCSHIELD_SUBSCRIPTION: "1" },
    shieldPaths: ({ lane }) => ({ lane }),
    inspectService: async () => ({ installed: false, loaded: false, active: false }),
    readIdentity: async () => null,
    readPolicy: async () => null,
    readAssets: async () => null,
    launcherDescriptors: (options) => {
      descriptorOptions = options;
      return [];
    },
  });
  assert.deepEqual(descriptorOptions, { subscriptionShield: true });
});

test("operational Shield status fails closed for broken local state and never returns sensitive state", async () => {
  const result = await readShieldOperationalStatus({
    audit: "unavailable",
    shieldPaths: ({ lane }) => ({ lane }),
    inspectService: async () => { throw new Error("/Users/private/com.ccshield.plist"); },
    readIdentity: async () => ({ pid: 1, capability: "must-not-render", origin: "http://127.0.0.1:8811" }),
    readPolicy: async () => { throw new Error("policy invalid"); },
    readAssets: async () => { throw new Error("privacy invalid"); },
    launcherDescriptors: () => [],
  });

  assert.equal(result.state, "unavailable");
  const notRunning = { text: "n/a", images: "n/a", documents: "n/a" };
  assert.deepEqual(result.lanes, [
    { lane: "subscription", state: "unavailable", service: "unavailable", policy: "unavailable", privacy: "unavailable", audit: "unavailable", content_coverage: notRunning },
    { lane: "managed", state: "unavailable", service: "unavailable", policy: "unavailable", privacy: "unavailable", audit: "unavailable", content_coverage: notRunning },
  ]);
  assert.doesNotMatch(JSON.stringify(result), /Users|capability|8811|must-not-render/i);
});

test("operational Shield status isolates an unreadable lane instead of hiding the other lane", async () => {
  const result = await readShieldOperationalStatus({
    audit: "healthy",
    shieldPaths: ({ lane }) => {
      if (lane === "managed") throw new Error("/Users/private/managed-state");
      return { lane };
    },
    inspectService: async () => ({ installed: false, loaded: false, active: false }),
    readIdentity: async () => null,
    readPolicy: async () => null,
    readAssets: async () => null,
    launcherDescriptors: () => [],
  });
  assert.equal(result.state, "unavailable");
  assert.deepEqual(result.lanes[1], {
    lane: "managed", state: "unavailable", service: "unavailable", policy: "unavailable", privacy: "unavailable", audit: "healthy",
    content_coverage: { text: "n/a", images: "n/a", documents: "n/a" },
  });
  assert.doesNotMatch(JSON.stringify(result), /Users|private/i);
});
