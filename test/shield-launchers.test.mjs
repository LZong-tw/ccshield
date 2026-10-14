import { test } from "node:test";
import assert from "node:assert/strict";

import { resolveShieldLauncher, resolveShieldLauncherMarker, shieldLauncherDescriptors } from "../src/shield/launchers.mjs";
import { createDecisionCache } from "../src/shield/decision-cache.mjs";

test("every declared AirKit and Headroom launcher has an explicit Shield disposition", () => {
  const cases = [
    ["airclaude", "managed", "managed", ["airclaude", "shield", "managed"]],
    ["cclaude-work", "managed", "managed", ["cclaude-*", "airclaude", "shield", "managed"]],
    ["hr-airclaude", "managed", "managed", ["headroom", "airclaude", "shield", "managed"]],
    ["hr-claude-web", "managed", "managed", ["headroom", "web", "shield", "managed"]],
  ];

  for (const [launcher, lane, destinationClass, hopChain] of cases) {
    assert.deepEqual(
      resolveShieldLauncher({ launcher, mode: "auto", headroom: launcher.startsWith("hr-"), providerOverride: lane }),
      { coverage: "protected", clientLane: lane, destinationClass, hopChain },
      launcher,
    );
  }
});

test("declared direct client bypasses are visible and undeclared helpers fail closed", () => {
  assert.deepEqual(
    resolveShieldLauncher({ launcher: "claude", mode: "auto" }),
    { coverage: "bypass", bypassReason: "direct_client" },
  );
  assert.deepEqual(
    resolveShieldLauncher({ launcher: "hr-claude-sub", mode: "auto", headroom: true }),
    { coverage: "bypass", bypassReason: "zsh_direct_subscription" },
  );
  assert.throws(
    () => resolveShieldLauncher({ launcher: "hr-unknown", mode: "auto" }),
    /undeclared Shield launcher/i,
  );
});

test("Headroom launcher markers require their exact loopback compatibility override", () => {
  assert.equal(
    resolveShieldLauncherMarker({
      AIRKIT_SHIELD_LAUNCHER: "headroom/hr-airclaude/v1",
      AIRCLAUDE_PROVIDER_BASE_URL: "http://127.0.0.1:8804/v1/chat/completions",
    }),
    "hr-airclaude",
  );
  assert.equal(
    resolveShieldLauncherMarker({
      AIRKIT_SHIELD_LAUNCHER: "headroom/hr-claude-web/v1",
      AIRCLAUDE_ANTHROPIC_PROVIDER_BASE_URL: "http://127.0.0.1:8807/v1/messages",
    }),
    "hr-claude-web",
  );
});

test("spoofed or malformed Headroom launcher markers fail closed", () => {
  for (const env of [
    { AIRKIT_SHIELD_LAUNCHER: "headroom/hr-airclaude/v1" },
    { AIRKIT_SHIELD_LAUNCHER: "headroom/hr-airclaude/v1", AIRCLAUDE_PROVIDER_BASE_URL: "http://localhost:8804/v1/chat/completions" },
    { AIRKIT_SHIELD_LAUNCHER: "headroom/hr-claude-web/v1", AIRCLAUDE_ANTHROPIC_PROVIDER_BASE_URL: "http://127.0.0.1:8807/v1/chat/completions" },
    { AIRKIT_SHIELD_LAUNCHER: "headroom/hr-airclaude/v2", AIRCLAUDE_PROVIDER_BASE_URL: "http://127.0.0.1:8804/v1/chat/completions" },
  ]) {
    assert.throws(() => resolveShieldLauncherMarker(env), /shield launcher marker/i);
  }
});

test("launcher descriptor inventory exposes protected hops and zsh bypasses distinctly", () => {
  const descriptors = shieldLauncherDescriptors();
  assert.deepEqual(descriptors.find((entry) => entry.launcher === "hr-claude-sub"), {
    coverage: "bypass", launcher: "hr-claude-sub", bypassReason: "zsh_direct_subscription",
  });
  assert.deepEqual(descriptors.find((entry) => entry.launcher === "hr-claude-web"), {
    coverage: "protected", launcher: "hr-claude-web", lanes: ["managed"], hopChain: ["headroom", "web", "shield", "managed"],
  });
});

test("feature-enabled Headroom subscription is represented as protected without exposing its destination", () => {
  assert.deepEqual(
    resolveShieldLauncher({ launcher: "hr-claude-sub", mode: "auto", headroom: true, subscriptionShield: true }),
    {
      coverage: "protected",
      clientLane: "subscription",
      destinationClass: "subscription",
      hopChain: ["headroom", "subscription", "shield", "subscription"],
    },
  );
  assert.deepEqual(
    shieldLauncherDescriptors({ subscriptionShield: true }).find((entry) => entry.launcher === "hr-claude-sub"),
    {
      coverage: "protected",
      launcher: "hr-claude-sub",
      lanes: ["subscription"],
      hopChain: ["headroom", "subscription", "shield", "subscription"],
    },
  );
});

test("decision cache reuses only exact terminal retry metadata and invalidates transitions", async () => {
  let now = 1_000;
  const cache = createDecisionCache({ clock: () => now, ttlMs: 100, maxEntries: 2 });
  const first = {
    body: Buffer.from('{"safe":"redacted"}'),
    action: "redact",
    detectorVersions: { Gitleaks: "1", Privacy: "1" },
    destinationClass: "managed",
    lane: "managed",
    policyVersion: "policy-1",
    requestDigest: "a".repeat(64),
    reasonCodes: ["pii_redacted"], transformCount: 1,
  };
  cache.set(first);
  const hit = await cache.getOrCompute(first, async () => assert.fail("exact cached retry must not evaluate"));
  assert.equal(hit.source, "cache_hit");
  assert.equal(hit.decision.action, "redact");
  assert.deepEqual(hit.decision.body, Buffer.from('{"safe":"redacted"}'));
  assert.notEqual(hit.decision.body, first.body);
  const miss = await cache.getOrCompute({ ...first, requestDigest: "b".repeat(64) }, async () => ({ ...first, requestDigest: "b".repeat(64) }));
  assert.equal(miss.source, "evaluated");
  const policyMiss = await cache.getOrCompute({ ...first, policyVersion: "policy-2" }, async () => ({ ...first, policyVersion: "policy-2" }));
  assert.equal(policyMiss.source, "evaluated");
  const laneMiss = await cache.getOrCompute({ ...first, lane: "subscription", destinationClass: "subscription" }, async () => ({ ...first, lane: "subscription", destinationClass: "subscription" }));
  assert.equal(laneMiss.source, "evaluated");

  cache.invalidateTransition({ policyVersion: "policy-2", detectorVersions: { Gitleaks: "2", Privacy: "1" } });
  const invalidated = await cache.getOrCompute(first, async () => ({ ...first }));
  assert.equal(invalidated.source, "evaluated");
  cache.set({ ...first, policyVersion: "policy-2", detectorVersions: { Gitleaks: "2", Privacy: "1" } });
  now += 101;
  const expired = await cache.getOrCompute({ ...first, policyVersion: "policy-2", detectorVersions: { Gitleaks: "2", Privacy: "1" } }, async () => ({ ...first, policyVersion: "policy-2", detectorVersions: { Gitleaks: "2", Privacy: "1" } }));
  assert.equal(expired.source, "evaluated");
});

test("decision cache atomically identifies concurrent exact retry provenance without retaining request input", async () => {
  const cache = createDecisionCache();
  const key = {
    detectorVersions: { Gitleaks: "1", Privacy: "1" }, destinationClass: "managed", lane: "managed", policyVersion: "policy-1", requestDigest: "c".repeat(64),
  };
  let calls = 0;
  const compute = async () => {
    calls += 1;
    return { ...key, action: "allow", body: Buffer.alloc(0), reasonCodes: ["policy_allow"], transformCount: 0 };
  };
  const [left, right] = await Promise.all([cache.getOrCompute(key, compute), cache.getOrCompute(key, compute)]);
  assert.equal(calls, 1);
  assert.equal(left.decision.action, "allow");
  assert.equal(right.decision.action, "allow");
  assert.equal(left.source, "evaluated");
  assert.equal(right.source, "coalesced");
  assert.equal(JSON.stringify(cache.inspect()).includes("requestDigest"), false);
});

test("decision cache rejects a computed decision whose identity differs from the pending retry", async () => {
  const cache = createDecisionCache();
  const key = {
    detectorVersions: { Gitleaks: "1", Privacy: "1" }, destinationClass: "managed", lane: "managed", policyVersion: "policy-1", requestDigest: "d".repeat(64),
  };
  await assert.rejects(
    cache.getOrCompute(key, async () => ({ ...key, requestDigest: "e".repeat(64), action: "allow", body: Buffer.alloc(0), reasonCodes: ["policy_allow"], transformCount: 0 })),
    /identity mismatch/i,
  );
  const retry = await cache.getOrCompute(key, async () => ({ ...key, action: "allow", body: Buffer.alloc(0), reasonCodes: ["policy_allow"], transformCount: 0 }));
  assert.equal(retry.source, "evaluated");
});

test("policy transition invalidation prevents an older pending decision from entering the cache", async () => {
  const cache = createDecisionCache();
  const key = {
    detectorVersions: { Gitleaks: "1", Privacy: "1" }, destinationClass: "managed", lane: "managed", policyVersion: "policy-1", requestDigest: "e".repeat(64),
  };
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const pending = cache.getOrCompute(key, async () => {
    await gate;
    return { ...key, action: "allow", body: Buffer.alloc(0), reasonCodes: ["policy_allow"], transformCount: 0 };
  });
  await new Promise((resolve) => setImmediate(resolve));
  cache.invalidateTransition({ policyVersion: "policy-2", detectorVersions: { Gitleaks: "2", Privacy: "1" } });
  release();
  await assert.rejects(pending, /invalidated/);
  const retry = await cache.getOrCompute(key, async () => ({ ...key, action: "allow", body: Buffer.alloc(0), reasonCodes: ["policy_allow"], transformCount: 0 }));
  assert.equal(retry.source, "evaluated");
});
