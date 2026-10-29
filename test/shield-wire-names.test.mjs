import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { shieldSessionCheck } from "../src/plugin/session-check.mjs";
import { assertShieldIdentity, shieldPaths, writeShieldConfig, writeShieldIdentity, writeShieldPolicyState } from "../src/shield/paths.mjs";
import { startShieldProxy } from "../src/shield/proxy.mjs";
import {
  buildShieldChildEnv,
  createShieldDestinationLease,
  ensureShieldReady,
  registerShieldApprovalChannel,
  registerShieldImageOverride,
  renewShieldDestinationLease,
  revokeShieldDestinationLease,
  transitionShieldPolicy,
  unregisterShieldApprovalChannel,
  unregisterShieldImageOverride,
} from "../src/shield/service.mjs";

// Phase 5 Stage A: the daemon accepts both the AirKit-era and the ccshield
// wire names; a client sends the new ones only to a daemon that publishes
// identity.wire >= 2. Every old-name case here must keep passing until Stage C.
const CAPABILITY = "c".repeat(32);
const CONTROL = "d".repeat(32);
const LAUNCH = "1".repeat(32);
const OLD = { capability: "x-airkit-shield", launch: "x-airkit-shield-launch", control: "x-airkit-shield-control", prefix: "/_airkit/shield/" };
const NEW = { capability: "x-ccshield-capability", launch: "x-ccshield-launch", control: "x-ccshield-control", prefix: "/_ccshield/" };
const SHIELD_HEADER = /^x-(?:airkit-shield|ccshield)(?:-|$)/i;
const policyState = { version: "2026.09.02.1", detectorVersions: { gitleaks: "8.24.0", privacy: "privacy-1" } };

async function startUpstream(t) {
  const requests = [];
  const server = createServer((request, response) => {
    request.resume();
    requests.push({ url: request.url, headers: request.headers });
    response.writeHead(200, { "content-type": "application/json", "x-ccshield-capability": "echoed", "x-airkit-shield": "echoed" });
    response.end("{}");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return { origin: `http://127.0.0.1:${server.address().port}`, requests };
}

async function startShield(t, options = {}) {
  const shield = await startShieldProxy({
    capability: CAPABILITY,
    controlCapability: CONTROL,
    recordShieldDecision: async () => {},
    ...options,
  });
  t.after(() => shield.close());
  return shield;
}

const allow = async () => ({ action: "allow", reasonCodes: ["allow"], lane: "subscription", destinationClass: "subscription" });

test("control routes accept both path prefixes and both control header names", async (t) => {
  const upstream = await startUpstream(t);
  const shield = await startShield(t, { targetOrigin: upstream.origin, allowDestinationLeases: true, decide: allow });
  const send = (path, method, headers = {}, body) => fetch(`${shield.origin}${path}`, { method, headers: { "content-type": "application/json", ...headers }, body });
  for (const names of [OLD, NEW]) {
    for (const control of [OLD.control, NEW.control]) {
      const auth = { [control]: CONTROL };
      const label = `${names.prefix} with ${control}`;
      assert.equal((await send(`${names.prefix}diagnostics`, "GET", auth)).status, 200, label);
      assert.equal((await send(`${names.prefix}image-override`, "POST", auth, JSON.stringify({ launchId: LAUNCH }))).status, 204, label);
      assert.equal((await send(`${names.prefix}image-override`, "DELETE", auth, JSON.stringify({ launchId: LAUNCH }))).status, 204, label);
      // An authorised but malformed lease or channel is refused (403), never unauthorised (401).
      assert.equal((await send(`${names.prefix}destination-lease`, "POST", auth, "{}")).status, 403, label);
      assert.equal((await send(`${names.prefix}approval-channel`, "DELETE", auth, "{}")).status, 403, label);
    }
    for (const path of ["diagnostics", "image-override", "destination-lease", "approval-channel"]) {
      const method = path === "diagnostics" ? "GET" : "DELETE";
      const body = method === "GET" ? undefined : JSON.stringify({ launchId: LAUNCH });
      assert.equal((await send(`${names.prefix}${path}`, method, {}, body)).status, 401, `${names.prefix}${path} without a control header`);
    }
    for (const capability of [OLD.capability, NEW.capability]) {
      assert.equal((await send(`${names.prefix}ready`, "GET", { [capability]: CAPABILITY })).status, 204, `${names.prefix}ready with ${capability}`);
    }
    assert.equal((await send(`${names.prefix}ready`, "GET")).status, 401);
  }
  assert.equal(upstream.requests.length, 0, "no control route reaches upstream");
});

test("both capability header names authorise /v1/messages and neither reaches upstream", async (t) => {
  const upstream = await startUpstream(t);
  const shield = await startShield(t, { targetOrigin: upstream.origin, decide: allow });
  for (const names of [OLD, NEW]) {
    const response = await fetch(`${shield.origin}/v1/messages`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        [names.capability]: CAPABILITY,
        [names.launch]: LAUNCH,
        "x-ccshield-future": "1",
        "x-airkit-mode": "glm",
        "x-tenant": "fixture",
      },
      body: "{}",
    });
    assert.equal(response.status, 200, names.capability);
    assert.equal([...response.headers.keys()].some((name) => SHIELD_HEADER.test(name)), false, "upstream shield headers never reach the client");
  }
  assert.equal(upstream.requests.length, 2);
  for (const { headers } of upstream.requests) {
    assert.deepEqual(Object.keys(headers).filter((name) => SHIELD_HEADER.test(name)), []);
    assert.equal(headers["x-airkit-mode"], "glm", "the AirKit mode header is not a shield header");
    assert.equal(headers["x-tenant"], "fixture");
  }
  const missing = await fetch(`${shield.origin}/v1/messages`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  assert.equal(missing.status, 401);
  const conflict = await fetch(`${shield.origin}/v1/messages`, {
    method: "POST",
    headers: { "content-type": "application/json", [OLD.capability]: CAPABILITY, [NEW.capability]: "other-spelling" },
    body: "{}",
  });
  assert.equal(conflict.status, 401, "two spellings with different values are rejected");
  assert.equal(upstream.requests.length, 2);
});

test("the new launch header selects the per-launch image override", async (t) => {
  const upstream = await startUpstream(t);
  const seen = [];
  const shield = await startShield(t, { targetOrigin: upstream.origin, decide: async (input) => { seen.push(input.allowUnscannedImages); return allow(); } });
  const override = await fetch(`${shield.origin}${NEW.prefix}image-override`, { method: "POST", headers: { [NEW.control]: CONTROL }, body: JSON.stringify({ launchId: LAUNCH }) });
  assert.equal(override.status, 204);
  for (const names of [NEW, OLD]) {
    const response = await fetch(`${shield.origin}/v1/messages`, { method: "POST", headers: { [names.capability]: CAPABILITY, [names.launch]: LAUNCH }, body: "{}" });
    assert.equal(response.status, 200);
  }
  assert.deepEqual(seen, [true, true]);
});

test("the child env carries new names only for a wire-2 daemon and scrubs both spellings", () => {
  const ready = { origin: "http://127.0.0.1:8811", capability: CAPABILITY, lane: "subscription", targetClass: "subscription" };
  const inherited = [
    "x-tenant: fixture",
    "X-AirKit-Shield: stale",
    "x-airkit-shield-launch: ffffffffffffffffffffffffffffffff",
    "x-ccshield-capability: stale",
    "x-ccshield-launch: eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "x-airkit-mode: glm",
  ].join("\n");
  const env = { ANTHROPIC_CUSTOM_HEADERS: inherited };
  assert.equal(
    buildShieldChildEnv({ ...ready, wire: 2 }, env, LAUNCH).ANTHROPIC_CUSTOM_HEADERS,
    `x-tenant: fixture\nx-airkit-mode: glm\nx-ccshield-capability: ${CAPABILITY}\nx-ccshield-launch: ${LAUNCH}`,
  );
  for (const legacy of [ready, { ...ready, wire: 1 }]) {
    assert.equal(
      buildShieldChildEnv(legacy, env, LAUNCH).ANTHROPIC_CUSTOM_HEADERS,
      `x-tenant: fixture\nx-airkit-mode: glm\nx-airkit-shield: ${CAPABILITY}\nx-airkit-shield-launch: ${LAUNCH}`,
    );
  }
});

test("control calls use the daemon's own wire names", async (t) => {
  const homeDir = await mkdtemp(join(tmpdir(), "ccshield-wire-"));
  t.after(() => rm(homeDir, { recursive: true, force: true }));
  const paths = shieldPaths({ homeDir, uid: process.getuid?.() ?? 501, platform: "darwin" });
  await writeShieldConfig({ paths, config: { capability: CAPABILITY, controlCapability: CONTROL, targetOrigin: "https://api.anthropic.com", lane: "subscription", generation: "generation-1" } });
  for (const [wire, names] of [[undefined, OLD], [1, OLD], [2, NEW]]) {
    const calls = [];
    const fetchImpl = async (url, init) => { calls.push({ url, headers: init.headers }); return { status: 204 }; };
    const ready = { origin: "http://127.0.0.1:8811", capability: CAPABILITY, lane: "subscription", targetClass: "subscription", ...(wire === undefined ? {} : { wire }) };
    const common = { ready, paths, fetchImpl };
    await registerShieldApprovalChannel({ ...common, channel: { kind: "socket", path: "/tmp/channel.sock" }, launchId: LAUNCH }).catch(() => {});
    await unregisterShieldApprovalChannel({ ...common, launchId: LAUNCH });
    await registerShieldImageOverride({ ...common, launchId: LAUNCH });
    await unregisterShieldImageOverride({ ...common, launchId: LAUNCH });
    const leased = await createShieldDestinationLease({ ...common, targetOrigin: "https://api.anthropic.com" });
    assert.equal(leased.wire, wire, "a lease keeps the daemon's wire version");
    await renewShieldDestinationLease({ ...common, targetOrigin: "https://api.anthropic.com" });
    await revokeShieldDestinationLease(common);
    assert.ok(calls.length >= 6, `wire ${wire}`);
    for (const call of calls) {
      assert.ok(call.url.startsWith(`${ready.origin}${names.prefix}`), `${call.url} for wire ${wire}`);
      assert.deepEqual(Object.keys(call.headers).filter((name) => SHIELD_HEADER.test(name)), [names.control]);
    }
  }
});

async function readyFixture(t, identityExtra) {
  const homeDir = await mkdtemp(join(tmpdir(), "ccshield-wire-ready-"));
  t.after(() => rm(homeDir, { recursive: true, force: true }));
  const paths = shieldPaths({ homeDir, uid: process.getuid?.() ?? 501, platform: "darwin" });
  await writeShieldConfig({ paths, config: { capability: CAPABILITY, controlCapability: CONTROL, targetOrigin: "https://api.anthropic.com", lane: "subscription", generation: "generation-1" } });
  await writeShieldPolicyState({ paths, state: policyState });
  await writeShieldIdentity({ paths, identity: {
    origin: "http://127.0.0.1:8811", capability: CAPABILITY, version: 1, pid: 42, lane: "subscription", generation: "generation-1",
    targetClass: "subscription", policyVersion: policyState.version, detectorVersions: policyState.detectorVersions, ...identityExtra,
  } });
  return paths;
}

test("readiness carries the identity's wire version to the probe and the launcher", async (t) => {
  for (const [extra, wire] of [[{}, undefined], [{ wire: 2 }, 2]]) {
    const paths = await readyFixture(t, extra);
    const probes = [];
    const ready = await ensureShieldReady({
      lane: "subscription",
      paths,
      inspectService: async () => ({ loaded: true, active: true, pid: 42 }),
      isProcessAlive: async () => true,
      probeShield: async (...args) => { probes.push(args); return true; },
    });
    assert.equal(ready.wire, wire);
    assert.deepEqual(probes, [["http://127.0.0.1:8811", CAPABILITY, wire]]);
  }
});

test("a policy transition probes the previous daemon with that daemon's names", async (t) => {
  const paths = await readyFixture(t, {});
  const probes = [];
  await assert.rejects(transitionShieldPolicy({
    paths,
    installPolicy: async () => { throw new Error("stop after the quiesce probe"); },
    inspectService: async () => ({ loaded: false, active: false, pid: null }),
    isProcessAlive: async () => false,
    probeShield: async (...args) => { probes.push(args); return false; },
  }), /stop after the quiesce probe/);
  assert.deepEqual(probes, [["http://127.0.0.1:8811", CAPABILITY, undefined]]);
});

test("identity keeps a valid wire version and rejects a malformed one", () => {
  const identity = {
    origin: "http://127.0.0.1:8811", capability: CAPABILITY, version: 1, pid: 42, lane: "subscription", generation: "generation-1",
    targetClass: "subscription", policyVersion: policyState.version, detectorVersions: policyState.detectorVersions,
  };
  assert.equal(Object.hasOwn(assertShieldIdentity(identity), "wire"), false);
  assert.equal(assertShieldIdentity({ ...identity, wire: 2 }).wire, 2);
  for (const wire of [0, -1, 1.5, "2", null]) {
    assert.throws(() => assertShieldIdentity({ ...identity, wire }), /wire/, String(wire));
  }
});

test("the session check accepts either capability header name", () => {
  const base = "http://127.0.0.1:48211";
  for (const header of ["x-airkit-shield: cap", "x-ccshield-capability: cap"]) {
    assert.deepEqual(shieldSessionCheck({ ANTHROPIC_BASE_URL: base, ANTHROPIC_CUSTOM_HEADERS: `x-other: 1\n${header}` }), { behind: true }, header);
  }
  for (const header of ["x-ccshield-capability:   ", "x-ccshield-launch: 1", "x-airkit-shield-launch: 1"]) {
    assert.equal(shieldSessionCheck({ ANTHROPIC_BASE_URL: base, ANTHROPIC_CUSTOM_HEADERS: header }).behind, false, header);
  }
});

test("CLI picks wire names from the daemon identity", async () => {
  const { shieldWireNames } = await import("../src/shield/service.mjs");
  assert.equal(shieldWireNames({}).capability, "x-airkit-shield");
  assert.equal(shieldWireNames({ wire: 1 }).prefix, "/_airkit/shield/");
  assert.deepEqual(shieldWireNames({ wire: 2 }), { capability: "x-ccshield-capability", control: "x-ccshield-control", launch: "x-ccshield-launch", prefix: "/_ccshield/" });
});

test("identity keeps wire and rejects a bad one", async () => {
  const { assertShieldIdentity } = await import("../src/shield/paths.mjs");
  const base = { origin: "http://127.0.0.1:4000", capability: "c".repeat(32), version: 1, pid: 1, lane: "managed", targetClass: "managed", generation: "g", policyVersion: policyState.version, detectorVersions: policyState.detectorVersions };
  for (const wire of [0, "2", 1.5]) {
    assert.throws(() => assertShieldIdentity({ ...base, wire }), /wire/);
  }
});
