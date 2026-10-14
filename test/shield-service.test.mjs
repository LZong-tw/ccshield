import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { runShieldCli } from "../src/shield/cli.mjs";
import {
  ensureShieldReady,
  inspectShieldService,
  installShieldService,
  launchShieldChild,
  planShieldService,
  readShieldConfig,
  startShieldService,
  stopShieldService,
  uninstallShieldService,
  transitionShieldPolicy,
} from "../src/shield/service.mjs";
import { invalidateShieldPolicyBinding, shieldPaths, writeShieldConfig, writeShieldIdentity, writeShieldPolicyState } from "../src/shield/paths.mjs";
import { startShieldProxy } from "../src/shield/proxy.mjs";
import { installShieldPolicyProvision } from "../src/shield/policy-bundle.mjs";

const capability = "c".repeat(32);
const generation = "generation-1";
const policyState = { version: "2026.09.02.1", detectorVersions: { gitleaks: "8.24.0", privacy: "privacy-1" } };

function fixture(homeDir = "/tmp/ccshield-service-home") {
  const paths = shieldPaths({ homeDir, uid: 501 });
  return {
    paths,
    options: {
      paths,
      nodePath: "/opt/node/bin/node",
      daemonPath: "/opt/ccshield/src/shieldd.mjs",
    },
  };
}

function capture() {
  let value = "";
  return { stdout: { write(chunk) { value += String(chunk); } }, value: () => value };
}

test("shield install previews without launchctl mutation", async () => {
  const { options } = fixture();
  const calls = [];
  const io = new Proxy({}, { get: () => async (...args) => calls.push(args) });
  const plan = await installShieldService({ ...options, io, runLaunchctl: async (args) => calls.push(args) });

  assert.equal(plan.label, "com.ccshield.subscription");
  assert.deepEqual(calls, []);
  assert.match(plan.plistXml, /<string>com\.ccshield\.subscription<\/string>/);
  assert.deepEqual(plan.plist.ProgramArguments, [options.nodePath, options.daemonPath, "--config", options.paths.configPath]);
  assert.deepEqual(Object.keys(plan.plist.EnvironmentVariables), []);
  assert.equal(plan.plist.ProcessType, "Standard");
  assert.match(plan.plistXml, /<key>ProcessType<\/key>\s*<string>Standard<\/string>/);
});

test("shield privacy provision is preview-first and keeps asset references out of CLI output", async () => {
  const output = capture();
  const calls = [];
  const code = await runShieldCli(["privacy", "provision", "--bundle", "/private/privacy.json", "--gitleaks", "/private/gitleaks", "--gitleaks-rules", "/private/rules.toml"], {
    stdout: output.stdout,
    shield: {
      async privacyProvision(request) { calls.push(request); return { state: "preview", write: request.write }; },
    },
  });
  assert.equal(code, 0);
  assert.deepEqual(calls, [{ bundlePath: "/private/privacy.json", gitleaksPath: "/private/gitleaks", gitleaksRulesPath: "/private/rules.toml", lane: "subscription", write: false }]);
  await assert.rejects(
    runShieldCli(["privacy", "provision", "--bundle", "/private/privacy.json", "--gitleaks", "/private/gitleaks"], { stdout: capture().stdout, shield: {} }),
    /usage: ccshield privacy provision/i,
  );
  assert.match(output.value(), /privacy/);
  assert.doesNotMatch(output.value(), /private/);
});

test("clean-lane privacy preview accepts its explicit policy bundle without persisted policy state", async () => {
  const calls = [];
  await runShieldCli([
    "privacy", "provision", "--lane", "managed",
    "--policy-bundle", "/private/policy.json",
    "--bundle", "/private/privacy.json", "--gitleaks", "/private/gitleaks", "--gitleaks-rules", "/private/rules.toml",
  ], {
    stdout: capture().stdout,
    shield: { async privacyProvision(request) { calls.push(request); return { state: "preview" }; } },
  });
  assert.deepEqual(calls, [{
    lane: "managed", write: false, policyBundlePath: "/private/policy.json",
    bundlePath: "/private/privacy.json", gitleaksPath: "/private/gitleaks", gitleaksRulesPath: "/private/rules.toml",
  }]);
});

test("shield policy install is preview-first and hides source paths", async () => {
  const output = capture();
  const calls = [];
  const code = await runShieldCli(["policy", "install", "--bundle", "/private/policy.bundle", "--public-key", "/private/policy.pub"], {
    stdout: output.stdout,
    shield: { async policyInstall(request) { calls.push(request); return { state: "preview", version: "2026.09.02.9" }; } },
  });
  assert.equal(code, 0);
  assert.deepEqual(calls, [{ bundlePath: "/private/policy.bundle", publicKeyPath: "/private/policy.pub", lane: "subscription", write: false }]);
  assert.match(output.value(), /2026\.09\.02\.9/);
  assert.doesNotMatch(output.value(), /private/);
});

test("shield policy status renders only active metadata", async () => {
  const output = capture();
  const code = await runShieldCli(["policy", "status"], {
    stdout: output.stdout,
    shield: { async policyStatus() { return { state: "healthy", version: "2026.09.02.9", detectorVersions: { gitleaks: "8.24.0", privacy: "privacy-1" } }; } },
  });
  assert.equal(code, 0);
  assert.match(output.value(), /2026\.09\.02\.9/);
  assert.doesNotMatch(output.value(), /private|path|origin|capability/i);
});

test("shield install writes a private plist only with --write semantics", async () => {
  const homeDir = await mkdtemp(join(tmpdir(), "ccshield-service-"));
  const { options, paths } = fixture(homeDir);
  const calls = [];
  try {
    await installShieldService({ ...options, write: true, runLaunchctl: async (args) => { calls.push(args); return { ok: true }; } });
    assert.equal((await stat(paths.launchAgentPath)).mode & 0o777, 0o600);
    assert.equal(await stat(paths.configPath).then(() => true, () => false), true);
    assert.equal((await stat(paths.configPath)).mode & 0o777, 0o600);
    const config = JSON.parse(await readFile(paths.configPath, "utf8"));
    assert.deepEqual(config, {
      capability: config.capability,
      controlCapability: config.controlCapability,
      targetOrigin: "https://api.anthropic.com",
      lane: "subscription",
      generation: config.generation,
      targetClass: "subscription",
    });
    assert.deepEqual(await readShieldConfig({ paths }), config);
    assert.match(await readFile(paths.launchAgentPath, "utf8"), /<string>--config<\/string>/);
    assert.deepEqual(calls, [
      ["bootstrap", paths.launchdDomain, paths.launchAgentPath],
      ["kickstart", "-k", paths.launchdTarget],
    ]);
  } finally {
    await rm(homeDir, { recursive: true, force: true });
  }
});

test("shield start tolerates a service install already bootstrapped but still requires a live kickstart", async () => {
  const homeDir = await mkdtemp(join(tmpdir(), "ccshield-restart-"));
  const { options, paths } = fixture(homeDir);
  try {
    await installShieldService({ ...options, write: true, runLaunchctl: async () => ({ ok: true }) });
    const alreadyLoaded = { ok: false, status: 5, stdout: "", stderr: "Bootstrap failed: 5: Input/output error\n" };
    const calls = [];
    await startShieldService({
      ...options,
      runLaunchctl: async (args) => { calls.push(args[0]); return args[0] === "bootstrap" ? alreadyLoaded : { ok: true }; },
    });
    assert.deepEqual(calls, ["bootstrap", "kickstart"]);
    await assert.rejects(
      startShieldService({ ...options, runLaunchctl: async () => alreadyLoaded }),
      /launchctl kickstart failed/i,
    );
    assert.ok(paths.launchAgentPath);
  } finally {
    await rm(homeDir, { recursive: true, force: true });
  }
});

test("shield start refuses an uninstalled service without provisioning state", async () => {
  const { options } = fixture();
  const calls = [];
  const missing = Object.assign(new Error("missing"), { code: "ENOENT" });
  await assert.rejects(
    startShieldService({
      ...options,
      io: {
        async readFile() { throw missing; },
        async mkdir(...args) { calls.push(["mkdir", ...args]); },
        async writeFile(...args) { calls.push(["writeFile", ...args]); },
        async chmod(...args) { calls.push(["chmod", ...args]); },
        async rename(...args) { calls.push(["rename", ...args]); },
      },
      runLaunchctl: async (args) => { calls.push(["launchctl", ...args]); return { ok: true }; },
    }),
    /shield install --write/i,
  );
  assert.equal(calls.length, 0);
});

test("stale identity blocks shield launch", async () => {
  const homeDir = await mkdtemp(join(tmpdir(), "ccshield-ready-"));
  const { paths } = fixture(homeDir);
  try {
    await writeShieldIdentity({
      paths,
      identity: { origin: "http://127.0.0.1:8811", capability, version: 1, pid: 42, lane: "subscription", generation, targetClass: "subscription", policyVersion: policyState.version, detectorVersions: policyState.detectorVersions },
    });
    await assert.rejects(
      ensureShieldReady({ lane: "subscription", paths, isProcessAlive: async () => false }),
      /shield identity is stale/i,
    );
  } finally {
    await rm(homeDir, { recursive: true, force: true });
  }
});

test("launchd inspection reports only a running service PID as active", async () => {
  const { paths } = fixture();
  const service = await inspectShieldService({
    paths,
    io: { async readFile() { return "plist"; } },
    runLaunchctl: async () => ({ ok: true, stdout: "state = running\npid = 4242\n" }),
  });

  assert.equal(service.loaded, true);
  assert.equal(service.active, true);
  assert.equal(service.pid, 4242);
});

test("lane and configuration generation mismatches reject readiness before probing", async () => {
  const { paths } = fixture();
  const probes = [];
  const identity = {
    origin: "http://127.0.0.1:8811",
    capability,
    version: 1,
    pid: 42,
    lane: "subscription",
    generation,
    targetClass: "subscription",
    policyVersion: policyState.version,
    detectorVersions: policyState.detectorVersions,
  };
  const io = shieldStateIo(paths, {
    identity,
    config: { capability, targetOrigin: "https://api.anthropic.com", lane: "subscription", generation },
  });
  const options = {
    paths,
    io,
    inspectService: async () => ({ loaded: true, active: true, pid: 42 }),
    isProcessAlive: async () => true,
    probeShield: async (...args) => probes.push(args),
  };

  await assert.rejects(ensureShieldReady({ ...options, lane: "managed" }), /lane mismatch/i);
  await assert.rejects(
    ensureShieldReady({ ...options, lane: "subscription", io: shieldStateIo(paths, { identity: { ...identity, generation: "old-generation" }, config: { capability, targetOrigin: "https://api.anthropic.com", lane: "subscription", generation } }) }),
    /generation mismatch/i,
  );
  assert.deepEqual(probes, []);
});

test("readiness keeps subscription fixed and rejects persisted managed targets", async () => {
  const { paths } = fixture();
  const probes = [];
  const baseIdentity = {
    origin: "http://127.0.0.1:8811",
    capability,
    version: 1,
    pid: 42,
    generation,
    policyVersion: policyState.version,
    detectorVersions: policyState.detectorVersions,
  };
  const readyOptions = {
    paths,
    inspectService: async () => ({ loaded: true, active: true, pid: 42 }),
    isProcessAlive: async () => true,
    probeShield: async (...args) => probes.push(args),
  };

  await assert.rejects(
    ensureShieldReady({
      ...readyOptions,
      lane: "subscription",
      io: shieldStateIo(paths, {
        identity: { ...baseIdentity, lane: "subscription", targetClass: "subscription" },
        config: { capability, targetOrigin: "https://managed.example", lane: "subscription", generation },
      }),
    }),
    /shield target origin mismatch/,
  );
  await assert.rejects(
    ensureShieldReady({
      ...readyOptions,
      lane: "managed",
      io: shieldStateIo(paths, {
        identity: { ...baseIdentity, lane: "managed", targetClass: "managed" },
        config: { capability, targetOrigin: "http://127.0.0.1:3456", lane: "managed", generation },
      }),
    }),
    /managed configuration must not persist/,
  );
  assert.deepEqual(probes, []);
});

test("launchd PID mismatch and failed authenticated listener probe reject readiness", async () => {
  const { paths } = fixture();
  const identity = {
    origin: "http://127.0.0.1:8811",
    capability,
    version: 1,
    pid: 42,
    lane: "managed",
    generation,
    targetClass: "managed",
    policyVersion: policyState.version,
    detectorVersions: policyState.detectorVersions,
  };
  const io = shieldStateIo(paths, {
    identity,
    config: { capability, lane: "managed", generation },
  });

  await assert.rejects(
    ensureShieldReady({ lane: "managed", paths, io, inspectService: async () => ({ loaded: true, active: true, pid: 41 }), isProcessAlive: async () => true, probeShield: async () => true }),
    /PID mismatch/i,
  );
  await assert.rejects(
    ensureShieldReady({ lane: "managed", paths, io, inspectService: async () => ({ loaded: true, active: true, pid: 42 }), isProcessAlive: async () => true, probeShield: async () => false }),
    /listener.*readiness/i,
  );
});

test("readiness returns only after the active identity answers the capability probe", async () => {
  const { paths } = fixture();
  const identity = {
    origin: "http://127.0.0.1:8811",
    capability,
    version: 1,
    pid: 42,
    lane: "subscription",
    generation,
    targetClass: "subscription",
    policyVersion: policyState.version,
    detectorVersions: policyState.detectorVersions,
  };
  const probes = [];
  const ready = await ensureShieldReady({
    lane: "subscription",
    paths,
    io: shieldStateIo(paths, {
      identity,
      config: { capability, targetOrigin: "https://api.anthropic.com", lane: "subscription", generation },
    }),
    inspectService: async () => ({ loaded: true, active: true, pid: 42 }),
    isProcessAlive: async () => true,
    probeShield: async (origin, receivedCapability) => {
      probes.push({ origin, capability: receivedCapability });
      return true;
    },
  });

  assert.deepEqual(probes, [{ origin: identity.origin, capability }]);
  assert.deepEqual(ready, {
    origin: identity.origin,
    capability,
    lane: "subscription",
    targetClass: "subscription",
    policyVersion: policyState.version,
    detectorVersions: policyState.detectorVersions,
  });
});

test("readiness rejects a daemon identity bound to a stale policy transition before probing", async () => {
  const { paths } = fixture();
  const identity = {
    origin: "http://127.0.0.1:8811",
    capability,
    version: 1,
    pid: 42,
    lane: "subscription",
    generation,
    targetClass: "subscription",
    policyVersion: "2026.09.01.1",
    detectorVersions: policyState.detectorVersions,
  };
  let probes = 0;
  await assert.rejects(
    ensureShieldReady({
      lane: "subscription",
      paths,
      io: shieldStateIo(paths, { identity, config: { capability, targetOrigin: "https://api.anthropic.com", lane: "subscription", generation } }),
      inspectService: async () => ({ loaded: true, active: true, pid: 42 }),
      isProcessAlive: async () => true,
      probeShield: async () => { probes += 1; return true; },
    }),
    /policy version mismatch/i,
  );
  assert.equal(probes, 0);
});

test("policy install quiesces a live old daemon binding until a fresh policy identity is published", async (t) => {
  const homeDir = await mkdtemp(join(tmpdir(), "ccshield-policy-transition-"));
  t.after(() => rm(homeDir, { recursive: true, force: true }));
  const paths = shieldPaths({ homeDir, uid: process.getuid?.() ?? 501 });
  const oldIdentity = {
    origin: "http://127.0.0.1:8811", capability, version: 1, pid: 42,
    lane: "subscription", generation, targetClass: "subscription",
    policyVersion: "2026.09.01.1", detectorVersions: policyState.detectorVersions,
  };
  const newState = { version: "2026.09.02.2", detectorVersions: policyState.detectorVersions };
  await writeShieldConfig({ paths, config: { capability, controlCapability: "d".repeat(32), targetOrigin: "https://api.anthropic.com", lane: "subscription", generation } });
  await writeShieldIdentity({ paths, identity: oldIdentity });
  await writeShieldPolicyState({ paths, state: { version: oldIdentity.policyVersion, detectorVersions: oldIdentity.detectorVersions } });
  const sourceDir = join(homeDir, "policy-source");
  await mkdir(sourceDir, { mode: 0o700 });
  const bundlePath = join(sourceDir, "policy.json");
  const publicKeyPath = join(sourceDir, "policy.pub");
  await writeFile(bundlePath, JSON.stringify({ manifest: {}, signature: "aGVsbG8=", wasm: "d2FzbQ==" }), { mode: 0o600 });
  await writeFile(publicKeyPath, "fixture-public-key", { mode: 0o600 });
  await chmod(bundlePath, 0o600);
  await chmod(publicKeyPath, 0o600);

  await installShieldPolicyProvision({ bundlePath, publicKeyPath, write: true, paths, loadPolicy: async () => newState });

  let probes = 0;
  await assert.rejects(
    ensureShieldReady({
      lane: "subscription", paths,
      inspectService: async () => ({ loaded: true, active: true, pid: 42 }),
      isProcessAlive: async () => true,
      probeShield: async () => { probes += 1; return true; },
    }),
    /identity is stale/i,
  );
  assert.equal(probes, 0, "the old live daemon cannot authorize another managed launch");

  await writeShieldPolicyState({ paths, state: newState });
  await writeShieldIdentity({ paths, identity: { ...oldIdentity, policyVersion: newState.version } });
  const ready = await ensureShieldReady({
    lane: "subscription", paths,
    inspectService: async () => ({ loaded: true, active: true, pid: 42 }),
    isProcessAlive: async () => true,
    probeShield: async () => true,
  });
  assert.equal(ready.policyVersion, newState.version);
});

test("policy lifecycle transaction stops a live proxy before activating and binding a replacement", async (t) => {
  const homeDir = await mkdtemp(join(tmpdir(), "ccshield-policy-proxy-transition-"));
  t.after(() => rm(homeDir, { recursive: true, force: true }));
  const paths = shieldPaths({ homeDir, uid: process.getuid?.() ?? 501 });
  const controlCapability = "d".repeat(32);
  const oldPolicy = { version: "policy-old", detectorVersions: policyState.detectorVersions };
  const newPolicy = { version: "policy-new", detectorVersions: policyState.detectorVersions };
  let upstreamCalls = 0;
  const upstream = await startServer(async (_request, response) => { upstreamCalls += 1; response.end("ok"); });
  t.after(() => upstream.close());
  let oldProxy = await startShieldProxy({ capability, controlCapability, targetOrigin: upstream.origin, decide: async () => ({ action: "allow", reasonCodes: ["allow"], lane: "subscription", destinationClass: "subscription", bundleVersion: oldPolicy.version, detectorVersions: oldPolicy.detectorVersions }), recordShieldDecision: async () => {} });
  const oldIdentity = { origin: oldProxy.origin, capability, version: 1, pid: 777, lane: "subscription", generation, targetClass: "subscription", policyVersion: oldPolicy.version, detectorVersions: oldPolicy.detectorVersions };
  await writeShieldConfig({ paths, config: { capability, controlCapability, targetOrigin: "https://api.anthropic.com", lane: "subscription", generation } });
  await writeShieldIdentity({ paths, identity: oldIdentity });
  await writeShieldPolicyState({ paths, state: oldPolicy });
  assert.equal((await fetch(`${oldProxy.origin}/v1/messages`, { method: "POST", headers: { "x-airkit-shield": capability }, body: "{}" })).status, 200);
  let activePid = 777;
  let replacement = null;
  const transitions = [];
  const probe = async (origin, receivedCapability) => {
    try { return (await fetch(`${origin}/_airkit/shield/ready`, { headers: { "x-airkit-shield": receivedCapability } })).status === 204; } catch { return false; }
  };
  await transitionShieldPolicy({
    paths,
    installPolicy: async () => { await invalidateShieldPolicyBinding({ paths }); return newPolicy; },
    inspectService: async () => ({ loaded: true, active: activePid > 0, pid: activePid || null }),
    isProcessAlive: async (pid) => pid === activePid,
    probeShield: probe,
    stopService: async () => { await oldProxy.close(); activePid = 0; assert.equal(await probe(oldIdentity.origin, capability), false); },
    startService: async () => {
      replacement = await startShieldProxy({ capability, controlCapability, targetOrigin: upstream.origin, decide: async () => ({ action: "allow", reasonCodes: ["allow"], lane: "subscription", destinationClass: "subscription", bundleVersion: newPolicy.version, detectorVersions: newPolicy.detectorVersions }), recordShieldDecision: async () => {} });
      activePid = 778;
      await writeShieldPolicyState({ paths, state: newPolicy });
      await writeShieldIdentity({ paths, identity: { ...oldIdentity, origin: replacement.origin, pid: activePid, policyVersion: newPolicy.version } });
    },
    recordShieldPolicyTransition: async (transition) => { transitions.push(transition); return { durable: "ack" }; },
  });
  t.after(() => replacement?.close());
  assert.equal(upstreamCalls, 1, "the old proxy forwarded only before the transaction");
  assert.equal((await fetch(`${replacement.origin}/v1/messages`, { method: "POST", headers: { "x-airkit-shield": capability }, body: "{}" })).status, 200);
  assert.equal(upstreamCalls, 2);
  assert.equal(transitions.length, 1);
  assert.equal(transitions[0].action, "transition");
  assert.equal(transitions[0].bundleVersion, newPolicy.version);
});

test("policy lifecycle transaction rejects a launchd respawn before installing", async () => {
  const { paths } = fixture();
  const identity = { origin: "http://127.0.0.1:8811", capability, version: 1, pid: 42, lane: "subscription", generation, targetClass: "subscription", policyVersion: policyState.version, detectorVersions: policyState.detectorVersions };
  let inspections = 0;
  let installs = 0;
  await assert.rejects(transitionShieldPolicy({
    paths,
    io: shieldStateIo(paths, { identity, config: { capability, targetOrigin: "https://api.anthropic.com", lane: "subscription", generation } }),
    inspectService: async () => ++inspections === 1 ? { loaded: true, active: true, pid: 42 } : { loaded: true, active: true, pid: 43 },
    stopService: async () => {}, isProcessAlive: async () => false, probeShield: async () => false,
    installPolicy: async () => { installs += 1; return policyState; },
  }), /could not stop/i);
  assert.equal(installs, 0);
});

test("policy lifecycle transaction rejects an inactive service with a live old identity before install", async () => {
  const { paths } = fixture();
  const identity = { origin: "http://127.0.0.1:8811", capability, version: 1, pid: 42, lane: "subscription", generation, targetClass: "subscription", policyVersion: policyState.version, detectorVersions: policyState.detectorVersions };
  let installs = 0;
  await assert.rejects(transitionShieldPolicy({
    paths,
    io: shieldStateIo(paths, { identity, config: { capability, targetOrigin: "https://api.anthropic.com", lane: "subscription", generation } }),
    inspectService: async () => ({ loaded: true, active: false, pid: null }),
    isProcessAlive: async () => true, probeShield: async () => true,
    installPolicy: async () => { installs += 1; return policyState; },
  }), /live stale daemon/i);
  assert.equal(installs, 0);
});

test("policy lifecycle transaction rejects an inactive service when a dead PID still leaves its old proxy reachable", async () => {
  const { paths } = fixture();
  const identity = { origin: "http://127.0.0.1:8811", capability, version: 1, pid: 42, lane: "subscription", generation, targetClass: "subscription", policyVersion: policyState.version, detectorVersions: policyState.detectorVersions };
  let installs = 0;
  await assert.rejects(transitionShieldPolicy({
    paths,
    io: shieldStateIo(paths, { identity, config: { capability, targetOrigin: "https://api.anthropic.com", lane: "subscription", generation } }),
    inspectService: async () => ({ loaded: true, active: false, pid: null }),
    isProcessAlive: async () => false, probeShield: async () => true,
    installPolicy: async () => { installs += 1; return policyState; },
  }), /proxy remains reachable/i);
  assert.equal(installs, 0);
});

test("offline policy transition durably records its replacement before returning", async () => {
  const { paths } = fixture();
  const recorded = [];
  const installed = { version: "2026.09.03.1", detectorVersions: policyState.detectorVersions };
  const result = await transitionShieldPolicy({
    paths,
    io: { readFile: async () => { throw Object.assign(new Error("ENOENT"), { code: "ENOENT" }); } },
    installPolicy: async () => installed,
    inspectService: async () => ({ active: false }),
    isProcessAlive: async () => { throw new Error("offline transition must not probe a process"); },
    probeShield: async () => { throw new Error("offline transition must not probe a proxy"); },
    startService: async () => { throw new Error("offline transition must not start the daemon"); },
    ensureReady: async () => { throw new Error("offline transition must not bind a daemon"); },
    recordShieldPolicyTransition: async (event) => { recorded.push(event); return { durable: "ack" }; },
  });
  assert.equal(result, installed);
  assert.deepEqual(recorded, [{
    requestId: recorded[0].requestId,
    lane: "subscription", destinationClass: "subscription", bundleVersion: "2026.09.03.1",
    detectorVersions: policyState.detectorVersions, action: "transition", reasonCodes: ["policy_replaced"],
    transformCount: 0, override: false, elapsedMs: 0,
  }]);
  assert.match(recorded[0].requestId, /^policy-[0-9a-f]{32}$/);
});

test("offline policy transition fails closed when the durable recorder rejects", async () => {
  const { paths } = fixture();
  await assert.rejects(transitionShieldPolicy({
    paths,
    io: { readFile: async () => { throw Object.assign(new Error("ENOENT"), { code: "ENOENT" }); } },
    installPolicy: async () => ({ version: "2026.09.03.1", detectorVersions: policyState.detectorVersions }),
    inspectService: async () => ({ active: false }),
    recordShieldPolicyTransition: async () => { throw new Error("audit spool is unavailable"); },
  }), /audit spool is unavailable/);
});

test("policy install --write reaches the durable recorder on an inactive lane", async () => {
  const home = await mkdtemp(join(tmpdir(), "ccshield-offline-policy-"));
  const recorded = [];
  try {
    const code = await runShieldCli(["policy", "install", "--bundle", "/tmp/p", "--public-key", "/tmp/k", "--write"], {
      env: { HOME: home },
      stdout: capture().stdout,
      runLaunchctl: async () => ({ ok: false, stdout: "", stderr: "could not find service" }),
      installShieldPolicyProvision: async () => ({ version: "2026.09.03.1", detectorVersions: policyState.detectorVersions }),
      createDecisionRecorder: async () => ({
        recordShieldPolicyTransition: async (event) => { recorded.push(event); return { durable: "ack" }; },
      }),
    });
    assert.equal(code, 1);
    assert.equal(recorded.length, 1);
    assert.equal(recorded[0].action, "transition");
    assert.equal(recorded[0].lane, "subscription");
    assert.equal(recorded[0].destinationClass, "subscription");
    assert.deepEqual(recorded[0].reasonCodes, ["policy_replaced"]);
  } finally { await rm(home, { recursive: true, force: true }); }
});

test("policy install --write refuses to replace policy without a durable recorder", async () => {
  const home = await mkdtemp(join(tmpdir(), "ccshield-offline-policy-norecorder-"));
  let installs = 0;
  try {
    await assert.rejects(runShieldCli(["policy", "install", "--bundle", "/tmp/p", "--public-key", "/tmp/k", "--write"], {
      env: { HOME: home },
      stdout: capture().stdout,
      runLaunchctl: async () => ({ ok: false, stdout: "", stderr: "could not find service" }),
      installShieldPolicyProvision: async ({ write }) => { if (write) installs += 1; return { version: "v", detectorVersions: {} }; },
      createDecisionRecorder: async () => ({}),
    }), /audit recorder is unavailable/);
    assert.equal(installs, 0);
  } finally { await rm(home, { recursive: true, force: true }); }
});

test("readiness rejects an incomplete detector binding before probing", async () => {
  const { paths } = fixture();
  const identity = {
    origin: "http://127.0.0.1:8811", capability, version: 1, pid: 42,
    lane: "subscription", generation, targetClass: "subscription",
    policyVersion: policyState.version, detectorVersions: { gitleaks: "8.24.0" },
  };
  let probes = 0;
  await assert.rejects(
    ensureShieldReady({
      lane: "subscription", paths,
      io: shieldStateIo(paths, { identity, config: { capability, targetOrigin: "https://api.anthropic.com", lane: "subscription", generation }, state: { version: policyState.version, detectorVersions: { gitleaks: "8.24.0" } } }),
      inspectService: async () => ({ loaded: true, active: true, pid: 42 }),
      isProcessAlive: async () => true,
      probeShield: async () => { probes += 1; return true; },
    }),
    /detector.*privacy/i,
  );
  assert.equal(probes, 0);
});

test("start refuses launchd plist path drift before mutating the job", async () => {
  const { options } = fixture();
  const calls = [];
  await assert.rejects(
    startShieldService({
      ...options,
      io: { async readFile() { return "different plist"; } },
      runLaunchctl: async (args) => calls.push(args),
    }),
    /shield launch plist path drift/i,
  );
  assert.equal(calls.length, 0);
});

test("shield stop only unloads its own job and preserves shield state", async () => {
  const { paths } = fixture();
  const calls = [];
  const result = await stopShieldService({ paths, runLaunchctl: async (args) => { calls.push(args); return { ok: true }; } });
  assert.equal(result.stopped, true);
  assert.deepEqual(calls, [["bootout", paths.launchdTarget]]);
});

test("shield uninstall previews, then removes only its own LaunchAgent and keeps lane state", async () => {
  const { paths } = fixture();
  const plist = renderedPlist(paths.serviceLabel);
  const calls = [];
  const unlinked = [];
  const io = {
    async lstat(path) { assert.equal(path, paths.launchAgentPath); return { isFile: () => true, uid: 501 }; },
    async readFile() { return plist; },
    async unlink(path) { unlinked.push(path); },
  };
  const runLaunchctl = async (args) => { calls.push(args); return { ok: true }; };
  const preview = await uninstallShieldService({ paths, io, runLaunchctl, uid: 501 });
  assert.deepEqual({ installed: preview.installed, removed: preview.removed }, { installed: true, removed: false });
  assert.deepEqual(preview.operations.map((entry) => entry.op), ["bootout", "unlink"]);
  assert.deepEqual([calls, unlinked], [[], []]);
  const result = await uninstallShieldService({ paths, io, runLaunchctl, uid: 501, write: true });
  assert.equal(result.removed, true);
  assert.deepEqual(calls, [["bootout", paths.launchdTarget]]);
  assert.deepEqual(unlinked, [paths.launchAgentPath]);
});

test("shield uninstall is a no-op when absent and refuses plists it does not own", async () => {
  const { paths } = fixture();
  const calls = [];
  const runLaunchctl = async (args) => { calls.push(args); return { ok: true }; };
  const unlink = async () => { throw new Error("must not unlink"); };
  const missing = { async lstat() { throw Object.assign(new Error("missing"), { code: "ENOENT" }); }, unlink };
  assert.equal((await uninstallShieldService({ paths, runLaunchctl, uid: 501, io: missing })).installed, false);
  assert.deepEqual(calls, [], "preview never unloads");
  const absent = await uninstallShieldService({ paths, runLaunchctl, write: true, uid: 501, io: missing });
  assert.deepEqual({ installed: absent.installed, removed: absent.removed }, { installed: false, removed: false });
  assert.deepEqual(calls.splice(0), [["bootout", paths.launchdTarget]], "a hand-deleted plist can leave its job loaded");
  const owned = { async lstat() { return { isFile: () => true, uid: 501 }; }, async readFile() { return renderedPlist(paths.serviceLabel); }, unlink };
  await assert.rejects(uninstallShieldService({ paths, runLaunchctl, write: true, uid: 502, io: owned }), /is not this user's gui\/502/);
  await assert.rejects(uninstallShieldService({ paths, write: true, uid: 501, io: owned,
    runLaunchctl: async () => ({ ok: false, stderr: "Boot-out failed: 1: Operation not permitted" }) }), /launchctl bootout failed: Boot-out failed: 1: Operation not permitted/,
    "an untolerated bootout failure keeps the plist so a rerun can finish");
  for (const [stat, plist, pattern] of [
    [{ isFile: () => false, uid: 501 }, renderedPlist(paths.serviceLabel), /not a regular file/],
    [{ isFile: () => true, uid: 0 }, renderedPlist(paths.serviceLabel), /not a regular file owned by this user/],
    [{ isFile: () => true, uid: 501 }, renderedPlist("com.example.other"), /does not belong/],
    [{ isFile: () => true, uid: 501 }, "not a plist", /does not belong/],
  ]) {
    await assert.rejects(uninstallShieldService({ paths, runLaunchctl, write: true, uid: 501,
      io: { async lstat() { return stat; }, async readFile() { return plist; }, unlink } }), pattern);
  }
  assert.deepEqual(calls, []);
});

function renderedPlist(label) {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n  <key>Label</key>\n  <string>${label}</string>\n</dict>\n</plist>\n`;
}

test("AirKit keeps capability out of argv and injects Claude's Shield transport environment", async () => {
  const calls = [];
  const child = new EventEmitter();
  const outcome = launchShieldChild({
    command: "/usr/bin/env",
    args: ["true"],
    ready: { origin: "http://127.0.0.1:8811", capability, lane: "subscription", targetClass: "subscription" },
    env: {
      ANTHROPIC_API_BASE_URL: "https://stale-provider.invalid",
      ANTHROPIC_BASE_URL: "https://stale-provider.invalid",
      CLAUDE_AGENT_API_BASE_URL: "https://stale-provider.invalid",
      ANTHROPIC_CUSTOM_HEADERS: "x-tenant: fixture\nX-AirKit-Shield: stale-capability",
      CLAUDE_CODE_OAUTH_TOKEN: "subscription-oauth-sentinel",
      PATH: "/usr/bin",
    },
    spawnChild(command, args, options) {
      calls.push({ command, args, options });
      queueMicrotask(() => child.emit("close", 0, null));
      return child;
    },
  });
  assert.deepEqual(await outcome, { code: 0, signal: null });
  assert.deepEqual(calls[0].args, ["true"]);
  assert.equal(calls[0].options.env.ANTHROPIC_API_BASE_URL, "http://127.0.0.1:8811");
  assert.equal(calls[0].options.env.ANTHROPIC_BASE_URL, "http://127.0.0.1:8811");
  assert.equal(calls[0].options.env.CLAUDE_AGENT_API_BASE_URL, "http://127.0.0.1:8811");
  assert.equal(
    calls[0].options.env.ANTHROPIC_CUSTOM_HEADERS,
    `x-tenant: fixture\nx-airkit-shield: ${capability}`,
  );
  assert.equal(calls[0].options.env.AIRKIT_SHIELD_CAPABILITY, undefined);
  assert.equal(calls[0].options.env.CLAUDE_CODE_OAUTH_TOKEN, "subscription-oauth-sentinel");
  assert.equal(calls[0].args.includes(capability), false);
  assert.equal(calls[0].options.stdio, "inherit");
});

test("Shield child refuses Claude settings that redirect around its transport", async () => {
  let spawned = false;
  await assert.rejects(
    launchShieldChild({
      command: "/usr/bin/env",
      args: ["--settings", '{"env":{"CLAUDE_AGENT_API_BASE_URL":"http://127.0.0.1:4599"}}'],
      ready: { origin: "http://127.0.0.1:8811", capability, lane: "subscription", targetClass: "subscription" },
      spawnChild() { spawned = true; },
    }),
    /Shield launch settings cannot override.*CLAUDE_AGENT_API_BASE_URL/i,
  );
  assert.equal(spawned, false);
});

test("Shield child refuses persisted Claude settings that redirect around its transport", async () => {
  const home = await mkdtemp(join(tmpdir(), "ccshield-persisted-settings-"));
  let spawned = false;
  try {
    await mkdir(join(home, ".claude"), { recursive: true });
    await writeFile(join(home, ".claude", "settings.json"), JSON.stringify({
      env: { CLAUDE_AGENT_API_BASE_URL: "http://127.0.0.1:4599" },
    }));
    await assert.rejects(
      launchShieldChild({
        command: "/usr/bin/env",
        args: ["true"],
        env: { HOME: home, CLAUDE_CONFIG_DIR: join(home, ".claude") },
        ready: { origin: "http://127.0.0.1:8811", capability, lane: "subscription", targetClass: "subscription" },
        spawnChild() { spawned = true; },
      }),
      /Shield launch settings cannot override.*CLAUDE_AGENT_API_BASE_URL/i,
    );
    assert.equal(spawned, false);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test("Shield launch rejects a capability that cannot be represented as one custom header", async () => {
  let spawnCalls = 0;

  await assert.rejects(
    launchShieldChild({
      command: "/usr/bin/env",
      args: ["true"],
      ready: {
        origin: "http://127.0.0.1:8811",
        capability: `${capability}\nx-escape: injected`,
        lane: "subscription",
        targetClass: "subscription",
      },
      spawnChild() {
        spawnCalls += 1;
        const child = new EventEmitter();
        queueMicrotask(() => child.emit("close", 0, null));
        return child;
      },
    }),
    /shield capability cannot be represented as an HTTP header/,
  );
  assert.equal(spawnCalls, 0);
});

test("Shield child environment fails closed without a durable decision recorder", async () => {
  let upstreamCalls = 0;
  const upstream = createServer((request, response) => {
    upstreamCalls += 1;
    request.resume();
    response.writeHead(200, { "content-type": "application/json" });
    response.end('{"ok":true}');
  });
  upstream.listen(0, "127.0.0.1");
  await new Promise((resolvePromise, reject) => {
    upstream.once("listening", resolvePromise);
    upstream.once("error", reject);
  });
  const upstreamAddress = upstream.address();
  const shield = await startShieldProxy({
    capability,
    controlCapability: "d".repeat(32),
    targetOrigin: `http://127.0.0.1:${upstreamAddress.port}`,
    decide: async () => ({ action: "allow" }),
  });
  const calls = [];
  const child = new EventEmitter();

  try {
    const outcome = launchShieldChild({
      command: "/usr/bin/env",
      args: ["true"],
      ready: { origin: shield.origin, capability, lane: "subscription", targetClass: "subscription" },
      env: {},
      spawnChild(command, args, options) {
        calls.push({ command, args, options });
        queueMicrotask(() => child.emit("close", 0, null));
        return child;
      },
    });
    assert.deepEqual(await outcome, { code: 0, signal: null });
    const childEnv = calls[0].options.env;
    const headers = Object.fromEntries(childEnv.ANTHROPIC_CUSTOM_HEADERS.split("\n").map((line) => {
      const separator = line.indexOf(":");
      return [line.slice(0, separator), line.slice(separator + 1).trim()];
    }));
    const response = await fetch(`${childEnv.ANTHROPIC_BASE_URL}/v1/messages`, {
      body: "{}",
      headers,
      method: "POST",
    });

    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: { code: "shield_unavailable" } });
    assert.equal(upstreamCalls, 0);
  } finally {
    await shield.close();
    await new Promise((resolvePromise) => upstream.close(resolvePromise));
  }
});

test("shield status never displays capability or target metadata", async () => {
  const output = capture();
  const code = await runShieldCli(["status"], {
    stdout: output.stdout,
    shield: {
      async status() {
        return {
          state: "healthy",
          identity: { present: true, origin: "http://127.0.0.1:8811", capability, targetClass: "loopback" },
          service: { installed: true, loaded: true },
        };
      },
    },
  });
  assert.equal(code, 0);
  assert.match(output.value(), /state: healthy/);
  assert.equal(output.value().includes(capability), false);
  assert.equal(output.value().includes("127.0.0.1"), false);
  assert.equal(output.value().includes("loopback"), false);
});

test("shield launch CLI requires a lane and command boundary", async () => {
  await assert.rejects(
    runShieldCli(["launch", "--lane", "subscription", "echo", "unsafe"], { shield: {} }),
    /usage: ccshield launch --lane subscription\|managed .*-- command/i,
  );
});

test("managed shield CLI launch fails closed without an AirKit destination lease", async () => {
  await assert.rejects(
    runShieldCli(["launch", "--lane", "managed", "--", "echo", "unsafe"], { shield: { async launch() { throw new Error("managed Shield launch requires AirKit lease lifecycle"); } } }),
    /requires AirKit lease lifecycle/i,
  );
});

test("subscription shield CLI accepts only an explicit loopback dynamic target", async () => {
  const calls = [];
  await runShieldCli(["launch", "--lane", "subscription", "--target", "http://127.0.0.1:8804", "--", "echo", "ok"], {
    stdout: capture().stdout,
    shield: { async launch(options) { calls.push(options); return { state: "healthy", exitCode: 0 }; } },
  });
  assert.equal(calls[0].targetOrigin, "http://127.0.0.1:8804");
  for (const target of ["https://127.0.0.1:8804", "http://localhost:8804", "http://127.0.0.1", "http://example.com:80"]) {
    await assert.rejects(runShieldCli(["launch", "--lane", "subscription", "--target", target, "--", "echo", "no"], { shield: {} }), /usage: ccshield launch/i);
  }
});

test("subscription --pxpipe launch points Shield at a pxpipe hop and closes it with the lease", async () => {
  const events = [];
  await runShieldCli(["launch", "--lane", "subscription", "--pxpipe", "--", "echo", "ok"], {
    stdout: capture().stdout,
    ensureShieldReady: async () => ({ origin: "http://127.0.0.1:8811", capability: "a".repeat(32), lane: "subscription", targetClass: "subscription" }),
    startPxpipeHop: async ({ upstream }) => {
      events.push(`hop:${upstream}`);
      return { origin: "http://127.0.0.1:8805", async close() { events.push("hop-close"); } };
    },
    createShieldDestinationLease: async ({ ready, targetOrigin }) => { events.push(`create:${targetOrigin}`); return ready; },
    renewShieldDestinationLease: async () => true,
    revokeShieldDestinationLease: async () => events.push("revoke"),
    shieldLeaseSetInterval: () => ({ unref() {} }),
    shieldLeaseClearInterval: () => {},
    launchShieldChild: async () => { events.push("child-exit"); return { code: 0 }; },
  });
  assert.deepEqual(events, ["hop:https://api.anthropic.com", "create:http://127.0.0.1:8805", "child-exit", "revoke", "hop-close"]);
});

test("--pxpipe is subscription-only and excludes --target", async () => {
  await assert.rejects(runShieldCli(["launch", "--lane", "managed", "--pxpipe", "--", "echo", "no"], { shield: {} }), /lease lifecycle/);
  await assert.rejects(runShieldCli(["launch", "--lane", "subscription", "--pxpipe", "--target", "http://127.0.0.1:8804", "--", "echo", "no"], { shield: {} }), /not both/);
});

test("subscription --pxpipe closes the hop when the lease cannot be created", async () => {
  let closed = false;
  await assert.rejects(runShieldCli(["launch", "--lane", "subscription", "--pxpipe", "--", "echo", "no"], {
    stdout: capture().stdout,
    ensureShieldReady: async () => ({ origin: "http://127.0.0.1:8811", capability: "a".repeat(32), lane: "subscription", targetClass: "subscription" }),
    startPxpipeHop: async () => ({ origin: "http://127.0.0.1:8805", async close() { closed = true; } }),
    createShieldDestinationLease: async () => { throw new Error("lease refused"); },
  }), /lease refused/);
  assert.equal(closed, true);
});

test("subscription target launch renews its lease until its foreground child exits", async () => {
  const intervals = [];
  const cleared = [];
  const events = [];
  await runShieldCli(["launch", "--lane", "subscription", "--target", "http://127.0.0.1:8804", "--", "echo", "ok"], {
    stdout: capture().stdout,
    ensureShieldReady: async () => ({ origin: "http://127.0.0.1:8811", capability: "a".repeat(32), lane: "subscription", targetClass: "subscription" }),
    createShieldDestinationLease: async ({ ready, targetOrigin }) => {
      events.push(`create:${targetOrigin}`);
      return { ...ready, capability: "b".repeat(32) };
    },
    renewShieldDestinationLease: async ({ ready, targetOrigin }) => {
      events.push(`renew:${ready.capability}:${targetOrigin}`);
      return true;
    },
    revokeShieldDestinationLease: async ({ ready }) => events.push(`revoke:${ready.capability}`),
    shieldLeaseSetInterval: (callback, delay) => {
      assert.equal(delay, 15_000);
      const timer = { unref() {} };
      intervals.push({ callback, timer });
      return timer;
    },
    shieldLeaseClearInterval: (timer) => cleared.push(timer),
    launchShieldChild: async () => {
      assert.equal(intervals.length, 1);
      await intervals[0].callback();
      events.push("child-exit");
      return { code: 0 };
    },
  });
  assert.deepEqual(events, [
    "create:http://127.0.0.1:8804",
    `renew:${"b".repeat(32)}:http://127.0.0.1:8804`,
    "child-exit",
    `revoke:${"b".repeat(32)}`,
  ]);
  assert.deepEqual(cleared, [intervals[0].timer]);
});

test("subscription target launch retains its lease while a matching background host remains", async () => {
  const intervals = [];
  const checks = [];
  const cleared = [];
  const events = [];
  let active = true;
  await runShieldCli(["launch", "--lane", "subscription", "--target", "http://127.0.0.1:8804", "--", "echo", "ok"], {
    stdout: capture().stdout,
    ensureShieldReady: async () => ({ origin: "http://127.0.0.1:8811", capability: "a".repeat(32), lane: "subscription", targetClass: "subscription" }),
    createShieldDestinationLease: async ({ ready }) => ({ ...ready, capability: "b".repeat(32) }),
    renewShieldDestinationLease: async () => events.push("renew"),
    revokeShieldDestinationLease: async () => events.push("revoke"),
    shieldLeaseSetInterval: (callback) => {
      const timer = { unref() {} };
      intervals.push({ callback, timer });
      return timer;
    },
    shieldLeaseClearInterval: (timer) => cleared.push(timer),
    backgroundHostDetector: async (origin) => {
      assert.equal(origin, "http://127.0.0.1:8811");
      return active;
    },
    backgroundMiddlewareGraceMs: 1_000,
    backgroundSetTimeout: (callback) => {
      checks.push(callback);
      return { unref() {} };
    },
    launchShieldChild: async () => ({ code: 0 }),
  });
  assert.equal(intervals.length, 1);
  assert.equal(checks.length, 1);
  assert.deepEqual(events, []);
  await intervals[0].callback();
  assert.deepEqual(events, ["renew"]);
  active = false;
  await checks[0]();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(events, ["renew", "revoke"]);
  assert.deepEqual(cleared, [intervals[0].timer]);
});

test("sequential interactive Shield children unregister each approval channel before the next launch", async () => {
  const ready = { origin: "http://127.0.0.1:8811", capability: "c".repeat(32), lane: "subscription", targetClass: "subscription" };
  const events = [];
  const channels = [
    { socketPath: "/tmp/approval-one.sock", capability: "a".repeat(32), async close() { events.push("close:one"); } },
    { socketPath: "/tmp/approval-two.sock", capability: "b".repeat(32), async close() { events.push("close:two"); } },
  ];
  for (const channel of channels) {
    await launchShieldChild({
      command: "echo",
      ready,
      createApprovalChannel: async () => channel,
      registerApprovalChannel: async ({ channel: registered }) => events.push(`register:${registered.socketPath}`),
      unregisterApprovalChannel: async () => events.push("unregister"),
      spawnChild: () => {
        const child = new EventEmitter();
        queueMicrotask(() => child.emit("close", 0, null));
        return child;
      },
    });
  }
  assert.deepEqual(events, [
    "register:/tmp/approval-one.sock", "unregister", "close:one",
    "register:/tmp/approval-two.sock", "unregister", "close:two",
  ]);
});

test("shield install applies lifecycle only with --write", async () => {
  const calls = [];
  const output = capture();
  const code = await runShieldCli(["install", "--write"], {
    stdout: output.stdout,
    shield: {
      async install(options) {
        calls.push(options);
        return { state: "degraded", write: options.write };
      },
    },
  });
  assert.equal(code, 1);
  assert.deepEqual(calls, [{ write: true, lane: "subscription" }]);
});

test("shield install requires an explicit valid lane and passes it to provisioning", async () => {
  const calls = [];
  await runShieldCli(["install", "--lane", "managed", "--write"], {
    stdout: capture().stdout,
    shield: { async install(options) { calls.push(options); return { state: "degraded", write: true, lane: options.lane }; } },
  });
  assert.deepEqual(calls, [{ write: true, lane: "managed" }]);
  await assert.rejects(runShieldCli(["install", "--lane", "unknown"], { shield: {} }), /usage: ccshield install/i);
});

test("shield lifecycle commands pass the selected lane without sharing subscription state", async () => {
  const calls = [];
  await runShieldCli(["status", "--lane", "managed"], { stdout: capture().stdout, shield: { async status(options) { calls.push(options); return { state: "stopped" }; } } });
  assert.deepEqual(calls, [{ lane: "managed" }]);
  await assert.rejects(runShieldCli(["doctor", "--lane", "invalid"], { shield: {} }), /usage: ccshield doctor/i);
});

test("managed install parses through the CLI and binds same-lane verified provisions", async () => {
  const home = await mkdtemp(join(tmpdir(), "ccshield-cli-"));
  const calls = [];
  try {
    await runShieldCli(["install", "--lane", "managed"], {
      env: { HOME: home }, stdout: capture().stdout,
      readShieldAssetsProvision: async ({ paths }) => { calls.push(["assets", paths.lane]); return { gitleaks: { path: "/opt/gitleaks", sha256: "a".repeat(64), rules: { path: "/opt/gitleaks-rules.toml", sha256: "b".repeat(64), version: "rules-bbbbbbbbbbbb" } } }; },
      readShieldPolicyProvision: async ({ paths }) => { calls.push(["policy", paths.lane]); return { bundle: {}, publicKey: "key" }; },
      loadShieldPolicy: async () => ({ version: "policy-1" }),
      installShieldService: async ({ paths, config, write }) => {
        calls.push(["install", paths.lane, config.gitleaks.executable, write]);
        assert.deepEqual(config.gitleaks.ruleBundle, {
          path: "/opt/gitleaks-rules.toml",
          sha256: "b".repeat(64),
          version: "rules-bbbbbbbbbbbb",
          commandProfile: {
            versionArgs: ["version"],
            scanArgs: ["stdin", "--config", "{rules}", "--report-format", "json", "--report-path", "-", "--redact"],
          },
        });
        return { label: paths.serviceLabel };
      },
    });
    assert.deepEqual(calls, [["assets", "managed"], ["policy", "managed"], ["install", "managed", "/opt/gitleaks", false]]);
  } finally { await rm(home, { recursive: true, force: true }); }
});

test("managed policy privacy and install CLI sequence stays in one lane", async () => {
  const home = await mkdtemp(join(tmpdir(), "ccshield-cli-sequence-"));
  const calls = [];
  const dependencies = {
    env: { HOME: home }, stdout: capture().stdout,
    installShieldPolicyProvision: async ({ paths, write }) => { calls.push(["policy", paths.lane, write]); return { version: "p", detectorVersions: {} }; },
    provisionShieldAssets: async ({ paths, write }) => { calls.push(["privacy", paths.lane, write]); return {}; },
    readShieldAssetsProvision: async () => ({ gitleaks: { path: "/opt/gitleaks", sha256: "a".repeat(64), rules: { path: "/opt/gitleaks-rules.toml", sha256: "b".repeat(64), version: "rules-bbbbbbbbbbbb" } } }),
    readShieldPolicyProvision: async () => ({ bundle: {}, publicKey: "key" }), loadShieldPolicy: async () => ({}),
    installShieldService: async ({ paths }) => { calls.push(["install", paths.lane]); return { label: paths.serviceLabel }; },
  };
  try {
    await runShieldCli(["policy", "install", "--bundle", "/tmp/p", "--public-key", "/tmp/k", "--lane", "managed"], dependencies);
    await runShieldCli(["privacy", "provision", "--bundle", "/tmp/privacy", "--gitleaks", "/tmp/g", "--gitleaks-rules", "/tmp/rules.toml", "--lane", "managed"], dependencies);
    await runShieldCli(["install", "--lane", "managed"], dependencies);
    assert.deepEqual(calls, [["policy", "managed", undefined], ["privacy", "managed", false], ["install", "managed"]]);
  } finally { await rm(home, { recursive: true, force: true }); }
});

test("managed status and doctor CLI commands preserve their lane", async () => {
  const calls = [];
  const shield = {
    async status(options) { calls.push(["status", options.lane]); return { state: "stopped" }; },
    async doctor(options) { calls.push(["doctor", options.lane]); return { state: "stopped" }; },
  };
  await runShieldCli(["status", "--lane", "managed"], { shield, stdout: capture().stdout });
  await runShieldCli(["doctor", "--lane", "managed"], { shield, stdout: capture().stdout });
  assert.deepEqual(calls, [["status", "managed"], ["doctor", "managed"]]);
});

test("shield doctor degrades a live service when its operational lane is unavailable", async () => {
  const output = capture();
  const code = await runShieldCli(["doctor", "--lane", "subscription"], {
    stdout: output.stdout,
    shieldStatus: async () => ({ state: "healthy", service: { active: true }, identity: { present: true } }),
    readShieldOperationalStatus: async () => ({ state: "unavailable", lanes: [{ lane: "subscription", state: "unavailable" }] }),
    readAuditHealth: async () => "unavailable",
    inspectMasterKey: async () => ({ source: "keychain", present: true, warning: null }),
  });
  assert.equal(code, 1);
  assert.match(output.value(), /state: degraded/);
  assert.match(output.value(), /masterKey\.source: keychain/);
  assert.match(output.value(), /operational\.lanes\.0\.lane: subscription/);
  assert.match(output.value(), /operational\.lanes\.0\.state: unavailable/);
  assert.doesNotMatch(output.value(), /\[object Object\]/);
});

test("shield doctor reports the probed audit health instead of a fixed unavailable", async () => {
  for (const audit of ["healthy", "unavailable"]) {
    const seen = [];
    const output = capture();
    await runShieldCli(["doctor", "--lane", "subscription"], {
      stdout: output.stdout,
      shieldStatus: async () => ({ state: "healthy", service: { active: true }, identity: { present: true } }),
      readShieldOperationalStatus: async (options) => {
        seen.push(options.audit);
        return { state: "protected", lanes: [{ lane: "subscription", state: "protected", audit: options.audit }] };
      },
      readAuditHealth: async () => audit,
      inspectMasterKey: async () => ({ source: "keychain", present: true, warning: null }),
    });
    assert.deepEqual(seen, [audit]);
    assert.match(output.value(), new RegExp(`operational\\.lanes\\.0\\.audit: ${audit}`));
  }
});

test("audit health collapses every non-healthy or failing store to unavailable", async (t) => {
  const { openShieldStore, readAuditHealth } = await import("../src/store.mjs");
  const root = await mkdtemp(join(tmpdir(), "ccshield-audit-health-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const auditDatabasePath = join(root, "audit.sqlite");
  const paths = { auditDatabasePath };

  assert.equal(readAuditHealth({ paths }), "unavailable");
  openShieldStore({ databasePath: auditDatabasePath, masterKey: Buffer.alloc(32, 3) }).close();
  assert.equal(readAuditHealth({ paths }), "healthy");

  class Throwing { constructor() { throw new Error("socket gone"); } }
  class Unreadable { exec() {} prepare() { throw new Error("database disk image is malformed"); } close() {} }
  class CloseThrows { exec() {} prepare() { throw new Error("locked"); } close() { throw new Error("close failed"); } }
  for (const Database of [Throwing, Unreadable, CloseThrows]) {
    assert.equal(readAuditHealth({ paths, Database }), "unavailable", Database.name);
  }
  assert.equal(readAuditHealth(), "unavailable");

  const corrupt = join(root, "corrupt.sqlite");
  await writeFile(corrupt, "not a database");
  assert.equal(readAuditHealth({ paths: { auditDatabasePath: corrupt } }), "unavailable");
});

test("ccshield routes status to the injected service without touching real lane state", async () => {
  const output = capture();
  const code = await runShieldCli(["status"], {
    stdout: output.stdout,
    shield: {
      async status() {
        return { state: "healthy", service: { installed: true, loaded: true } };
      },
    },
  });
  assert.equal(code, 0);
  assert.match(output.value(), /state: healthy/);
});

test("ccshield install preview fails closed when lane assets are absent", async () => {
  const { paths, options } = fixture();
  const output = capture();
  const calls = [];
  const io = new Proxy({}, { get: () => async (...args) => calls.push(args) });
  await assert.rejects(runShieldCli(["install"], {
    stdout: output.stdout,
    paths,
    nodePath: options.nodePath,
    daemonPath: options.daemonPath,
    io,
    runLaunchctl: async (args) => calls.push(args),
  }), /shield asset provision|isSymbolicLink/i);
  assert.equal(calls.length, 1);
});

function shieldStateIo(paths, { identity, config, state = policyState }) {
  const storedConfig = { ...config, controlCapability: config.controlCapability ?? "d".repeat(32) };
  return {
    async lstat(path) {
      if (path === paths.policyStatePath) {
        return {
          uid: process.getuid?.(),
          mode: 0o600,
          isFile: () => true,
          isSymbolicLink: () => false,
        };
      }
      throw new Error(`unexpected fixture stat path: ${path}`);
    },
    async readFile(path) {
      if (path === paths.identityPath) return `${JSON.stringify(identity)}\n`;
      if (path === paths.configPath) return `${JSON.stringify(storedConfig)}\n`;
      if (path === paths.policyStatePath) return `${JSON.stringify(state)}\n`;
      throw new Error(`unexpected fixture path: ${path}`);
    },
  };
}

async function startServer(handler) {
  const server = createServer((request, response) => void handler(request, response));
  server.listen(0, "127.0.0.1");
  await new Promise((resolvePromise, reject) => { server.once("listening", resolvePromise); server.once("error", reject); });
  const address = server.address();
  return { origin: `http://127.0.0.1:${address.port}`, close: () => new Promise((resolvePromise) => server.close(resolvePromise)) };
}
