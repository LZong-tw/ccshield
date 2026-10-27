import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { EventEmitter, once } from "node:events";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import test from "node:test";

import { createDefaultDecisionRecorder, startShieldDaemon } from "../src/shieldd.mjs";
import { canonicalJson } from "../src/shield/policy-bundle.mjs";
import { createPrivacyFilter } from "../src/shield/privacy.mjs";
import { startShieldProxy } from "../src/shield/proxy.mjs";
import { createShieldDecisionRecorder } from "../src/shield/audit.mjs";

const config = {
  capability: "c".repeat(32),
  controlCapability: "d".repeat(32),
  targetOrigin: "https://api.anthropic.com",
  lane: "subscription",
  generation: "generation-1",
  targetClass: "subscription",
  launcherContext: {
    repository: { remoteHash: "a".repeat(64), trustClass: "internal" },
    pathClasses: ["source"],
    destinationClass: "subscription",
    interactive: false,
  },
  gitleaks: { executable: "/opt/ccshield/gitleaks", sha256: "b".repeat(64), ruleBundle: { path: "/opt/ccshield/rules.toml", sha256: "c".repeat(64), version: "rules-1", commandProfile: { versionArgs: ["version"], scanArgs: ["stdin", "--config", "{rules}", "--report-format", "json", "--report-path", "-", "--redact"] } } },
};

const paths = {
  configPath: "/private/config.json",
  policyBundlePath: "/private/policy.bundle.json",
  policyPublicKeyPath: "/private/policy-public.pem",
};

const compiledPolicyWasm = await readFile(new URL("./fixtures/shield-policy.wasm", import.meta.url));
const compiledPolicyKeyPair = generateKeyPairSync("ed25519");

const policy = {
  version: "2026.09.02.2",
  detectorVersions: { gitleaks: "8.24.0", privacy: "privacy-1" },
  async evaluate() {
    return { action: "block", reasonCodes: ["fixture"], approvalEligible: false, redactions: [] };
  },
};

test("daemon activates validated policy before proxy readiness and publishes its identity binding", async () => {
  const calls = [];
  const daemon = await startDaemon({
    config,
    paths,
    pid: 4242,
    readPolicyBundle: async ({ receivedPaths }) => {
      calls.push(["bundle", receivedPaths]);
      return { bundle: { fixture: true }, publicKey: "pinned-ed25519-public-key" };
    },
    loadPolicy: async (options) => {
      calls.push(["policy", options]);
      return policy;
    },
    createScanner: async (options) => {
      calls.push(["scanner", options]);
      return { version: "8.24.0", scan: async () => ({ findings: [] }) };
    },
    writePolicyState: async (options) => calls.push(["state", options]),
    startProxy: async (options) => {
      calls.push(["proxy", options]);
      return { origin: "http://127.0.0.1:8811", close: async () => calls.push(["close"]) };
    },
    writeIdentity: async (options) => calls.push(["identity", options]),
  });

  assert.equal(daemon.policy, policy);
  assert.deepEqual(await calls.find(([name]) => name === "proxy")[1].decide({ body: Buffer.alloc(0) }), {
    action: "block",
    reasonCodes: ["fixture"],
    approvalEligible: false,
    redactions: [],
    lane: "subscription",
    destinationClass: "subscription",
    bundleVersion: "2026.09.02.2",
    detectorVersions: { gitleaks: "8.24.0", privacy: "privacy-1" },
  });
  assert.deepEqual(calls.map(([name]) => name), ["bundle", "policy", "scanner", "state", "proxy", "identity"]);
  assert.deepEqual(calls.at(-1)[1].identity, {
    origin: "http://127.0.0.1:8811",
    capability: config.capability,
    version: 1,
    pid: 4242,
    lane: "subscription",
    generation: "generation-1",
    targetClass: "subscription",
    policyVersion: policy.version,
    detectorVersions: policy.detectorVersions,
    media: { documents: "blocked", images: "unscanned" },
  });
});

test("daemon closes the proxy when publishing the bound identity fails", async () => {
  const calls = [];
  await assert.rejects(
    startDaemon({
      config,
      paths,
      readPolicyBundle: async () => ({ bundle: {}, publicKey: "pinned-ed25519-public-key" }),
      loadPolicy: async () => policy,
      createScanner: async () => ({ version: "8.24.0", scan: async () => ({ findings: [] }) }),
      writePolicyState: async () => {},
      startProxy: async () => ({ origin: "http://127.0.0.1:8811", close: async () => calls.push("close") }),
      writeIdentity: async () => { throw new Error("identity write failed"); },
    }),
    /identity write failed/,
  );
  assert.deepEqual(calls, ["close"]);
});

test("daemon requires a durable audit recorder before it publishes an identity", async () => {
  const calls = [];
  await assert.rejects(
    startDaemon({
      config,
      paths,
      readPolicyBundle: async () => ({ bundle: {}, publicKey: "pinned-ed25519-public-key" }),
      loadPolicy: async () => policy,
      createScanner: async () => ({ version: "8.24.0", scan: async () => ({ findings: [] }) }),
      createDecisionRecorder: async () => { throw new Error("audit not durable"); },
      startProxy: async () => { calls.push("proxy"); return { origin: "http://127.0.0.1:8811", close: async () => {} }; },
      writePolicyState: async () => calls.push("state"),
      writeIdentity: async () => calls.push("identity"),
    }),
    /audit not durable/,
  );
  assert.deepEqual(calls, []);
});

test("daemon passes its durable decision recorder to the protected proxy", async () => {
  const recorder = { recordShieldDecision: async () => ({ durable: "ack" }) };
  let proxyOptions = null;
  await startDaemon({
    config,
    paths,
    readPolicyBundle: async () => ({ bundle: {}, publicKey: "pinned-ed25519-public-key" }),
    loadPolicy: async () => policy,
    createScanner: async () => ({ version: "8.24.0", scan: async () => ({ findings: [] }) }),
    createDecisionRecorder: async () => recorder,
    writePolicyState: async () => {},
    startProxy: async (options) => { proxyOptions = options; return { origin: "http://127.0.0.1:8811", close: async () => {} }; },
    writeIdentity: async () => {},
  });
  assert.equal(proxyOptions.recordShieldDecision, recorder.recordShieldDecision);
});

test("daemon readiness requires both audit durability and a live privacy worker", async () => {
  let privacyReady = true;
  let auditReady = true;
  let proxyOptions;
  const daemon = await startDaemon({
    config,
    paths,
    readPolicyBundle: async () => ({ bundle: {}, publicKey: "pinned-ed25519-public-key" }),
    loadPolicy: async () => policy,
    createScanner: async () => ({ version: "8.24.0", scan: async () => ({ findings: [] }) }),
    createPrivacy: async () => ({ version: "privacy-1", async scan() { return { status: "ok", findings: [] }; }, async isReady() { return privacyReady; }, close() {} }),
    createDecisionRecorder: async () => ({ recordShieldDecision: async () => ({ durable: "ack" }), async isReady() { return auditReady; } }),
    writePolicyState: async () => {},
    startProxy: async (options) => { proxyOptions = options; return { origin: "http://127.0.0.1:8811", close: async () => {} }; },
    writeIdentity: async () => {},
  });
  try {
    assert.equal(await proxyOptions.isReady(), true);
    privacyReady = false;
    assert.equal(await proxyOptions.isReady(), false);
    privacyReady = true;
    auditReady = false;
    assert.equal(await proxyOptions.isReady(), false);
  } finally {
    await daemon.shield.close();
  }
});

test("default daemon recorder requires a key and the lane store, and fails closed when the store refuses", async () => {
  const opened = [];
  const recorded = [];
  let closed = false;
  const key = Buffer.alloc(32, 7);
  const lanePaths = { auditDatabasePath: "/private/lane/audit.sqlite" };
  const recorder = await createDefaultDecisionRecorder({
    config: { auditRetentionDays: 7 },
    paths: lanePaths,
    masterKeyProvider: { get: async () => key },
    openStore: (options) => {
      opened.push(options);
      return { recordEvent: (event) => recorded.push(event), purgeExpiredEvidence: () => 0, close: () => { closed = true; } };
    },
  });
  assert.deepEqual(opened, [{ databasePath: "/private/lane/audit.sqlite", masterKey: key, retentionDays: 7 }]);
  const result = await recorder.recordShieldDecision({
    requestId: "request-1", lane: "subscription", destinationClass: "subscription", bundleVersion: "policy-1",
    detectorVersions: { gitleaks: "8.24.0" }, action: "allow", reasonCodes: ["policy_allow"], transformCount: 0, override: false, elapsedMs: 1,
  });
  assert.equal(result.durable, "store");
  assert.equal(recorded.length, 1);
  await recorder.close();
  assert.equal(closed, true);

  await assert.rejects(createDefaultDecisionRecorder({ masterKeyProvider: { get: async () => key }, openStore: () => assert.fail("not reached") }), /store path is required/);
  await assert.rejects(
    createDefaultDecisionRecorder({ paths: lanePaths, masterKeyProvider: { get: async () => { throw new Error("key unavailable"); } }, openStore: () => assert.fail("not reached") }),
    /key unavailable/,
  );
  await assert.rejects(
    createDefaultDecisionRecorder({ paths: lanePaths, masterKeyProvider: { get: async () => key }, openStore: () => { throw new Error("shield store migration 001_initial checksum mismatch"); } }),
    /checksum mismatch/,
  );
});

test("daemon normalizes conflicting launcher destination class before policy evaluation", async () => {
  const policyInputs = [];
  const proxyDecisions = [];
  await startDaemon({
    config: {
      ...config,
      launcherContext: { ...config.launcherContext, destinationClass: "managed" },
    },
    paths,
    readPolicyBundle: async () => ({ bundle: {}, publicKey: "pinned-ed25519-public-key" }),
    loadPolicy: async () => ({
      ...policy,
      async evaluate(input) {
        policyInputs.push(input);
        return { action: "require_approval", reasonCodes: ["internal_repository_code"], approvalEligible: true, redactions: [] };
      },
    }),
    createScanner: async () => ({ version: "8.24.0", scan: async () => ({ findings: [] }) }),
    writePolicyState: async () => {},
    startProxy: async ({ decide }) => {
      proxyDecisions.push(await decide({ body: Buffer.alloc(0) }));
      return { origin: "http://127.0.0.1:8811", close: async () => {} };
    },
    writeIdentity: async () => {},
  });

  assert.equal(policyInputs[0].destinationClass, "subscription");
  assert.equal(proxyDecisions[0].destinationClass, "subscription");
});

test("daemon rejects a target class that conflicts with its lane before policy activation", async () => {
  let loaded = false;
  await assert.rejects(
    startDaemon({
      config: { ...config, targetClass: "managed" },
      paths,
      readPolicyBundle: async () => ({ bundle: {}, publicKey: "pinned-ed25519-public-key" }),
      loadPolicy: async () => { loaded = true; return policy; },
    }),
    /targetClass must match/i,
  );
  assert.equal(loaded, false);
});

test("proxy requests reach Gitleaks, category-only classification, and policy evaluation", async (t) => {
  const upstream = createServer(async (request, response) => {
    request.resume();
    response.writeHead(200, { "content-type": "application/json" });
    response.end('{"ok":true}');
  });
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  t.after(() => new Promise((resolve) => upstream.close(resolve)));
  const address = upstream.address();
  const scannerCalls = [];
  const policyInputs = [];
  let privacyScans = 0;
  const daemon = await startDaemon({
    config: { ...config, targetOrigin: `http://127.0.0.1:${address.port}` },
    paths,
    readPolicyBundle: async () => ({ bundle: {}, publicKey: "pinned-ed25519-public-key" }),
    createScanner: async () => ({
      version: "8.24.0",
      async scan(body) {
        scannerCalls.push(Buffer.from(body).toString("utf8"));
        return { findings: [{ category: "private-key", count: 1 }] };
      },
    }),
    createPrivacy: async () => ({
      version: "privacy-1",
      async scan() { privacyScans += 1; return { status: "unknown", findings: [] }; },
      close() {},
    }),
    loadPolicy: async () => ({
      ...policy,
      async evaluate(input) {
        policyInputs.push(input);
        return { action: "block", reasonCodes: ["confirmed-secret"], approvalEligible: false, redactions: [] };
      },
    }),
    writePolicyState: async () => {},
    writeIdentity: async () => {},
  });
  t.after(() => daemon.shield.close());

  const response = await fetch(`${daemon.shield.origin}/v1/messages`, {
    method: "POST",
    headers: { "x-airkit-shield": config.capability },
    body: '{"content":"fixture-private-key"}',
  });

  assert.equal(response.status, 403);
  assert.equal(privacyScans, 0);
  assert.deepEqual(scannerCalls, ['{"content":"fixture-private-key"}']);
  assert.deepEqual(policyInputs, [{
    lane: "subscription",
    destinationClass: "subscription",
    interactive: false,
    repositoryClass: "internal",
    pathClasses: ["source"],
    secretFindings: [{ category: "private-key", count: 1 }],
    piiFindings: [],
  }]);
  assert.doesNotMatch(JSON.stringify(policyInputs), /fixture-private-key|aaaa/);
});

test("a dynamic launch lease carries bounded classifier facts into the daemon policy without raw workspace data", async (t) => {
  const workspace = "/private/workspaces/restricted-production-app";
  const upstream = createServer((request, response) => {
    request.resume();
    response.end("must not forward");
  });
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  t.after(() => new Promise((resolve) => upstream.close(resolve)));
  const address = upstream.address();
  const policyInputs = [];
  const managedConfig = { ...config, lane: "managed", targetClass: "managed" };
  delete managedConfig.targetOrigin;
  const daemon = await startDaemon({
    config: managedConfig,
    paths,
    readPolicyBundle: async () => ({ bundle: {}, publicKey: "pinned-ed25519-public-key" }),
    createScanner: async () => ({ version: "8.24.0", scan: async () => ({ findings: [] }) }),
    loadPolicy: async () => ({
      ...policy,
      async evaluate(input) {
        policyInputs.push(input);
        return { action: input.repositoryClass === "restricted" ? "block" : "allow", reasonCodes: ["workspace_policy"], approvalEligible: false, redactions: [] };
      },
    }),
    writePolicyState: async () => {},
    writeIdentity: async () => {},
  });
  t.after(() => daemon.shield.close());
  const context = {
    repository: { remoteHash: createHash("sha256").update(workspace).digest("hex"), trustClass: "restricted" },
    pathClasses: ["production_config"],
    destinationClass: "managed",
    interactive: true,
  };
  const lease = "e".repeat(32);
  const registered = await fetch(`${daemon.shield.origin}/_airkit/shield/destination-lease`, {
    method: "POST",
    headers: { "x-airkit-shield-control": managedConfig.controlCapability, "content-type": "application/json" },
    body: JSON.stringify({ capability: lease, targetOrigin: `http://127.0.0.1:${address.port}`, expiresAt: Date.now() + 30_000, launcherContext: context }),
  });
  assert.equal(registered.status, 204);
  const response = await fetch(`${daemon.shield.origin}/v1/messages`, {
    method: "POST", headers: { "x-airkit-shield": lease }, body: '{"content":"ordinary"}',
  });
  assert.equal(response.status, 403);
  assert.deepEqual(policyInputs, [{
    lane: "managed", destinationClass: "managed", interactive: true, repositoryClass: "restricted",
    pathClasses: ["production_config"], secretFindings: [], piiFindings: [],
  }]);
  assert.doesNotMatch(JSON.stringify({ config: managedConfig, policyInputs }), /restricted-production-app|\/private\/workspaces/);
});

test("missing launcher context reaches policy facts and forwards only after durable audit", async (t) => {
  const upstream = createServer((request, response) => {
    request.resume();
    response.end('{"ok":true}');
  });
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  t.after(() => new Promise((resolve) => upstream.close(resolve)));
  const address = upstream.address();
  const policyInputs = [];
  const { launcherContext: _launcherContext, ...configWithoutContext } = config;
  const daemon = await startDaemon({
    config: { ...configWithoutContext, targetOrigin: `http://127.0.0.1:${address.port}` },
    paths,
    readPolicyBundle: async () => ({ bundle: {}, publicKey: "pinned-ed25519-public-key" }),
    createScanner: async () => ({ version: "8.24.0", scan: async () => ({ findings: [] }) }),
    loadPolicy: async () => ({
      ...policy,
      async evaluate(input) {
        policyInputs.push(input);
        return { action: "allow", reasonCodes: [], approvalEligible: false, redactions: [] };
      },
    }),
    writePolicyState: async () => {},
    writeIdentity: async () => {},
  });
  t.after(() => daemon.shield.close());

  const response = await fetch(`${daemon.shield.origin}/v1/messages`, {
    method: "POST",
    headers: { "x-airkit-shield": config.capability },
    body: '{"content":"ordinary"}',
  });

  assert.equal(response.status, 200);
  assert.deepEqual(policyInputs, [{
    lane: "subscription",
    destinationClass: "subscription",
    interactive: false,
    repositoryClass: "unknown",
    pathClasses: ["unknown"],
    secretFindings: [],
    piiFindings: [],
  }]);
});

test("daemon composes provisioned Privacy findings and sends only a valid policy redaction to the proxy", async () => {
  const policyInputs = [];
  const decisions = [];
  await startDaemon({
    config,
    paths,
    readPolicyBundle: async () => ({ bundle: {}, publicKey: "pinned-ed25519-public-key" }),
    readAssetsProvision: async () => assetsProvision(),
    readImageProvision: async () => null,
    createPrivacy: async () => ({
      version: "privacy-1",
      async scan() {
        return { status: "ok", findings: [{ label: "email", count: 1 }], redactions: [{ label: "email", count: 1, spans: [{ start: 12, end: 47 }] }], redactedBody: Buffer.from('{"content":"[EMAIL]"}') };
      },
      close() {},
    }),
    createScanner: async () => ({ version: "8.24.0", scan: async () => ({ findings: [] }) }),
    loadPolicy: async () => ({
      version: "2026.09.02.4",
      detectorVersions: { gitleaks: "8.24.0", privacy: "privacy-1" },
      async evaluate(input) {
        policyInputs.push(input);
        return { action: "redact", reasonCodes: ["pii_email_redacted"], approvalEligible: false, redactions: [] };
      },
    }),
    writePolicyState: async () => {},
    startProxy: async ({ decide }) => {
      decisions.push(await decide({ body: Buffer.from('{"content":"privacy-raw-sentinel-must-not-escape"}') }));
      return { origin: "http://127.0.0.1:8811", close: async () => {} };
    },
    writeIdentity: async () => {},
  });

  assert.deepEqual(policyInputs[0].piiFindings, [{ category: "email", count: 1 }]);
  assert.equal(decisions[0].action, "redact");
  assert.deepEqual(decisions[0].redactedBody, Buffer.from('{"content":"[EMAIL]"}'));
  assert.doesNotMatch(JSON.stringify(decisions[0]), /privacy-raw/);
});

test("daemon uses the signed OPA policy to redact a non-email Privacy finding before upstream forwarding", async (t) => {
  let upstreamBody = null;
  const upstream = createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      upstreamBody = Buffer.concat(chunks).toString("utf8");
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{"ok":true}');
    });
  });
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  t.after(() => new Promise((resolve) => upstream.close(resolve)));
  const address = upstream.address();
  const original = '{"content":"555-0100"}';
  let evaluatedDecision = null;
  const daemon = await startDaemon({
    config: { ...config, targetOrigin: `http://127.0.0.1:${address.port}` },
    paths,
    readPolicyBundle: async () => signedCompiledPolicyBundle(),
    readAssetsProvision: async () => assetsProvision(),
    readImageProvision: async () => null,
    createPrivacy: async () => ({
      version: "privacy-1",
      async scan() {
        return {
          status: "ok",
          findings: [{ label: "phone", count: 1 }],
          redactions: [{ label: "phone", count: 1, spans: [{ start: 12, end: 20 }] }],
          redactedBody: Buffer.from('{"content":"[PHONE]"}'),
        };
      },
      close() {},
    }),
    createScanner: async () => ({ version: "8.24.0", scan: async () => ({ findings: [] }) }),
    writePolicyState: async () => {},
    writeIdentity: async () => {},
    startProxy: async (options) => startShieldProxy({
      ...options,
      recordShieldDecision: async () => {},
      decide: async (request) => {
        evaluatedDecision = await options.decide(request);
        return evaluatedDecision;
      },
    }),
  });
  t.after(() => daemon.shield.close());

  const response = await fetch(`${daemon.shield.origin}/v1/messages`, {
    method: "POST",
    headers: { "x-airkit-shield": config.capability },
    body: original,
  });

  assert.equal(evaluatedDecision?.action, "redact");
  assert.equal(response.status, 200);
  assert.equal(upstreamBody, '{"content":"[PHONE]"}');
  assert.notEqual(upstreamBody, original);
});

test("real gateway requires complete OPF secret redaction proof before forwarding", async (t) => {
  const original = '{"content":"fixture-token"}';
  const redacted = '{"content":"[SECRET]"}';
  const secretRedaction = { label: "secret", count: 1, spans: [{ start: 12, end: 25 }] };
  const mixedOriginal = '{"content":"fixture-token alice@example.com"}';
  const mixedFindings = [{ label: "secret", count: 1 }, { label: "private_email", count: 1 }];
  const cases = [
    { name: "verified secret", status: 200, body: redacted, transforms: 1 },
    { name: "verified secret and private email", original: mixedOriginal, reply: { findings: mixedFindings, redactions: [secretRedaction, { label: "private_email", count: 1, spans: [{ start: 26, end: 43 }] }], redactedBody: '{"content":"[SECRET] [PRIVATE_EMAIL]"}' }, status: 200, body: '{"content":"[SECRET] [PRIVATE_EMAIL]"}', transforms: 2 },
    { name: "unchanged body", reply: { redactedBody: original }, status: 503 },
    { name: "secret survives elsewhere", reply: { redactedBody: '{"content":"[SECRET]","other":"fixture-token"}' }, status: 503 },
    { name: "missing replacement body", reply: { redactedBody: undefined }, status: 503 },
    { name: "replacement is not JSON", reply: { redactedBody: "[SECRET]" }, status: 503 },
    { name: "missing proof", reply: { redactions: undefined }, status: 503 },
    { name: "empty proof", reply: { redactions: [] }, status: 503 },
    { name: "missing spans", reply: { redactions: [{ label: "secret", count: 1 }] }, status: 503 },
    { name: "out-of-bounds span", reply: { redactions: [{ label: "secret", count: 1, spans: [{ start: 12, end: 100 }] }] }, status: 503 },
    { name: "finding count exceeds proof", reply: { findings: [{ label: "secret", count: 2 }] }, status: 503 },
    { name: "proof label does not cover secret", reply: { redactions: [{ ...secretRedaction, label: "private_email" }] }, status: 503 },
    { name: "mixed finding lacks email proof", original: mixedOriginal, reply: { findings: mixedFindings, redactedBody: '{"content":"[SECRET] [PRIVATE_EMAIL]"}' }, status: 503 },
    { name: "Gitleaks confirmation", secretFindings: [{ category: "private-key", count: 1 }], status: 403 },
    { name: "restricted repository", repositoryClass: "restricted", status: 403 },
    { name: "restricted path", pathClasses: ["terraform_state"], status: 403 },
    { name: "managed lane", lane: "managed", status: 403 },
  ];
  for (const fixture of cases) {
    await t.test(fixture.name, async (t) => {
      const upstreamBodies = [];
      const events = [];
      let privacyScans = 0;
      const upstream = createServer((request, response) => {
        const chunks = [];
        request.on("data", (chunk) => chunks.push(chunk));
        request.on("end", () => {
          upstreamBodies.push(Buffer.concat(chunks).toString("utf8"));
          response.writeHead(200, { "content-type": "application/json" });
          response.end('{"ok":true}');
        });
      });
      upstream.listen(0, "127.0.0.1");
      await once(upstream, "listening");
      t.after(() => new Promise((resolve) => upstream.close(resolve)));
      const lane = fixture.lane ?? "subscription";
      const reply = {
        status: "ok", findings: [{ label: "secret", count: 1 }],
        redactions: [secretRedaction], redactedBody: redacted, ...fixture.reply,
      };
      const daemon = await startDaemon({
        config: {
          ...config, lane, targetClass: lane, targetOrigin: `http://127.0.0.1:${upstream.address().port}`,
          launcherContext: {
            ...config.launcherContext, destinationClass: lane,
            repository: { ...config.launcherContext.repository, trustClass: fixture.repositoryClass ?? "internal" },
            pathClasses: fixture.pathClasses ?? ["source"],
          },
        },
        paths,
        readPolicyBundle: async () => signedCompiledPolicyBundle(),
        createScanner: async () => ({ version: "8.24.0", scan: async () => ({ findings: fixture.secretFindings ?? [] }) }),
        createPrivacy: async ({ provision }) => createPrivacyFilter({
          provision,
          validateWorker: async () => {},
          spawnWorker: () => fakePrivacyWorker((message, emit) => {
            if (message.type === "health") emit(privacyHealth(message));
            else {
              privacyScans += 1;
              emit({ ...reply, type: "scan", id: message.id, redactedBody: reply.redactedBody === undefined ? undefined : Buffer.from(reply.redactedBody).toString("base64") });
            }
          }),
        }),
        createDecisionRecorder: async () => ({ recordShieldDecision: async (event) => { events.push(event); return { durable: "ack" }; } }),
        writePolicyState: async () => {},
        writeIdentity: async () => {},
      });
      t.after(() => daemon.shield.close());
      const response = await fetch(`${daemon.shield.origin}/v1/messages`, {
        method: "POST", headers: { "x-airkit-shield": config.capability }, body: fixture.original ?? original,
      });
      assert.equal(response.status, fixture.status);
      if (fixture.status === 200) {
        assert.deepEqual(await response.json(), { ok: true });
        assert.deepEqual(upstreamBodies, [fixture.body]);
        assert.equal(events[0].action, "redact");
        assert.equal(events[0].transformCount, fixture.transforms);
      } else {
        assert.deepEqual(await response.json(), { error: { code: fixture.status === 403 ? "shield_blocked" : "shield_unavailable" } });
        assert.deepEqual(upstreamBodies, []);
      }
      if (fixture.secretFindings) assert.equal(privacyScans, 0);
      assert.doesNotMatch(JSON.stringify(events), /fixture-token|alice@example/);
    });
  }
});

test("daemon blocks every privacy worker failure before a real upstream fetch", async (t) => {
  const failures = [
    { name: "unknown", handle(message, reply) { if (message.type === "health") reply(privacyHealth(message)); else reply({ type: "scan", id: message.id, status: "unknown" }); } },
    { name: "timeout", handle(message, reply) { if (message.type === "health") reply(privacyHealth(message)); } },
    { name: "malformed", handle(message, reply, worker) { if (message.type === "health") reply(privacyHealth(message)); else worker.stdout.emit("data", "not-json\n"); } },
    { name: "exit", handle(message, reply, worker) { if (message.type === "health") reply(privacyHealth(message)); else worker.emit("exit", 1); } },
    { name: "oversized", handle(message, reply, worker) { if (message.type === "health") reply(privacyHealth(message)); else worker.stdout.emit("data", "x".repeat(1_048_577)); } },
  ];
  for (const failure of failures) {
    let upstreamCalls = 0;
    const upstream = createServer((request, response) => { upstreamCalls += 1; request.resume(); response.end("wrong"); });
    upstream.listen(0, "127.0.0.1");
    await once(upstream, "listening");
    t.after(() => new Promise((resolve) => upstream.close(resolve)));
    const address = upstream.address();
    const daemon = await startDaemon({
      config: { ...config, targetOrigin: `http://127.0.0.1:${address.port}` },
      paths,
      readPolicyBundle: async () => ({ bundle: {}, publicKey: "pinned-ed25519-public-key" }),
      readAssetsProvision: async () => assetsProvision(),
      readImageProvision: async () => null,
      createPrivacy: async ({ provision }) => createPrivacyFilter({
        provision,
        spawnWorker: () => fakePrivacyWorker(failure.handle),
        validateWorker: async () => {},
        timeoutMs: 50,
      }),
      createScanner: async () => ({ version: "8.24.0", scan: async () => ({ findings: [] }) }),
      loadPolicy: async () => ({ version: "2026.09.02.4", detectorVersions: { gitleaks: "8.24.0", privacy: "privacy-1" }, async evaluate() { return { action: "allow", reasonCodes: [], redactions: [] }; } }),
      writePolicyState: async () => {},
      startProxy: async (options) => startShieldProxy({ ...options, recordShieldDecision: async () => {} }),
      writeIdentity: async () => {},
    });
    const response = await fetch(`${daemon.shield.origin}/v1/messages`, { method: "POST", headers: { "x-airkit-shield": config.capability }, body: '{"content":"privacy-raw-sentinel-must-not-escape"}' });
    assert.equal(response.status, 503, failure.name);
    assert.equal(upstreamCalls, 0, failure.name);
    await daemon.shield.close();
    await new Promise((resolve) => upstream.close(resolve));
  }
});

const PNG_BASE64 = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(24, 7)]).toString("base64");
const mediaBody = (...content) => Buffer.from(JSON.stringify({ model: "claude-sonnet-5", messages: [{ role: "user", content: [{ type: "text", text: "look" }, ...content] }] }));
const pngBlock = { type: "image", source: { type: "base64", media_type: "image/png", data: PNG_BASE64 } };
const pdfBlock = { type: "document", source: { type: "base64", media_type: "application/pdf", data: Buffer.from("%PDF-1.7 fake").toString("base64") } };

async function mediaDecide() {
  const calls = { scanner: 0, privacy: 0, policy: 0 };
  let decide;
  await startDaemon({
    config,
    paths,
    readPolicyBundle: async () => ({ bundle: {}, publicKey: "pinned-ed25519-public-key" }),
    createPrivacy: async () => ({ version: "privacy-1", async scan() { calls.privacy += 1; return { status: "ok", findings: [], redactions: [] }; }, close() {} }),
    createScanner: async () => ({ version: "8.24.0", scan: async () => { calls.scanner += 1; return { findings: [] }; } }),
    loadPolicy: async () => ({
      version: "2026.09.02.4",
      detectorVersions: { gitleaks: "8.24.0", privacy: "privacy-1" },
      async evaluate() { calls.policy += 1; return { action: "allow", reasonCodes: ["policy_allow"], approvalEligible: false, redactions: [] }; },
    }),
    writePolicyState: async () => {},
    startProxy: async (options) => { decide = options.decide; return { origin: "http://127.0.0.1:8811", close: async () => {} }; },
    writeIdentity: async () => {},
  });
  return { calls, decide: (body) => decide({ body }) };
}

test("daemon blocks a document before any scanner runs and marks the decision uncacheable", async () => {
  const { calls, decide } = await mediaDecide();
  const decision = await decide(mediaBody(pdfBlock));
  assert.equal(decision.action, "block");
  assert.deepEqual(decision.reasonCodes, ["media_document_blocked"]);
  assert.equal(decision.noCache, true);
  assert.equal(decision.documentCount, 1);
  assert.equal(decision.imageCount, 0);
  assert.equal(decision.mediaOutcome, "blocked_document");
  assert.equal(decision.transformCount, 0);
  assert.equal(decision.lane, "subscription");
  assert.equal(decision.bundleVersion, "2026.09.02.4");
  assert.deepEqual(calls, { scanner: 0, privacy: 0, policy: 0 });
});

test("daemon blocks an image it cannot inspect by source", async () => {
  const { calls, decide } = await mediaDecide();
  const decision = await decide(mediaBody({ type: "image", source: { type: "url", url: "https://example.invalid/a.png" } }));
  assert.equal(decision.action, "block");
  assert.deepEqual(decision.reasonCodes, ["media_image_source_blocked"]);
  assert.equal(decision.mediaOutcome, "blocked_source");
  assert.equal(decision.noCache, true);
  assert.deepEqual(calls, { scanner: 0, privacy: 0, policy: 0 });
});

test("daemon forwards base64 images unscanned through the normal text pipeline, uncached", async () => {
  const { calls, decide } = await mediaDecide();
  const decision = await decide(mediaBody(pngBlock, pngBlock));
  assert.equal(decision.action, "allow");
  assert.equal(decision.noCache, true);
  assert.equal(decision.imageCount, 2);
  assert.equal(decision.documentCount, 0);
  assert.equal(decision.mediaOutcome, "none");
  assert.deepEqual(calls, { scanner: 1, privacy: 1, policy: 1 });
});

test("daemon leaves media-free decisions cacheable and without media fields", async () => {
  const { decide } = await mediaDecide();
  const decision = await decide(mediaBody());
  assert.equal(decision.action, "allow");
  for (const key of ["noCache", "imageCount", "documentCount", "mediaOutcome"]) assert.equal(Object.hasOwn(decision, key), false, key);
});

test("a media walk failure is a media_scan shield failure, not a block or an allow", async () => {
  const { calls, decide } = await mediaDecide();
  const deep = Buffer.from(`{"messages":${"[".repeat(600)}${"]".repeat(600)}}`);
  await assert.rejects(decide(deep), (error) => error.shieldFailure?.stage === "media_scan" && error.shieldFailure?.reason === "media_scan_failed");
  assert.deepEqual(calls, { scanner: 0, privacy: 0, policy: 0 });
});

test("a document block through the real proxy is an audited 403 with media columns, every time", async (t) => {
  let upstreamCalls = 0;
  const upstream = createServer((request, response) => { upstreamCalls += 1; request.resume(); response.end("{}"); });
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  t.after(() => new Promise((resolve) => upstream.close(resolve)));
  const events = [];
  const recorder = createShieldDecisionRecorder({ store: { recordEvent: (event) => events.push(event) } });
  const daemon = await startDaemon({
    config: { ...config, targetOrigin: `http://127.0.0.1:${upstream.address().port}` },
    paths,
    readPolicyBundle: async () => ({ bundle: {}, publicKey: "pinned-ed25519-public-key" }),
    createDecisionRecorder: async () => recorder,
    createScanner: async () => ({ version: "8.24.0", scan: async () => ({ findings: [] }) }),
    loadPolicy: async () => ({ version: "2026.09.02.4", detectorVersions: { gitleaks: "8.24.0", privacy: "privacy-1" }, async evaluate() { return { action: "allow", reasonCodes: ["policy_allow"], redactions: [] }; } }),
    writePolicyState: async () => {},
    writeIdentity: async () => {},
  });
  t.after(() => daemon.shield.close());
  const send = (body) => fetch(`${daemon.shield.origin}/v1/messages`, { method: "POST", headers: { "x-airkit-shield": config.capability, "content-type": "application/json" }, body });

  for (let attempt = 0; attempt < 2; attempt += 1) {
    const response = await send(mediaBody(pdfBlock));
    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), { error: { code: "shield_blocked" } });
  }
  assert.equal((await send(mediaBody(pngBlock))).status, 200);

  assert.equal(upstreamCalls, 1);
  assert.deepEqual(events.map((event) => event.payload.decision_source), ["evaluated", "evaluated", "evaluated"]);
  const [blocked, , image] = events.map((event) => event.payload);
  assert.equal(blocked.action, "block");
  assert.deepEqual(blocked.reasons, ["media_document_blocked"]);
  assert.equal(blocked.media_outcome, "blocked_document");
  assert.equal(blocked.document_count, 1);
  assert.equal(blocked.image_count, 0);
  assert.equal(image.action, "allow");
  assert.equal(image.media_outcome, "none");
  assert.equal(image.image_count, 1);
  assert.doesNotMatch(JSON.stringify(events), /JVBER|example\.invalid|iVBOR/);
});

function assetsProvision() {
  return {
    version: 2,
    bundle: { version: "policy-1", sha256: "a".repeat(64), path: "/opt/ccshield/policy.json" },
    gitleaks: {
      sha256: "b".repeat(64),
      path: "/opt/ccshield/gitleaks",
      rules: { path: "/opt/ccshield/rules.toml", sha256: "c".repeat(64), version: "rules-1" },
    },
    privacy: { state: "verified", version: "privacy-1", sha256: "c".repeat(64), path: "/opt/ccshield/privacy.json", worker: { command: "/opt/ccshield/privacy-worker", args: ["--stdio"], sha256: "d".repeat(64) } },
  };
}

function privacyHealth(message) {
  return { type: "health", id: message.id, protocol: "airkit-privacy-ndjson-v1", version: "privacy-1" };
}

function fakePrivacyWorker(handle) {
  const worker = new EventEmitter();
  worker.stdout = new EventEmitter();
  worker.stderr = new EventEmitter();
  worker.stdin = {
    write(chunk) {
      const message = JSON.parse(String(chunk).trim());
      handle(message, (reply) => worker.stdout.emit("data", `${JSON.stringify(reply)}\n`), worker);
      return true;
    },
    end() {},
  };
  worker.kill = () => worker.emit("exit", 0);
  return worker;
}

function signedCompiledPolicyBundle() {
  const manifest = {
    formatVersion: 1,
    version: "2026.09.02.5",
    opaAbi: "1",
    opaWasmSdkVersion: "1.8.0",
    wasmSha256: createHash("sha256").update(compiledPolicyWasm).digest("hex"),
    detectorVersions: { gitleaks: "8.24.0", privacy: "privacy-1" },
    selfTest: {
      input: {
        lane: "subscription",
        destinationClass: "subscription",
        interactive: false,
        repositoryClass: "public",
        pathClasses: ["source"],
        secretFindings: [],
        piiFindings: [],
      },
      expected: { action: "allow", reasonCodes: [], approvalEligible: false, redactions: [] },
    },
  };
  return {
    bundle: {
      manifest,
      wasm: compiledPolicyWasm,
      signature: sign(null, Buffer.from(canonicalJson(manifest)), compiledPolicyKeyPair.privateKey).toString("base64"),
    },
    publicKey: compiledPolicyKeyPair.publicKey,
  };
}

function startDaemon(options) {
  return startShieldDaemon({
    readAssetsProvision: async () => assetsProvision(),
    readImageProvision: async () => null,
    createPrivacy: async () => ({ version: "privacy-1", async scan() { return { status: "ok", findings: [], redactions: [] }; }, close() {} }),
    createDecisionRecorder: async () => ({ recordShieldDecision: async () => ({ durable: "ack" }) }),
    ...options,
  });
}

const MASKED_PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(24, 9)]);
const imageVersions = { gitleaks: "8.24.0", image: "image-0123456789ab", privacy: "privacy-1" };

async function imageDecide({ ready = true, inspect = async (images) => images.map(() => ({ status: "ok", bytes: MASKED_PNG, maskCount: 0, lowConfidenceMasked: 0, piiFindings: [] })), evaluate, privacyScan } = {}) {
  const calls = { scanner: [], privacy: [], policy: [], inspect: [] };
  let decide;
  await startDaemon({
    config,
    paths,
    readPolicyBundle: async () => ({ bundle: {}, publicKey: "pinned-ed25519-public-key" }),
    readImageProvision: async () => ({ version: "image-0123456789ab", path: "/opt/w", sha256: "a".repeat(64) }),
    createImageScanner: async () => ({ isReady: () => ready, inspect: async (images) => { calls.inspect.push(images); return inspect(images); }, close() {} }),
    createPrivacy: async () => ({ version: "privacy-1", async scan(body) { calls.privacy.push(Buffer.from(body)); return privacyScan?.(body) ?? { status: "ok", findings: [], redactions: [] }; }, close() {} }),
    createScanner: async () => ({ version: "8.24.0", scan: async (body) => { calls.scanner.push(Buffer.from(body)); return { findings: [] }; } }),
    loadPolicy: async () => ({
      version: "2026.09.02.4",
      detectorVersions: imageVersions,
      async evaluate(input) {
        calls.policy.push(input);
        if (evaluate) return evaluate(input);
        if (input.secretFindings.length) return { action: "block", reasonCodes: ["secret"], approvalEligible: false, redactions: [] };
        if (input.piiFindings.length) return { action: "redact", reasonCodes: ["subscription-pii"], approvalEligible: false, redactions: [] };
        return { action: "allow", reasonCodes: ["policy_allow"], approvalEligible: false, redactions: [] };
      },
    }),
    writePolicyState: async () => {},
    startProxy: async (options) => { decide = options.decide; return { origin: "http://127.0.0.1:8811", close: async () => {} }; },
    writeIdentity: async () => {},
  });
  return { calls, decide: (body) => decide({ body }) };
}

const sourceOf = (body, index = 1) => JSON.parse(body.toString("utf8")).messages[0].content[index].source;
const jpegBlock = { type: "image", source: { type: "base64", media_type: "image/jpeg", data: Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(24, 3)]).toString("base64") } };

test("a provisioned worker that is not ready makes image requests unavailable before any scanner", async () => {
  const { calls, decide } = await imageDecide({ ready: false });
  await assert.rejects(decide(mediaBody(pngBlock)), (error) => error.shieldFailure?.stage === "image_scan" && error.shieldFailure?.reason === "image_unavailable");
  assert.equal(calls.scanner.length + calls.privacy.length + calls.policy.length + calls.inspect.length, 0);
  const plain = await decide(mediaBody());
  assert.equal(plain.action, "allow", "text-only requests do not wait for image readiness");
});

test("a clean text request plus a PII image is redacted with the text unchanged and the masked PNG spliced in", async () => {
  const { calls, decide } = await imageDecide({ inspect: async (images) => images.map(() => ({ status: "ok", bytes: MASKED_PNG, maskCount: 2, lowConfidenceMasked: 0, piiFindings: [{ label: "email", count: 1 }] })) });
  const decision = await decide(mediaBody(jpegBlock));
  assert.equal(decision.action, "redact");
  assert.deepEqual(sourceOf(decision.redactedBody), { type: "base64", media_type: "image/png", data: MASKED_PNG.toString("base64") });
  assert.equal(JSON.parse(decision.redactedBody.toString("utf8")).messages[0].content[0].text, "look");
  assert.equal(decision.transformCount, 2);
  assert.deepEqual(calls.policy[0].piiFindings, [{ category: "email", count: 1 }]);
  assert.deepEqual(sourceOf(calls.privacy[0]).data, MASKED_PNG.toString("base64"), "text scanners see the spliced body");
  assert.equal(calls.inspect[0][0].lastTurn, true);
});

test("an allowed clean image still leaves normalized, as a transform", async () => {
  const { decide } = await imageDecide();
  const decision = await decide(mediaBody(jpegBlock));
  assert.equal(decision.action, "redact");
  assert.deepEqual(decision.reasonCodes, ["policy_allow"]);
  assert.equal(sourceOf(decision.redactedBody).data, MASKED_PNG.toString("base64"));
  assert.equal(decision.transformCount, 1);
  assert.equal(decision.noCache, true);
});

test("a secret image blocks through policy as a confirmed secret", async () => {
  const { calls, decide } = await imageDecide({ inspect: async (images) => images.map(() => ({ status: "secret", confirmedSecret: true })) });
  const decision = await decide(mediaBody(pngBlock));
  assert.equal(decision.action, "block");
  assert.deepEqual(calls.policy[0].secretFindings, [{ category: "image-ocr-secret", count: 1 }]);
  assert.equal(calls.privacy.length, 0);
  assert.equal(Object.hasOwn(decision, "redactedBody"), false);
});

test("too many new images in the last turn is an audited block; other inspector failures are unavailable", async () => {
  const limit = await imageDecide({ inspect: async () => { throw Object.assign(new Error("x"), { code: "too_many_images" }); } });
  const blocked = await limit.decide(mediaBody(pngBlock));
  assert.equal(blocked.action, "block");
  assert.deepEqual(blocked.reasonCodes, ["media_image_limit_blocked"]);
  for (const code of ["image_timeout", "image_queue_full", "image_scan_unavailable"]) {
    const { decide } = await imageDecide({ inspect: async () => { throw Object.assign(new Error("x"), { code }); } });
    await assert.rejects(decide(mediaBody(pngBlock)), (error) => error.shieldFailure?.stage === "image_scan" && error.shieldFailure?.reason === code);
  }
});

test("text redaction runs on the spliced body, so both the text and the image are replaced", async () => {
  const privacyScan = (body) => {
    const text = body.toString("utf8");
    const start = Buffer.from(text).indexOf("look");
    return { status: "ok", findings: [{ label: "word", count: 1 }], redactions: [{ label: "word", count: 1, spans: [{ start, end: start + 4 }] }], redactedBody: Buffer.from(text.replace('"look"', '"[WORD]"')) };
  };
  const { decide } = await imageDecide({ privacyScan });
  const decision = await decide(mediaBody(jpegBlock));
  assert.equal(decision.action, "redact");
  const parsed = JSON.parse(decision.redactedBody.toString("utf8"));
  assert.equal(parsed.messages[0].content[0].text, "[WORD]");
  assert.equal(parsed.messages[0].content[1].source.data, MASKED_PNG.toString("base64"));
  assert.equal(decision.transformCount, 2);
});
