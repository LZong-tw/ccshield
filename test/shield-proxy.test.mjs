import assert from "node:assert/strict";
import { EventEmitter, once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, request as httpRequest } from "node:http";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { gzipSync } from "node:zlib";

import { startShieldProxy } from "../src/shield/proxy.mjs";
import { createApprovalBroker } from "../src/shield/approval.mjs";
import { approvalChannelRegistration, createApprovalChannel } from "../src/shield/approval-channel.mjs";
import { createDecisionCache } from "../src/shield/decision-cache.mjs";
import { createPrivacyFilter } from "../src/shield/privacy.mjs";
import { startShieldDaemon } from "../src/shieldd.mjs";

const CAPABILITY = "c".repeat(32);
const CONTROL_CAPABILITY = "d".repeat(32);

test("diagnostics are control-only, nondestructive and never forward endpoint variants", async (t) => {
  let upstreamCalls = 0;
  const upstream = await startFixture(t, async (_request, response) => { upstreamCalls += 1; response.end('{}'); });
  const shield = await startShield(t, { targetOrigin: upstream.origin, allowDestinationLeases: true, decide: async () => { throw new Error("private-body credential-secret"); } });
  const lease = "l".repeat(32);
  assert.equal((await fetch(`${shield.origin}/_airkit/shield/destination-lease`, {
    method: "POST", headers: { "x-airkit-shield-control": CONTROL_CAPABILITY },
    body: JSON.stringify({ capability: lease, targetOrigin: upstream.origin, expiresAt: Date.now() + 30_000 }),
  })).status, 204);
  for (const headers of [{}, { "x-airkit-shield": CAPABILITY }, { "x-airkit-shield": lease }, { "x-airkit-shield-control": CAPABILITY }, { "x-airkit-shield-control": "wrong" }]) {
    const response = await fetch(`${shield.origin}/_airkit/shield/diagnostics`, { headers });
    assert.equal(response.status, 401);
    assert.equal(response.headers.get("cache-control"), "no-store");
  }
  assert.deepEqual(await readDiagnostics(shield), { failures: [] });
  for (const method of ["POST", "PUT", "DELETE", "HEAD", "OPTIONS"]) {
    assert.equal((await fetch(`${shield.origin}/_airkit/shield/diagnostics`, { method, headers: { "x-airkit-shield-control": CONTROL_CAPABILITY } })).status, 403);
  }
  for (const path of ["/_airkit/shield/diagnostics?reset=true", "/_airkit/shield/diagnostics/", "/_airkit/shield/diagnostics-extra", "/_airkit/shield/diagnostics/%2e%2e/diagnostics", "/_airkit/shield/diagnostics/../other", "/_airkit/shield/%64iagnostics", "/_airkit/shield/diagnostics%ZZ"]) {
    const reply = await rawRequest(shield.origin, path, { "x-airkit-shield-control": CONTROL_CAPABILITY, "x-airkit-shield": CAPABILITY }, "", "GET");
    assert.equal(reply.status, 403, path);
  }
  for (const path of ["/x/../_airkit/shield/diagnostics?x=%ZZ", "/_airkit/shield/%64iagnostics?x=%ZZ"]) {
    for (const headers of [{ "x-airkit-shield": CAPABILITY }, { "x-airkit-shield": lease }]) {
      const reply = await rawRequest(shield.origin, path, headers, "", "GET");
      assert.equal(reply.status, 401, path);
    }
    const reply = await rawRequest(shield.origin, path, { "x-airkit-shield-control": CONTROL_CAPABILITY }, "", "GET");
    assert.equal(reply.status, 403, path);
  }
  for (let bytes = 1; bytes <= 20; bytes += 1) {
    const response = await fetch(`${shield.origin}/v1/messages?private=query-secret`, {
      method: "POST", headers: { "x-airkit-shield": CAPABILITY, authorization: "Bearer credential-secret" }, body: "x".repeat(bytes),
    });
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: { code: "shield_unavailable" } });
  }
  const diagnostics = await readDiagnostics(shield);
  assert.equal(diagnostics.failures.length, 16);
  assert.deepEqual(diagnostics.failures.map((failure) => failure.bytes), Array.from({ length: 16 }, (_, index) => index + 5));
  for (const failure of diagnostics.failures) {
    assert.deepEqual(Object.keys(failure).sort(), ["bytes", "elapsedMs", "reason", "stage"]);
    assert.equal(failure.stage, "evaluation");
    assert.equal(failure.reason, "evaluation_unavailable");
    assert.equal(Number.isInteger(failure.elapsedMs) && failure.elapsedMs >= 0 && failure.elapsedMs <= 3_600_000, true);
  }
  assert.deepEqual(await readDiagnostics(shield), diagnostics);
  assert.doesNotMatch(JSON.stringify(diagnostics), /private|credential|query-secret|authorization|requestId|timestamp|digest/);
  assert.equal(upstreamCalls, 0);
  const fresh = await startShield(t, { targetOrigin: upstream.origin, decide: async () => ({ action: "allow" }) });
  assert.deepEqual(await readDiagnostics(fresh), { failures: [] });
});

test("diagnostics include recent scan counts only when a scan stats source is configured", async (t) => {
  const upstream = await startFixture(t, async (_request, response) => { response.end('{}'); });
  const scans = [{ status: "ok", reason: null, hits: 2, misses: 1, elapsedMs: 40 }];
  const shield = await startShield(t, { targetOrigin: upstream.origin, decide: async () => ({ action: "allow" }), scanStats: () => scans });
  assert.deepEqual(await readDiagnostics(shield), { failures: [], scans });
  await assert.rejects(startShield(t, { targetOrigin: upstream.origin, decide: async () => ({ action: "allow" }), scanStats: scans }), /scan stats source is invalid/);
});

test("diagnostics separate real daemon scan, policy and redaction failures while readiness remains healthy", async (t) => {
  let upstreamCalls = 0;
  const upstream = await startFixture(t, async (_request, response) => { upstreamCalls += 1; response.end('{}'); });
  let mode = "prediction";
  const worker = new EventEmitter();
  worker.stdout = new EventEmitter(); worker.stderr = new EventEmitter();
  worker.kill = () => {};
  worker.stdin = Object.assign(new EventEmitter(), { write(chunk) {
    const request = JSON.parse(String(chunk).trim());
    const reply = request.type === "health"
      ? { type: "health", id: request.id, protocol: request.protocol, version: "privacy-1" }
      : mode === "prediction" ? { type: "scan", id: request.id, status: "unknown", reason: "invalid-prediction", private: "prediction-secret" }
        : ["model_timeout", "model_error", "model_killed", "protocol-graph-mutation", "protocol-control-mutation", "signed-block-mutation", "invalid-source-provenance", "json-key-collision", "invalid-json-topology", "redaction-projection-limit", "redaction-match-limit", "redaction-body-limit", "redaction-frame-limit"].includes(mode) ? { type: "scan", id: request.id, status: "unknown", reason: mode, private: "worker-private-secret" }
        : mode === "unknown" ? { type: "scan", id: request.id, status: "unknown", reason: "credential-secret" }
          : { type: "scan", id: request.id, status: "ok", findings: [] };
    worker.stdout.emit("data", `${JSON.stringify(reply)}\n`);
  } });
  const gitleaks = { executable: "/private/fixture/gitleaks", sha256: "a".repeat(64), ruleBundle: { path: "/private/fixture/rules", sha256: "b".repeat(64), version: "rules-1" } };
  const daemon = await startShieldDaemon({
    config: { capability: CAPABILITY, controlCapability: CONTROL_CAPABILITY, lane: "subscription", targetOrigin: upstream.origin, gitleaks },
    paths: { configPath: "/private/fixture/config" },
    readPolicyBundle: async () => ({ bundle: {}, publicKey: "fixture" }),
    loadPolicy: async () => ({ version: "policy-1", detectorVersions: { gitleaks: "8", privacy: "privacy-1" }, async evaluate() {
      if (mode === "policy") throw new Error("policy-secret");
      return { action: mode === "redaction" ? "redact" : "allow" };
    } }),
    readAssetsProvision: async () => ({ gitleaks: { path: gitleaks.executable, sha256: gitleaks.sha256, rules: gitleaks.ruleBundle }, privacy: { version: "privacy-1", worker: { command: "/private/fixture/worker", args: [], sha256: "c".repeat(64) } } }),
    createScanner: async () => ({ version: "8", async scan() { if (mode === "secret") throw new Error("scanner-secret"); return { findings: [] }; } }),
    createPrivacy: async (options) => {
      const privacy = await createPrivacyFilter({ ...options, spawnWorker: () => worker, validateWorker: async () => {} });
      return { ...privacy, async scan(body) {
        if (mode === "privacy_throw") throw Object.assign(new Error("worker-private-secret"), { shieldFailure: { stage: "privacy_scan", reason: "credential-secret" } });
        return privacy.scan(body);
      } };
    },
    createDecisionRecorder: async () => ({ isReady: async () => true, async recordShieldDecision() { if (mode === "audit") throw new Error("audit-secret"); } }),
    writePolicyState: async () => {}, writeIdentity: async () => {},
  });
  t.after(() => daemon.shield.close());
  for (const [nextMode, stage, reason] of [
    ["prediction", "privacy_scan", "invalid-prediction"], ["unknown", "privacy_scan", "privacy_unavailable"],
    ["model_timeout", "privacy_scan", "model_timeout"], ["model_error", "privacy_scan", "model_error"], ["model_killed", "privacy_scan", "model_killed"],
    ["protocol-graph-mutation", "privacy_scan", "protocol-graph-mutation"], ["protocol-control-mutation", "privacy_scan", "protocol-control-mutation"],
    ["signed-block-mutation", "privacy_scan", "signed-block-mutation"],
    ["invalid-source-provenance", "privacy_scan", "invalid-source-provenance"], ["json-key-collision", "privacy_scan", "json-key-collision"],
    ["invalid-json-topology", "privacy_scan", "invalid-json-topology"],
    ["redaction-projection-limit", "privacy_scan", "redaction-projection-limit"], ["redaction-match-limit", "privacy_scan", "redaction-match-limit"],
    ["redaction-body-limit", "privacy_scan", "redaction-body-limit"], ["redaction-frame-limit", "privacy_scan", "redaction-frame-limit"],
    ["privacy_throw", "privacy_scan", "privacy_unavailable"],
    ["secret", "secret_scan", "scanner_unavailable"], ["policy", "policy", "policy_unavailable"],
    ["redaction", "redaction", "redaction_invalid"], ["audit", "audit", "audit_unavailable"],
  ]) {
    mode = nextMode;
    const response = await fetch(`${daemon.shield.origin}/v1/messages`, { method: "POST", headers: { "x-airkit-shield": CAPABILITY }, body: '{"private":"body-secret"}' });
    assert.equal(response.status, 503, mode);
    assert.deepEqual(await response.json(), { error: { code: "shield_unavailable" } });
    const latest = (await readDiagnostics(daemon.shield)).failures.at(-1);
    assert.equal(latest.stage, stage, mode); assert.equal(latest.reason, reason, mode);
    assert.equal(latest.bytes, 25);
    const ready = () => fetch(`${daemon.shield.origin}/_airkit/shield/ready`, { headers: { "x-airkit-shield": CAPABILITY } });
    if (["model_killed", "model_error", "model_timeout"].includes(mode)) assert.equal((await ready()).status, 503);
    assert.equal((await ready()).status, 204);
  }
  assert.equal(upstreamCalls, 0);
  assert.doesNotMatch(JSON.stringify(await readDiagnostics(daemon.shield)), /body-secret|prediction-secret|credential-secret|scanner-secret|policy-secret|audit-secret|worker-private-secret|fixture|requestId/);
  const { scans } = await readDiagnostics(daemon.shield);
  assert.equal(Array.isArray(scans) && scans.length > 0 && scans.length <= 32, true);
  for (const scan of scans) assert.deepEqual(Object.keys(scan).sort(), ["elapsedMs", "hits", "misses", "reason", "status"]);
});

test("diagnostics sanitize arbitrary metadata and separate redaction, audit and upstream failures", async (t) => {
  const redirect = await startFixture(t, async (_request, response) => { response.writeHead(302, { location: "http://127.0.0.1:1/private-secret" }); response.end(); });
  for (const [options, stage, reason] of [
    [{ decide: async () => { throw Object.assign(new Error("credential-secret"), { shieldFailure: { stage: "private-secret", reason: "credential-secret", bytes: Infinity } }); } }, "evaluation", "evaluation_unavailable"],
    [{ decide: async () => { throw Object.assign(new Error("credential-secret"), { shieldFailure: { stage: "privacy_scan", reason: "transport_unavailable" } }); } }, "evaluation", "evaluation_unavailable"],
    [{ decide: async () => ({ action: "redact", redactedBody: Buffer.from("private-secret") }) }, "redaction", "redaction_invalid"],
    [{ decide: async () => ({ action: "allow" }), recordShieldDecision: async () => { throw new Error("credential-secret"); } }, "audit", "audit_unavailable"],
    [{ decide: async () => ({ action: "allow" }), targetOrigin: "http://127.0.0.1:1" }, "upstream", "transport_unavailable"],
    [{ decide: async () => ({ action: "allow" }), targetOrigin: redirect.origin }, "upstream", "redirect_blocked"],
    [{ decide: async () => ({ action: "allow" }), targetOrigin: undefined, allowDestinationLeases: true }, "upstream", "target_unavailable"],
  ]) {
    const shield = await startShield(t, { targetOrigin: redirect.origin, ...options });
    const response = await fetch(`${shield.origin}/v1/messages`, { method: "POST", headers: { "x-airkit-shield": CAPABILITY }, body: "{}" });
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: { code: "shield_unavailable" } });
    const diagnostics = await readDiagnostics(shield);
    assert.equal(diagnostics.failures.length, 1);
    assert.equal(diagnostics.failures[0].stage, stage); assert.equal(diagnostics.failures[0].reason, reason);
    assert.doesNotMatch(JSON.stringify(diagnostics), /private-secret|credential-secret|Infinity/);
  }
});

test("diagnostics record incomplete body reads without retaining partially received content", async (t) => {
  const upstream = await startFixture(t, async (_request, response) => { assert.fail("an incomplete body must never forward"); response.end(); });
  const shield = await startShield(t, { targetOrigin: upstream.origin, decide: async () => assert.fail("an incomplete body must never be evaluated") });
  const url = new URL(shield.origin);
  const client = httpRequest({ host: url.hostname, port: url.port, method: "POST", path: "/v1/messages", headers: { "x-airkit-shield": CAPABILITY, expect: "100-continue", "content-length": "100" } });
  client.on("error", () => {});
  client.flushHeaders();
  await once(client, "continue");
  client.write("private-partial-secret");
  const closed = new Promise((resolve) => client.once("close", resolve));
  client.destroy();
  await closed;
  let diagnostics;
  for (let attempts = 0; attempts < 10; attempts += 1) {
    diagnostics = await readDiagnostics(shield);
    if (diagnostics.failures.length > 0) break;
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.equal(diagnostics.failures.length, 1);
  assert.equal(diagnostics.failures[0].stage, "body_read");
  assert.equal(diagnostics.failures[0].reason, "body_read_failed");
  assert.doesNotMatch(JSON.stringify(diagnostics), /private-partial-secret/);
});

async function readDiagnostics(shield) {
  const response = await fetch(`${shield.origin}/_airkit/shield/diagnostics`, { headers: { "x-airkit-shield-control": CONTROL_CAPABILITY } });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("content-type"), "application/json");
  const text = await response.text();
  assert.equal(Buffer.byteLength(text) < 4096, true);
  return JSON.parse(text);
}

test("proxy forwards only after allow and never emits OAuth", async (t) => {
  const events = [];
  const upstream = await startFixture(t, async (request, response) => {
    assert.equal(request.url, "/v1/messages");
    assert.equal(request.headers.authorization, "Bearer oauth-secret");
    assert.equal(request.headers.cookie, "session=cookie-secret");
    assert.equal(request.headers["x-forwarded-host"], undefined);
    assert.equal(request.headers["x-airkit-shield"], undefined);
    assert.equal(await readBody(request), '{"private":"body-secret"}');
    response.writeHead(200, { "content-type": "application/json" });
    response.end('{"type":"message"}');
  });
  const shield = await startShield(t, {
    targetOrigin: upstream.origin,
    decide: async () => ({ action: "allow" }),
    onDecision: (event) => events.push(event),
  });

  const result = await fetch(`${shield.origin}/v1/messages`, {
    method: "POST",
    headers: {
      authorization: "Bearer oauth-secret",
      cookie: "session=cookie-secret",
      "content-type": "application/json",
      "x-forwarded-host": "target-switch-secret",
      "x-airkit-shield": CAPABILITY,
    },
    body: '{"private":"body-secret"}',
  });

  assert.equal(result.status, 200);
  assert.equal(await result.text(), '{"type":"message"}');
  assert.equal(events.length, 1);
  assert.equal(events[0].action, "allow");
  assert.deepEqual(events[0].reasonCodes, ["policy_allow"]);
  assert.equal(Number.isInteger(events[0].elapsedMs), true);
  assert.doesNotMatch(JSON.stringify(events), /oauth-secret|cookie-secret|body-secret|target-switch-secret/);
});

test("proxy reuses an exact terminal decision but re-audits and forwards each retry", async (t) => {
  let decisions = 0;
  let upstreamCalls = 0;
  const events = [];
  const upstream = await startFixture(t, async (_request, response) => {
    upstreamCalls += 1;
    response.end("{}");
  });
  const shield = await startShield(t, {
    targetOrigin: upstream.origin,
    decisionCache: createDecisionCache(),
    decisionContext: { lane: "subscription", destinationClass: "subscription", policyVersion: "policy-1", detectorVersions: { gitleaks: "1", privacy: "1" } },
    decide: async () => {
      decisions += 1;
      return { action: "allow", reasonCodes: ["policy_allow"], lane: "subscription", destinationClass: "subscription", bundleVersion: "policy-1", detectorVersions: { gitleaks: "1", privacy: "1" } };
    },
    onDecision: (event) => events.push(event),
  });
  const send = (body) => fetch(`${shield.origin}/v1/messages`, {
    method: "POST", headers: { "x-airkit-shield": CAPABILITY, "content-type": "application/json" }, body,
  });

  assert.equal((await send('{"same":true}')).status, 200);
  assert.equal((await send('{"same":true}')).status, 200);
  assert.equal((await send('{"same":false}')).status, 200);
  assert.equal(decisions, 2);
  assert.equal(upstreamCalls, 3);
  assert.equal(events.length, 3);
  assert.deepEqual(events.map((event) => event.decisionSource), ["evaluated", "cache_hit", "evaluated"]);
});

test("proxy preserves atomic cache provenance in its re-audit metadata", async (t) => {
  const events = [];
  const upstream = await startFixture(t, async (_request, response) => response.end("{}"));
  const shield = await startShield(t, {
    targetOrigin: upstream.origin,
    decisionCache: {
      async getOrCompute() {
        return {
          source: "coalesced",
          decision: { action: "allow", reasonCodes: ["policy_allow"], transformCount: 0, body: Buffer.alloc(0) },
        };
      },
    },
    decisionContext: { lane: "subscription", destinationClass: "subscription", policyVersion: "policy-1", detectorVersions: { gitleaks: "1", privacy: "1" } },
    decide: async () => assert.fail("atomic cache result must avoid reevaluation"),
    onDecision: (event) => events.push(event),
  });
  const result = await rawRequest(shield.origin, "/v1/messages", {
    "x-airkit-shield": CAPABILITY, "content-type": "application/json",
  }, '{"same":true}');
  assert.equal(result.status, 200);
  assert.deepEqual(events.map((event) => event.decisionSource), ["coalesced"]);
});

test("authentication and decision failure never contact upstream", async (t) => {
  let upstreamCalls = 0;
  const upstream = await startFixture(t, async (_request, response) => {
    upstreamCalls += 1;
    response.end();
  });
  const denied = await startShield(t, {
    targetOrigin: upstream.origin,
    decide: async () => ({ action: "deny", reason: "policy" }),
  });

  const unauthenticated = await fetch(`${denied.origin}/v1/messages`, { method: "POST", body: "{}" });
  assert.equal(unauthenticated.status, 401);
  assert.deepEqual(await unauthenticated.json(), { error: { code: "shield_unauthorized" } });
  assert.equal(upstreamCalls, 0);

  const blocked = await fetch(`${denied.origin}/v1/messages`, {
    method: "POST",
    headers: { "x-airkit-shield": CAPABILITY },
    body: "{}",
  });
  assert.equal(blocked.status, 403);
  assert.deepEqual(await blocked.json(), { error: { code: "shield_blocked" } });
  assert.equal(upstreamCalls, 0);
});

test("readiness probe authenticates the live loopback listener without policy or upstream access", async (t) => {
  let decisions = 0;
  let upstreamCalls = 0;
  const upstream = await startFixture(t, async (_request, response) => {
    upstreamCalls += 1;
    response.end();
  });
  const shield = await startShield(t, {
    targetOrigin: upstream.origin,
    decide: async () => {
      decisions += 1;
      return { action: "deny" };
    },
  });

  const ready = await fetch(`${shield.origin}/_airkit/shield/ready`, {
    headers: { "x-airkit-shield": CAPABILITY },
  });
  const unauthorized = await fetch(`${shield.origin}/_airkit/shield/ready`, {
    headers: { "x-airkit-shield": "x".repeat(32) },
  });

  assert.equal(ready.status, 204);
  assert.equal(unauthorized.status, 401);
  assert.equal(decisions, 0);
  assert.equal(upstreamCalls, 0);
});

test("readiness probe fails closed when durable audit storage is unavailable", async (t) => {
  const upstream = await startFixture(t, async (_request, response) => response.end());
  const shield = await startShield(t, {
    targetOrigin: upstream.origin,
    decide: async () => ({ action: "deny" }),
    isReady: async () => false,
  });

  const ready = await fetch(`${shield.origin}/_airkit/shield/ready`, {
    headers: { "x-airkit-shield": CAPABILITY },
  });

  assert.equal(ready.status, 503);
  assert.deepEqual(await ready.json(), { error: { code: "shield_unavailable" } });
});

test("proxy has a loopback listener and refuses malformed fixed targets", async (t) => {
  const upstream = await startFixture(t, async (_request, response) => response.end());
  const shield = await startShield(t, { targetOrigin: upstream.origin, decide: async () => ({ action: "deny" }) });
  assert.equal(new URL(shield.origin).hostname, "127.0.0.1");
  await assert.rejects(
    startShieldProxy({ capability: CAPABILITY, controlCapability: CONTROL_CAPABILITY, targetOrigin: "https://user:password@example.test", decide: async () => ({ action: "deny" }) }),
    /target origin/i,
  );
});

test("scheme-relative and backslash paths cannot change the fixed upstream target", async (t) => {
  let upstreamCalls = 0;
  const upstream = await startFixture(t, async (_request, response) => {
    upstreamCalls += 1;
    response.end();
  });
  const shield = await startShield(t, { targetOrigin: upstream.origin, decide: async () => ({ action: "allow" }) });

  for (const path of ["//other.example/v1/messages", "/\\other.example/v1/messages"]) {
    const result = await rawRequest(shield.origin, path, { "x-airkit-shield": CAPABILITY }, "{}");
    assert.equal(result.status, 403);
    assert.deepEqual(JSON.parse(result.body), { error: { code: "shield_blocked" } });
  }
  assert.equal(upstreamCalls, 0);
});

test("oversized inspection is blocked before contacting upstream", async (t) => {
  let upstreamCalls = 0;
  const upstream = await startFixture(t, async (_request, response) => {
    upstreamCalls += 1;
    response.end();
  });
  const shield = await startShield(t, { targetOrigin: upstream.origin, decide: async () => ({ action: "allow" }) });
  const result = await fetch(`${shield.origin}/v1/messages`, {
    method: "POST",
    headers: { "x-airkit-shield": CAPABILITY },
    body: "x".repeat(1_048_577),
  });

  assert.equal(result.status, 403);
  assert.deepEqual(await result.json(), { error: { code: "shield_blocked" } });
  assert.equal(upstreamCalls, 0);
  const diagnostic = (await readDiagnostics(shield)).failures.at(-1);
  assert.equal(diagnostic.stage, "body_read");
  assert.equal(diagnostic.reason, "body_too_large");
  assert.equal(diagnostic.bytes, 1_048_576);
});

test("zero-body liveness probes forward to upstream without a policy decision", async (t) => {
  let upstreamCalls = 0;
  let seenMethod = null;
  let seenPath = null;
  let decisions = 0;
  const upstream = await startFixture(t, async (request, response) => {
    upstreamCalls += 1;
    seenMethod = request.method;
    seenPath = request.url;
    response.writeHead(200, { "content-type": "application/json" });
    response.end('{"ok":true}');
  });
  const shield = await startShield(t, {
    targetOrigin: upstream.origin,
    decide: async () => { decisions += 1; return { action: "allow" }; },
  });

  const head = await fetch(`${shield.origin}/api/hello`, {
    method: "HEAD",
    headers: { "x-airkit-shield": CAPABILITY },
  });
  assert.equal(head.status, 200);
  assert.equal(seenMethod, "HEAD");
  assert.equal(seenPath, "/api/hello");

  const get = await fetch(`${shield.origin}/api/hello`, {
    method: "GET",
    headers: { "x-airkit-shield": CAPABILITY, "content-length": "0" },
  });
  assert.equal(get.status, 200);

  assert.equal(upstreamCalls, 2);
  assert.equal(decisions, 0, "liveness probes must not invoke the decision function");
});

test("a body-carrying request runs the policy pipeline instead of the probe path", async (t) => {
  let upstreamCalls = 0;
  let decisions = 0;
  const upstream = await startFixture(t, async (_request, response) => {
    upstreamCalls += 1;
    response.end();
  });
  const shield = await startShield(t, {
    targetOrigin: upstream.origin,
    decide: async () => { decisions += 1; return { action: "allow" }; },
  });

  const postWithBody = await fetch(`${shield.origin}/v1/messages`, {
    method: "POST",
    headers: { "x-airkit-shield": CAPABILITY, "content-type": "application/json" },
    body: '{"prompt":"hello"}',
  });
  assert.equal(postWithBody.status, 200);
  assert.equal(decisions, 1, "a request that carries a body is not a liveness probe");
  assert.equal(upstreamCalls, 1);
});

test("proxy rejects compressed request bodies before inspection or forwarding", async (t) => {
  let upstreamCalls = 0;
  let decisions = 0;
  const upstream = await startFixture(t, async (_request, response) => {
    upstreamCalls += 1;
    response.end();
  });
  const shield = await startShield(t, {
    targetOrigin: upstream.origin,
    decide: async () => {
      decisions += 1;
      return { action: "allow" };
    },
  });

  const result = await rawRequest(shield.origin, "/v1/messages", {
    "content-encoding": "gzip",
    "x-airkit-shield": CAPABILITY,
  }, gzipSync('{"private":"compressed"}'));

  assert.equal(result.status, 403);
  assert.deepEqual(JSON.parse(result.body), { error: { code: "shield_blocked" } });
  assert.equal(decisions, 0);
  assert.equal(upstreamCalls, 0);
});

test("proxy preserves streaming upstream responses", async (t) => {
  const upstream = await startFixture(t, async (_request, response) => {
    response.writeHead(200, { "content-type": "text/event-stream" });
    response.write("data: first\n\n");
    setTimeout(() => response.end("data: second\n\n"), 5);
  });
  const shield = await startShield(t, { targetOrigin: upstream.origin, decide: async () => ({ action: "allow" }) });

  const result = await fetch(`${shield.origin}/v1/messages`, {
    method: "POST",
    headers: { "x-airkit-shield": CAPABILITY },
    body: "{}",
  });
  assert.equal(result.status, 200);
  assert.equal(result.headers.get("content-type"), "text/event-stream");
  assert.equal(await result.text(), "data: first\n\ndata: second\n\n");
});

test("proxy blocks upstream redirects before a default-following client can leave the fixed origin", async (t) => {
  let secondaryCalls = 0;
  const secondary = await startFixture(t, async (_request, response) => {
    secondaryCalls += 1;
    response.end("must not be contacted");
  });
  const upstream = await startFixture(t, async (_request, response) => {
    response.writeHead(302, { location: `${secondary.origin}/v1/messages` });
    response.end();
  });
  const shield = await startShield(t, { targetOrigin: upstream.origin, decide: async () => ({ action: "allow" }) });

  const result = await fetch(`${shield.origin}/v1/messages`, {
    method: "POST",
    headers: { "x-airkit-shield": CAPABILITY },
    body: "{}",
  });

  assert.equal(result.status, 503);
  assert.equal(result.headers.get("location"), null);
  assert.deepEqual(await result.json(), { error: { code: "shield_unavailable" } });
  assert.equal(secondaryCalls, 0);
});

test("proxy removes stale compression headers after fetch decompression", async (t) => {
  const body = '{"type":"message","content":[]}';
  const compressed = gzipSync(body);
  const upstream = await startFixture(t, async (_request, response) => {
    response.writeHead(200, {
      "content-encoding": "gzip",
      "content-length": String(compressed.byteLength),
      "content-type": "application/json",
    });
    response.end(compressed);
  });
  const shield = await startShield(t, { targetOrigin: upstream.origin, decide: async () => ({ action: "allow" }) });

  const result = await fetch(`${shield.origin}/v1/messages`, {
    method: "POST",
    headers: { "x-airkit-shield": CAPABILITY },
    body: "{}",
  });

  assert.equal(result.headers.get("content-encoding"), null);
  assert.equal(result.headers.get("content-length"), null);
  assert.equal(await result.text(), body);
});

test("proxy aborts an upstream request when the downstream client disconnects", async (t) => {
  let notifyStarted;
  let notifyClosed;
  let upstreamResponse;
  const upstreamStarted = new Promise((resolve) => { notifyStarted = resolve; });
  const upstreamClosed = new Promise((resolve) => { notifyClosed = resolve; });
  const upstream = await startFixture(t, async (request, response) => {
    await readBody(request);
    upstreamResponse = response;
    response.once("close", notifyClosed);
    notifyStarted();
    await once(response, "close");
  });
  const shield = await startShield(t, { targetOrigin: upstream.origin, decide: async () => ({ action: "allow" }) });
  const target = new URL(shield.origin);
  const client = httpRequest({
    host: target.hostname,
    port: target.port,
    method: "POST",
    path: "/v1/messages",
    headers: { "content-length": "2", "x-airkit-shield": CAPABILITY },
  });
  const clientClosed = new Promise((resolve) => client.once("close", resolve));
  client.once("error", () => {});
  client.end("{}");

  await upstreamStarted;
  client.destroy();
  await clientClosed;
  const upstreamAborted = await Promise.race([
    upstreamClosed.then(() => true),
    new Promise((resolve) => setTimeout(() => resolve(false), 250)),
  ]);
  if (!upstreamAborted) upstreamResponse.destroy();
  assert.equal(upstreamAborted, true, "upstream request was not aborted after downstream disconnect");
});

test("proxy does not forward after a downstream disconnect during decision", async (t) => {
  let releaseDecision;
  let notifyDecisionStarted;
  let observedSignal;
  let upstreamCalls = 0;
  const decisionStarted = new Promise((resolve) => { notifyDecisionStarted = resolve; });
  const upstream = await startFixture(t, async (_request, response) => {
    upstreamCalls += 1;
    response.end();
  });
  const shield = await startShield(t, {
    targetOrigin: upstream.origin,
    decide: ({ signal }) => {
      observedSignal = signal;
      notifyDecisionStarted();
      return new Promise((resolve) => { releaseDecision = () => resolve({ action: "allow" }); });
    },
  });
  const target = new URL(shield.origin);
  const client = httpRequest({
    host: target.hostname,
    port: target.port,
    method: "POST",
    path: "/v1/messages",
    headers: { "content-length": "2", "x-airkit-shield": CAPABILITY },
  });
  const clientClosed = new Promise((resolve) => client.once("close", resolve));
  client.once("error", () => {});
  client.end("{}");

  await decisionStarted;
  client.destroy();
  await clientClosed;
  await new Promise((resolve) => setTimeout(resolve, 25));
  const decisionAborted = observedSignal?.aborted === true;
  releaseDecision();
  await new Promise((resolve) => setTimeout(resolve, 25));

  assert.equal(decisionAborted, true, "decision did not receive the downstream lifecycle abort");
  assert.equal(upstreamCalls, 0);
});

test("proxy does not forward when the downstream disconnects as inspection completes", async (t) => {
  let upstreamCalls = 0;
  const upstream = await startFixture(t, async (_request, response) => {
    upstreamCalls += 1;
    response.end();
  });
  const shield = await startShield(t, { targetOrigin: upstream.origin, decide: async () => ({ action: "allow" }) });
  const target = new URL(shield.origin);
  const client = httpRequest({
    host: target.hostname,
    port: target.port,
    method: "POST",
    path: "/v1/messages",
    headers: { "content-length": "2", "x-airkit-shield": CAPABILITY },
  });
  const clientClosed = new Promise((resolve) => client.once("close", resolve));
  client.once("error", () => {});
  client.end("{}");
  setImmediate(() => client.destroy());

  await clientClosed;
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(upstreamCalls, 0);
});

test("decision exceptions are unavailable and diagnostics never contain credentials or body", async (t) => {
  let upstreamCalls = 0;
  const events = [];
  const upstream = await startFixture(t, async (_request, response) => {
    upstreamCalls += 1;
    response.end();
  });
  const shield = await startShield(t, {
    targetOrigin: upstream.origin,
    decide: async () => { throw new Error("oauth-secret body-secret cookie-secret"); },
    onDecision: (event) => events.push(event),
  });
  const result = await fetch(`${shield.origin}/v1/messages`, {
    method: "POST",
    headers: {
      authorization: "Bearer oauth-secret",
      cookie: "session=cookie-secret",
      "x-airkit-shield": CAPABILITY,
    },
    body: "body-secret",
  });

  assert.equal(result.status, 503);
  assert.deepEqual(await result.json(), { error: { code: "shield_unavailable" } });
  assert.equal(upstreamCalls, 0);
  assert.deepEqual(events, []);
  assert.doesNotMatch(JSON.stringify(events), /oauth-secret|cookie-secret|body-secret/);
});

test("proxy durably records the policy action and reason before its first upstream fetch", async (t) => {
  const terminal = [];
  let upstreamCalls = 0;
  const upstream = await startFixture(t, async (_request, response) => {
    upstreamCalls += 1;
    assert.equal(terminal.length, 1, "audit gate must precede upstream fetch");
    response.end("ok");
  });
  const shield = await startShield(t, {
    targetOrigin: upstream.origin,
    decide: async () => ({
      action: "allow",
      reasonCodes: ["policy_allow"],
      lane: "subscription",
      destinationClass: "subscription",
      bundleVersion: "2026.09.02",
      detectorVersions: { gitleaks: "8.24.3" },
    }),
    recordShieldDecision: async (decision) => terminal.push(decision),
  });

  const result = await fetch(`${shield.origin}/v1/messages`, {
    method: "POST",
    headers: { "x-airkit-shield": CAPABILITY },
    body: "body-secret",
  });
  assert.equal(result.status, 200);
  assert.equal(upstreamCalls, 1);
  assert.equal(terminal.length, 1);
  assert.equal(terminal[0].action, "allow");
  assert.deepEqual(terminal[0].reasonCodes, ["policy_allow"]);
  assert.doesNotMatch(JSON.stringify(terminal), /body-secret|digest|\/v1\/messages/);
});

test("proxy forwards only a newly validated policy redaction buffer and never persists either body", async (t) => {
  const original = '{"content":"privacy-raw-sentinel-must-not-escape"}';
  const redacted = Buffer.from('{"content":"[EMAIL]"}');
  let upstreamBody = null;
  let terminal = null;
  const upstream = await startFixture(t, async (request, response) => {
    upstreamBody = await readBody(request);
    response.end("ok");
  });
  const shield = await startShield(t, {
    targetOrigin: upstream.origin,
    decide: async () => ({
      action: "redact",
      redactedBody: redacted,
      transformCount: 1,
      reasonCodes: ["pii_email_redacted"],
      lane: "subscription",
      destinationClass: "subscription",
      bundleVersion: "2026.09.02.4",
      detectorVersions: { privacy: "privacy-1", gitleaks: "8.24.0" },
    }),
    recordShieldDecision: async (decision) => { terminal = decision; },
  });

  const response = await fetch(`${shield.origin}/v1/messages`, {
    method: "POST",
    headers: { "x-airkit-shield": CAPABILITY, "content-type": "application/json" },
    body: original,
  });
  assert.equal(response.status, 200);
  assert.equal(upstreamBody, redacted.toString("utf8"));
  assert.equal(redacted.toString("utf8"), '{"content":"[EMAIL]"}');
  assert.equal(terminal.action, "redact");
  assert.equal(terminal.transformCount, 1);
  assert.doesNotMatch(JSON.stringify(terminal), /privacy-raw|\[EMAIL\]/);
});

test("proxy blocks malformed redaction instead of forwarding the original request", async (t) => {
  let upstreamCalls = 0;
  const upstream = await startFixture(t, async (_request, response) => { upstreamCalls += 1; response.end("wrong"); });
  const shield = await startShield(t, {
    targetOrigin: upstream.origin,
    decide: async () => ({ action: "redact", redactedBody: Buffer.from("not json"), transformCount: 1 }),
  });
  const response = await fetch(`${shield.origin}/v1/messages`, {
    method: "POST", headers: { "x-airkit-shield": CAPABILITY }, body: '{"content":"privacy-raw-sentinel-must-not-escape"}',
  });
  assert.equal(response.status, 503);
  assert.equal(upstreamCalls, 0);
});

test("approval and audit unavailability block before upstream fetch with generic responses", async (t) => {
  let upstreamCalls = 0;
  const upstream = await startFixture(t, async (_request, response) => {
    upstreamCalls += 1;
    response.end();
  });
  const requireApproval = () => ({
    action: "require_approval",
    reasonCodes: ["internal_repository_code"],
    lane: "subscription",
    destinationClass: "subscription",
    bundleVersion: "2026.09.02",
    detectorVersions: { gitleaks: "8.24.3" },
  });
  const headless = await startShield(t, {
    targetOrigin: upstream.origin,
    decide: async () => requireApproval(),
    recordShieldDecision: async () => {},
  });
  const denied = await fetch(`${headless.origin}/v1/messages`, {
    method: "POST", headers: { "x-airkit-shield": CAPABILITY }, body: "body-secret",
  });
  assert.equal(denied.status, 403);
  assert.deepEqual(await denied.json(), { error: { code: "shield_blocked" } });

  const auditDown = await startShield(t, {
    targetOrigin: upstream.origin,
    decide: async () => ({ ...requireApproval(), action: "allow", reasonCodes: ["policy_allow"] }),
    recordShieldDecision: async () => { throw new Error("audit secret/path/body"); },
  });
  const unavailable = await fetch(`${auditDown.origin}/v1/messages`, {
    method: "POST", headers: { "x-airkit-shield": CAPABILITY }, body: "body-secret",
  });
  assert.equal(unavailable.status, 503);
  assert.deepEqual(await unavailable.json(), { error: { code: "shield_unavailable" } });
  assert.equal(upstreamCalls, 0);
});

test("proxy scopes approval with evaluated lane, destination, and policy versions", async (t) => {
  let upstreamCalls = 0;
  let approvalScope;
  let terminal;
  const upstream = await startFixture(t, async (_request, response) => {
    upstreamCalls += 1;
    response.end("ok");
  });
  const grant = {};
  const shield = await startShield(t, {
    targetOrigin: upstream.origin,
    approvalBroker: {
      async request(scope) { approvalScope = scope; return grant; },
      consume(receivedGrant, scope) { return receivedGrant === grant && scope === approvalScope; },
    },
    decide: async () => ({
      action: "require_approval",
      reasonCodes: ["internal_repository_code"],
      lane: "subscription",
      destinationClass: "subscription",
      bundleVersion: "2026.09.02.2",
      detectorVersions: { gitleaks: "8.24.0" },
    }),
    recordShieldDecision: async (decision) => { terminal = decision; },
  });

  const result = await fetch(`${shield.origin}/v1/messages`, {
    method: "POST", headers: { "x-airkit-shield": CAPABILITY }, body: "body-secret",
  });
  assert.equal(result.status, 200);
  assert.equal(upstreamCalls, 1);
  assert.deepEqual({
    bundleVersion: approvalScope.bundleVersion,
    destinationClass: approvalScope.destinationClass,
    reasonCodes: approvalScope.reasonCodes,
  }, {
    bundleVersion: "2026.09.02.2",
    destinationClass: "subscription",
    reasonCodes: ["internal_repository_code"],
  });
  assert.match(approvalScope.digest, /^[a-f0-9]{64}$/);
  assert.equal(terminal.lane, "subscription");
  assert.equal(terminal.destinationClass, "subscription");
  assert.equal(terminal.bundleVersion, "2026.09.02.2");
  assert.deepEqual(terminal.detectorVersions, { gitleaks: "8.24.0" });
  assert.doesNotMatch(JSON.stringify(terminal), /body-secret|digest/);
});

test("proxy obtains one approval through the launcher-registered private channel and ignores channel headers upstream", async (t) => {
  let upstreamHeaders = null;
  const upstream = await startFixture(t, async (request, response) => {
    upstreamHeaders = request.headers;
    request.resume();
    response.end('{"ok":true}');
  });
  const directory = await mkdtemp(join(tmpdir(), "airkit-shield-approval-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const channel = await createApprovalChannel({
    directory,
    capability: "a".repeat(32),
    broker: createApprovalBroker({ tty: { interactive: true, write() {}, prompt: async () => "y" } }),
  });
  t.after(() => channel.close());
  const shield = await startShield(t, {
    targetOrigin: upstream.origin,
    decide: async () => ({ action: "require_approval", reasonCodes: ["internal-subscription"], lane: "subscription", destinationClass: "subscription", bundleVersion: "policy-1", detectorVersions: { gitleaks: "8", privacy: "1" } }),
  });
  await registerApprovalChannel(shield, channel);
  const headers = { "x-airkit-shield": CAPABILITY };
  assert.equal((await fetch(`${shield.origin}/v1/messages`, { method: "POST", headers, body: '{"content":"ordinary"}' })).status, 200);
  assert.equal((await fetch(`${shield.origin}/v1/messages`, { method: "POST", headers, body: '{"content":"ordinary"}' })).status, 403);
  assert.equal(upstreamHeaders["x-airkit-shield-approval"], undefined);
  assert.equal(upstreamHeaders["x-airkit-shield-approval-socket"], undefined);
});

test("proxy blocks a client-spoofed approval socket even when it reports approval", async (t) => {
  let upstreamCalls = 0;
  const upstream = await startFixture(t, (_request, response) => { upstreamCalls += 1; response.end(); });
  const directory = await mkdtemp(join(tmpdir(), "airkit-shield-approval-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const channel = await createApprovalChannel({
    directory,
    capability: "a".repeat(32),
    broker: createApprovalBroker({ tty: { interactive: true, write() {}, prompt: async () => "n" } }),
  });
  t.after(() => channel.close());
  const attacker = createNetServer((socket) => socket.end('{"approved":true}'));
  const attackerSocket = join(directory, "attacker.sock");
  await new Promise((resolve) => attacker.listen(attackerSocket, resolve));
  t.after(() => new Promise((resolve) => attacker.close(resolve)));
  const shield = await startShield(t, {
    targetOrigin: upstream.origin,
    decide: async () => ({ action: "require_approval", reasonCodes: ["internal-subscription"], lane: "subscription", destinationClass: "subscription", bundleVersion: "policy-1", detectorVersions: { gitleaks: "8", privacy: "1" } }),
  });
  const normalTransportRegistration = await fetch(`${shield.origin}/_airkit/shield/approval-channel`, {
    method: "POST",
    headers: { "x-airkit-shield": CAPABILITY, "content-type": "application/json" },
    body: JSON.stringify({ socketPath: attackerSocket, capability: "b".repeat(32) }),
  });
  assert.equal(normalTransportRegistration.status, 401);
  const beforeRegistration = await fetch(`${shield.origin}/v1/messages`, {
    method: "POST", headers: { "x-airkit-shield": CAPABILITY }, body: '{"content":"ordinary"}',
  });
  assert.equal(beforeRegistration.status, 403);
  await registerApprovalChannel(shield, channel);
  const response = await fetch(`${shield.origin}/v1/messages`, {
    method: "POST",
    headers: {
      "x-airkit-shield": CAPABILITY,
      "x-airkit-shield-approval-socket": attackerSocket,
      "x-airkit-shield-approval": "b".repeat(32),
    },
    body: '{"content":"ordinary"}',
  });
  assert.equal(response.status, 403);
  assert.equal(upstreamCalls, 0);
});

test("approval channel registration is control-only and can be replaced after lifecycle unregister", async (t) => {
  const firstDirectory = await mkdtemp("/tmp/as1-");
  const secondDirectory = await mkdtemp("/tmp/as2-");
  t.after(() => rm(firstDirectory, { recursive: true, force: true }));
  t.after(() => rm(secondDirectory, { recursive: true, force: true }));
  const broker = createApprovalBroker({ tty: { interactive: true, write() {}, prompt: async () => "n" } });
  const first = await createApprovalChannel({ directory: firstDirectory, capability: "a".repeat(32), broker });
  const second = await createApprovalChannel({ directory: secondDirectory, capability: "b".repeat(32), broker });
  t.after(() => first.close());
  t.after(() => second.close());
  const shield = await startShield(t, {
    targetOrigin: "https://api.anthropic.com",
    decide: async () => ({ action: "require_approval", reasonCodes: ["internal-subscription"], lane: "subscription", destinationClass: "subscription", bundleVersion: "policy-1", detectorVersions: { gitleaks: "8", privacy: "1" } }),
  });
  await registerApprovalChannel(shield, first);
  const secondWhileBound = await fetch(`${shield.origin}/_airkit/shield/approval-channel`, {
    method: "POST", headers: { "x-airkit-shield-control": CONTROL_CAPABILITY, "content-type": "application/json" }, body: JSON.stringify(approvalChannelRegistration(second)),
  });
  assert.equal(secondWhileBound.status, 403);
  const normalDelete = await fetch(`${shield.origin}/_airkit/shield/approval-channel`, { method: "DELETE", headers: { "x-airkit-shield": CAPABILITY } });
  assert.equal(normalDelete.status, 401);
  const unregister = await fetch(`${shield.origin}/_airkit/shield/approval-channel`, { method: "DELETE", headers: { "x-airkit-shield-control": CONTROL_CAPABILITY } });
  assert.equal(unregister.status, 204);
  const secondRegistration = await fetch(`${shield.origin}/_airkit/shield/approval-channel`, {
    method: "POST", headers: { "x-airkit-shield-control": CONTROL_CAPABILITY, "content-type": "application/json" }, body: JSON.stringify(approvalChannelRegistration(second)),
  });
  assert.equal(secondRegistration.status, 204);
});

async function registerApprovalChannel(shield, channel) {
  const response = await fetch(`${shield.origin}/_airkit/shield/approval-channel`, {
    method: "POST",
    headers: { "x-airkit-shield-control": CONTROL_CAPABILITY, "content-type": "application/json" },
    body: JSON.stringify(approvalChannelRegistration(channel)),
  });
  assert.equal(response.status, 204);
}

test("managed destination leases are control-authenticated, session-scoped, and revocable", async (t) => {
  let calls = 0;
  let observedContext = null;
  const upstream = await startFixture(t, async (_request, response) => { calls += 1; response.end("ok"); });
  const lease = "d".repeat(32);
  const shield = await startShield(t, {
    targetOrigin: undefined,
    allowDestinationLeases: true,
    decide: async ({ launcherContext }) => {
      observedContext = launcherContext;
      return { action: "allow", reasonCodes: ["policy_allow"], lane: "managed", destinationClass: "managed", bundleVersion: "policy-1", detectorVersions: { gitleaks: "8", privacy: "1" } };
    },
  });
  const unregistered = await fetch(`${shield.origin}/v1/messages`, { method: "POST", headers: { "x-airkit-shield": lease }, body: "{}" });
  assert.equal(unregistered.status, 401);
  const registered = await fetch(`${shield.origin}/_airkit/shield/destination-lease`, {
    method: "POST", headers: { "x-airkit-shield-control": CONTROL_CAPABILITY, "content-type": "application/json" }, body: JSON.stringify({ capability: lease, targetOrigin: upstream.origin, expiresAt: Date.now() + 30_000, launcherContext: { repository: { remoteHash: "a".repeat(64), trustClass: "internal" }, pathClasses: ["source"], destinationClass: "managed", interactive: true } }),
  });
  assert.equal(registered.status, 204);
  const forwarded = await fetch(`${shield.origin}/v1/messages`, { method: "POST", headers: { "x-airkit-shield": lease }, body: "{}" });
  assert.equal(forwarded.status, 200);
  assert.equal(calls, 1);
  assert.deepEqual(observedContext, { repository: { remoteHash: "a".repeat(64), trustClass: "internal" }, pathClasses: ["source"], destinationClass: "managed", interactive: true });
  const replay = await fetch(`${shield.origin}/_airkit/shield/destination-lease`, {
    method: "POST", headers: { "x-airkit-shield-control": CONTROL_CAPABILITY, "content-type": "application/json" }, body: JSON.stringify({ capability: lease, targetOrigin: upstream.origin, expiresAt: Date.now() + 30_000 }),
  });
  assert.equal(replay.status, 403);
  const renewed = await fetch(`${shield.origin}/_airkit/shield/destination-lease`, {
    method: "POST", headers: { "x-airkit-shield-control": CONTROL_CAPABILITY, "content-type": "application/json" }, body: JSON.stringify({ capability: lease, targetOrigin: upstream.origin, expiresAt: Date.now() + 30_000, renew: true }),
  });
  assert.equal(renewed.status, 204);
  const revoked = await fetch(`${shield.origin}/_airkit/shield/destination-lease`, { method: "DELETE", headers: { "x-airkit-shield-control": CONTROL_CAPABILITY, "content-type": "application/json" }, body: JSON.stringify({ capability: lease }) });
  assert.equal(revoked.status, 204);
  const afterRevoke = await fetch(`${shield.origin}/v1/messages`, { method: "POST", headers: { "x-airkit-shield": lease }, body: "{}" });
  assert.equal(afterRevoke.status, 401);
  assert.equal(calls, 1);
});

test("expired destination leases are removed before they can forward without renewal", async (t) => {
  let now = 1_000_000;
  let calls = 0;
  const upstream = await startFixture(t, async (_request, response) => { calls += 1; response.end("ok"); });
  const lease = "e".repeat(32);
  const shield = await startShield(t, {
    targetOrigin: undefined,
    allowDestinationLeases: true,
    now: () => now,
    decide: async () => ({ action: "allow", reasonCodes: ["policy_allow"], lane: "managed", destinationClass: "managed", bundleVersion: "policy-1", detectorVersions: { gitleaks: "8", privacy: "1" } }),
  });
  const registered = await fetch(`${shield.origin}/_airkit/shield/destination-lease`, {
    method: "POST", headers: { "x-airkit-shield-control": CONTROL_CAPABILITY, "content-type": "application/json" }, body: JSON.stringify({ capability: lease, targetOrigin: upstream.origin, expiresAt: now + 1_000 }),
  });
  assert.equal(registered.status, 204);
  now += 1_001;
  const expired = await fetch(`${shield.origin}/v1/messages`, { method: "POST", headers: { "x-airkit-shield": lease }, body: "{}" });
  assert.equal(expired.status, 401);
  assert.equal(calls, 0);
  const renewalAfterExpiry = await fetch(`${shield.origin}/_airkit/shield/destination-lease`, {
    method: "POST", headers: { "x-airkit-shield-control": CONTROL_CAPABILITY, "content-type": "application/json" }, body: JSON.stringify({ capability: lease, targetOrigin: upstream.origin, expiresAt: now + 1_000, renew: true }),
  });
  assert.equal(renewalAfterExpiry.status, 403, "renewal cannot recreate an expired session lease");
  const reusedAfterExpiry = await fetch(`${shield.origin}/_airkit/shield/destination-lease`, {
    method: "POST", headers: { "x-airkit-shield-control": CONTROL_CAPABILITY, "content-type": "application/json" }, body: JSON.stringify({ capability: lease, targetOrigin: upstream.origin, expiresAt: now + 1_000 }),
  });
  assert.equal(reusedAfterExpiry.status, 204, "expiry cleanup permits a fresh session registration");
});

test("lease renewal cannot revive a capability after control revocation", async (t) => {
  const upstream = await startFixture(t, async (_request, response) => response.end("ok"));
  const lease = "f".repeat(32);
  const shield = await startShield(t, {
    targetOrigin: undefined,
    allowDestinationLeases: true,
    decide: async () => ({ action: "allow", reasonCodes: ["policy_allow"], lane: "managed", destinationClass: "managed", bundleVersion: "policy-1", detectorVersions: { gitleaks: "8", privacy: "1" } }),
  });
  const headers = { "x-airkit-shield-control": CONTROL_CAPABILITY, "content-type": "application/json" };
  const create = await fetch(`${shield.origin}/_airkit/shield/destination-lease`, { method: "POST", headers, body: JSON.stringify({ capability: lease, targetOrigin: upstream.origin, expiresAt: Date.now() + 30_000 }) });
  assert.equal(create.status, 204);
  const revoke = await fetch(`${shield.origin}/_airkit/shield/destination-lease`, { method: "DELETE", headers, body: JSON.stringify({ capability: lease }) });
  assert.equal(revoke.status, 204);
  const renew = await fetch(`${shield.origin}/_airkit/shield/destination-lease`, { method: "POST", headers, body: JSON.stringify({ capability: lease, targetOrigin: upstream.origin, expiresAt: Date.now() + 30_000, renew: true }) });
  assert.equal(renew.status, 403);
});

async function startShield(t, options) {
  const shield = await startShieldProxy({
    capability: CAPABILITY,
    controlCapability: CONTROL_CAPABILITY,
    ...(options.recordShieldDecision || options.onDecision ? options : { ...options, recordShieldDecision: async () => {} }),
  });
  t.after(() => shield.close());
  return shield;
}

async function startFixture(t, handler) {
  const server = createServer((request, response) => void handler(request, response));
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const address = server.address();
  return { origin: `http://127.0.0.1:${address.port}` };
}

function rawRequest(origin, path, headers, body, method = "POST") {
  const target = new URL(origin);
  return new Promise((resolve, reject) => {
    const client = httpRequest({
      host: target.hostname,
      port: target.port,
      method,
      path,
      headers: { ...headers, "content-length": String(Buffer.byteLength(body)) },
    }, async (response) => {
      const chunks = [];
      for await (const chunk of response) chunks.push(chunk);
      resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString("utf8") });
    }).once("error", reject);
    client.end(body);
  });
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}
