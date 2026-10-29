import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createFailureLog, readFailureLog } from "../src/shield/failure-log.mjs";
import { runShieldCli } from "../src/shield/cli.mjs";
import { startShieldProxy, createShieldFailure } from "../src/shield/proxy.mjs";
import { planLaunchdService } from "../src/shield/service.mjs";
import { shieldPaths } from "../src/shield/paths.mjs";

async function tempDir(t) {
  const dir = await mkdtemp(join(tmpdir(), "ccshield-failure-log-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

const record = (overrides = {}) => ({ ts: "2026-10-29T01:02:03.000Z", stage: "privacy_scan", reason: "model_timeout", bytes: 249442, elapsedMs: 59000, queuedMs: 12, ...overrides });

test("failure log appends one allowlisted JSON line per failure with mode 0600", async (t) => {
  const path = join(await tempDir(t), "failures.jsonl");
  const log = createFailureLog({ path });
  log.append({ ...record(), launch: "abc123", body: "secret body", redacted: "x", headers: { authorization: "Bearer y" } });
  log.append(record({ reason: "queue_timeout", queuedMs: undefined }));
  const lines = (await readFile(path, "utf8")).trim().split("\n");
  assert.equal(lines.length, 2);
  assert.deepEqual(JSON.parse(lines[0]), { ...record(), launch: "abc123" });
  assert.deepEqual(Object.keys(JSON.parse(lines[1])).sort(), ["bytes", "elapsedMs", "reason", "stage", "ts"]);
  assert.doesNotMatch(lines.join("\n"), /secret|Bearer|redacted|headers/);
  assert.equal((await stat(path)).mode & 0o777, 0o600);
});

test("failure log rotates once and stays bounded", async (t) => {
  const path = join(await tempDir(t), "failures.jsonl");
  const log = createFailureLog({ path, maxBytes: 1024 });
  for (let index = 0; index < 100; index += 1) log.append(record({ bytes: index }));
  const current = await stat(path);
  const rotated = await stat(`${path}.1`);
  assert.equal(current.size <= 1024 && rotated.size <= 1024, true);
  assert.equal(rotated.mode & 0o777, 0o600);
  const recent = await readFailureLog(path, { limit: 5 });
  assert.deepEqual(recent.map((entry) => entry.bytes), [95, 96, 97, 98, 99]);
});

test("reading the failure log tolerates a missing file and garbage lines", async (t) => {
  const dir = await tempDir(t);
  assert.deepEqual(await readFailureLog(join(dir, "missing.jsonl")), []);
  const path = join(dir, "failures.jsonl");
  await writeFile(path, `not json\n${JSON.stringify(record())}\n{"partial`, { mode: 0o600 });
  assert.deepEqual(await readFailureLog(path), [record()]);
});

test("failure log never throws into the request path", () => {
  const log = createFailureLog({ path: "/nonexistent-dir/for/sure/failures.jsonl" });
  assert.doesNotThrow(() => log.append(record()));
});

test("proxy reports each failure with timing, queue wait and a hashed launch id", async (t) => {
  const seen = [];
  const shield = await startShieldProxy({
    capability: "c".repeat(32), controlCapability: "d".repeat(32), targetOrigin: "http://127.0.0.1:9",
    decide: async () => { throw createShieldFailure("privacy_scan", "model_timeout", "timeout", { queuedMs: 1234.7 }); },
    onFailure: (entry) => seen.push(entry),
  });
  t.after(() => shield.close());
  const response = await fetch(`${shield.origin}/v1/messages`, {
    method: "POST", headers: { "x-airkit-shield": "c".repeat(32), "x-ccshield-launch": "1".repeat(32), authorization: "Bearer credential-secret" }, body: "private body text",
  });
  assert.equal(response.status, 503);
  await response.arrayBuffer();
  assert.equal(seen.length, 1);
  const [entry] = seen;
  assert.equal(entry.stage, "privacy_scan");
  assert.equal(entry.reason, "model_timeout");
  assert.equal(entry.bytes, Buffer.byteLength("private body text"));
  assert.equal(entry.queuedMs, 1234);
  assert.equal(Number.isInteger(entry.elapsedMs), true);
  assert.equal(Number.isNaN(Date.parse(entry.ts)), false);
  assert.match(entry.launch, /^[0-9a-f]{12}$/);
  assert.doesNotMatch(JSON.stringify(entry), /private|credential|1111/);
});

test("the failure cause stays in the diagnostics ring and never reaches the persisted log", async (t) => {
  const seen = [];
  const cause = new SyntaxError("Unexpected token near private body text");
  const shield = await startShieldProxy({
    capability: "c".repeat(32), controlCapability: "d".repeat(32), targetOrigin: "http://127.0.0.1:9",
    decide: async () => { throw createShieldFailure("image_scan", "image_scan_unavailable", "unavailable", { cause }); },
    onFailure: (entry) => seen.push(entry),
  });
  t.after(() => shield.close());
  const response = await fetch(`${shield.origin}/v1/messages`, { method: "POST", headers: { "x-airkit-shield": "c".repeat(32) }, body: "{}" });
  assert.equal(response.status, 503);
  await response.arrayBuffer();
  assert.equal(seen.length, 1);
  assert.equal("cause" in seen[0], false);
  assert.doesNotMatch(JSON.stringify(seen[0]), /SyntaxError|private/);
  const diagnostics = await fetch(`${shield.origin}/_airkit/shield/diagnostics`, { headers: { "x-airkit-shield-control": "d".repeat(32) } });
  const [failure] = (await diagnostics.json()).failures;
  assert.equal(failure.cause, "SyntaxError: Unexpected token near private body text");
});

test("launchd plist sends daemon stdout and stderr into the lane state dir", () => {
  const paths = shieldPaths({ env: {}, homeDir: "/Users/test", uid: 501, platform: "darwin" });
  const plan = planLaunchdService({ paths, nodePath: "/usr/bin/node", daemonPath: "/opt/ccshield/src/shieldd.mjs" });
  assert.equal(plan.plist.StandardOutPath, join(paths.rootDir, "daemon.out.log"));
  assert.equal(plan.plist.StandardErrorPath, join(paths.rootDir, "daemon.err.log"));
  assert.equal(paths.failureLogPath, join(paths.rootDir, "failures.jsonl"));
  assert.match(plan.plistXml, /<key>StandardErrorPath<\/key>\s*<string>[^<]*daemon\.err\.log<\/string>/);
});

test("doctor prints the most recent logged failures, one line each", async (t) => {
  const home = await tempDir(t);
  const output = [];
  const paths = [];
  await runShieldCli(["doctor"], {
    env: { HOME: home },
    stdout: { write: (chunk) => output.push(String(chunk)) },
    shieldStatus: async () => ({ state: "healthy" }),
    readAuditHealth: async () => ({}),
    readShieldOperationalStatus: async () => ({ lanes: [{ lane: "subscription", state: "protected" }] }),
    inspectMasterKey: async () => ({ source: "keychain" }),
    readShieldAssetsProvision: async () => null,
    doctorDetectorAssets: async () => ({ warnings: [] }),
    readFailureLog: async (path, options) => { paths.push([path, options.limit]); return [record(), record({ reason: "queue_timeout", queuedMs: undefined, launch: "abc123abc123" })]; },
  });
  assert.deepEqual(paths, [[join(home, ".local", "share", "ccshield", "subscription", "failures.jsonl"), 10]]);
  const text = output.join("");
  assert.match(text, /^recentFailures\.0: 2026-10-29T01:02:03\.000Z privacy_scan\/model_timeout bytes=249442 elapsedMs=59000 queuedMs=12$/m);
  assert.match(text, /^recentFailures\.1: 2026-10-29T01:02:03\.000Z privacy_scan\/queue_timeout bytes=249442 elapsedMs=59000 launch=abc123abc123$/m);
});
