import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { chmod, mkdtemp, realpath, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { buildOpfWorkerArgs } from "../src/shield/opf-args.mjs";
import { shieldPaths } from "../src/shield/paths.mjs";
import { attestShieldCheckpoint } from "../src/shield/checkpoint.mjs";
import { createPrivacyFilter, isVerifiedRedaction, privacyWorkerEnv, runPrivacyWorkerSelfTest } from "../src/shield/privacy.mjs";

const sentinel = "privacy-raw-sentinel-must-not-escape";
const provision = {
  privacy: {
    version: "privacy-1",
    worker: { command: "/opt/ccshield/privacy-worker", args: ["--stdio"], sha256: "a".repeat(64) },
  },
};
const opfProvision = {
  privacy: {
    ...provision.privacy,
    checkpoint: { path: "/opt/ccshield/model", sha256: "b".repeat(64), version: "opf-2026-09" },
    source: { path: "/opt/ccshield/opf-source", sha256: "c".repeat(64), version: "opf-source-1" },
    adapter: { path: "/opt/ccshield/opf-adapter.mjs", sha256: "d".repeat(64) },
    tokenizer: { path: "/opt/ccshield/tiktoken-cache/fb374d419588a4632f3f557e76b4b70aebbca790", sha256: "e".repeat(64), version: "o200k_base" },
  },
};
opfProvision.privacy.worker = { ...opfProvision.privacy.worker,
  args: buildOpfWorkerArgs({ ...opfProvision.privacy, python: "/opt/ccshield/python", scanTimeoutMs: 2_000 }) };
const validateWorker = async () => {};
const validateFile = async () => {};

test("persistent privacy worker health-checks then returns a validated redacted JSON buffer", async (t) => {
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit({ type: "health", id: message.id, protocol: "airkit-privacy-ndjson-v1", version: "privacy-1" });
    if (message.type === "scan") emit({
      type: "scan", id: message.id, status: "ok", findings: [{ label: "email", count: 1 }],
      redactedBody: Buffer.from('{"content":"[EMAIL]"}').toString("base64"),
    });
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker });
  t.after(() => filter.close());

  const result = await filter.scan(Buffer.from(`{"content":"${sentinel}"}`));
  assert.equal(result.status, "ok");
  assert.deepEqual(result.findings, [{ label: "email", count: 1 }]);
  assert.deepEqual(result.redactedBody, Buffer.from('{"content":"[EMAIL]"}'));
  assert.equal(result.redactedBody.equals(Buffer.from(`{"content":"${sentinel}"}`)), false);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(sentinel));
  assert.equal(worker.messages.filter((entry) => entry.type === "health").length, 1);
  assert.equal(worker.messages.filter((entry) => entry.type === "scan").length, 1);
});

test("recent scans keep an allowlisted protocol-graph detail and drop any other", async (t) => {
  const replies = [
    { status: "unknown", reason: "invalid-protocol-graph", detail: "orphan" },
    { status: "unknown", reason: "protocol-id-limit", detail: "limit" },
    { status: "unknown", reason: "invalid-protocol-graph", detail: sentinel },
    { status: "unknown", reason: "model_timeout", detail: "orphan" },
    { status: "ok", findings: [], detail: "duplicate" },
  ];
  let next = 0;
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit({ ...health(message), capabilities: ["cooperative-timeout"] });
    if (message.type === "scan") emit({ type: "scan", id: message.id, ...replies[next++] });
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker });
  t.after(() => filter.close());
  for (let index = 0; index < replies.length; index += 1) {
    const result = await filter.scan(Buffer.from(`{"n":${index}}`));
    assert.equal("detail" in result, false);
  }
  assert.deepEqual(filter.recentScans().map((scan) => [scan.reason, scan.detail]), [
    ["invalid-protocol-graph", "orphan"],
    ["protocol-id-limit", "limit"],
    ["invalid-protocol-graph", undefined],
    ["model_timeout", undefined],
    [null, undefined],
  ]);
  assert.doesNotMatch(JSON.stringify(filter.recentScans()), new RegExp(sentinel));
});

test("recent scans keep only bounded window cache counts, status and allowlisted reasons", async (t) => {
  const replies = [
    { status: "ok", findings: [], cache: { hits: 3, misses: 1 } },
    { status: "unknown", reason: "model_timeout", cache: { hits: 0, misses: 2 } },
    { status: "ok", findings: [], cache: { hits: -1, misses: 1 } },
    { status: "ok", findings: [], cache: { hits: 1, misses: 65_537 } },
    { status: "ok", findings: [], cache: { hits: 1.5, misses: 0, private: sentinel } },
    { status: "unknown", reason: sentinel },
    { status: "ok", findings: [], segmentHits: 40, segmentMisses: 2 },
    { status: "ok", findings: [], segmentHits: -1, segmentMisses: 2 },
    { status: "ok", findings: [], segmentHits: 1, segmentMisses: 65_537 },
    { status: "ok", findings: [], segmentHits: "3", segmentMisses: 0 },
    { status: "unknown", reason: "segment-coverage", segmentHits: 4, segmentMisses: 1 },
    { status: "unknown", reason: "segment-cache-invalid" },
  ];
  let next = 0;
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit({ ...health(message), capabilities: ["cooperative-timeout"] });
    if (message.type === "scan") emit({ type: "scan", id: message.id, ...replies[next++ % replies.length] });
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker });
  t.after(() => filter.close());
  assert.deepEqual(filter.recentScans(), []);
  for (let index = 0; index < replies.length; index += 1) {
    const result = await filter.scan(Buffer.from('{}'));
    assert.equal("cache" in result, false);
    assert.equal("segmentHits" in result || "segmentMisses" in result, false);
  }
  const scans = filter.recentScans();
  const counts = { segmentHits: null, segmentMisses: null, attached: 0 };
  assert.deepEqual(scans.map(({ elapsedMs, queuedMs, ...scan }) => scan), [
    { status: "ok", reason: null, hits: 3, misses: 1, ...counts },
    { status: "unknown", reason: "model_timeout", hits: 0, misses: 2, ...counts },
    { status: "ok", reason: null, hits: null, misses: null, ...counts },
    { status: "ok", reason: null, hits: null, misses: null, ...counts },
    { status: "ok", reason: null, hits: null, misses: null, ...counts },
    { status: "unknown", reason: "privacy_unavailable", hits: null, misses: null, ...counts },
    { status: "ok", reason: null, hits: null, misses: null, ...counts, segmentHits: 40, segmentMisses: 2 },
    { status: "ok", reason: null, hits: null, misses: null, ...counts },
    { status: "ok", reason: null, hits: null, misses: null, ...counts },
    { status: "ok", reason: null, hits: null, misses: null, ...counts },
    { status: "unknown", reason: "segment-coverage", hits: null, misses: null, ...counts, segmentHits: 4, segmentMisses: 1 },
    { status: "unknown", reason: "segment-cache-invalid", hits: null, misses: null, ...counts },
  ]);
  for (const scan of scans) assert.equal(Number.isInteger(scan.elapsedMs) && scan.elapsedMs >= 0 && Number.isInteger(scan.queuedMs) && scan.queuedMs >= 0, true);
  assert.doesNotMatch(JSON.stringify(scans), new RegExp(sentinel));
  scans[0].hits = 99;
  assert.equal(filter.recentScans()[0].hits, 3);
  const totals = filter.scanTotals();
  assert.deepEqual({ ...totals, failuresByReason: { ...totals.failuresByReason } }, {
    scans: 12, ok: 8, unknown: 4, unavailable: 0, coalesced: 0, aborted: 0,
    failuresByReason: { admission_limit: 0, queue_timeout: 0, scan_timeout: 0, model_timeout: 1, model_error: 0, model_killed: 0, worker_unavailable: 0, other: 3 },
  });
  assert.doesNotMatch(JSON.stringify(totals), new RegExp(sentinel));
  for (let index = 0; index < 40; index += 1) await filter.scan(Buffer.from('{}'));
  assert.equal(filter.recentScans().length, 32);
  assert.equal(filter.scanTotals().scans, 52, "totals keep counting after the recent window rolls over");
});

test("recent scans split queue wait from scan time", async (t) => {
  const { filter, complete, fill } = await retryAfterFilter(t);
  const scans = await fill(2);
  await complete(2_000);
  await complete(500);
  await Promise.all(scans);
  assert.deepEqual(filter.recentScans().map(({ queuedMs, elapsedMs }) => ({ queuedMs, elapsedMs })), [
    { queuedMs: 0, elapsedMs: 2_000 },
    { queuedMs: 2_000, elapsedMs: 500 },
  ]);
});

test("scan totals count every caller outcome since start, including rejections that never reach the worker", async (t) => {
  const { filter, complete, fill } = await retryAfterFilter(t);
  const held = await fill(4);
  const shared = filter.scan(Buffer.from(JSON.stringify({ body: 3 })));
  const controller = new AbortController();
  const abandoned = filter.scan(Buffer.from(JSON.stringify({ body: 2 })), { signal: controller.signal });
  controller.abort();
  assert.equal((await abandoned).reason, "aborted");
  assert.equal((await filter.scan(Buffer.from('{"content":"extra"}'))).reason, "admission_limit");
  for (let index = 0; index < 4; index += 1) await complete(2_000);
  assert.deepEqual((await Promise.all([...held, shared])).map((result) => result.status), Array(5).fill("ok"));
  const timed = await fill(4);
  t.mock.timers.tick(30_000);
  assert.deepEqual((await Promise.all(timed)).map((result) => result.reason), ["scan_timeout", "queue_timeout", "queue_timeout", "queue_timeout"]);
  assert.deepEqual(filter.scanTotals(), {
    scans: 11, ok: 5, unknown: 0, unavailable: 6, coalesced: 2, aborted: 1,
    failuresByReason: { admission_limit: 1, queue_timeout: 3, scan_timeout: 1, model_timeout: 0, model_error: 0, model_killed: 0, worker_unavailable: 0, other: 0 },
  });
  const copy = filter.scanTotals();
  copy.failuresByReason.admission_limit = 99;
  assert.equal(filter.scanTotals().failuresByReason.admission_limit, 1);
});

test("privacy readiness probes the live worker and fails closed after exit", async (t) => {
  let healthy = true;
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health" && healthy) emit(health(message));
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker, timeoutMs: 10 });
  t.after(() => filter.close());

  assert.equal(await filter.isReady(), true);
  healthy = false;
  assert.equal(await filter.isReady(), false);
  worker.emit("exit", 1);
  assert.equal(await filter.isReady(), false);
});

test("Privacy Filter labels retain their original categories across the worker boundary", async (t) => {
  const labels = ["account_number", "private_address", "private_email", "private_person", "private_phone", "private_url", "private_date", "secret"];
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
    if (message.type === "scan") emit({
      type: "scan", id: message.id, status: "ok",
      findings: labels.map((label) => ({ label, count: 1 })),
    });
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker });
  t.after(() => filter.close());

  const result = await filter.scan(Buffer.from('{"content":"synthetic data"}'));
  assert.equal(result.status, "ok");
  assert.deepEqual(result.findings, labels.map((label) => ({ label, count: 1 })));
});

test("privacy unknown reasons preserve only the pinned worker and adapter's fixed codes", async (t) => {
  const allowed = ["invalid-prediction", "inconsistent-counts", "invalid-span", "unmapped-span", "cross-field-span", "inconsistent-quoting", "unmapped-finding", "redaction-too-large", "value-survived", "invalid-protocol-graph", "protocol-id-collision", "conflicting-protocol-context", "protocol-id-limit", "adapter-error", "model_timeout", "model_error", "model_killed", "protocol-graph-mutation", "protocol-control-mutation", "signed-block-mutation", "invalid-source-provenance", "json-key-collision", "invalid-json-topology", "redaction-projection-limit", "redaction-match-limit", "redaction-body-limit", "redaction-frame-limit"];
  for (const reason of [...allowed, sentinel, null, {}, 42, "scan_timeout", undefined]) {
    const worker = fakeWorker((message, emit) => {
      if (message.type === "health") emit(health(message));
      if (message.type === "scan") emit({ type: "scan", id: message.id, status: "unknown", reason, body: sentinel });
    });
    const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker });
    t.after(() => filter.close());
    const result = await filter.scan(Buffer.from(JSON.stringify({ content: sentinel })));
    assert.deepEqual(result, { status: "unknown", findings: [], reason: allowed.includes(reason) ? reason : "privacy_unavailable" });
    assert.doesNotMatch(JSON.stringify(result), new RegExp(sentinel));
    if (["model_killed", "model_error", "model_timeout"].includes(reason)) {
      assert.equal(await filter.isReady(), false);
      await flushTasks();
    }
    assert.equal(await filter.isReady(), true);
  }
});

test("every reason the pinned OPF adapter and worker emit survives the privacy boundary", async (t) => {
  const adapterReasons = [
    "invalid-prediction", "inconsistent-counts", "invalid-span", "unmapped-span", "cross-field-span", "inconsistent-quoting",
    "unmapped-finding", "redaction-projection-limit", "redaction-match-limit", "redaction-body-limit", "value-survived",
    "invalid-protocol-graph", "protocol-id-collision", "conflicting-protocol-context", "protocol-id-limit",
    "invalid-source-provenance", "json-key-collision", "invalid-json-topology",
    "protocol-graph-mutation", "protocol-control-mutation", "signed-block-mutation",
  ];
  const workerReasons = ["adapter-error", "model_timeout", "model_error", "model_killed"];
  let reason;
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(cooperativeHealth(message));
    if (message.type === "scan") emit({ type: "scan", id: message.id, status: "unknown", reason });
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker });
  t.after(() => filter.close());
  for (reason of [...adapterReasons, ...workerReasons]) {
    assert.equal((await filter.scan(Buffer.from('{}'))).reason, reason);
    if (!await filter.isReady()) await flushTasks();
  }
});

test("privacy distinguishes body, admission, frame, queue, timeout and protocol failures without raw data", async (t) => {
  const worker = fakeWorker((message, emit) => { if (message.type === "health") emit(health(message)); });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker, timeoutMs: 100 });
  t.after(() => filter.close());
  assert.equal((await filter.scan(Buffer.alloc(1_048_577))).reason, "body_invalid");
  assert.notEqual((await filter.scan(Buffer.alloc(786_400))).reason, "frame_limit");
  const first = filter.scan(Buffer.from('{}'));
  const waiting = Array.from({ length: 3 }, (_, index) => filter.scan(Buffer.from(JSON.stringify({ content: sentinel, index }))));
  assert.equal((await filter.scan(Buffer.from('{"content":"fifth"}'))).reason, "admission_limit");
  await flushTasks();
  worker.stdout.emit("data", `${sentinel}\n`);
  assert.equal((await first).reason, "protocol_invalid");
  assert.deepEqual((await Promise.all(waiting)).map((result) => result.reason), Array(3).fill("protocol_invalid"));
  assert.doesNotMatch(JSON.stringify(await Promise.all(waiting)), new RegExp(sentinel));
  filter.close();
  assert.equal((await filter.scan(Buffer.from('{}'))).reason, "worker_closed");

  const timedWorker = fakeWorker((message, emit) => { if (message.type === "health") emit(health(message)); });
  const timed = await createPrivacyFilter({ provision, spawnWorker: () => timedWorker, validateWorker, timeoutMs: 100 });
  t.after(() => timed.close());
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const active = timed.scan(Buffer.from('{"content":"active"}'));
  const queued = timed.scan(Buffer.from('{"content":"queued"}'));
  await flushTasks();
  t.mock.timers.tick(100);
  assert.equal((await queued).reason, "queue_timeout");
  assert.equal((await active).reason, "scan_timeout");
  const nextActive = timed.scan(Buffer.from('{}'));
  await flushTasks();
  t.mock.timers.tick(10);
  const nextQueued = timed.scan(Buffer.from('{"content":"next"}'));
  t.mock.timers.tick(90);
  assert.equal((await nextActive).reason, "scan_timeout");
  assert.equal((await nextQueued).reason, "worker_unavailable", "a waiting request must not inherit another scan's timeout diagnosis");
});

test("admission and queue failures carry a Retry-After estimate from recent scan times", async (t) => {
  const { filter, complete, fill } = await retryAfterFilter(t);
  const extra = () => filter.scan(Buffer.from('{"content":"extra"}'));

  const first = await fill();
  assert.equal((await extra()).retryAfterSeconds, 30, "no recent scans falls back to the scan timeout");
  for (let index = 0; index < 4; index += 1) await complete(2_000);
  await Promise.all(first);

  const second = await fill();
  assert.equal((await extra()).retryAfterSeconds, 8, "one active plus three queued at a 2 s median");
  t.mock.timers.tick(30_000);
  const results = await Promise.all(second);
  assert.deepEqual(results.map(({ reason, retryAfterSeconds }) => [reason, retryAfterSeconds]), [
    ["scan_timeout", undefined],
    ["queue_timeout", 6],
    ["queue_timeout", 4],
    ["queue_timeout", 2],
  ]);
});

test("Retry-After estimates are clamped to 60 seconds", async (t) => {
  const { filter, complete, fill } = await retryAfterFilter(t);
  for (let index = 0; index < 3; index += 1) {
    const [scan] = await fill(1);
    await complete(25_000);
    await scan;
  }
  await fill();
  const result = await filter.scan(Buffer.from('{"content":"extra"}'));
  assert.equal(result.reason, "admission_limit");
  assert.equal(result.retryAfterSeconds, 60);
});

async function retryAfterFilter(t) {
  const replies = [];
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
    if (message.type === "scan") replies.push(() => emit({ type: "scan", id: message.id, status: "ok", findings: [] }));
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker, timeoutMs: 30_000 });
  t.after(() => filter.close());
  t.mock.timers.enable({ apis: ["setTimeout", "Date"], now: 0 });
  let bodies = 0;
  const fill = async (count = 4) => {
    const scans = Array.from({ length: count }, () => filter.scan(Buffer.from(JSON.stringify({ body: bodies++ }))));
    await flushTasks();
    return scans;
  };
  const complete = async (elapsedMs) => {
    t.mock.timers.tick(elapsedMs);
    replies.shift()();
    await flushTasks();
  };
  return { filter, complete, fill };
}

test("privacy worker assets are revalidated immediately before each worker spawn", async () => {
  let validations = 0;
  let spawns = 0;
  await assert.rejects(
    createPrivacyFilter({
      provision,
      validateWorker: async () => { validations += 1; throw new Error("digest changed"); },
      spawnWorker: () => { spawns += 1; return fakeWorker(() => {}); },
    }),
    /worker unavailable/i,
  );
  assert.equal(validations, 1);
  assert.equal(spawns, 0);
});

test("OPF filter accepts the pinned ten-second scan budget", async (t) => {
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
    if (message.type === "scan") emit({ type: "scan", id: message.id, status: "ok", findings: [] });
  });
  const extended = { privacy: {
    ...opfProvision.privacy,
    worker: { ...opfProvision.privacy.worker, args: opfProvision.privacy.worker.args.with(21, "10000") },
  } };
  const filter = await createPrivacyFilter({
    provision: extended, spawnWorker: () => worker, validateWorker, validateFile,
    validateCheckpoint: async () => async () => {},
  });
  t.after(() => filter.close());
  assert.equal((await filter.scan(Buffer.from('{"content":"synthetic"}'))).status, "ok");
});

test("OPF filter accepts a pinned twenty-five-second scan budget", async (t) => {
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
    if (message.type === "scan") emit({ type: "scan", id: message.id, status: "ok", findings: [] });
  });
  const extended = { privacy: {
    ...opfProvision.privacy,
    worker: { ...opfProvision.privacy.worker, args: opfProvision.privacy.worker.args.with(21, "25000") },
  } };
  const filter = await createPrivacyFilter({
    provision: extended, spawnWorker: () => worker, validateWorker, validateFile,
    validateCheckpoint: async () => async () => {},
  });
  t.after(() => filter.close());
  assert.equal((await filter.scan(Buffer.from('{"content":"synthetic"}'))).status, "ok");
});

async function opfFilter(t, handler, budget = "60000") {
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
    else handler?.(message, emit);
  });
  const extended = { privacy: { ...opfProvision.privacy,
    worker: { ...opfProvision.privacy.worker, args: opfProvision.privacy.worker.args.with(21, budget) } } };
  const filter = await createPrivacyFilter({ provision: extended, spawnWorker: () => worker, validateWorker, validateFile,
    validateCheckpoint: async () => async () => {} });
  t.after(() => filter.close());
  return { worker, filter };
}

test("OPF scans hand the worker their whole budget and wait six seconds past it for the reply", async (t) => {
  const { worker, filter } = await opfFilter(t);
  t.mock.timers.enable({ apis: ["setTimeout", "Date"] });
  let settled = false;
  const scan = filter.scan(Buffer.from('{"content":"synthetic"}')).then((result) => { settled = true; return result; });
  await flushTasks();
  const message = worker.messages.find((entry) => entry.type === "scan");
  assert.equal(message.budgetMs, 60_000);
  t.mock.timers.tick(65_999);
  await flushTasks();
  assert.equal(settled, false);
  emit(worker, { type: "scan", id: message.id, status: "ok", findings: [] });
  assert.equal((await scan).status, "ok");
});

test("an OPF reply arriving after the request deadline is dropped and never reads as ok", async (t) => {
  const { worker, filter } = await opfFilter(t);
  t.mock.timers.enable({ apis: ["setTimeout", "Date"] });
  const scan = filter.scan(Buffer.from('{"content":"synthetic"}'));
  await flushTasks();
  const message = worker.messages.find((entry) => entry.type === "scan");
  t.mock.timers.tick(66_000);
  await flushTasks();
  emit(worker, { type: "scan", id: message.id, status: "ok", findings: [] });
  const result = await scan;
  assert.notEqual(result.status, "ok");
  assert.equal(result.reason, "scan_timeout");
});

test("time an OPF scan spends queued comes out of the budget its worker frame carries", async (t) => {
  const { worker, filter } = await opfFilter(t);
  t.mock.timers.enable({ apis: ["setTimeout", "Date"] });
  const first = filter.scan(Buffer.from('{"content":"first"}'));
  await flushTasks();
  const second = filter.scan(Buffer.from('{"content":"second"}'));
  t.mock.timers.tick(20_000);
  await flushTasks();
  const [head] = worker.messages.filter((entry) => entry.type === "scan");
  emit(worker, { type: "scan", id: head.id, status: "ok", findings: [] });
  await first;
  await flushTasks();
  const tail = worker.messages.filter((entry) => entry.type === "scan")[1];
  assert.equal(tail.budgetMs, 40_000);
  emit(worker, { type: "scan", id: tail.id, status: "ok", findings: [] });
  assert.equal((await second).status, "ok");
});

test("only a model_timeout keeps the worker's bounded Retry-After", async (t) => {
  const replies = [
    [{ reason: "model_timeout", retryAfterSeconds: 7 }, 7],
    [{ reason: "model_timeout", retryAfterSeconds: 61 }, undefined],
    [{ reason: "model_timeout", retryAfterSeconds: 0 }, undefined],
    [{ reason: "model_timeout", retryAfterSeconds: 2.5 }, undefined],
    [{ reason: "model_error", retryAfterSeconds: 7 }, undefined],
  ];
  let next = 0;
  const { filter } = await opfFilter(t, (message, emit) => emit({ type: "scan", id: message.id, status: "unknown", ...replies[next++][0] }));
  for (const [, expected] of replies) {
    const result = await filter.scan(Buffer.from(`{"content":"synthetic-${next}"}`));
    assert.equal(result.status, "unknown");
    assert.equal(result.retryAfterSeconds, expected);
  }
});

test("OPF filter refuses a request budget beyond 240 seconds", async () => {
  await assert.rejects(createPrivacyFilter({ provision: opfProvision, timeoutMs: 240_001, spawnWorker: () => assert.fail("no worker may start"),
    validateWorker, validateFile, validateCheckpoint: async () => async () => {} }), /timeout is invalid/);
});

test("the OPF worker is spawned with its lane's window cache directory", async (t) => {
  const paths = shieldPaths({ homeDir: "/tmp/home", uid: 501, lane: "managed" });
  let spawned;
  const worker = fakeWorker((message, emit) => { if (message.type === "health") emit(health(message)); });
  const filter = await createPrivacyFilter({
    provision: opfProvision, paths, validateWorker, validateFile, validateCheckpoint: async () => async () => {},
    spawnWorker: ({ args }) => { spawned = args; return worker; },
  });
  t.after(() => filter.close());
  assert.deepEqual(spawned, [opfProvision.privacy.worker.command, ...opfProvision.privacy.worker.args, "--window-cache-dir", paths.windowCachePath]);
});

test("OPF filter rejects lane paths that did not come from shieldPaths", async () => {
  const real = shieldPaths({ homeDir: "/tmp/home", uid: 501 });
  for (const paths of [{ ...real }, { ...real, windowCachePath: "/tmp/elsewhere" }]) {
    await assert.rejects(createPrivacyFilter({
      provision: opfProvision, paths, validateWorker, validateFile, validateCheckpoint: async () => async () => {},
      spawnWorker: () => assert.fail("no worker may start"),
    }), /canonical/);
  }
});

test("the regex worker never receives a window cache directory", async (t) => {
  let spawned;
  const worker = fakeWorker((message, emit) => { if (message.type === "health") emit(health(message)); });
  const filter = await createPrivacyFilter({ provision, paths: shieldPaths({ homeDir: "/tmp/home", uid: 501 }), validateWorker,
    spawnWorker: ({ args }) => { spawned = args; return worker; } });
  t.after(() => filter.close());
  assert.deepEqual(spawned, provision.privacy.worker.args);
});

test("OPF filter accepts the 240-second request budget", async (t) => {
  const worker = fakeWorker((message, emit) => { if (message.type === "health") emit(health(message)); });
  const extended = { privacy: { ...opfProvision.privacy,
    worker: { ...opfProvision.privacy.worker, args: opfProvision.privacy.worker.args.with(21, "240000") } } };
  const filter = await createPrivacyFilter({ provision: extended, spawnWorker: () => worker, validateWorker, validateFile,
    validateCheckpoint: async () => async () => {} });
  t.after(() => filter.close());
  assert.equal(filter.version, "privacy-1");
});

test("privacy scans serialize four admitted requests while health bypasses the scan queue", async (t) => {
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker });
  t.after(() => filter.close());
  const bodies = Array.from({ length: 4 }, (_, index) => Buffer.from(JSON.stringify({ content: `synthetic-${index}` })));
  const scans = bodies.map((body) => filter.scan(body));
  await flushTasks();
  const overflow = await filter.scan(Buffer.from(`{"content":"${sentinel}"}`));
  assert.equal(overflow.status, "unavailable");
  assert.doesNotMatch(JSON.stringify(overflow), new RegExp(sentinel));
  assert.equal(worker.messages.filter((message) => message.type === "scan").length, 1);
  assert.equal(await filter.isReady(), true);
  for (const [index, body] of bodies.entries()) {
    const sent = worker.messages.filter((message) => message.type === "scan");
    assert.equal(sent.length, index + 1);
    assert.deepEqual(Buffer.from(sent[index].body, "base64"), body);
    emit(worker, { type: "scan", id: sent[index].id, status: "ok", findings: [] });
    assert.equal((await scans[index]).status, "ok");
    await flushTasks();
  }
  assert.equal(new Set(worker.messages.map((message) => message.id)).size, worker.messages.length);
});

test("expired waiting scans never dispatch and each admitted scan gets its timeout from dispatch", async (t) => {
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker, timeoutMs: 100 });
  t.after(() => filter.close());
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const first = filter.scan(Buffer.from('{"content":"first"}'));
  const second = filter.scan(Buffer.from('{"content":"second"}'));
  const expired = filter.scan(Buffer.from(`{"content":"${sentinel}"}`));
  await flushTasks();
  assert.equal(worker.messages.filter((message) => message.type === "scan").length, 1);
  t.mock.timers.tick(80);
  emit(worker, { type: "scan", id: worker.messages.at(-1).id, status: "ok", findings: [] });
  assert.equal((await first).status, "ok");
  await flushTasks();
  let settled = false;
  second.then(() => { settled = true; });
  t.mock.timers.tick(30);
  await flushTasks();
  assert.equal((await expired).status, "unavailable");
  assert.equal(settled, false);
  emit(worker, { type: "scan", id: worker.messages.at(-1).id, status: "ok", findings: [] });
  assert.equal((await second).status, "ok");
  await flushTasks();
  assert.equal(worker.messages.filter((message) => message.type === "scan").length, 2);
});

test("identical concurrent bodies share one worker scan but each caller owns its result and buffer", async (t) => {
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker });
  t.after(() => filter.close());
  const body = Buffer.from(`{"content":"${sentinel}"}`);
  const first = filter.scan(body);
  const second = filter.scan(Buffer.from(body));
  await flushTasks();
  const sent = worker.messages.filter((message) => message.type === "scan");
  assert.equal(sent.length, 1);
  emit(worker, { type: "scan", id: sent[0].id, status: "ok", findings: [{ label: "email", count: 1 }], redactedBody: Buffer.from('{"content":"[EMAIL]"}').toString("base64") });
  const [a, b] = await Promise.all([first, second]);
  assert.deepEqual(a, b);
  assert.notEqual(a, b);
  assert.notEqual(a.redactedBody, b.redactedBody);
  a.redactedBody.fill(0);
  assert.deepEqual(b.redactedBody, Buffer.from('{"content":"[EMAIL]"}'));
  assert.deepEqual(filter.recentScans().map(({ attached }) => attached), [1]);
});

test("same-length bodies with different content are never merged", async (t) => {
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
    if (message.type === "scan") emit({ type: "scan", id: message.id, status: "ok", findings: [] });
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker });
  t.after(() => filter.close());
  const results = await Promise.all([filter.scan(Buffer.from('{"c":"a"}')), filter.scan(Buffer.from('{"c":"b"}'))]);
  assert.deepEqual(results.map((result) => result.status), ["ok", "ok"]);
  assert.deepEqual(worker.messages.filter((message) => message.type === "scan").map((message) => Buffer.from(message.body, "base64").toString()), ['{"c":"a"}', '{"c":"b"}']);
});

test("attaching to a queued identical body bypasses the admission limit", async (t) => {
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker });
  t.after(() => filter.close());
  const bodies = Array.from({ length: 4 }, (_, index) => Buffer.from(JSON.stringify({ content: `synthetic-${index}` })));
  const scans = bodies.map((body) => filter.scan(body));
  await flushTasks();
  assert.equal((await filter.scan(Buffer.from('{"content":"other"}'))).reason, "admission_limit");
  const attached = filter.scan(Buffer.from(bodies[2]));
  for (let index = 0; index < bodies.length; index += 1) {
    const sent = worker.messages.filter((message) => message.type === "scan");
    emit(worker, { type: "scan", id: sent[index].id, status: "ok", findings: [] });
    await scans[index];
    await flushTasks();
  }
  assert.equal((await attached).status, "ok");
  assert.equal(worker.messages.filter((message) => message.type === "scan").length, 4);
});

test("an entry accepts at most eight attached waiters before identical bodies take the admission path", async (t) => {
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker });
  t.after(() => filter.close());
  const body = Buffer.from('{"content":"shared"}');
  const scans = Array.from({ length: 10 }, () => filter.scan(Buffer.from(body)));
  await flushTasks();
  for (let index = 0; index < 2; index += 1) {
    const sent = worker.messages.filter((message) => message.type === "scan");
    assert.equal(sent.length, index + 1);
    emit(worker, { type: "scan", id: sent[index].id, status: "ok", findings: [] });
    await flushTasks();
  }
  assert.deepEqual((await Promise.all(scans)).map((result) => result.status), Array(10).fill("ok"));
  assert.deepEqual(filter.recentScans().map(({ attached }) => attached), [8, 0]);
});

test("a body arriving after its entry timed out in the queue starts a fresh scan", async (t) => {
  const workers = [];
  const filter = await createPrivacyFilter({
    provision,
    spawnWorker: () => {
      const worker = fakeWorker((message, emit) => { if (message.type === "health") emit(health(message)); });
      workers.push(worker);
      return worker;
    },
    validateWorker,
    timeoutMs: 100,
  });
  t.after(() => filter.close());
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const active = filter.scan(Buffer.from('{"content":"active"}'));
  const queued = filter.scan(Buffer.from('{"content":"queued"}'));
  await flushTasks();
  t.mock.timers.tick(100);
  assert.equal((await queued).reason, "queue_timeout");
  assert.equal((await active).reason, "scan_timeout");
  const retry = filter.scan(Buffer.from('{"content":"queued"}'));
  for (let i = 0; i < 5; i += 1) await flushTasks();
  const sent = workers.flatMap((worker) => worker.messages.filter((message) => message.type === "scan").map((message) => ({ worker, message })));
  const last = sent.at(-1);
  assert.equal(Buffer.from(last.message.body, "base64").toString(), '{"content":"queued"}');
  emit(last.worker, { type: "scan", id: last.message.id, status: "ok", findings: [] });
  assert.equal((await retry).status, "ok");
});

test("a failed shared scan hands every waiter the same unknown result", async (t) => {
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(cooperativeHealth(message));
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker });
  t.after(() => filter.close());
  const scans = Array.from({ length: 3 }, () => filter.scan(Buffer.from('{"content":"shared"}')));
  await flushTasks();
  emit(worker, { type: "scan", id: worker.messages.at(-1).id, status: "unknown", reason: "model_error" });
  const results = await Promise.all(scans);
  for (const result of results) assert.deepEqual(result, { status: "unknown", findings: [], reason: "model_error" });
  assert.equal(worker.messages.filter((message) => message.type === "scan").length, 1);
});

test("aborting the only waiter of a queued scan frees its admission slot without dispatching it", async (t) => {
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker });
  t.after(() => filter.close());
  const controller = new AbortController();
  const scans = [0, 1, 2].map((index) => filter.scan(Buffer.from(JSON.stringify({ content: `synthetic-${index}` }))));
  const abandoned = filter.scan(Buffer.from(`{"content":"${sentinel}"}`), { signal: controller.signal });
  await flushTasks();
  assert.equal((await filter.scan(Buffer.from('{"content":"late"}'))).reason, "admission_limit");
  controller.abort();
  assert.equal((await abandoned).reason, "aborted");
  const late = filter.scan(Buffer.from('{"content":"late"}'));
  for (let index = 0; index < 4; index += 1) {
    await flushTasks();
    emit(worker, { type: "scan", id: worker.messages.at(-1).id, status: "ok", findings: [] });
  }
  assert.deepEqual((await Promise.all([...scans, late])).map((result) => result.status), Array(4).fill("ok"));
  assert.doesNotMatch(JSON.stringify(worker.messages), new RegExp(Buffer.from(sentinel).toString("base64").slice(0, 16)));
  assert.equal((await filter.scan(Buffer.from('{}'), { signal: AbortSignal.abort() })).reason, "aborted");
});

test("one aborted waiter leaves a shared queued scan running for the other", async (t) => {
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker });
  t.after(() => filter.close());
  const owner = new AbortController();
  const active = filter.scan(Buffer.from('{"content":"active"}'));
  const first = filter.scan(Buffer.from('{"content":"shared"}'), { signal: owner.signal });
  const second = filter.scan(Buffer.from('{"content":"shared"}'));
  await flushTasks();
  owner.abort();
  assert.equal((await first).reason, "aborted");
  emit(worker, { type: "scan", id: worker.messages.at(-1).id, status: "ok", findings: [] });
  await active;
  await flushTasks();
  const sent = worker.messages.filter((message) => message.type === "scan");
  assert.equal(Buffer.from(sent.at(-1).body, "base64").toString(), '{"content":"shared"}');
  emit(worker, { type: "scan", id: sent.at(-1).id, status: "ok", findings: [] });
  assert.equal((await second).status, "ok");
});

test("aborting an active scan releases the caller while the worker still finishes and records it", async (t) => {
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker });
  t.after(() => filter.close());
  const controller = new AbortController();
  const scan = filter.scan(Buffer.from('{"content":"active"}'), { signal: controller.signal });
  await flushTasks();
  controller.abort();
  assert.equal((await scan).reason, "aborted");
  assert.deepEqual(filter.recentScans(), []);
  emit(worker, { type: "scan", id: worker.messages.at(-1).id, status: "ok", findings: [], cache: { hits: 1, misses: 2 } });
  await flushTasks();
  assert.deepEqual(filter.recentScans().map(({ elapsedMs, queuedMs, ...scan }) => scan), [
    { status: "ok", reason: null, hits: 1, misses: 2, segmentHits: null, segmentMisses: null, attached: 0 },
  ]);
  assert.equal(worker.messages.filter((message) => message.type === "scan").length, 1);
});

test("privacy close releases active and waiting scans without dispatching retained bodies", async () => {
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker });
  const scans = Array.from({ length: 4 }, () => filter.scan(Buffer.from(`{"content":"${sentinel}"}`)));
  await flushTasks();
  filter.close();
  assert.deepEqual((await Promise.all(scans)).map((result) => result.status), Array(4).fill("unavailable"));
  assert.equal(worker.messages.filter((message) => message.type === "scan").length, 1);
  assert.equal((await filter.scan(Buffer.from('{}'))).status, "unavailable");
  assert.equal(await filter.isReady(), false);
});

test("privacy transport timeout releases the queue and recovers one freshly validated worker", async (t) => {
  const workers = [];
  let validations = 0;
  const filter = await createPrivacyFilter({
    provision, timeoutMs: 40,
    validateWorker: async () => { validations += 1; },
    spawnWorker: () => {
      const worker = fakeWorker((message, emit) => {
        if (message.type === "health") emit(health(message));
        if (message.type === "scan" && workers.length === 2) emit({ type: "scan", id: message.id, status: "ok", findings: [] });
      });
      workers.push(worker);
      return worker;
    },
  });
  t.after(() => filter.close());
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const failed = Array.from({ length: 4 }, () => filter.scan(Buffer.from(`{"content":"${sentinel}"}`)));
  await flushTasks();
  t.mock.timers.tick(40);
  await flushTasks();
  assert.deepEqual((await Promise.all(failed)).map((result) => result.status), Array(4).fill("unavailable"));
  assert.equal(workers[0].messages.filter((message) => message.type === "scan").length, 1);
  assert.deepEqual(await Promise.all([filter.isReady(), filter.isReady(), filter.isReady()]), [false, false, false]);
  await flushTasks();
  assert.equal(await filter.isReady(), true);
  assert.equal(workers.length, 2);
  assert.equal(validations, 2);
  workers[0].stdout.emit("data", "malformed stale generation\n");
  assert.equal((await filter.scan(Buffer.from('{"content":"fresh"}'))).status, "ok");
});

test("privacy readiness stays responsive and singleflight through repeated worker startup failures", async (t) => {
  const workers = [];
  const filter = await createPrivacyFilter({
    provision, validateWorker, startupTimeoutMs: 50,
    spawnWorker: () => {
      const worker = fakeWorker((message, emit) => {
        if (message.type === "health" && workers.length === 1) emit(health(message));
      });
      workers.push(worker);
      return worker;
    },
  });
  t.after(() => filter.close());
  t.mock.timers.enable({ apis: ["setTimeout"] });
  workers[0].emit("exit", 1);
  for (let attempt = 2; attempt <= 3; attempt += 1) {
    let settled = false;
    const readiness = Promise.all(Array.from({ length: 20 }, () => filter.isReady())).then((result) => { settled = true; return result; });
    await flushTasks();
    assert.equal(settled, true);
    assert.deepEqual(await readiness, Array(20).fill(false));
    assert.equal(workers.length, attempt);
    t.mock.timers.tick(50);
    await flushTasks();
  }
  filter.close();
  assert.equal(await filter.isReady(), false);
  assert.equal(workers.length, 3);
});

test("an asynchronous worker stdin error fails admitted scans closed and allows a new generation", async (t) => {
  const workers = [];
  const filter = await createPrivacyFilter({
    provision, validateWorker,
    spawnWorker: () => {
      const worker = fakeWorker((message, emit) => {
        if (message.type === "health") emit(health(message));
        if (message.type === "scan" && workers.length === 2) emit({ type: "scan", id: message.id, status: "ok", findings: [] });
      });
      workers.push(worker);
      return worker;
    },
  });
  t.after(() => filter.close());
  const scans = Array.from({ length: 4 }, () => filter.scan(Buffer.from(`{"content":"${sentinel}"}`)));
  await flushTasks();
  workers[0].stdin.emit("error", Object.assign(new Error("broken pipe"), { code: "EPIPE" }));
  assert.deepEqual((await Promise.all(scans)).map((result) => result.status), Array(4).fill("unavailable"));
  assert.equal((await filter.scan(Buffer.from('{"content":"fresh"}'))).status, "ok");
  workers[0].emit("exit", 1);
  assert.equal(await filter.isReady(), true);
  assert.equal(workers.length, 2);
});

test("startup health followed by immediate worker exit never admits a ready filter", async () => {
  const worker = fakeWorker((message, emit, worker) => {
    if (message.type === "health") { emit(health(message)); worker.emit("exit", 1); }
  });
  await assert.rejects(createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker }), /worker unavailable/i);
});

test("health followed by a broken frame in the same batch never reports ready", async (t) => {
  let startup = true;
  const worker = fakeWorker((message, emit, worker) => {
    if (message.type !== "health") return;
    if (startup) { startup = false; emit(health(message)); return; }
    worker.stdout.emit("data", `${JSON.stringify(health(message))}\nmalformed\n`);
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker });
  t.after(() => filter.close());
  assert.equal(await filter.isReady(), false);
});

test("an idle soft health timeout preserves recovery and scan waits before starting its own deadline", async (t) => {
  let startup = true;
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health" && startup) { startup = false; emit(health(message)); }
  });
  let spawns = 0;
  let kills = 0;
  worker.kill = () => { kills += 1; worker.emit("exit", 0); };
  const filter = await createPrivacyFilter({
    provision, validateWorker, timeoutMs: 100, startupTimeoutMs: 2_000,
    spawnWorker: () => { spawns += 1; return worker; },
  });
  t.after(() => filter.close());
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const ready = filter.isReady();
  await flushTasks();
  t.mock.timers.tick(750);
  assert.equal(await ready, false);
  assert.equal(kills, 0);
  const scan = filter.scan(Buffer.from('{"content":"fresh"}'));
  await flushTasks();
  t.mock.timers.tick(500);
  await flushTasks();
  assert.equal(worker.messages.filter((message) => message.type === "scan").length, 0);
  assert.equal(spawns, 1);
  emit(worker, health(worker.messages.at(-1)));
  await flushTasks();
  const message = worker.messages.find((message) => message.type === "scan");
  assert.ok(message);
  t.mock.timers.tick(99);
  emit(worker, { type: "scan", id: message.id, status: "ok", findings: [] });
  assert.equal((await scan).status, "ok");
});

test("model recovery health is singleflight and does not spend the next scan's inference budget", async (t) => {
  let recovering = false;
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health" && !recovering) emit(health(message));
    if (message.type === "scan" && !recovering) {
      recovering = true;
      emit({ type: "scan", id: message.id, status: "unknown", reason: "model_killed" });
    }
  });
  let spawns = 0;
  const filter = await createPrivacyFilter({ provision, validateWorker, timeoutMs: 100, startupTimeoutMs: 1_000, spawnWorker: () => { spawns += 1; return worker; } });
  t.after(() => filter.close());
  t.mock.timers.enable({ apis: ["setTimeout"] });
  assert.equal((await filter.scan(Buffer.from('{}'))).reason, "model_killed");
  const next = filter.scan(Buffer.from('{"content":"next"}'));
  assert.deepEqual(await Promise.all([filter.isReady(), filter.isReady()]), [false, false]);
  await flushTasks();
  t.mock.timers.tick(900);
  await flushTasks();
  assert.equal(worker.messages.filter((message) => message.type === "scan").length, 1);
  assert.equal(worker.messages.filter((message) => message.type === "health").length, 2);
  assert.equal(spawns, 1);
  emit(worker, health(worker.messages.at(-1)));
  await flushTasks();
  const dispatched = worker.messages.at(-1);
  assert.equal(dispatched.type, "scan");
  t.mock.timers.tick(99);
  emit(worker, { type: "scan", id: dispatched.id, status: "ok", findings: [] });
  assert.equal((await next).status, "ok");
});

test("a worker backing off a failed model restart stays alive until its health recovers", async (t) => {
  let phase = "ready";
  let spawns = 0;
  let kills = 0;
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(phase === "backoff" ? { type: "health", id: message.id, status: "unknown" } : cooperativeHealth(message));
    if (message.type !== "scan") return;
    if (phase === "ready") { phase = "backoff"; emit({ type: "scan", id: message.id, status: "unknown", reason: "model_killed" }); return; }
    emit({ type: "scan", id: message.id, status: "ok", findings: [] });
  });
  worker.kill = () => { kills += 1; worker.emit("exit", 0); };
  const filter = await createPrivacyFilter({ provision, validateWorker, timeoutMs: 100, spawnWorker: () => { spawns += 1; return worker; } });
  t.after(() => filter.close());
  assert.equal((await filter.scan(Buffer.from('{}'))).reason, "model_killed");
  assert.equal((await filter.scan(Buffer.from('{"content":"during"}'))).reason, "worker_unavailable");
  assert.equal(await filter.isReady(), false);
  await flushTasks();
  assert.equal(kills, 0, "a recovering worker keeps its process and boot digest");
  phase = "recovered";
  assert.equal((await filter.scan(Buffer.from('{"content":"after"}'))).status, "ok");
  assert.equal(await filter.isReady(), true);
  assert.equal(spawns, 1);
  assert.equal(kills, 0);
});

test("health replies that only resemble the recovering shape still stop the worker", async (t) => {
  for (const reply of [{ status: "unknown", reason: "x" }, { status: "ok" }, { status: "unknown", protocol: "airkit-privacy-ndjson-v1" }]) {
    let started = false;
    let kills = 0;
    const worker = fakeWorker((message, emit) => {
      if (message.type !== "health") return;
      emit(started ? { type: "health", id: message.id, ...reply } : cooperativeHealth(message));
      started = true;
    });
    worker.kill = () => { kills += 1; worker.emit("exit", 0); };
    const filter = await createPrivacyFilter({ provision, validateWorker, timeoutMs: 100, spawnWorker: () => worker });
    t.after(() => filter.close());
    assert.equal(await filter.isReady(), false, JSON.stringify(reply));
    assert.equal(kills, 1, JSON.stringify(reply));
  }
});

test("a model timeout from a worker without the cooperative-timeout capability keeps the not-ready health path", async (t) => {
  for (const capabilities of [undefined, "cooperative-timeout", ["model_killed"], { 0: "cooperative-timeout" }]) {
    let timedOut = false;
    let kills = 0;
    const worker = fakeWorker((message, emit) => {
      if (message.type === "health") emit(capabilities === undefined ? health(message) : { ...health(message), capabilities });
      if (message.type !== "scan") return;
      if (!timedOut) { timedOut = true; emit({ type: "scan", id: message.id, status: "unknown", reason: "model_timeout" }); return; }
      emit({ type: "scan", id: message.id, status: "ok", findings: [] });
    });
    worker.kill = () => { kills += 1; worker.emit("exit", 0); };
    const filter = await createPrivacyFilter({ provision, validateWorker, timeoutMs: 100, spawnWorker: () => worker });
    t.after(() => filter.close());
    assert.equal((await filter.scan(Buffer.from('{}'))).reason, "model_timeout");
    assert.equal(await filter.isReady(), false, JSON.stringify(capabilities));
    await flushTasks();
    assert.equal((await filter.scan(Buffer.from('{"content":"next"}'))).status, "ok");
    assert.deepEqual(worker.messages.map((message) => message.type), ["health", "scan", "health", "scan"]);
    assert.equal(kills, 0);
  }
});

test("a worker-reported model timeout keeps the same ready worker without a health round trip", async (t) => {
  let timedOut = false;
  let spawns = 0;
  let kills = 0;
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(cooperativeHealth(message));
    if (message.type !== "scan") return;
    if (!timedOut) { timedOut = true; emit({ type: "scan", id: message.id, status: "unknown", reason: "model_timeout" }); return; }
    emit({ type: "scan", id: message.id, status: "ok", findings: [] });
  });
  worker.kill = () => { kills += 1; worker.emit("exit", 0); };
  const filter = await createPrivacyFilter({ provision, validateWorker, timeoutMs: 100, spawnWorker: () => { spawns += 1; return worker; } });
  t.after(() => filter.close());
  assert.equal((await filter.scan(Buffer.from('{}'))).reason, "model_timeout");
  assert.equal((await filter.scan(Buffer.from('{"content":"next"}'))).status, "ok");
  assert.equal(worker.messages.filter((message) => message.type === "health").length, 1);
  assert.equal(await filter.isReady(), true);
  assert.equal(spawns, 1);
  assert.equal(kills, 0);
});

test("queued scans dispatch to the same worker after the active scan reports model_timeout", async (t) => {
  let startup = true;
  let kills = 0;
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health" && startup) { startup = false; emit(cooperativeHealth(message)); }
  });
  worker.kill = () => { kills += 1; worker.emit("exit", 0); };
  const filter = await createPrivacyFilter({ provision, validateWorker, timeoutMs: 5_000, startupTimeoutMs: 200, spawnWorker: () => worker });
  t.after(() => filter.close());
  const sent = () => worker.messages.filter((message) => message.type === "scan");
  const active = filter.scan(Buffer.from('{"content":"active"}'));
  const queued = Array.from({ length: 3 }, (_, index) => filter.scan(Buffer.from(JSON.stringify({ content: `queued-${index}` }))));
  await flushTasks();
  assert.equal(sent().length, 1);
  emit(worker, { type: "scan", id: sent()[0].id, status: "unknown", reason: "model_timeout" });
  assert.equal((await active).reason, "model_timeout");
  for (const [index, scan] of queued.entries()) {
    await flushTasks();
    assert.equal(sent().length, index + 2);
    emit(worker, { type: "scan", id: sent()[index + 1].id, status: "ok", findings: [] });
    assert.equal((await scan).status, "ok");
  }
  assert.equal(worker.messages.filter((message) => message.type === "health").length, 1);
  assert.equal(kills, 0);
});

test("OPF respawns reuse the first checkpoint attestation and close on metadata drift", async (t) => {
  for (const drift of [false, true]) {
    const workers = [];
    const hashes = { checkpoint: 0, source: 0 };
    const asserts = { checkpoint: 0, source: 0 };
    let exited = false;
    const filter = await createPrivacyFilter({
      provision: opfProvision, validateWorker, validateFile,
      validateCheckpoint: async (_asset, { label = "checkpoint" } = {}) => {
        hashes[label] += 1;
        return async () => {
          asserts[label] += 1;
          if (drift && exited) throw new Error("checkpoint metadata changed");
        };
      },
      spawnWorker: () => {
        const worker = fakeWorker((message, emit) => {
          if (message.type === "health") emit(health(message));
          if (message.type === "scan") emit({ type: "scan", id: message.id, status: "ok", findings: [] });
        });
        workers.push(worker);
        return worker;
      },
    });
    t.after(() => filter.close());
    assert.equal((await filter.scan(Buffer.from('{"content":"first"}'))).status, "ok");
    assert.deepEqual(asserts, { checkpoint: 1, source: 1 });
    exited = true;
    workers[0].emit("exit", 1);
    const result = await filter.scan(Buffer.from(`{"content":"${sentinel}"}`));
    assert.deepEqual(hashes, { checkpoint: 1, source: 1 }, `drift=${drift}`);
    if (drift) {
      assert.equal(result.reason, "assets_invalid");
      // The ring keeps the reason close() delivered, not the drain default; drain records once startup unwinds.
      await new Promise((resolve) => setImmediate(resolve));
      assert.deepEqual(filter.recentScans().map(({ status, reason }) => [status, reason]), [["ok", null], ["unavailable", "assets_invalid"]]);
      assert.equal(workers.length, 1);
      assert.equal((await filter.scan(Buffer.from('{}'))).reason, "worker_closed");
      continue;
    }
    assert.equal(result.status, "ok");
    assert.equal(workers.length, 2);
    assert.deepEqual(asserts, { checkpoint: 3, source: 3 });
  }
});

test("recovery startup deadline and malformed health both fail closed before scan dispatch", async (t) => {
  for (const failure of ["deadline", "malformed", "exit"]) {
    let recovering = false;
    let kills = 0;
    const worker = fakeWorker((message, emit) => {
      if (message.type === "health" && !recovering) emit(health(message));
      if (message.type === "scan") { recovering = true; emit({ type: "scan", id: message.id, status: "unknown", reason: "model_error" }); }
    });
    worker.kill = () => { kills += 1; worker.emit("exit", 0); };
    const filter = await createPrivacyFilter({ provision, validateWorker, spawnWorker: () => worker, timeoutMs: 100, startupTimeoutMs: 1_000 });
    t.after(() => filter.close());
    await filter.scan(Buffer.from('{}'));
    t.mock.timers.enable({ apis: ["setTimeout"] });
    const scan = filter.scan(Buffer.from(JSON.stringify({ content: sentinel })));
    await flushTasks();
    if (failure === "deadline") t.mock.timers.tick(1_000);
    if (failure === "malformed") worker.stdout.emit("data", `${sentinel}\n`);
    if (failure === "exit") worker.emit("exit", 1);
    const result = await scan;
    assert.equal(result.status, "unavailable", failure);
    assert.equal(result.reason, failure === "malformed" ? "protocol_invalid" : "worker_unavailable", failure);
    assert.equal(kills, 1, failure);
    assert.equal(worker.messages.filter((message) => message.type === "scan").length, 1, failure);
    assert.doesNotMatch(JSON.stringify(result), new RegExp(sentinel));
    filter.close();
    t.mock.timers.reset();
  }
});

test("checkpoint startup includes attestation and preload within one bounded outer deadline", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") setTimeout(() => emit(health(message)), 30_000);
  });
  const starting = createPrivacyFilter({
    provision: opfProvision, validateWorker, validateFile, spawnWorker: () => worker,
    validateCheckpoint: async (_asset, { label } = {}) => {
      if (label !== "source") await new Promise((resolve) => setTimeout(resolve, 15_000));
      return async () => {};
    },
  });
  let settled = false;
  starting.then(() => { settled = true; }, () => { settled = true; });
  await flushTasks();
  t.mock.timers.tick(15_000);
  await flushTasks();
  t.mock.timers.tick(30_000);
  const filter = await starting;
  t.after(() => filter.close());
  assert.equal(settled, true);
  assert.equal(filter.version, "privacy-1");

  const unhandled = [];
  const onUnhandled = (error) => unhandled.push(error);
  process.on("unhandledRejection", onUnhandled);
  t.after(() => process.off("unhandledRejection", onUnhandled));
  for (const outcome of ["resolve", "reject"]) {
    let releaseCheckpoint;
    let releaseSource;
    const checkpoint = new Promise((resolve, reject) => { releaseCheckpoint = outcome === "resolve" ? resolve : () => reject(new Error("late attestation failure")); });
    const source = new Promise((resolve) => { releaseSource = resolve; });
    let spawns = 0;
    const completed = [];
    const expired = createPrivacyFilter({
      provision: opfProvision, validateWorker, startupTimeoutMs: 50,
      validateCheckpoint: async (_asset, { label = "checkpoint" } = {}) => {
        await (label === "source" ? source : checkpoint);
        completed.push(label);
        return async () => {};
      },
      validateFile: async (_asset, { label }) => { completed.push(label); },
      spawnWorker: () => { spawns += 1; return worker; },
    });
    const rejected = assert.rejects(expired, /worker unavailable/i);
    await flushTasks();
    t.mock.timers.tick(50);
    await rejected;
    releaseCheckpoint();
    await flushTasks();
    if (outcome === "resolve") {
      assert.deepEqual(completed, ["checkpoint"]);
      releaseSource();
      await flushTasks();
    }
    assert.deepEqual(completed, outcome === "resolve" ? ["checkpoint", "source", "adapter", "tokenizer"] : []);
    assert.equal(spawns, 0, `late ${outcome} must never launch a generation after the startup deadline`);
    assert.deepEqual(unhandled, [], "late validation rejection must be consumed by the expired startup operation");
  }
});

test("concurrent readiness probes share a deadline and late health does not invalidate a live scan", async (t) => {
  let startup = true;
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health" && startup) { startup = false; emit(health(message)); }
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker });
  t.after(() => filter.close());
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const scan = filter.scan(Buffer.from('{"content":"synthetic"}'));
  const readiness = Array.from({ length: 20 }, () => filter.isReady());
  await flushTasks();
  const probe = worker.messages.filter((message) => message.type === "health").at(-1);
  t.mock.timers.tick(750);
  assert.deepEqual(await Promise.all(readiness), Array(20).fill(false));
  assert.equal(worker.messages.filter((message) => message.type === "health").length, 2);
  emit(worker, health(probe));
  const message = worker.messages.find((message) => message.type === "scan");
  emit(worker, { type: "scan", id: message.id, status: "ok", findings: [] });
  assert.equal((await scan).status, "ok");
});

test("OPF scan waits beyond the generic two-second deadline when provisioned for ten seconds", async (t) => {
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
    if (message.type === "scan") setTimeout(() => emit({ type: "scan", id: message.id, status: "ok", findings: [] }), 2_100);
  });
  const extended = { privacy: {
    ...opfProvision.privacy,
    worker: { ...opfProvision.privacy.worker, args: opfProvision.privacy.worker.args.with(21, "10000") },
  } };
  const filter = await createPrivacyFilter({
    provision: extended, spawnWorker: () => worker, validateWorker, validateFile,
    validateCheckpoint: async () => async () => {},
  });
  t.after(() => filter.close());
  assert.equal((await filter.scan(Buffer.from('{"content":"synthetic"}'))).status, "ok");
});

test("a missing or replaced checkpoint blocks before the worker receives request bytes", async (t) => {
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
    if (message.type === "scan") emit({ type: "scan", id: message.id, status: "ok", findings: [] });
  });
  let spawns = 0;
  await assert.rejects(createPrivacyFilter({
    provision: opfProvision,
    validateWorker,
    validateFile,
    validateCheckpoint: async () => { throw new Error("missing model"); },
    spawnWorker: () => { spawns += 1; return worker; },
  }), /checkpoint unavailable/i);
  assert.equal(spawns, 0);

  let validations = 0;
  const filter = await createPrivacyFilter({
    provision: opfProvision,
    validateWorker,
    validateFile,
    validateCheckpoint: async (_asset, { label } = {}) => {
      if (label !== "source") validations += 1;
      return async () => { if (label !== "source" && ++validations === 2) throw new Error("checkpoint replaced"); };
    },
    spawnWorker: () => worker,
  });
  t.after(() => filter.close());
  const result = await filter.scan(Buffer.from(`{"content":"${sentinel}"}`));
  assert.equal(result.status, "unavailable");
  assert.equal(validations, 2);
  assert.equal(worker.messages.filter((message) => message.type === "scan").length, 0);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(sentinel));
});

test("OPF source, adapter and tokenizer drift fail closed before scan bytes", async (t) => {
  for (const changed of ["source", "adapter", "tokenizer"]) {
    const worker = fakeWorker((message, emit) => {
      if (message.type === "health") emit(health(message));
      if (message.type === "scan") emit({ type: "scan", id: message.id, status: "ok", findings: [] });
    });
    let ready = false;
    const filter = await createPrivacyFilter({
      provision: opfProvision, validateWorker, spawnWorker: () => worker,
      validateCheckpoint: async (_asset, { label } = {}) => async () => {
        if (ready && label === changed) throw new Error("tree replaced");
      },
      validateFile: async (_asset, { label } = {}) => {
        if (ready && label === changed) throw new Error("file replaced");
      },
    });
    t.after(() => filter.close());
    ready = true;
    const result = await filter.scan(Buffer.from(`{"content":"${sentinel}"}`));
    assert.equal(result.status, "unavailable", changed);
    assert.equal(result.reason, "assets_invalid", changed);
    assert.equal(worker.messages.filter((message) => message.type === "scan").length, 0, changed);
  }
  await assert.rejects(createPrivacyFilter({
    provision: { privacy: { ...opfProvision.privacy, source: undefined } },
    validateWorker, validateFile, validateCheckpoint: async () => async () => {},
  }), /provision is invalid/i);
});

test("runtime redaction proof requires every reported privacy span to be absent from replacement JSON", () => {
  const original = Buffer.from('{"content":"alice@example.com"}');
  const span = { start: 12, end: 29 };
  const result = {
    status: "ok",
    findings: [{ label: "email", count: 1 }],
    redactions: [{ label: "email", count: 1, spans: [span] }],
    redactedBody: Buffer.from('{"content":"[EMAIL]"}'),
  };
  assert.equal(isVerifiedRedaction({ original, result }), true);
  assert.equal(isVerifiedRedaction({ original, result: { ...result, redactedBody: Buffer.from('{"content":"alice@example.com (reviewed)"}') } }), false);
  assert.equal(isVerifiedRedaction({ original, result: { ...result, redactions: [{ label: "email", count: 1, spans: [] }] } }), false);
});

test("runtime redaction proof lets a value survive only inside an unchanged provider-signed field", () => {
  const signature = "EqQBCkYIBxgCKkBAliceSmith0123456789abcdef";
  const body = (text, signed = signature, role = "assistant") => Buffer.from(JSON.stringify({ messages: [
    { role: "user", content: [{ type: "text", text }] },
    { role, content: [{ type: "thinking", thinking: "plan", signature: signed }] },
  ] }));
  const original = body("Alice");
  const start = original.indexOf("Alice");
  const result = {
    status: "ok",
    findings: [{ label: "private_person", count: 1 }],
    redactions: [{ label: "private_person", count: 1, spans: [{ start, end: start + 5 }] }],
    redactedBody: body("[redacted:private_person]"),
  };
  assert.equal(isVerifiedRedaction({ original, result }), true);
  assert.equal(isVerifiedRedaction({ original, result: { ...result, redactedBody: body("[redacted:private_person]", signature.replace("Alice", "Xxxxx")) } }), false,
    "a signed field must stay byte-identical");
  assert.equal(isVerifiedRedaction({ original, result: { ...result, redactedBody: body("[redacted:private_person] Alice") } }), false);
  const forged = body("Alice", signature, "user");
  assert.equal(isVerifiedRedaction({ original: forged, result: { ...result, redactedBody: body("[redacted:private_person]", signature, "user") } }), false,
    "a look-alike signature outside an assistant thinking block is ordinary text");
});

test("runtime redaction proof stays linear in the number of provider-signed fields", () => {
  const citations = Array.from({ length: 12_000 }, (_, index) =>
    ({ type: "web_search_result_location", encrypted_index: `Alice${String(index).padStart(16, "0")}` }));
  const body = (text) => Buffer.from(JSON.stringify({ messages: [
    { role: "user", content: [{ type: "text", text }] },
    { role: "assistant", content: [{ type: "text", text: "cited", citations }] },
  ] }));
  const original = body("Alice");
  const start = original.indexOf("Alice");
  const result = {
    status: "ok",
    findings: [{ label: "private_person", count: 1 }],
    redactions: [{ label: "private_person", count: 1, spans: [{ start, end: start + 5 }] }],
    redactedBody: body("[redacted:private_person]"),
  };
  const started = performance.now();
  assert.equal(isVerifiedRedaction({ original, result }), true);
  assert.ok(performance.now() - started < 5_000, "verification must not scale with the square of the opaque entry count");
  assert.equal(isVerifiedRedaction({ original, result: { ...result, redactedBody: body("[redacted:private_person] Alice") } }), false);
});

test("runtime redaction proof covers the combined findings of duplicate label batches", () => {
  const original = Buffer.from('{"content":"alice@example.com bob@example.com carol@example.com"}');
  const firstTwo = [{ start: 12, end: 29 }, { start: 30, end: 45 }];
  const last = { start: 46, end: 63 };
  const result = {
    status: "ok",
    findings: [{ label: "email", count: 2 }, { label: "email", count: 1 }],
    redactions: [{ label: "email", count: 2, spans: firstTwo }, { label: "email", count: 1, spans: [last] }],
    redactedBody: Buffer.from('{"content":"[EMAIL] [EMAIL] [EMAIL]"}'),
  };
  assert.equal(isVerifiedRedaction({ original, result }), true, "all three findings have proof across two batches");
  assert.equal(isVerifiedRedaction({ original, result: { ...result, redactions: [{ label: "email", count: 2, spans: firstTwo }] } }), false, "two proofs cannot cover three findings even when each batch count is at most two");
});

test("summed runtime proof preserves missing-label rejection and extra proof coverage", () => {
  const original = Buffer.from('{"content":"alice@example.com bob@example.com carol@example.com"}');
  const spans = [{ start: 12, end: 29 }, { start: 30, end: 45 }, { start: 46, end: 63 }];
  const result = {
    status: "ok",
    findings: [{ label: "email", count: 1 }, { label: "email", count: 1 }],
    redactions: [{ label: "email", count: 3, spans }],
    redactedBody: Buffer.from('{"content":"[EMAIL] [EMAIL] [EMAIL]"}'),
  };
  assert.equal(isVerifiedRedaction({ original, result }), true, "three proofs still cover two combined findings");
  assert.equal(isVerifiedRedaction({ original, result: { ...result, findings: [...result.findings, { label: "phone", count: 1 }] } }), false);
  assert.equal(isVerifiedRedaction({ original, result: { ...result, redactions: [...result.redactions, { label: "phone", count: 1, spans: [spans[0]] }] } }), true);
});

test("privacy normalization accepts complete same-label proof batches above 1024 total", async (t) => {
  const original = Buffer.from(JSON.stringify({ content: "alice@example.com ".repeat(1025) }));
  const spans = Array.from({ length: 1025 }, (_, index) => ({ start: 12 + index * 18, end: 29 + index * 18 }));
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
    if (message.type === "scan") emit({
      type: "scan", id: message.id, status: "ok",
      findings: [{ label: "email", count: 1024 }, { label: "email", count: 1 }],
      redactions: [{ label: "email", count: 1024, spans: spans.slice(0, 1024) }, { label: "email", count: 1, spans: spans.slice(1024) }],
      redactedBody: Buffer.from(JSON.stringify({ content: "[EMAIL] ".repeat(1025) })).toString("base64"),
    });
  });
  const filter = await createPrivacyFilter({ provision, validateWorker, spawnWorker: () => worker });
  t.after(() => filter.close());
  const result = await filter.scan(original);
  assert.equal(result.status, "ok");
  assert.deepEqual(result.findings, [{ label: "email", count: 1024 }, { label: "email", count: 1 }]);
  assert.equal(isVerifiedRedaction({ original, result }), true);
});

test("privacy provision self-test requires deterministic supported-label redaction", async () => {
  const goodWorker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
    if (message.type === "scan") emit({ type: "scan", id: message.id, status: "ok", findings: [{ label: "email", count: 1 }], redactions: [{ label: "email", count: 1, spans: [{ start: 12, end: 47 }] }], redactedBody: Buffer.from('{"content":"[EMAIL]"}').toString("base64") });
  });
  assert.deepEqual(await runPrivacyWorkerSelfTest(provision, { spawnWorker: () => goodWorker, validateWorker }), { version: "privacy-1" });

  const inadequateWorker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
    if (message.type === "scan") emit({ type: "scan", id: message.id, status: "ok", findings: [] });
  });
  await assert.rejects(runPrivacyWorkerSelfTest(provision, { spawnWorker: () => inadequateWorker, validateWorker }), /self-test failed/i);
});

test("OPF provision self-test uses a valid synthetic mailbox and requires private_email", async () => {
  let scannedBody;
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
    if (message.type === "scan") {
      scannedBody = Buffer.from(message.body, "base64").toString("utf8");
      emit({ type: "scan", id: message.id, status: "ok",
        findings: [{ label: "private_email", count: 1 }],
        redactions: [{ label: "private_email", count: 1, spans: [{ start: 12, end: 29 }] }],
        redactedBody: Buffer.from('{"content":"[EMAIL]"}').toString("base64"),
      });
    }
  });
  let selfTestArgs;
  assert.deepEqual(await runPrivacyWorkerSelfTest(opfProvision, {
    spawnWorker: ({ args }) => { selfTestArgs = args; return worker; }, validateWorker, validateFile, validateCheckpoint: async () => async () => {},
  }), { version: "privacy-1" });
  assert.equal(scannedBody, '{"content":"alice@example.com"}');
  assert.equal(selfTestArgs.includes("--window-cache-dir"), false, "the self-test must stay on the memory cache");

  const wrongLabel = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
    if (message.type === "scan") emit({ type: "scan", id: message.id, status: "ok",
      findings: [{ label: "email", count: 1 }],
      redactions: [{ label: "email", count: 1, spans: [{ start: 12, end: 29 }] }],
      redactedBody: Buffer.from('{"content":"[EMAIL]"}').toString("base64"),
    });
  });
  await assert.rejects(runPrivacyWorkerSelfTest(opfProvision, {
    spawnWorker: () => wrongLabel, validateWorker, validateFile, validateCheckpoint: async () => async () => {},
  }), /self-test failed/i);
});

test("privacy self-test rejects unchanged or category-incomplete replacement bodies", async () => {
  const unchangedWorker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
    if (message.type === "scan") emit({ type: "scan", id: message.id, status: "ok", findings: [{ label: "email", count: 1 }], redactions: [{ label: "email", count: 1, spans: [{ start: 12, end: 49 }] }], redactedBody: Buffer.from('{"content":"CCSHIELD_PRIVACY_PROTOCOL_PROBE_EMAIL"}').toString("base64") });
  });
  await assert.rejects(runPrivacyWorkerSelfTest(provision, { spawnWorker: () => unchangedWorker, validateWorker }), /self-test failed/i);

  const incompleteWorker = fakeWorker((message, emit) => {
    if (message.type === "health") emit(health(message));
    if (message.type === "scan") emit({ type: "scan", id: message.id, status: "ok", findings: [{ label: "email", count: 1 }], redactions: [], redactedBody: Buffer.from('{"content":"[EMAIL]"}').toString("base64") });
  });
  await assert.rejects(runPrivacyWorkerSelfTest(provision, { spawnWorker: () => incompleteWorker, validateWorker }), /self-test failed/i);
});

test("privacy worker timeout, exit, malformed reply, unknown labels, and oversized output fail closed without raw data", async (t) => {
  const cases = [
    { name: "timeout", handler: (message, emit) => { if (message.type === "health") emit(health(message)); }, expected: "unavailable", reason: "scan_timeout" },
    { name: "exit", handler: (message, emit, worker) => message.type === "health" ? emit(health(message)) : worker.emit("exit", 1), expected: "unavailable", reason: "worker_unavailable" },
    { name: "malformed", handler: (message, emit) => message.type === "health" ? emit(health(message)) : emit({ type: "scan", id: message.id, status: "ok", findings: "bad" }), expected: "unavailable", reason: "reply_invalid" },
    { name: "mismatched", handler: (message, emit) => message.type === "health" ? emit(health(message)) : emit({ type: "scan", id: "different", status: "ok", findings: [] }), expected: "unavailable", reason: "scan_timeout" },
    { name: "unknown", handler: (message, emit) => message.type === "health" ? emit(health(message)) : emit({ type: "scan", id: message.id, status: "ok", findings: [{ label: "mystery", count: 1 }] }), expected: "unknown", reason: "findings_invalid" },
    { name: "oversized", handler: (message, emit, worker) => message.type === "health" ? emit(health(message)) : worker.stdout.emit("data", "x".repeat(4 * 1_048_576 + 1)), expected: "unavailable", reason: "frame_limit" },
    { name: "invalid redaction", handler: (message, emit) => message.type === "health" ? emit(health(message)) : emit({ type: "scan", id: message.id, status: "ok", findings: [], redactions: [{ label: sentinel, count: 1 }] }), expected: "unavailable", reason: "redaction_invalid" },
    { name: "invalid replacement", handler: (message, emit) => message.type === "health" ? emit(health(message)) : emit({ type: "scan", id: message.id, status: "ok", findings: [], redactedBody: sentinel }), expected: "unavailable", reason: "redaction_invalid" },
  ];

  for (const fixture of cases) {
    const worker = fakeWorker(fixture.handler);
    const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker, timeoutMs: 5 });
    t.after(() => filter.close());
    const result = await filter.scan(Buffer.from(`{"content":"${sentinel}"}`));
    assert.equal(result.status, fixture.expected, fixture.name);
    assert.equal(result.reason, fixture.reason, fixture.name);
    assert.equal(result.redactedBody, undefined, fixture.name);
    assert.doesNotMatch(JSON.stringify(result), new RegExp(sentinel), fixture.name);
  }
});

test("privacy startup can exceed the scan deadline without disabling scan fail-closed", async (t) => {
  const worker = fakeWorker((message, emit) => {
    if (message.type === "health") setTimeout(() => emit(health(message)), 20);
  });
  const filter = await createPrivacyFilter({ provision, spawnWorker: () => worker, validateWorker, timeoutMs: 5, startupTimeoutMs: 50 });
  t.after(() => filter.close());
  assert.equal((await filter.scan(Buffer.from('{"content":"synthetic"}'))).status, "unavailable");
  assert.equal(worker.messages.filter((message) => message.type === "scan").length, 1);
});

test("OPF worker runs through the current Node interpreter instead of its executable shebang", async (t) => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "ccshield-opf-interpreter-")));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const workerPath = join(directory, "worker.mjs");
  await writeFile(workerPath, `#!/usr/bin/false\nprocess.stdin.on("data", (chunk) => {\n  const request = JSON.parse(String(chunk).trim());\n  process.stdout.write(JSON.stringify({ type: "health", id: request.id, protocol: request.protocol, version: "privacy-1" }) + "\\n");\n});\n`);
  await chmod(workerPath, 0o700);
  const pinned = { privacy: {
    ...opfProvision.privacy,
    worker: { ...opfProvision.privacy.worker, command: workerPath },
    adapter: { ...opfProvision.privacy.adapter, path: join(directory, "opf-adapter.mjs") },
  } };
  const filter = await createPrivacyFilter({
    provision: pinned,
    validateWorker,
    validateFile,
    validateCheckpoint: async () => async () => {},
    startupTimeoutMs: 1_000,
  });
  t.after(() => filter.close());
  assert.equal(filter.version, "privacy-1");
});

test("checkpoint startup digest and per-scan metadata detect same-size inode replacement", async (t) => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "ccshield-privacy-attest-")));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const model = join(directory, "model.bin");
  const bytes = Buffer.from("synthetic-model");
  await writeFile(model, bytes);
  const sha256 = createHash("sha256").update("model.bin\0").update(String(bytes.length)).update("\0").update(bytes).update("\0").digest("hex");
  const assertUnchanged = await attestShieldCheckpoint({ path: directory, sha256, version: "test" });
  await assertUnchanged();
  const replacement = join(directory, "new.bin");
  await writeFile(replacement, Buffer.from("synthetic-other"));
  await rename(replacement, model);
  await assert.rejects(assertUnchanged(), /metadata changed/i);
});

function health(message) {
  return { type: "health", id: message.id, protocol: "airkit-privacy-ndjson-v1", version: "privacy-1" };
}

function cooperativeHealth(message) {
  return { ...health(message), capabilities: ["cooperative-timeout"] };
}

async function flushTasks() {
  await new Promise((resolve) => setImmediate(resolve));
}

function fakeWorker(handler) {
  const worker = new EventEmitter();
  worker.stdout = new EventEmitter();
  worker.stderr = new EventEmitter();
  worker.messages = [];
  worker.stdin = Object.assign(new EventEmitter(), {
    write(chunk) {
      const message = JSON.parse(String(chunk).trim());
      worker.messages.push(message);
      handler(message, (reply) => emit(worker, reply), worker);
      return true;
    },
    end() {},
  });
  worker.kill = () => worker.emit("exit", 0);
  return worker;
}

function emit(worker, reply) {
  worker.stdout.emit("data", `${JSON.stringify(reply)}\n`);
}

test("the worker environment maps the old OPF warm-budget name and lets the new one win", () => {
  assert.deepEqual(privacyWorkerEnv({ PATH: "/bin", AIRKIT_SHIELD_OPF_WARM_SECONDS: "0" }), { PATH: "/bin", CCSHIELD_OPF_WARM_SECONDS: "0" });
  assert.deepEqual(privacyWorkerEnv({ AIRKIT_SHIELD_OPF_WARM_SECONDS: "0", CCSHIELD_OPF_WARM_SECONDS: "30" }), { CCSHIELD_OPF_WARM_SECONDS: "30" });
  assert.deepEqual(privacyWorkerEnv({ PATH: "/bin" }), { PATH: "/bin" });
});
