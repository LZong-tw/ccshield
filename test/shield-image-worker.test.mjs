import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { appendFile, chmod, readFile, rm } from "node:fs/promises";
import test from "node:test";

import { ImageWorkerError, createImageWorker } from "../shield-image/worker.mjs";
import { fakeWorker, png } from "./fixtures/image-corpus.mjs";

const sha256 = async (path) => createHash("sha256").update(await readFile(path)).digest("hex");

async function setup(t, behaviour, options = {}) {
  const fake = await fakeWorker(behaviour);
  t.after(() => rm(fake.dir, { recursive: true, force: true }));
  const worker = createImageWorker({ path: fake.path, sha256: await sha256(fake.path), timeoutMs: 2000, ...options });
  t.after(() => worker.close());
  return { fake, worker };
}

async function rejectsWith(promise, code) {
  await assert.rejects(promise, (error) => error instanceof ImageWorkerError && error.code === code);
}

test("probe, ocr and mask round-trip through a Node-shebang fake", async (t) => {
  const { worker } = await setup(t, "echo");
  assert.deepEqual(await worker.probe(), { worker: "image-fake00000000", languages: ["en-US"] });
  const bytes = png(4, 2);
  const ocr = await worker.ocr(bytes);
  assert.deepEqual(ocr, { width: 4, height: 2, regions: [{ text: "alice@example.invalid", confidence: 0.9, rect: { x: 0, y: 0, w: 4, h: 2 } }] });
  const masked = await worker.mask(bytes, [{ x: 0, y: 0, w: 4, h: 2 }]);
  assert.equal(masked.width, 4);
  assert.ok(Buffer.isBuffer(masked.image));
  assert.deepEqual(masked.image, bytes);
});

test("concurrent requests are serialized and matched by id", async (t) => {
  const { worker } = await setup(t, "echo");
  const results = await Promise.all([worker.probe(), worker.ocr(png(4, 2)), worker.probe()]);
  assert.equal(results.length, 3);
  assert.equal(results[1].regions.length, 1);
});

test("a worker error code is surfaced without any text", async (t) => {
  const { worker } = await setup(t, "error");
  await rejectsWith(worker.ocr(png(4, 2)), "multi_frame");
});

test("an error response with extra fields is a protocol violation", async (t) => {
  const { worker } = await setup(t, "leaky");
  await assert.rejects(worker.ocr(png(4, 2)), (error) => error.code === "worker_protocol" && !String(error.message).includes("alice"));
});

test("a stdout line over maxFrame kills the worker", async (t) => {
  const { worker } = await setup(t, "huge");
  await rejectsWith(worker.probe(), "worker_frame_too_large");
});

test("a silent worker times out", async (t) => {
  const { worker } = await setup(t, "silent", { timeoutMs: 200 });
  await rejectsWith(worker.probe(), "worker_timeout");
});

test("probe has its own deadline, separate from requests", async (t) => {
  const { worker } = await setup(t, "silent", { timeoutMs: 60_000, probeTimeoutMs: 200 });
  await rejectsWith(worker.probe(), "worker_timeout");
});

test("a response for another id is a protocol violation", async (t) => {
  const { worker } = await setup(t, "wrongId");
  await rejectsWith(worker.probe(), "worker_protocol");
});

test("non-JSON output is a protocol violation", async (t) => {
  const { worker } = await setup(t, "garbage");
  await rejectsWith(worker.probe(), "worker_protocol");
});

test("non-integer rects are rejected", async (t) => {
  const { worker } = await setup(t, "badRect");
  await rejectsWith(worker.ocr(png(4, 2)), "worker_protocol");
});

test("a worker that exits fails the pending request", async (t) => {
  const { worker } = await setup(t, "exit");
  await rejectsWith(worker.probe(), "worker_exited");
});

test("a dead worker is re-attested and respawned on the next request", async (t) => {
  const { worker } = await setup(t, "pid", { timeoutMs: 2000 });
  const first = await worker.probe();
  worker.kill();
  const second = await worker.probe();
  assert.notEqual(first.worker, second.worker);
});

test("re-attestation rejects a tampered binary before spawning", async (t) => {
  const { fake, worker } = await setup(t, "pid");
  await worker.probe();
  worker.kill();
  await appendFile(fake.path, "// tampered\n");
  await rejectsWith(worker.probe(), "worker_attestation");
});

test("attestation rejects a group-writable or non-executable binary", async (t) => {
  const { fake, worker } = await setup(t, "echo");
  await chmod(fake.path, 0o775);
  await rejectsWith(worker.probe(), "worker_attestation");
  await chmod(fake.path, 0o644);
  await rejectsWith(worker.probe(), "worker_attestation");
});

test("attestation rejects a relative path", async () => {
  const worker = createImageWorker({ path: "image-worker", sha256: "0".repeat(64) });
  await rejectsWith(worker.probe(), "worker_attestation");
});

test("oversized input is refused before it reaches the worker", async (t) => {
  const { worker } = await setup(t, "echo");
  await rejectsWith(worker.ocr(Buffer.alloc(786433)), "bad_request");
});

test("a closed worker refuses new requests", async (t) => {
  const { worker } = await setup(t, "echo");
  await worker.probe();
  worker.close();
  await rejectsWith(worker.probe(), "worker_closed");
});
