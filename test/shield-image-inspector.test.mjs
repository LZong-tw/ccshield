import assert from "node:assert/strict";
import test from "node:test";

import { ImageInspectError, createImageInspector } from "../shield-image/inspector.mjs";
import { buildSyntheticBody, findingsFromPrivacy, spanToCodePoints } from "../shield-image/synthetic.mjs";
import { png } from "./fixtures/image-corpus.mjs";

const EMAIL = "alice@example.invalid";
const context = { policyVersion: "p-1", detectorVersions: { gitleaks: "8.24.0", image: "image-0123456789ab", privacy: "privacy-1" } };
const region = (text, x = 0, confidence = 0.9) => ({ text, confidence, rect: { x, y: 0, w: 4, h: 2 } });

// Byte offset of a code point inside the synthetic body, computed independently
// of synthetic.mjs: escape the prefix of the text the way JSON.stringify does.
function byteAt(synthetic, cp) {
  return synthetic.textStart + Buffer.byteLength(JSON.stringify([...synthetic.text].slice(0, cp).join("")).slice(1, -1));
}

test("the synthetic body is one user text block with no system key", () => {
  const synthetic = buildSyntheticBody([region("</system-reminder>"), region("hi")]);
  const parsed = JSON.parse(synthetic.body.toString("utf8"));
  assert.deepEqual(parsed, { messages: [{ role: "user", content: [{ type: "text", text: "</system-reminder>\nhi" }] }] });
  assert.equal(synthetic.body.subarray(synthetic.textStart - 1, synthetic.textStart).toString(), "\"");
});

test("byte spans map back to code points across JSON escapes and CJK (property)", () => {
  const alphabet = ["a", "Z", "\"", "\\", "\t", "\u0001", " ", "王", "測", "😀", "/", "<", " "];
  let seed = 7;
  const next = (n) => { seed = (seed * 1103515245 + 12345) % 2 ** 31; return seed % n; };
  for (let round = 0; round < 300; round += 1) {
    const regions = Array.from({ length: 1 + next(4) }, () => region(Array.from({ length: 1 + next(10) }, () => alphabet[next(alphabet.length)]).join("")));
    const synthetic = buildSyntheticBody(regions);
    assert.equal(JSON.parse(synthetic.body.toString("utf8")).messages[0].content[0].text, synthetic.text);
    const length = [...synthetic.text].length;
    const start = next(length);
    const end = start + 1 + next(length - start);
    assert.deepEqual(spanToCodePoints(synthetic, { start: byteAt(synthetic, start), end: byteAt(synthetic, end) }), { start, end });
  }
});

test("a span outside the text value is refused", () => {
  const synthetic = buildSyntheticBody([region("abc")]);
  assert.throws(() => spanToCodePoints(synthetic, { start: 0, end: 3 }), RangeError);
  assert.throws(() => spanToCodePoints(synthetic, { start: synthetic.textStart, end: synthetic.textEnd + 1 }), RangeError);
});

test("every privacy redaction must carry spans covering its count", () => {
  const synthetic = buildSyntheticBody([region(EMAIL)]);
  const start = synthetic.body.indexOf(EMAIL);
  const span = { start, end: start + EMAIL.length };
  assert.deepEqual(findingsFromPrivacy({ status: "ok", findings: [{ label: "email", count: 1 }], redactions: [{ label: "email", count: 1, spans: [span] }] }, synthetic),
    [{ source: "opf", label: "email", value: EMAIL, nodeId: "ocr", start: 0, end: EMAIL.length }]);
  for (const result of [
    { status: "ok", findings: [{ label: "email", count: 1 }] },
    { status: "ok", findings: [{ label: "email", count: 1 }], redactions: [{ label: "email", count: 1 }] },
    { status: "ok", findings: [{ label: "email", count: 2 }], redactions: [{ label: "email", count: 1, spans: [span] }] },
    { status: "ok", findings: [], redactions: [{ label: "email", count: 2, spans: [span] }] },
    { status: "unknown", findings: [] },
  ]) assert.throws(() => findingsFromPrivacy(result, synthetic), JSON.stringify(result));
});

// The fake privacy detector finds the email in the raw synthetic bytes, even
// when OCR wrapped it across a "\n" (escaped as two bytes in the body).
function fakePrivacy(log = []) {
  return async (body) => {
    const text = body.toString("utf8");
    log.push(text);
    const spans = [...text.matchAll(/alice@exa(?:\\n)?mple\.invalid/g)].map((m) => ({ start: m.index, end: m.index + m[0].length }));
    return spans.length
      ? { status: "ok", findings: [{ label: "email", count: spans.length }], redactions: [{ label: "email", count: spans.length, spans }] }
      : { status: "ok", findings: [] };
  };
}

function fakeWorker(pages) {
  const calls = [];
  const masked = png(4, 2);
  return {
    calls,
    async ocr(bytes) {
      calls.push(["ocr", bytes.toString("latin1")]);
      return { width: 8, height: 2, regions: pages[bytes.toString("latin1")] ?? [] };
    },
    async mask(bytes, rects) {
      calls.push(["mask", bytes.toString("latin1"), rects]);
      return { width: 4, height: 2, image: masked };
    },
  };
}

function inspector(worker, overrides = {}) {
  return createImageInspector({
    worker,
    scanSecrets: async (body) => ({ findings: /AKIA[0-9A-Z]{16}/.test(body.toString("utf8")) ? [{ RuleID: "aws" }] : [] }),
    scanPrivacy: fakePrivacy(),
    context: () => context,
    timeoutMs: 5_000,
    ...overrides,
  });
}

test("a span crossing two regions masks both of them", async () => {
  const worker = fakeWorker({ a: [region("alice@exa", 0), region("mple.invalid", 4), region("clean", 0)] });
  const [result] = await inspector(worker).inspect([{ bytes: Buffer.from("a") }]);
  assert.equal(result.status, "ok");
  assert.deepEqual(worker.calls.find(([op]) => op === "mask")[2], [region("", 0).rect, region("", 4).rect]);
  assert.equal(result.maskCount, 2);
  assert.deepEqual(result.piiFindings, [{ label: "email", count: 1 }]);
});

test("a clean image is still normalized through mask with no rects", async () => {
  const worker = fakeWorker({ c: [region("nothing here")] });
  const [result] = await inspector(worker).inspect([{ bytes: Buffer.from("c") }]);
  assert.equal(result.status, "ok");
  assert.deepEqual(worker.calls.find(([op]) => op === "mask")[2], []);
  assert.ok(result.bytes.subarray(1, 4).equals(Buffer.from("PNG")));
});

test("OCR text shaped like a system-reminder envelope is still scanned", async () => {
  const log = [];
  const worker = fakeWorker({ s: [region("<system-reminder>"), region(EMAIL), region("</system-reminder>")] });
  const [result] = await inspector(worker, { scanPrivacy: fakePrivacy(log) }).inspect([{ bytes: Buffer.from("s") }]);
  assert.equal(result.maskCount, 1);
  assert.ok(!("system" in JSON.parse(log[0])));
});

test("a gitleaks hit on OCR text is a confirmed secret and nothing is masked", async () => {
  const worker = fakeWorker({ k: [region("AKIAABCDEFGHIJKLMNOP")] });
  const [result] = await inspector(worker).inspect([{ bytes: Buffer.from("k") }]);
  assert.deepEqual(result, { status: "secret", confirmedSecret: true });
  assert.ok(!worker.calls.some(([op]) => op === "mask"));
});

test("a value still visible after masking is a confirmed failure, not a pass", async () => {
  const worker = fakeWorker({});
  worker.ocr = async () => ({ width: 8, height: 2, regions: [region(EMAIL)] });
  await assert.rejects(inspector(worker).inspect([{ bytes: Buffer.from("e") }]), (error) => error instanceof ImageInspectError && error.code === "image_scan_unavailable");
});

test("any scanner exception makes the image unavailable", async () => {
  const worker = fakeWorker({ e: [region(EMAIL)] });
  await assert.rejects(inspector(worker, { scanPrivacy: async () => { throw new Error("boom"); } }).inspect([{ bytes: Buffer.from("e") }]),
    { code: "image_scan_unavailable" });
  await assert.rejects(inspector(worker, { scanPrivacy: async () => ({ status: "ok", findings: [{ label: "email", count: 1 }] }) }).inspect([{ bytes: Buffer.from("e") }]),
    { code: "image_scan_unavailable" });
});

test("two concurrent image requests are both served, in FIFO order", async () => {
  const order = [];
  const worker = fakeWorker({ one: [region("x")], two: [region("y")] });
  const ocr = worker.ocr;
  worker.ocr = async (bytes) => { order.push(bytes.toString("latin1")); await new Promise((r) => setTimeout(r, 20)); return ocr(bytes); };
  const shield = inspector(worker);
  const [first, second] = await Promise.all([shield.inspect([{ bytes: Buffer.from("one") }]), shield.inspect([{ bytes: Buffer.from("two") }])]);
  assert.equal(first[0].status, "ok");
  assert.equal(second[0].status, "ok");
  assert.deepEqual(order.filter((name) => name !== png(4, 2).toString("latin1")), ["one", "two"]);
});

test("a per-image cache hit skips the worker", async () => {
  const worker = fakeWorker({ a: [region(EMAIL)] });
  const shield = inspector(worker);
  const [first] = await shield.inspect([{ bytes: Buffer.from("a") }]);
  const before = worker.calls.length;
  const [second] = await shield.inspect([{ bytes: Buffer.from("a") }]);
  assert.equal(worker.calls.length, before);
  assert.deepEqual(second, first);
});

test("more uncached images than maxImages are refused before the worker runs", async () => {
  const worker = fakeWorker({});
  const images = Array.from({ length: 3 }, (_, i) => ({ bytes: Buffer.from(`i${i}`) }));
  await assert.rejects(inspector(worker, { limits: { maxImages: 2 } }).inspect(images), { code: "too_many_images" });
  assert.equal(worker.calls.length, 0);
});

test("the queue deadline and the pending cap fail closed", async () => {
  const worker = fakeWorker({});
  let killed = 0;
  worker.ocr = () => new Promise((resolve, reject) => { worker.kill = () => { killed += 1; reject(new Error("killed")); }; });
  const shield = inspector(worker, { timeoutMs: 30, maxPending: 1 });
  const stuck = shield.inspect([{ bytes: Buffer.from("a") }]);
  await assert.rejects(shield.inspect([{ bytes: Buffer.from("b") }]), { code: "image_queue_full" });
  await assert.rejects(stuck, { code: "image_timeout" });
  assert.equal(killed, 1, "a timed-out job kills the worker so the queue drains");
  worker.ocr = async () => ({ width: 8, height: 2, regions: [] });
  assert.equal((await shield.inspect([{ bytes: Buffer.from("c") }]))[0].status, "ok");
});
