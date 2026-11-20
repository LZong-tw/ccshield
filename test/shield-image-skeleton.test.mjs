import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import test from "node:test";

import { extractMedia, imageSkeleton, patchMedia, restoreImages } from "../src/shield/media.mjs";
import { isVerifiedRedaction, opaqueValues } from "../src/shield/privacy.mjs";

const TEXT_BUDGET = 1_048_576;
const MAGIC = {
  "image/png": Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  "image/jpeg": Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
  "image/gif": Buffer.from("GIF89a", "latin1"),
  "image/webp": Buffer.concat([Buffer.from("RIFF"), Buffer.alloc(4), Buffer.from("WEBP")]),
};

// Pseudo-random filler, so the payload base64 looks like a real screenshot's.
function fakeImage(mime, size, seed) {
  const bytes = Buffer.alloc(size);
  let state = seed * 2_654_435_761 >>> 0;
  for (let index = 0; index < size; index += 1) {
    state = (state * 1_103_515_245 + 12_345) >>> 0;
    bytes[index] = state >>> 24;
  }
  MAGIC[mime].copy(bytes);
  return bytes;
}

const image = (bytes, mime) => ({ type: "image", source: { type: "base64", media_type: mime, data: bytes.toString("base64") } });
const MIMES = Object.keys(MAGIC);
// Nine screenshots, about 1.48 MB of base64 together: the incident's history.
const screenshots = Array.from({ length: 9 }, (_, index) => image(fakeImage(MIMES[index % 4], 123_000, index + 1), MIMES[index % 4]));
const conversation = (tail) => Buffer.from(JSON.stringify({
  model: "claude-sonnet-5",
  messages: [
    { role: "user", content: [{ type: "text", text: "first look" }, ...screenshots.slice(0, 5)] },
    { role: "assistant", content: [{ type: "text", text: "seen" }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_1", content: screenshots.slice(5) }, { type: "text", text: tail }] },
  ],
}));

const workerPath = resolve(import.meta.dirname, "..", "detectors", "regex", "privacy-worker.mjs");

// The real regex privacy worker, answering in the shape privacy.scan hands to isVerifiedRedaction.
function regexScan(body) {
  const result = spawnSync(process.execPath, [workerPath], { input: `${JSON.stringify({ id: "t", type: "scan", body: body.toString("base64") })}\n`, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const reply = JSON.parse(result.stdout);
  assert.equal(reply.status, "ok");
  return { ...reply, redactions: reply.redactions ?? [], ...(reply.redactedBody ? { redactedBody: Buffer.from(reply.redactedBody, "base64") } : {}) };
}

test("the skeleton swaps each image payload for a 16-character stand-in and restores byte for byte", () => {
  const raw = conversation("thanks");
  assert.ok(raw.length > 1_400_000, "the fixture is well over the text budget");
  const media = extractMedia(raw);
  assert.deepEqual(media.reasonCodes, []);
  assert.equal(media.images.length, 9);

  const skeleton = imageSkeleton(raw, media.images);
  assert.ok(skeleton.length < 4096, `skeleton is ${skeleton.length} bytes`);
  const found = extractMedia(skeleton);
  assert.deepEqual(found.reasonCodes, [], "the skeleton still reads as the same images");
  assert.deepEqual(found.images.map(({ path, mime }) => [path, mime]), media.images.map(({ path, mime }) => [path, mime]));
  const standIns = found.images.map((item) => skeleton.subarray(item.rawOffset, item.rawOffset + item.rawLength).toString("latin1"));
  assert.ok(standIns.every((value) => value.length === 16), JSON.stringify(standIns));
  assert.equal(new Set(standIns).size, standIns.length, "no two stand-ins in one body are equal");
  assert.deepEqual(opaqueValues(skeleton).map(([, value]) => value), standIns, "privacy treats every stand-in as a protected opaque value");

  assert.deepEqual(restoreImages(skeleton, media.images), raw);
});

test("text alone still counts in full against the budget", () => {
  const raw = Buffer.from(JSON.stringify({ messages: [{ role: "user", content: [{ type: "text", text: "x".repeat(TEXT_BUDGET) }, screenshots[0]] }] }));
  const skeleton = imageSkeleton(raw, extractMedia(raw).images);
  assert.ok(skeleton.length > TEXT_BUDGET);
});

test("the real regex worker finds nothing in stand-ins of any image type", () => {
  const many = Array.from({ length: 40 }, (_, index) => image(fakeImage(MIMES[index % 4], 64, index), MIMES[index % 4]));
  const raw = Buffer.from(JSON.stringify({ messages: [{ role: "user", content: [{ type: "text", text: "clean" }, ...many] }] }));
  const scan = regexScan(imageSkeleton(raw, extractMedia(raw).images));
  assert.deepEqual(scan.findings, []);
});

test("text redacted after large images is spliced back around the original payloads", () => {
  const raw = conversation("reach me at alice@example.com please");
  const media = extractMedia(raw);
  const skeleton = imageSkeleton(raw, media.images);
  const scan = regexScan(skeleton);
  assert.deepEqual(scan.findings, [{ label: "email", count: 1 }]);
  const [span] = scan.redactions[0].spans;
  assert.equal(skeleton.subarray(span.start, span.end).toString("utf8"), "alice@example.com", "spans index into the skeleton the detector saw");
  assert.equal(isVerifiedRedaction({ original: skeleton, result: scan }), true);

  const restored = restoreImages(scan.redactedBody, media.images);
  const parsed = JSON.parse(restored.toString("utf8"));
  assert.equal(parsed.messages[2].content[1].text, "reach me at [redacted:email] please");
  assert.ok(!restored.includes("alice@example.com"));
  const after = extractMedia(restored);
  assert.deepEqual(after.images.map(({ path, bytes }) => [path, bytes.toString("base64")]), media.images.map(({ path, bytes }) => [path, bytes.toString("base64")]));
  // Only the email changed: everything else is the original body, byte for byte.
  assert.deepEqual(restored, Buffer.from(raw.toString("utf8").replace("alice@example.com", "[redacted:email]")));
});

test("a redacted skeleton whose stand-ins moved, changed or vanished does not restore", () => {
  const raw = conversation("thanks");
  const media = extractMedia(raw);
  const skeleton = imageSkeleton(raw, media.images);
  const [first, second] = extractMedia(skeleton).images;
  const standIn = (item) => skeleton.subarray(item.rawOffset, item.rawOffset + item.rawLength).toString("latin1");
  const cases = {
    swapped: patchMedia(skeleton, [{ ...first, text: standIn(second) }, { ...second, text: standIn(first) }]),
    altered: patchMedia(skeleton, [{ ...first, text: `${standIn(first).slice(0, 15)}${standIn(first).endsWith("Q") ? "R" : "Q"}` }]),
    emptied: patchMedia(skeleton, [{ ...first, text: "" }]),
    dropped: Buffer.from(JSON.stringify({ ...JSON.parse(skeleton), messages: JSON.parse(skeleton).messages.slice(1) })),
    duplicated: Buffer.from(skeleton.toString("utf8").replace('"model"', '"model":"x","model"')),
    unparseable: skeleton.subarray(0, skeleton.length - 1),
  };
  for (const [name, redacted] of Object.entries(cases)) {
    assert.throws(() => restoreImages(redacted, media.images), undefined, name);
  }
});
