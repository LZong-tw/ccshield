import assert from "node:assert/strict";
import test from "node:test";

import { ImageLimitError, SHIELD_IMAGE_LIMITS, assertImageWithinLimits, imageLimits, readImageDimensions } from "../shield-image/limits.mjs";
import { buildSyntheticText, mapFindingsToRects } from "../shield-image/regions.mjs";
import { assertContext, verifyImage } from "../shield-image/verify.mjs";

function png(width, height, extra = 0) {
  const b = Buffer.alloc(33 + extra);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(b);
  b.writeUInt32BE(13, 8);
  b.write("IHDR", 12, "latin1");
  b.writeUInt32BE(width, 16);
  b.writeUInt32BE(height, 20);
  return b;
}

const region = (text, confidence = 0.9, x = 0) => ({ text, confidence, rect: { x, y: 0, w: 10, h: 10 } });
const findingFor = (regions, index, value, label = "private_email") => {
  const { ranges } = buildSyntheticText(regions);
  const start = ranges[index].start + [...regions[index].text.slice(0, regions[index].text.indexOf(value))].length;
  return { source: "opf", label, value, nodeId: "n1", start, end: start + [...value].length };
};

test("Shield defaults live in the module", () => {
  assert.deepEqual(
    { ...SHIELD_IMAGE_LIMITS },
    { maxBytes: 786432, maxBody: 1048576, maxOutput: 1048576, maxPixels: 12_000_000, maxImages: 8, maxFrame: 2097152, confidenceFloor: 0.5 },
  );
  assert.ok(Object.isFrozen(SHIELD_IMAGE_LIMITS));
});

test("limits can only be tightened", () => {
  assert.equal(imageLimits({ maxBytes: 1000 }).maxBytes, 1000);
  assert.equal(imageLimits({ confidenceFloor: 0.8 }).confidenceFloor, 0.8);
  assert.throws(() => imageLimits({ maxBytes: 786433 }), RangeError);
  assert.throws(() => imageLimits({ maxPixels: 20_000_000 }), RangeError);
  assert.throws(() => imageLimits({ confidenceFloor: 0.2 }), RangeError);
  assert.throws(() => imageLimits({ maxImages: 0 }), TypeError);
  assert.throws(() => imageLimits({ bogus: 1 }), TypeError);
});

test("a 12 MP+ image is rejected from its header before inflate", () => {
  assert.deepEqual(assertImageWithinLimits(png(4000, 3000)), { width: 4000, height: 3000 });
  assert.throws(() => assertImageWithinLimits(png(4000, 3001)), (error) => error instanceof ImageLimitError && error.code === "image_too_many_pixels");
  assert.throws(() => assertImageWithinLimits(png(10, 10, 786432)), { code: "image_too_large" });
  assert.throws(() => assertImageWithinLimits(Buffer.from("not an image")), { code: "image_unreadable" });
});

test("dimensions are read for GIF, JPEG and WebP headers", () => {
  const gif = Buffer.concat([Buffer.from("GIF89a"), Buffer.from([0x40, 0x01, 0xf0, 0x00])]);
  assert.deepEqual(readImageDimensions(gif), { width: 320, height: 240 });
  const jpeg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0, 0, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x00, 0xf0, 0x01, 0x40, 0x03, 0, 0, 0]);
  assert.deepEqual(readImageDimensions(jpeg), { width: 320, height: 240 });
  const webp = Buffer.alloc(30);
  webp.write("RIFF", 0, "latin1");
  webp.write("WEBPVP8X", 8, "latin1");
  webp.writeUIntLE(319, 24, 3);
  webp.writeUIntLE(239, 27, 3);
  assert.deepEqual(readImageDimensions(webp), { width: 320, height: 240 });
});

test("synthetic text ranges are in code points", () => {
  const { text, ranges } = buildSyntheticText([region("名字 😀"), region("abc")]);
  assert.equal(text, "名字 😀\nabc");
  assert.deepEqual(ranges, [{ start: 0, end: 4 }, { start: 5, end: 8 }]);
});

test("a gateway-shaped finding with value maps to its region rect", () => {
  const regions = [region("hello", 0.9, 0), region("mail alice@example.invalid", 0.9, 20)];
  const result = mapFindingsToRects([findingFor(regions, 1, "alice@example.invalid")], regions);
  assert.deepEqual(result, { rects: [{ x: 20, y: 0, w: 10, h: 10 }], lowConfidenceMasked: 0 });
});

test("overlapping spans mask every touched region and repeated values are masked everywhere", () => {
  const regions = [region("token abc", 0.9, 0), region("def end", 0.9, 20), region("again abc", 0.9, 40), region("clean", 0.9, 60)];
  const { ranges } = buildSyntheticText(regions);
  const spanning = { source: "gitleaks", label: "secret", value: "abc\ndef", nodeId: "n1", start: ranges[0].start + 6, end: ranges[1].start + 3 };
  const repeated = findingFor(regions, 0, "abc");
  const { rects } = mapFindingsToRects([spanning, repeated, repeated], regions, { ranges });
  assert.deepEqual(rects.map((rect) => rect.x), [0, 20, 40]);
});

test("a span outside every region fails", () => {
  const regions = [region("ab"), region("cd")];
  assert.throws(() => mapFindingsToRects([{ source: "opf", label: "x", value: "z", nodeId: "n", start: 2, end: 3 }], regions), RangeError);
  assert.throws(() => mapFindingsToRects([{ source: "opf", label: "x", nodeId: "n", start: 0, end: 1 }], regions), TypeError);
});

test("Q3: low-confidence regions overlapping a finding are masked, the rest are ignored", () => {
  const regions = [region("bob@example.invalid", 0.2, 0), region("blurry noise", 0.1, 20), region("fine", 0.9, 40)];
  const result = mapFindingsToRects([findingFor(regions, 0, "bob@example.invalid")], regions);
  assert.deepEqual(result, { rects: [{ x: 0, y: 0, w: 10, h: 10 }], lowConfidenceMasked: 1 });
  assert.deepEqual(mapFindingsToRects([], regions), { rects: [], lowConfidenceMasked: 0 });
});

const context = { policyVersion: "p1", detectorVersions: { gitleaks: "8", privacy: "opf-1" } };
const cleanScan = { ocr: async () => [{ text: "nothing here" }], gitleaks: async () => [], privacy: async () => [] };

test("verify checks the policy and detector context", async () => {
  assert.doesNotThrow(() => assertContext(context, structuredClone(context)));
  assert.throws(() => assertContext({ ...context, policyVersion: "p2" }, context));
  assert.throws(() => assertContext({ ...context, detectorVersions: { gitleaks: "8" } }, context));
  await assert.rejects(verifyImage({ bytes: png(1, 1), context: { policyVersion: "p0" }, expected: context, scan: cleanScan }));
});

test("verify accepts a clean PNG and rejects every kind of leak", async () => {
  const base = { bytes: png(10, 10), knownValues: ["alice@example.invalid"], context, expected: context };
  assert.deepEqual(await verifyImage({ ...base, scan: cleanScan }), { ok: true });
  assert.deepEqual(await verifyImage({ ...base, bytes: Buffer.from("GIF89a\x01\x00\x01\x00"), scan: cleanScan }), { ok: false, reason: "not_png" });
  assert.equal((await verifyImage({ ...base, scan: { ...cleanScan, ocr: async () => [{ text: "to alice@example.invalid" }] } })).reason, "value_still_visible");
  assert.deepEqual(await verifyImage({ ...base, scan: { ...cleanScan, gitleaks: async () => [{}] } }), { ok: false, reason: "secret_still_visible", confirmedSecret: true });
  assert.equal((await verifyImage({ ...base, scan: { ...cleanScan, privacy: async () => [{}] } })).reason, "pii_still_visible");
  await assert.rejects(verifyImage({ ...base, bytes: png(5000, 5000), scan: cleanScan }), { code: "image_too_many_pixels" });
});
