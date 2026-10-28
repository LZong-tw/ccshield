import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { deflateSync } from "node:zlib";

import { decodePng } from "../shield-image/png.mjs";
import { READINESS_FIXTURE, READINESS_SHA256, checkImageReadiness } from "../shield-image/readiness.mjs";
import { png, rgbaPng } from "./fixtures/image-corpus.mjs";

// Encodes RGBA rows with one PNG filter per row so the decoder sees all five.
function filteredPng(width, height, pixel) {
  const bpp = 4;
  const raw = [];
  for (let y = 0; y < height; y += 1) raw.push(Buffer.from(Array.from({ length: width }, (_, x) => pixel(x, y)).flat()));
  const paeth = (a, b, c) => {
    const p = a + b - c;
    const [pa, pb, pc] = [Math.abs(p - a), Math.abs(p - b), Math.abs(p - c)];
    return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
  };
  const rows = raw.map((row, y) => {
    const type = y % 5;
    const prev = y > 0 ? raw[y - 1] : Buffer.alloc(row.length);
    const out = Buffer.alloc(row.length + 1);
    out[0] = type;
    for (let i = 0; i < row.length; i += 1) {
      const a = i >= bpp ? row[i - bpp] : 0;
      const b = prev[i];
      const c = i >= bpp ? prev[i - bpp] : 0;
      const predictor = [0, a, b, (a + b) >> 1, paeth(a, b, c)][type];
      out[i + 1] = (row[i] - predictor) & 0xff;
    }
    return out;
  });
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header.set([8, 6, 0, 0, 0], 8);
  const original = rgbaPng(width, height, pixel);
  const ihdrEnd = 8 + 12 + 13;
  const idat = deflateSync(Buffer.concat(rows));
  const chunk = (type, data) => {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(data.length);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(Buffer.concat([Buffer.from(type), data])));
    return Buffer.concat([length, Buffer.from(type), data, crc]);
  };
  return Buffer.concat([original.subarray(0, ihdrEnd), chunk("IDAT", idat), chunk("IEND", Buffer.alloc(0))]);
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let k = 0; k < 8; k += 1) crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

const pixel = (x, y) => [(x * 37 + y) & 0xff, (y * 91) & 0xff, (x ^ y) & 0xff, 255 - x];

test("decodePng reverses every PNG row filter for 8-bit RGBA", () => {
  const { width, height, channels, pixels } = decodePng(filteredPng(9, 10, pixel));
  assert.deepEqual([width, height, channels], [9, 10, 4]);
  for (let y = 0; y < 10; y += 1) for (let x = 0; x < 9; x += 1) {
    assert.deepEqual([...pixels.subarray((y * 9 + x) * 4, (y * 9 + x + 1) * 4)], pixel(x, y), `${x},${y}`);
  }
});

test("decodePng refuses what it does not understand", () => {
  assert.throws(() => decodePng(Buffer.from("not a png")), /PNG/);
  assert.throws(() => decodePng(png(4, 4)), /PNG/); // header only, no IDAT
});

test("the shipped readiness fixture matches its pinned digest", async () => {
  assert.equal(createHash("sha256").update(await readFile(READINESS_FIXTURE)).digest("hex"), READINESS_SHA256);
});

const EMAIL = "Alice@example.invalid";
const regions = [
  { text: "客戶電子郵件 Customer email", confidence: 0.9, rect: { x: 1, y: 1, w: 6, h: 2 } },
  { text: EMAIL, confidence: 0.9, rect: { x: 1, y: 4, w: 6, h: 2 } },
];

// A worker that paints its rects black for real, so readiness can decode them.
function fakeWorker({ paint = true, leak = false, fail = 0 } = {}) {
  let failures = fail;
  let masked = false;
  return {
    probes: 0,
    async probe() { this.probes += 1; if (failures > 0) { failures -= 1; throw Object.assign(new Error("x"), { code: "worker_timeout" }); } return { worker: "image-0123456789ab", languages: ["en-US", "zh-Hant"] }; },
    async ocr() { return { width: 8, height: 8, regions: masked && !leak ? regions.slice(0, 1) : regions }; },
    async mask(_bytes, rects) {
      masked = true;
      const inside = (x, y) => rects.some((r) => x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h);
      return { width: 8, height: 8, image: rgbaPng(8, 8, (x, y) => (paint && inside(x, y) ? [0, 0, 0, 255] : [255, 255, 255, 255])) };
    },
  };
}

const quick = { attempts: 3, sleep: async () => {} };

test("readiness passes when OCR finds the fixture text and the email rect is opaque and gone", async () => {
  assert.deepEqual(await checkImageReadiness({ worker: fakeWorker(), ...quick }), { ready: true });
});

test("readiness fails closed on unpainted rects, a surviving value or an exhausted retry", async () => {
  assert.deepEqual(await checkImageReadiness({ worker: fakeWorker({ paint: false }), ...quick }), { ready: false, reason: "mask_not_opaque" });
  assert.deepEqual(await checkImageReadiness({ worker: fakeWorker({ leak: true }), ...quick }), { ready: false, reason: "value_still_visible" });
  const flaky = fakeWorker({ fail: 2 });
  assert.deepEqual(await checkImageReadiness({ worker: flaky, ...quick }), { ready: true });
  assert.equal(flaky.probes, 3);
  assert.deepEqual(await checkImageReadiness({ worker: fakeWorker({ fail: 3 }), ...quick }), { ready: false, reason: "worker_timeout" });
});

test("readiness fails when OCR misses the fixture text", async () => {
  const worker = fakeWorker();
  worker.ocr = async () => ({ width: 8, height: 8, regions: regions.slice(1) });
  assert.deepEqual(await checkImageReadiness({ worker, ...quick }), { ready: false, reason: "fixture_text_missing" });
});

test("a fixture that does not match its pin is not ready", async () => {
  assert.deepEqual(await checkImageReadiness({ worker: fakeWorker(), fixture: new URL(import.meta.url).pathname, ...quick }), { ready: false, reason: "fixture_invalid" });
});
