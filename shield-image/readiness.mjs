// SPDX-License-Identifier: MPL-2.0
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { decodePng } from "./png.mjs";

// Rendered once with CoreText (zh-Hant + en-US) and pinned; see the plan's P7b.
export const READINESS_FIXTURE = join(dirname(fileURLToPath(import.meta.url)), "readiness.png");
export const READINESS_SHA256 = "a1008988ce1d7bf612dde86babca7c9d6da6e1a80c2371d1fd8e97652c7a77ef";
const SECRET = "Alice@example.invalid";
const ANCHOR = "客戶電子郵件";

class NotReady extends Error {
  constructor(reason) {
    super(reason);
    this.reason = reason;
  }
}

function assertOpaque(png, rect) {
  const { width, channels, pixels } = decodePng(png);
  for (let y = rect.y; y < rect.y + rect.h; y += 1) {
    for (let x = rect.x; x < rect.x + rect.w; x += 1) {
      const at = (y * width + x) * channels;
      const colour = channels >= 3 ? [pixels[at], pixels[at + 1], pixels[at + 2]] : [pixels[at]];
      const alpha = channels === 4 ? pixels[at + 3] : channels === 2 ? pixels[at + 1] : 255;
      if (alpha !== 255 || colour.some((value) => value !== 0)) throw new NotReady("mask_not_opaque");
    }
  }
}

async function once(worker, bytes) {
  await worker.probe();
  const { regions } = await worker.ocr(bytes);
  const secret = regions.find((region) => region.text.includes(SECRET));
  if (!secret || !regions.some((region) => region.text.includes(ANCHOR))) throw new NotReady("fixture_text_missing");
  const { image } = await worker.mask(bytes, [secret.rect]);
  assertOpaque(image, secret.rect);
  const after = (await worker.ocr(image)).regions;
  if (after.some((region) => region.text.includes(SECRET))) throw new NotReady("value_still_visible");
  if (!after.some((region) => region.text.includes(ANCHOR))) throw new NotReady("fixture_text_missing");
}

// The first Vision request in a process is slow, so a worker failure gets a
// bounded retry. A wrong answer from a working worker does not.
export async function checkImageReadiness({ worker, fixture = READINESS_FIXTURE, attempts = 3, delayMs = 2_000, sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)) }) {
  let bytes;
  try { bytes = await readFile(fixture); } catch { return { ready: false, reason: "fixture_missing" }; }
  if (createHash("sha256").update(bytes).digest("hex") !== READINESS_SHA256) return { ready: false, reason: "fixture_invalid" };
  let reason = "worker_unavailable";
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      await once(worker, bytes);
      return { ready: true };
    } catch (error) {
      if (error instanceof NotReady) return { ready: false, reason: error.reason };
      reason = typeof error?.code === "string" ? error.code : "worker_unavailable";
      if (attempt < attempts) await sleep(delayMs);
    }
  }
  return { ready: false, reason };
}
