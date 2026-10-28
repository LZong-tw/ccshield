// SPDX-License-Identifier: MPL-2.0
import { createHash } from "node:crypto";

import { ImageLimitError, assertImageComplete, assertImageWithinLimits, imageLimits } from "./limits.mjs";
import { mapFindingsToRects } from "./regions.mjs";
import { buildSyntheticBody, findingsFromPrivacy } from "./synthetic.mjs";
import { verifyImage } from "./verify.mjs";

export class ImageInspectError extends Error {
  constructor(code, cause) {
    super(`shield image inspection failed: ${code}`, cause === undefined ? undefined : { cause });
    this.code = code;
  }
}

const SECRET = Object.freeze({ status: "secret", confirmedSecret: true });

// Worker answers that are a property of the input, not of the worker: the same
// bytes fail the same way every time, so the request blocks instead of retrying.
const REJECTED_INPUT = new Set(["unsupported_type", "multi_frame", "too_many_pixels", "decode_failed", "output_too_large"]);

// Scanners are injected so this module needs nothing from the MIT side:
// scanSecrets(body) -> { findings }, scanPrivacy(body) -> privacy scan result,
// context() -> { policyVersion, detectorVersions } of the running daemon.
// One image at a time goes through the worker; requests queue FIFO, each with
// a deadline that counts its wait. Any exception means unavailable.
export function createImageInspector({ worker, scanSecrets, scanPrivacy, context, limits: overrides = {}, timeoutMs, maxPending = 16, cacheSize = 64 }) {
  const limits = imageLimits(overrides);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw new TypeError("image inspector timeoutMs is required");
  const cache = new Map();
  let tail = Promise.resolve();
  let pending = 0;

  const keyFor = (bytes, ctx) => {
    const versions = Object.entries(ctx.detectorVersions).sort(([a], [b]) => (a < b ? -1 : 1));
    return `${createHash("sha256").update(bytes).digest("hex")}:${JSON.stringify([ctx.policyVersion, versions])}`;
  };
  const remember = (key, result) => {
    cache.delete(key);
    cache.set(key, result);
    if (cache.size > cacheSize) cache.delete(cache.keys().next().value);
  };
  const copy = (result) => (result.bytes ? { ...result, bytes: Buffer.from(result.bytes) } : result);

  const scanText = {
    ocr: async (bytes) => (await worker.ocr(bytes)).regions,
    gitleaks: async (text) => (await scanSecrets(buildSyntheticBody([{ text }]).body)).findings,
    privacy: async (text) => {
      const result = await scanPrivacy(buildSyntheticBody([{ text }]).body);
      if (result?.status !== "ok") throw new Error("privacy rescan is unavailable");
      return result.findings;
    },
  };

  async function protect(bytes, expected) {
    assertImageWithinLimits(bytes, limits);
    assertImageComplete(bytes);
    const { regions } = await worker.ocr(bytes);
    const synthetic = buildSyntheticBody(regions);
    let findings = [];
    if (regions.length > 0) {
      if ((await scanSecrets(synthetic.body)).findings.length > 0) return SECRET;
      findings = findingsFromPrivacy(await scanPrivacy(synthetic.body), synthetic);
    }
    const { rects, lowConfidenceMasked } = mapFindingsToRects(findings, regions, { ranges: synthetic.ranges, limits });
    // Always re-encode: an image with no rects is still normalized.
    const { image } = await worker.mask(bytes, rects);
    const verdict = await verifyImage({ bytes: image, knownValues: findings.map((finding) => finding.value), context: context(), expected, scan: scanText, limits });
    if (!verdict.ok) {
      if (verdict.confirmedSecret) return SECRET;
      throw new Error(`masked image failed verification: ${verdict.reason}`);
    }
    const counts = new Map();
    for (const finding of findings) counts.set(finding.label, (counts.get(finding.label) ?? 0) + 1);
    return Object.freeze({
      status: "ok",
      bytes: image,
      maskCount: rects.length,
      lowConfidenceMasked,
      piiFindings: [...counts].map(([label, count]) => ({ label, count })),
    });
  }

  async function inspect(images) {
    const expected = context();
    const keys = images.map(({ bytes }) => keyFor(bytes, expected));
    // Only the newest user turn counts: history resent after a daemon restart
    // misses the process-local cache and would otherwise never converge.
    const fresh = new Set(keys.filter((key, index) => images[index].lastTurn !== false && !cache.has(key)));
    if (fresh.size > limits.maxImages) throw new ImageInspectError("too_many_images");
    if (keys.every((key) => cache.has(key))) return keys.map((key) => copy(cache.get(key)));
    if (pending >= maxPending) throw new ImageInspectError("image_queue_full");
    pending += 1;

    let running = false;
    let cancelled = false;
    let timer;
    const work = tail.then(async () => {
      if (cancelled) return null;
      running = true;
      const results = [];
      for (const [index, { bytes }] of images.entries()) {
        const key = keys[index];
        if (!cache.has(key)) remember(key, await protect(Buffer.from(bytes), expected));
        results.push(copy(cache.get(key)));
      }
      return results;
    });
    tail = work.catch(() => {});
    const deadline = new Promise((_, reject) => {
      timer = setTimeout(() => {
        cancelled = true;
        // Only a job that owns the worker may kill it; a queued one just leaves.
        if (running) worker.kill?.();
        reject(new ImageInspectError("image_timeout"));
      }, timeoutMs);
    });
    try {
      return await Promise.race([work, deadline]);
    } catch (error) {
      if (error instanceof ImageInspectError) throw error;
      if (error instanceof ImageLimitError || REJECTED_INPUT.has(error?.code)) throw new ImageInspectError("image_rejected", error);
      throw new ImageInspectError("image_scan_unavailable", error);
    } finally {
      clearTimeout(timer);
      pending -= 1;
    }
  }

  return Object.freeze({ inspect });
}
