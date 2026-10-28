#!/usr/bin/env node
// SPDX-License-Identifier: MPL-2.0
// Opt-in eval on your own screenshots. Not a gate.
//
//   HOME=<temp> node tools/image-local-eval.mjs <screenshot-dir> <workdir> [<assets-provision.json>]
//
// Every image in <screenshot-dir> goes through the real inspector (Vision,
// Gitleaks, Privacy). The output is aggregate counts only: no file names, OCR
// text, rects or image bytes. It goes to reports/local/, which is gitignored.
// With a provision path the privacy filter runs from its `privacy` entry (OPF)
// and that install is only read. Needs xcrun and Vision; run it outside the sandbox.
import { mkdir, readdir, readFile, realpath, writeFile } from "node:fs/promises";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REFUSED = new Set(["image_rejected", "too_many_images"]);
const FAILED = new Set(["image_unavailable", "image_timeout", "image_queue_full", "image_scan_unavailable", "worker_timeout", "worker_exited", "worker_protocol"]);
// Detector labels are short identifiers. Anything else is counted as `other`
// so a label can never carry recognized text into the summary.
const LABEL = /^[a-z][a-z0-9_-]{0,31}$/;

export function summarizeLocalEval(runs) {
  const summary = {
    images: runs.length,
    forwarded_masked: 0,
    forwarded_unmasked: 0,
    blocked_secret: 0,
    refused: {},
    failed: {},
    masks: 0,
    low_confidence_masks: 0,
    pii_findings: {},
    latency_ms: null,
  };
  const bump = (bucket, key, by = 1) => { bucket[key] = (bucket[key] ?? 0) + by; };
  for (const { result, error } of runs) {
    if (error) {
      const code = error.code;
      if (REFUSED.has(code)) bump(summary.refused, code);
      else bump(summary.failed, FAILED.has(code) ? code : "unknown");
      continue;
    }
    if (result.status === "secret") { summary.blocked_secret += 1; continue; }
    if (result.maskCount > 0) summary.forwarded_masked += 1;
    else summary.forwarded_unmasked += 1;
    summary.masks += result.maskCount;
    summary.low_confidence_masks += result.lowConfidenceMasked;
    for (const finding of result.piiFindings) bump(summary.pii_findings, LABEL.test(finding.label) ? finding.label : "other", finding.count);
  }
  const times = runs.map((run) => run.ms).sort((left, right) => left - right);
  if (times.length > 0) {
    const at = (p) => Math.round(times[Math.min(times.length - 1, Math.ceil((p / 100) * times.length) - 1)]);
    summary.latency_ms = { p50: at(50), p95: at(95), max: Math.round(times.at(-1)) };
  }
  return summary;
}

const IMAGE_EXTENSIONS = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp"]);

async function main([sourceArg, workArg, provisionPath]) {
  if (!sourceArg || !workArg) throw new Error("usage: image-local-eval.mjs <screenshot-dir> <workdir> [<assets-provision.json>]");
  const { createImageInspector } = await import("../shield-image/inspector.mjs");
  const { openNativeHarness } = await import("../test/fixtures/image-corpus/native-corpus.mjs");
  await mkdir(workArg, { recursive: true, mode: 0o700 });
  const work = await realpath(workArg);
  const privacyProvision = provisionPath ? JSON.parse(await readFile(provisionPath, "utf8")).privacy : undefined;
  const harness = await openNativeHarness(work, { privacyProvision });
  await harness.worker.probe();
  const files = (await readdir(sourceArg)).filter((name) => IMAGE_EXTENSIONS.has(extname(name).toLowerCase())).sort();
  const runs = [];
  try {
    for (const name of files) {
      const bytes = await readFile(join(sourceArg, name));
      // A fresh inspector per image: no cache hits, and each image counts as the last turn.
      const inspector = createImageInspector({ ...harness, timeoutMs: 60_000 });
      const started = performance.now();
      try {
        const [result] = await inspector.inspect([{ bytes, lastTurn: true }]);
        runs.push({ ms: performance.now() - started, result });
      } catch (error) {
        runs.push({ ms: performance.now() - started, error });
      }
    }
  } finally {
    harness.close();
  }
  const summary = { date: new Date().toISOString().slice(0, 10), privacy: harness.versions.privacy, ...summarizeLocalEval(runs) };
  const outDir = fileURLToPath(new URL("../reports/local/", import.meta.url));
  await mkdir(outDir, { recursive: true, mode: 0o700 });
  const outPath = join(outDir, `image-local-eval-${summary.date}.json`);
  await writeFile(outPath, `${JSON.stringify(summary, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${outPath}\n`);
}

if (process.argv[1] && (await realpath(process.argv[1])) === fileURLToPath(import.meta.url)) {
  await main(process.argv.slice(2));
}
