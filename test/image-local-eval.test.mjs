import assert from "node:assert/strict";
import test from "node:test";

import { summarizeLocalEval } from "../tools/image-local-eval.mjs";

const SENSITIVE = ["alice@example.invalid", "AKIAZ7WQ3MRX2KBTLRPV", "secret-screenshot.png", "rect", "\"x\""];

test("the local eval reports aggregate counts only", () => {
  const summary = summarizeLocalEval([
    { ms: 100, result: { status: "ok", maskCount: 2, lowConfidenceMasked: 1, piiFindings: [{ label: "email", count: 2 }], bytes: Buffer.from("alice@example.invalid") } },
    { ms: 300, result: { status: "ok", maskCount: 0, lowConfidenceMasked: 0, piiFindings: [], bytes: Buffer.from("x") } },
    { ms: 200, result: { status: "secret", maskCount: 0, lowConfidenceMasked: 0, piiFindings: [], bytes: Buffer.from("AKIAZ7WQ3MRX2KBTLRPV") } },
    { ms: 50, error: Object.assign(new Error("secret-screenshot.png"), { code: "image_rejected" }) },
    { ms: 60, error: Object.assign(new Error("boom"), { code: "image_timeout" }) },
    { ms: 70, error: new Error("no code") },
  ]);

  assert.deepEqual(summary, {
    images: 6,
    forwarded_masked: 1,
    forwarded_unmasked: 1,
    blocked_secret: 1,
    refused: { image_rejected: 1 },
    failed: { image_timeout: 1, unknown: 1 },
    masks: 2,
    low_confidence_masks: 1,
    pii_findings: { email: 2 },
    latency_ms: { p50: 70, p95: 300, max: 300 },
  });
  const serialized = JSON.stringify(summary);
  for (const value of SENSITIVE) assert.ok(!serialized.includes(value), value);
});

test("labels and error codes outside the known shape are not copied into the summary", () => {
  const summary = summarizeLocalEval([
    { ms: 1, result: { status: "ok", maskCount: 1, lowConfidenceMasked: 0, piiFindings: [{ label: "alice@example.invalid", count: 1 }] } },
    { ms: 1, error: Object.assign(new Error("x"), { code: "AKIAZ7WQ3MRX2KBTLRPV" }) },
  ]);
  assert.deepEqual(summary.pii_findings, { other: 1 });
  assert.deepEqual(summary.failed, { unknown: 1 });
});

test("an empty run reports zeros and no latency", () => {
  assert.equal(summarizeLocalEval([]).images, 0);
  assert.equal(summarizeLocalEval([]).latency_ms, null);
});
