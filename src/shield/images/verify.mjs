import { SHIELD_IMAGE_LIMITS, assertImageWithinLimits } from "./limits.mjs";

const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const sameVersions = (a = {}, b = {}) => {
  const keys = Object.keys(a);
  return keys.length === Object.keys(b).length && keys.every((key) => a[key] === b[key]);
};

export function assertContext(actual, expected) {
  if (!actual || actual.policyVersion !== expected.policyVersion || !sameVersions(actual.detectorVersions, expected.detectorVersions)) {
    throw new Error("image verify context does not match the running policy and detectors");
  }
}

// Verifies a redacted image before it may replace the original. The OCR,
// gitleaks and privacy scanners are injected; any throw propagates and the
// caller treats it as unavailable.
export async function verifyImage({ bytes, knownValues = [], context, expected, scan, limits = SHIELD_IMAGE_LIMITS }) {
  assertContext(context, expected);
  const output = Buffer.from(bytes);
  if (output.length < PNG_MAGIC.length || !output.subarray(0, 8).equals(PNG_MAGIC)) return { ok: false, reason: "not_png" };
  if (output.length > limits.maxOutput) return { ok: false, reason: "output_too_large" };
  assertImageWithinLimits(output, { ...limits, maxBytes: limits.maxOutput });

  const text = (await scan.ocr(output)).map((region) => region.text).join("\n");
  if (knownValues.some((value) => value && text.includes(value))) return { ok: false, reason: "value_still_visible" };
  if ((await scan.gitleaks(text)).length > 0) return { ok: false, reason: "secret_still_visible", confirmedSecret: true };
  if ((await scan.privacy(text)).length > 0) return { ok: false, reason: "pii_still_visible" };
  return { ok: true };
}
