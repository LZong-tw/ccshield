// SPDX-License-Identifier: MPL-2.0
import { buildSyntheticText } from "./regions.mjs";

const PREFIX = '{"messages":[{"role":"user","content":[{"type":"text","text":';

// OCR text goes to the detectors as one user text block with no `system` key,
// so text that looks like a harness envelope is scanned like any other text.
// `offsets[k]` is the body byte offset where code point k's JSON escape starts;
// offsets[n] is the closing quote. Detector spans are body byte offsets.
export function buildSyntheticBody(regions) {
  const { text, ranges } = buildSyntheticText(regions);
  const textStart = Buffer.byteLength(PREFIX) + 1;
  const offsets = [textStart];
  for (const char of text) offsets.push(offsets.at(-1) + Buffer.byteLength(JSON.stringify(char).slice(1, -1)));
  const body = Buffer.from(`${PREFIX}${JSON.stringify(text)}}]}]}`);
  return Object.freeze({ body, text, ranges, textStart, textEnd: offsets.at(-1), offsets });
}

// A span that starts or ends inside an escape widens to the whole code point.
export function spanToCodePoints(synthetic, span) {
  const { offsets, textStart, textEnd } = synthetic;
  if (!Number.isSafeInteger(span?.start) || !Number.isSafeInteger(span?.end)
    || span.start < textStart || span.end > textEnd || span.start >= span.end) {
    throw new RangeError("detector span is outside the OCR text");
  }
  let start = 0;
  while (offsets[start + 1] <= span.start) start += 1;
  let end = start + 1;
  while (offsets[end] < span.end) end += 1;
  return { start, end };
}

// Every redaction must carry one span per count, and redactions must cover
// every finding; otherwise there is nothing reliable to mask.
export function findingsFromPrivacy(result, synthetic) {
  if (result?.status !== "ok" || !Array.isArray(result.findings)) throw new Error("privacy scan of OCR text is unavailable");
  const redactions = result.redactions ?? [];
  if (!Array.isArray(redactions)) throw new Error("privacy redactions are invalid");
  const covered = new Map();
  const chars = [...synthetic.text];
  const findings = [];
  for (const redaction of redactions) {
    if (!Array.isArray(redaction?.spans) || redaction.spans.length !== redaction.count) throw new Error("privacy redaction is missing spans");
    for (const span of redaction.spans) {
      const { start, end } = spanToCodePoints(synthetic, span);
      findings.push({ source: "opf", label: redaction.label, value: chars.slice(start, end).join(""), nodeId: "ocr", start, end });
    }
    covered.set(redaction.label, (covered.get(redaction.label) ?? 0) + redaction.count);
  }
  const required = new Map();
  for (const finding of result.findings) required.set(finding.label, (required.get(finding.label) ?? 0) + finding.count);
  if ([...required].some(([label, count]) => (covered.get(label) ?? 0) < count)) throw new Error("privacy findings are not covered by redaction spans");
  if ([...covered].some(([label, count]) => (required.get(label) ?? 0) < count)) throw new Error("privacy redactions exceed their findings");
  return findings;
}
