import { SHIELD_IMAGE_LIMITS } from "./limits.mjs";

const codePoints = (text) => [...text].length;

// One synthetic text block: region texts joined by "\n", with each region's
// [start, end) in code points so detector spans map back to regions.
export function buildSyntheticText(regions) {
  const ranges = [];
  let offset = 0;
  for (const region of regions) {
    const length = codePoints(region.text);
    ranges.push({ start: offset, end: offset + length });
    offset += length + 1;
  }
  return { text: regions.map((region) => region.text).join("\n"), ranges };
}

function assertFinding(finding) {
  const ok = finding && typeof finding.value === "string" && finding.value.length > 0
    && Number.isSafeInteger(finding.start) && Number.isSafeInteger(finding.end) && finding.start < finding.end;
  if (!ok) throw new TypeError("finding must carry value, start and end");
}

// Findings use the gateway shape {source, label, value, nodeId, start, end}.
// A span touching several regions masks all of them; a span in no region is a
// mapping failure. Every other region that repeats the value is masked too.
// Q3: the confidence floor only matters for regions overlapping a finding.
// Those are masked like any other and counted; the image is not blocked.
export function mapFindingsToRects(findings, regions, { ranges = buildSyntheticText(regions).ranges, limits = SHIELD_IMAGE_LIMITS } = {}) {
  const masked = new Set();
  for (const finding of findings) {
    assertFinding(finding);
    const touched = ranges.flatMap((range, index) => (finding.start < range.end && finding.end > range.start ? [index] : []));
    if (touched.length === 0) throw new RangeError("finding span is outside every OCR region");
    for (const index of touched) masked.add(index);
    regions.forEach((region, index) => {
      if (region.text.includes(finding.value)) masked.add(index);
    });
  }
  const indexes = [...masked].sort((a, b) => a - b);
  return {
    rects: indexes.map((index) => ({ ...regions[index].rect })),
    lowConfidenceMasked: indexes.filter((index) => regions[index].confidence < limits.confidenceFloor).length,
  };
}
