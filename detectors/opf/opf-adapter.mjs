const LABELS = new Set([
  "account_number", "private_address", "private_email", "private_person",
  "private_phone", "private_url", "private_date", "secret",
]);
const MAX_BODY_BYTES = 1_048_576;
const MAX_PROJECTED_RANGES = 8192;
const MAX_PROOF_RANGES = 8192;
// Overlapping spans could repeat the same text thousands of times; disjoint spans never exceed the body.
// Counted in UTF-16 units, the unit FragmentMatcher is bounded in (MAX_TRIE_UNITS), so this limit trips first.
const MAX_SPAN_CHARS = MAX_BODY_BYTES;
// A request that keeps its findings needs at most MAX_PROOF_RANGES usable matches. Hits that split a
// surrogate pair are not occurrences and are skipped before they are counted. Unsigned hits past this are
// not kept: the replay still runs on the ones kept, then the request fails as a match limit.
const MAX_MATCH_HITS = 4 * MAX_PROOF_RANGES;
// A Map-backed trie is relatively expensive per code unit. Decoded fragments are already bounded by
// MAX_SPAN_CHARS; original byte slices can overlap and add up to many times the body, so they use the
// smaller bound and fall back to Buffer.indexOf without changing the survival check.
const MAX_TRIE_UNITS = MAX_BODY_BYTES;
const MAX_ORIGINAL_TRIE_BYTES = 256 * 1024;
// Distinct label:block pairs reported for hits left in signed thinking; further pairs are not listed.
const MAX_PASSTHROUGH_ENTRIES = 16;
const SIGNED_DETAIL = /^signed:(?:[a-z_]+|-):\d{1,6}\.\d{1,6}$/;
const MAX_PROOF_BATCH = 1024;
const MAX_PROOF_ENTRIES = 128;
const MAX_PROTOCOL_IDS = 4096;
const MAX_ID_ALIASES = 1024;
const PROTOCOL_ID = /^[a-zA-Z0-9_-]+$/;
const OPAQUE_VALUE = /^[A-Za-z0-9+/=_-]{16,}$/;
export const UNKNOWN_REASONS = new Map([
  ["invalid prediction", "invalid-prediction"],
  ["prediction span limit", "prediction-span-limit"],
  ["matcher pattern limit", "prediction-span-limit"],
  ["inconsistent counts", "inconsistent-counts"],
  ["invalid span", "invalid-span"],
  ["unmapped span", "unmapped-span"],
  ["cross-field span", "cross-field-span"],
  ["inconsistent quoting", "inconsistent-quoting"],
  ["unmapped finding", "unmapped-finding"],
  ["redaction projection limit", "redaction-projection-limit"],
  ["redaction match limit", "redaction-match-limit"],
  ["redaction body limit", "redaction-body-limit"],
  ["value survived", "value-survived"],
  ["invalid protocol graph", "invalid-protocol-graph"],
  ["protocol graph mutation", "protocol-graph-mutation"],
  ["protocol control mutation", "protocol-control-mutation"],
  ["signed block mutation", "signed-block-mutation"],
  ["protocol id collision", "protocol-id-collision"],
  ["conflicting protocol context", "conflicting-protocol-context"],
  ["protocol id limit", "protocol-id-limit"],
  ["invalid source provenance", "invalid-source-provenance"],
  ["JSON key collision", "json-key-collision"],
  ["invalid JSON topology", "invalid-json-topology"],
]);

export function prepareOpfScan(original) {
  if (!Buffer.isBuffer(original) || original.length === 0 || original.length > MAX_BODY_BYTES) throw new Error("invalid body");
  const source = new TextDecoder("utf-8", { fatal: true }).decode(original);
  JSON.parse(source);
  const byteAt = byteOffsets(source);
  let cursor = 0;
  const whitespace = () => { while (/\s/.test(source[cursor] ?? "") && cursor < source.length) cursor += 1; };
  const parseString = () => {
    const start = cursor++;
    while (cursor < source.length) {
      if (source[cursor] === "\\") { cursor += 2; continue; }
      if (source[cursor++] === '"') break;
    }
    const end = cursor;
    const value = JSON.parse(source.slice(start, end));
    const map = [];
    let at = start + 1;
    while (at < end - 1) {
      let next;
      if (source[at] === "\\") {
        next = at + (source[at + 1] === "u" ? 6 : 2);
        if (source[at + 1] === "u" && next + 5 < end && source.slice(next, next + 2) === "\\u") {
          const first = Number.parseInt(source.slice(at + 2, at + 6), 16);
          const second = Number.parseInt(source.slice(next + 2, next + 6), 16);
          if (first >= 0xd800 && first <= 0xdbff && second >= 0xdc00 && second <= 0xdfff) next += 6;
        }
      } else next = at + (source.codePointAt(at) > 0xffff ? 2 : 1);
      const piece = source.slice(at, next);
      const decoded = piece.startsWith("\\") ? JSON.parse(`"${piece}"`) : piece;
      if (Array.from(decoded).length !== 1) throw new Error("invalid character mapping");
      map.push({ start: byteAt[at], end: byteAt[next] });
      at = next;
    }
    if (map.length !== Array.from(value).length) throw new Error("invalid character mapping");
    return { type: "string", value, map, start, end };
  };
  const parse = (depth = 0) => {
    if (depth > 128) throw new Error("JSON nesting limit");
    whitespace();
    const start = cursor;
    if (source[cursor] === '"') return parseString();
    if (source[cursor] === "{" || source[cursor] === "[") {
      const object = source[cursor++] === "{";
      const children = [];
      whitespace();
      while (source[cursor] !== (object ? "}" : "]")) {
        let keyNode;
        if (object) { keyNode = parseString(); whitespace(); cursor += 1; }
        const value = parse(depth + 1);
        children.push({ key: keyNode?.value, keyNode, value });
        whitespace();
        if (source[cursor] !== ",") break;
        cursor += 1;
        whitespace();
      }
      cursor += 1;
      return { type: object ? "object" : "array", children, start, end: cursor };
    }
    while (cursor < source.length && !/[\s,}\]]/.test(source[cursor])) cursor += 1;
    const value = source.slice(start, cursor);
    return { type: "literal", value, map: Array.from(value, (_, offset) => ({ start: byteAt[start + offset], end: byteAt[start + offset + 1] })), start, end: cursor };
  };
  const root = parse();
  whitespace();
  if (cursor !== source.length) throw new Error("trailing JSON content");
  const protocolIds = collectProtocolIds(root);
  const opaque = collectOpaqueValues(root);
  const allValues = [];
  const parts = [];
  const map = [];
  const sources = [];
  const managedShape = root.type === "object" && root.children.some(({ key }) => key === "system")
    && root.children.some(({ key, value }) => key === "messages" && value.type === "array");
  const exemptNodes = new Set();
  const envelope = (node) => node?.type === "string" && (() => {
    const text = node.value.trim();
    return text.startsWith("<system-reminder>") && text.endsWith("</system-reminder>")
      && text.indexOf("<system-reminder>", 17) === -1
      && text.slice(0, -18).indexOf("</system-reminder>") === -1;
  })();
  if (managedShape) {
    const messages = root.children.find(({ key }) => key === "messages")?.value;
    for (const { value: message } of messages.children) {
      if (message.type !== "object") continue;
      const content = message.children.find(({ key }) => key === "content")?.value;
      if (content?.type !== "array" || !content.children.length) continue;
      const first = content.children[0].value;
      if (first.type !== "object") continue;
      const type = first.children.find(({ key }) => key === "type")?.value;
      const text = first.children.find(({ key }) => key === "text")?.value;
      if (type?.value === "text" && envelope(text)) exemptNodes.add(text);
    }
  }
  const visit = (node, included = true) => {
    if (node.type === "string" || (node.type === "literal" && /^-?\d/.test(node.value))) {
      allValues.push(node);
      if (included && !exemptNodes.has(node) && !opaque.nodes.has(node)) {
        if (parts.length) { parts.push("\n"); map.push(null); }
        sources.push({ start: map.length, end: map.length + node.map.length, node });
        parts.push(node.value);
        for (const entry of node.map) map.push(entry);
      }
      return;
    }
    if (node.type === "object") {
      for (const { key, keyNode, value } of node.children) {
        const childIncluded = included && !(managedShape && node === root && (key === "system" || key === "tools"));
        visit(keyNode, childIncluded);
        visit(value, childIncluded);
      }
    } else if (node.type === "array") for (const { value } of node.children) visit(value, included);
  };
  visit(root);
  return { text: parts.join(""), map, allValues, protocolIds, opaque, sources, root };
}

export function adaptOpfPrediction(original, scan, result) {
  try {
    if (result?.schema_version !== 1 || result?.text !== scan.text || result.summary?.output_mode !== "typed"
      || result.summary?.decoded_mismatch !== false || !Array.isArray(result.detected_spans)
      || result.summary.span_count !== result.detected_spans.length) throw new Error("invalid prediction");
    // Same bound as the ranges the spans project into; it also caps the per-span work below.
    if (result.detected_spans.length > MAX_PROJECTED_RANGES) throw new Error("prediction span limit");
    const reported = new Map();
    for (const span of result.detected_spans) reported.set(span.label, (reported.get(span.label) ?? 0) + 1);
    const byLabel = result.summary.by_label;
    if (!byLabel || typeof byLabel !== "object" || Array.isArray(byLabel)
      || Object.keys(byLabel).length !== reported.size
      || [...reported].some(([label, count]) => byLabel[label] !== count)) throw new Error("inconsistent counts");
    const chars = Array.from(scan.text);
    const canonical = prepareOpfScan(original);
    validateSourceProvenance(scan, canonical);
    validateAllValues(scan.allValues, canonical.allValues);
    const pinned = new Set();
    validateJsonShape(canonical.root, canonical.root, undefined, pinned);
    // Pinned values a kept span reaches into; replay still rewrites those so the shape check names the control.
    const spannedPins = new Set();
    const replacementsByRange = new Map();
    const fragments = new Map();
    const projectedRanges = new Set();
    const unitAt = new Int32Array(chars.length + 1);
    for (let index = 0; index < chars.length; index += 1) unitAt[index + 1] = unitAt[index] + chars[index].length;
    let kept = 0;
    let spanChars = 0;
    for (const span of result.detected_spans) {
      if (!LABELS.has(span.label) || !Number.isInteger(span.start) || !Number.isInteger(span.end)
        || span.start < 0 || span.end <= span.start || span.end > chars.length) throw new Error("invalid span");
      spanChars += unitAt[span.end] - unitAt[span.start];
      if (spanChars > MAX_SPAN_CHARS) throw new Error("prediction span limit");
      if (chars.slice(span.start, span.end).join("") !== span.text) throw new Error("invalid span");
      // A detector hit wholly inside a typed control or selector value (model, role, block type, tool name, ...)
      // is a false positive the API cannot accept altered; drop it. Spans reaching past that value stay fail-closed.
      // Sources are ordered and disjoint (provenance-checked above), so overlaps start at the first one ending after the span starts.
      const first = firstSourceEndingAfter(scan.sources, span.start);
      const home = first < scan.sources.length && scan.sources[first].start <= span.start && span.end <= scan.sources[first].end ? first : -1;
      if (home >= 0 && pinned.has(canonical.sources[home].node)) continue;
      let projected = false;
      // A span wholly inside signed thinking still yields its fragment, so the same text elsewhere is redacted,
      // but it does not have to be redacted itself.
      let redactable = false;
      for (let index = first; index < scan.sources.length && scan.sources[index].start < span.end; index += 1) {
        const source = scan.sources[index];
        const start = Math.max(source.start, span.start);
        const end = Math.min(source.end, span.end);
        if (end <= start) continue;
        projected = true;
        if (!canonical.opaque.passthrough.nodes.has(canonical.sources[index].node)) redactable = true;
        if (pinned.has(canonical.sources[index].node)) spannedPins.add(canonical.sources[index].node);
        const key = `${span.label}:${source.node.map[start - source.start].start}:${source.node.map[end - source.start - 1].end}`;
        if (projectedRanges.has(key)) continue;
        if (projectedRanges.size >= MAX_PROJECTED_RANGES) throw new Error("redaction projection limit");
        projectedRanges.add(key);
        const text = chars.slice(start, end).join("");
        fragments.set(`${span.label}:${text}`, { label: span.label, text });
      }
      if (!projected) throw new Error("unmapped span");
      if (redactable) kept += 1;
    }
    if (fragments.size && canonical.protocolIds.invalid) throw graphError("invalid protocol graph", canonical.protocolIds.invalid);
    if (fragments.size && canonical.protocolIds.overLimit) throw graphError("protocol id limit", "limit");
    const projectedIds = new Set();
    const keyNodes = collectKeyNodes(canonical.root);
    const characterOffsets = new WeakMap();
    // One pass finds the occurrences of every fragment; the replay below walks them fragment by fragment,
    // value by value, offset by offset, as a per-fragment search of every value would, without its
    // fragments x values cost on large bodies. Below MAX_MATCH_HITS that gives the same first failure and
    // kept replacements. Past it, other hits are dropped but each fragment's first hit in unsigned thinking is
    // still kept, so a fragment that reaches one fails as signed-block-mutation, as it would without the
    // bound. The replay may then report a later failure, or the match limit, where the unbounded search would
    // have failed first on a dropped hit. Hits in signed thinking are never replayed and never count.
    const decodedFragments = [...new Set([...fragments.values()].map(({ text }) => text))];
    const matcher = new FragmentMatcher(decodedFragments);
    const hits = decodedFragments.map(() => []);
    const labelsOf = decodedFragments.map(() => []);
    const patternOf = new Map(decodedFragments.map((text, index) => [text, index]));
    for (const { label, text } of fragments.values()) labelsOf[patternOf.get(text)].push(label);
    // Later locked hits are never reached: the replay fails on the first.
    const lockedSeen = new Uint8Array(decodedFragments.length);
    const skipped = new Map();
    let hitCount = 0;
    let overflow = false;
    canonical.allValues.forEach((node, nodeIndex) => {
      // A finding in prose is not replayed into a pinned control no span touched: a tool named
      // mcp__alice__lookup keeps its name when Alice is found in user text.
      if (canonical.opaque.nodes.has(node) || pinned.has(node) && !spannedPins.has(node)) return;
      // The API rejects an edited signed block, so its hits are left in place and only counted. A secret
      // cannot be left in place: nothing downstream would block it, so it fails closed like locked thinking.
      const at = canonical.opaque.passthrough.nodes.get(node);
      if (at !== undefined) {
        matcher.scanWhole(node.value, (pattern) => {
          for (const label of labelsOf[pattern]) {
            if (label === "secret") throw signedMutation(label, at);
            const key = `${label}:${at}`;
            if (skipped.has(key) || skipped.size < MAX_PASSTHROUGH_ENTRIES) skipped.set(key, (skipped.get(key) ?? 0) + 1);
          }
          return false;
        });
        return;
      }
      const locked = canonical.opaque.lockedThinking.has(node);
      // A hit that splits a surrogate pair is not an occurrence, so it never counts toward the bound.
      matcher.scanWhole(node.value, (pattern, end) => {
        if (locked) {
          if (lockedSeen[pattern]) return false;
          lockedSeen[pattern] = 1;
        } else if (hitCount >= MAX_MATCH_HITS) {
          overflow = true;
          return false;
        } else hitCount += 1;
        hits[pattern].push(nodeIndex, end - decodedFragments[pattern].length);
        return false;
      });
    });
    for (const fragment of fragments.values()) {
      const found = hits[patternOf.get(fragment.text)];
      for (let hit = 0; hit < found.length; hit += 2) {
        const node = canonical.allValues[found[hit]];
        const match = found[hit + 1];
        if (canonical.opaque.lockedThinking.has(node)) throw signedMutation(fragment.label, canonical.opaque.lockedThinking.get(node));
        if (!characterOffsets.has(node)) {
          const offsets = [];
          let codepoint = 0;
          for (let offset = 0; offset < node.value.length;) {
            offsets[offset] = codepoint++;
            offset += node.value.codePointAt(offset) > 0xffff ? 2 : 1;
          }
          offsets[node.value.length] = codepoint;
          characterOffsets.set(node, offsets);
        }
        const offsets = characterOffsets.get(node);
        const at = offsets[match];
        const end = offsets[match + fragment.text.length];
        if (at === undefined || end === undefined) continue;
        const replacement = { label: fragment.label, start: node.map[at].start, end: node.map[end - 1].end,
          quote: node.type === "literal", protocolId: node.protocolId, inKey: keyNodes.has(node) };
        const key = `${replacement.label}:${replacement.start}:${replacement.end}`;
        if (replacementsByRange.has(key) && replacementsByRange.get(key).quote !== replacement.quote) throw new Error("inconsistent quoting");
        if (replacementsByRange.has(key) && replacementsByRange.get(key).protocolId !== replacement.protocolId) throw new Error("conflicting protocol context");
        if (replacement.protocolId !== undefined) projectedIds.add(replacement.protocolId);
        if (projectedIds.size > MAX_ID_ALIASES) throw new Error("protocol id limit");
        if (replacementsByRange.size >= MAX_PROOF_RANGES && !replacementsByRange.has(key)) throw new Error("redaction match limit");
        replacementsByRange.set(key, replacement);
      }
    }
    if (overflow) throw new Error("redaction match limit");
    const replacements = [...replacementsByRange.values()].sort((a, b) => a.start - b.start || a.end - b.end);
    if (kept && !replacements.length) throw new Error("unmapped finding");
    const passthrough = skipped.size ? { passthrough: [...skipped].map(([key, count]) => {
      const [label, at] = key.split(":");
      return { label, at, count };
    }) } : {};
    if (!replacements.length) return { status: "ok", findings: [], ...passthrough };
    const grouped = new Map();
    const ranges = [];
    for (const span of replacements) {
      if (!grouped.has(span.label)) grouped.set(span.label, []);
      grouped.get(span.label).push({ start: span.start, end: span.end });
      const previous = ranges.at(-1);
      if (previous && span.start < previous.end) {
        if (span.quote !== previous.quote) throw new Error("inconsistent quoting");
        if (span.protocolId !== previous.protocolId) throw new Error("conflicting protocol context");
        previous.end = Math.max(previous.end, span.end);
        if (span.label === "secret" || (previous.label !== "secret" && span.label < previous.label)) previous.label = span.label;
      } else ranges.push({ ...span });
    }
    // A bounded Latin-1 trie handles the usual case. Large overlapping original slices would make a
    // trie much larger than the request itself, so OriginalBytesMatcher keeps Buffer views and uses
    // native indexOf instead; both paths perform the same byte-survival check.
    const originalMatcher = new OriginalBytesMatcher(original, replacements);
    const safeReplacement = (value) => !matcher.includesWhole(value)
      && !originalMatcher.includes(Buffer.from(JSON.stringify(value)));
    const markers = new Map();
    const markerFor = (label) => {
      if (markers.has(label)) return markers.get(label);
      let marker = `[redacted:${label}]`;
      if (!safeReplacement(marker)) {
        marker = "█";
        for (let attempt = 0; !safeReplacement(marker); attempt += 1) {
          if (attempt >= 256) throw new Error("value survived");
          marker = String.fromCharCode(0xe000 + attempt);
        }
      }
      markers.set(label, marker);
      return marker;
    };
    // Sibling keys must stay distinct, so each distinct redacted key value gets its own marker.
    const keyMarkers = new Map();
    const keyCounts = new Map();
    const keyMarkerFor = (label, bytes) => {
      const id = `${label}:${bytes.toString("base64")}`;
      if (keyMarkers.has(id)) return keyMarkers.get(id);
      let count = keyCounts.get(label) ?? 0;
      let marker = count === 0 ? markerFor(label) : null;
      count = Math.max(count, 1);
      while (marker === null) {
        if (++count > 4096) throw new Error("value survived");
        const next = `[redacted:${label}#${count}]`;
        if (safeReplacement(next)) marker = next;
      }
      keyCounts.set(label, count);
      keyMarkers.set(id, marker);
      return marker;
    };
    const reserved = new Set(canonical.protocolIds.nodes.map(({ value }) => value));
    const aliases = new Map();
    let ordinal = 0;
    const aliasFor = (id) => {
      if (aliases.has(id)) return aliases.get(id);
      if (aliases.size >= MAX_ID_ALIASES) throw new Error("protocol id limit");
      let alias;
      do {
        if (ordinal >= MAX_PROTOCOL_IDS + MAX_ID_ALIASES) throw new Error("protocol id limit");
        alias = `airkit_id_${alphabeticOrdinal(ordinal++)}`;
        if (!safeReplacement(alias)) alias = alphabeticOrdinal(ordinal - 1);
      } while (reserved.has(alias) || !safeReplacement(alias));
      reserved.add(alias);
      aliases.set(id, alias);
      return alias;
    };
    const pieces = [];
    let cursor = 0;
    for (const span of ranges) {
      const replacement = span.protocolId !== undefined ? aliasFor(span.protocolId)
        : span.inKey ? keyMarkerFor(span.label, original.subarray(span.start, span.end)) : markerFor(span.label);
      pieces.push(original.subarray(cursor, span.start), Buffer.from(span.quote ? JSON.stringify(replacement) : replacement));
      cursor = span.end;
    }
    pieces.push(original.subarray(cursor));
    const redacted = Buffer.concat(pieces);
    JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(redacted));
    if (redacted.length > MAX_BODY_BYTES) throw new Error("redaction body limit");
    const candidate = prepareOpfScan(redacted);
    validateOpaqueValues(canonical.opaque, candidate.opaque);
    // A changed control is named before residuals are counted: a span inside a key would otherwise surface as
    // value-survived through the key's untouched siblings.
    validateProtocolIds(canonical.protocolIds, candidate.protocolIds);
    validateJsonShape(canonical.root, candidate.root);
    // Pinned controls no span touched were left byte-identical on purpose, so a finding they repeat is not a
    // residual. The shape check above proved every control unchanged, and redaction rewrites values in place,
    // so the same index is the same node.
    const keptPins = new Set(canonical.allValues.flatMap((node, index) => pinned.has(node) && !spannedPins.has(node) ? [candidate.allValues[index]] : []));
    // Signed thinking travels byte-identical (validateOpaqueValues proved it), so a value it repeats is not a residual.
    const passed = [...candidate.opaque.passthrough.nodes.keys()];
    const keptRanges = [...candidate.opaque.entries.map(({ node }) => node), ...keptPins, ...passed].filter((node) => node.map.length > 0)
      .map((node) => node.type === "string" ? { start: node.map[0].start - 1, end: node.map.at(-1).end + 1 }
        : { start: node.map[0].start, end: node.map.at(-1).end });
    if (originalMatcher.includesOutside(redacted, keptRanges)) throw new Error("value survived");
    if (hasDecodedResidual(candidate.root, matcher, new Set([...candidate.opaque.nodes, ...keptPins, ...passed]))) throw new Error("value survived");
    const redactions = [];
    let proofCount = 0;
    for (const [label, spans] of grouped) {
      proofCount += spans.length;
      if (proofCount > MAX_PROOF_RANGES) throw new Error("redaction match limit");
      for (let offset = 0; offset < spans.length; offset += MAX_PROOF_BATCH) {
        if (redactions.length >= MAX_PROOF_ENTRIES) throw new Error("redaction match limit");
        const batch = spans.slice(offset, offset + MAX_PROOF_BATCH);
        redactions.push({ label, count: batch.length, spans: batch });
      }
    }
    const findings = redactions.map(({ label, count }) => ({ label, count }));
    return { status: "ok", findings, redactions, redactedBody: redacted.toString("base64"), ...passthrough };
  } catch (error) {
    const reason = error instanceof Error && !(error instanceof SyntaxError)
      ? UNKNOWN_REASONS.get(error.message) ?? "adapter-error" : "adapter-error";
    const detail = reason === "adapter-error" ? undefined : error.graphDefect;
    return GRAPH_DEFECTS.has(detail) || /^control:[a-z_]+:[a-z_]+:[a-z_-]+$/.test(detail ?? "") || SIGNED_DETAIL.test(detail ?? "")
      ? { status: "unknown", findings: [], reason, detail } : { status: "unknown", findings: [], reason };
  }
}

function collectKeyNodes(root) {
  const keys = new Set();
  const stack = [root];
  while (stack.length) {
    const node = stack.pop();
    if (node.type === "object") for (const { keyNode, value } of node.children) { keys.add(keyNode); stack.push(value); }
    else if (node.type === "array") for (const { value } of node.children) stack.push(value);
  }
  return keys;
}

function firstSourceEndingAfter(sources, offset) {
  let low = 0;
  let high = sources.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (sources[middle].end > offset) high = middle;
    else low = middle + 1;
  }
  return low;
}

class OriginalBytesMatcher {
  constructor(original, replacements) {
    const unique = new Set();
    const patterns = [];
    let units = 0;
    for (const { start, end } of replacements) {
      const pattern = original.toString("latin1", start, end);
      if (unique.has(pattern)) continue;
      if (units + pattern.length > MAX_ORIGINAL_TRIE_BYTES) {
        this.buffers = replacements.map((range) => original.subarray(range.start, range.end));
        return;
      }
      unique.add(pattern);
      patterns.push(pattern);
      units += pattern.length;
    }
    this.matcher = new FragmentMatcher(patterns, MAX_ORIGINAL_TRIE_BYTES);
  }

  includes(bytes) {
    if (this.matcher) return this.matcher.scan(bytes.toString("latin1"), () => true);
    return this.buffers.some((pattern) => bytes.indexOf(pattern) >= 0);
  }

  includesOutside(bytes, opaqueRanges) {
    const outside = (start, end) => !opaqueRanges.some((range) => start >= range.start && end <= range.end);
    if (this.matcher) return this.matcher.scan(bytes.toString("latin1"), (pattern, end) => {
      return outside(end - this.matcher.lengths[pattern], end);
    });
    for (const pattern of this.buffers) {
      for (let at = bytes.indexOf(pattern); at >= 0; at = bytes.indexOf(pattern, at + 1)) {
        if (outside(at, at + pattern.length)) return true;
      }
    }
    return false;
  }
}

// Aho-Corasick over UTF-16 code units: one pass over a value reports every occurrence of every pattern,
// so scanning costs the value length plus the hits rather than patterns x values.
export class FragmentMatcher {
  constructor(patterns, maxUnits = MAX_TRIE_UNITS) {
    let units = 0;
    for (const pattern of patterns) {
      if (typeof pattern !== "string" || pattern.length === 0 || pattern.length > maxUnits - units) throw new Error("matcher pattern limit");
      units += pattern.length;
    }
    this.lengths = patterns.map((pattern) => pattern.length);
    const size = 1 + units;
    this.edges = new Map();
    this.output = new Int32Array(size).fill(-1);
    this.fail = new Int32Array(size);
    this.next = new Int32Array(size);
    const parent = new Int32Array(size);
    const code = new Uint16Array(size);
    const depth = new Int32Array(size);
    let states = 1;
    patterns.forEach((pattern, index) => {
      let state = 0;
      for (let at = 0; at < pattern.length; at += 1) {
        const edge = state * 0x10000 + pattern.charCodeAt(at);
        let child = this.edges.get(edge);
        if (child === undefined) {
          child = states++;
          this.edges.set(edge, child);
          parent[child] = state;
          code[child] = pattern.charCodeAt(at);
          depth[child] = depth[state] + 1;
        }
        state = child;
      }
      this.output[state] = index;
    });
    const order = Array.from({ length: states - 1 }, (_, index) => index + 1).sort((a, b) => depth[a] - depth[b]);
    for (const state of order) {
      if (parent[state] === 0) continue;
      this.fail[state] = this.step(this.fail[parent[state]], code[state]);
      const fail = this.fail[state];
      this.next[state] = this.output[fail] >= 0 ? fail : this.next[fail];
    }
  }

  step(state, unit) {
    for (;;) {
      const child = this.edges.get(state * 0x10000 + unit);
      if (child !== undefined) return child;
      if (state === 0) return 0;
      state = this.fail[state];
    }
  }

  // Calls visit(pattern, end) for each occurrence in end order; a truthy return stops the scan.
  scan(text, visit) {
    let state = 0;
    for (let at = 0; at < text.length; at += 1) {
      state = this.step(state, text.charCodeAt(at));
      for (let hit = this.output[state] >= 0 ? state : this.next[state]; hit; hit = this.next[hit]) {
        if (visit(this.output[hit], at + 1)) return true;
      }
    }
    return false;
  }

  // Like scan, but skips occurrences that split a surrogate pair at either edge.
  scanWhole(text, visit) {
    const boundary = (offset) => !(offset > 0 && text.charCodeAt(offset - 1) >= 0xd800
      && text.charCodeAt(offset - 1) <= 0xdbff && text.charCodeAt(offset) >= 0xdc00 && text.charCodeAt(offset) <= 0xdfff);
    return this.scan(text, (pattern, end) => boundary(end - this.lengths[pattern]) && boundary(end) && visit(pattern, end));
  }

  includesWhole(value) {
    return this.scanWhole(value, () => true);
  }
}

function hasDecodedResidual(node, matcher, opaque) {
  if (opaque.has(node)) return false;
  if (node.type === "string" || node.type === "literal") return matcher.includesWhole(node.value);
  return node.children.some(({ keyNode, value }) => keyNode && hasDecodedResidual(keyNode, matcher, opaque)
    || hasDecodedResidual(value, matcher, opaque));
}

// Provider-issued values the API verifies byte for byte. Only these exact structural paths qualify, and a
// duplicated key anywhere on the path disqualifies it, so a look-alike field elsewhere is still scanned.
function collectOpaqueValues(root) {
  // passthrough: signed thinking text the API verifies against its opaque signature; it is scanned for
  // diagnostics but never rewritten. lockedThinking: thinking without an opaque signature, which nothing
  // upstream vouches for, so a finding in it still fails closed.
  const found = { entries: [], nodes: new Set(), lockedThinking: new Map(), passthrough: { entries: [], nodes: new Map() } };
  const only = (node, name) => {
    if (node?.type !== "object") return undefined;
    const matches = node.children.filter(({ key }) => key === name);
    return matches.length === 1 ? matches[0].value : undefined;
  };
  const text = (node) => node?.type === "string" ? node.value : undefined;
  const add = (path, node, pattern = OPAQUE_VALUE) => {
    if (node?.type !== "string" || !pattern.test(node.value)) return false;
    found.entries.push({ path, node });
    found.nodes.add(node);
    return true;
  };
  const pass = (path, at, node) => {
    if (node?.type !== "string" || found.nodes.has(node)) return;
    found.passthrough.entries.push({ path, node });
    found.passthrough.nodes.set(node, at);
  };
  const base64Source = (block, path) => {
    const source = only(block, "source");
    if (["image", "document"].includes(text(only(block, "type"))) && text(only(source, "type")) === "base64") {
      add(`${path}.source.data`, only(source, "data"));
    }
  };
  const each = (node, visit) => { if (node?.type === "array") for (const [index, { value }] of node.children.entries()) visit(value, index); };
  each(only(root, "messages"), (message, messageIndex) => {
    const role = text(only(message, "role"));
    each(only(message, "content"), (block, blockIndex) => {
      const path = `${messageIndex}.${blockIndex}`;
      const type = text(only(block, "type"));
      base64Source(block, path);
      if (role === "user" && type === "tool_result") each(only(block, "content"), (nested, index) => base64Source(nested, `${path}.content.${index}`));
      if (role !== "assistant") return;
      if (type === "thinking") {
        const thinking = only(block, "thinking");
        // Only a signature shaped like a provider token counts; a short or prose one leaves its thinking locked.
        if (add(`${path}.signature`, only(block, "signature"))) pass(`${path}.thinking`, path, thinking);
        else if (thinking?.type === "string") found.lockedThinking.set(thinking, path);
      } else if (type === "redacted_thinking") add(`${path}.data`, only(block, "data"));
      else if (type === "server_tool_use" || type === "mcp_tool_use") add(`${path}.id`, only(block, "id"), PROTOCOL_ID);
      else if (type?.endsWith("_tool_result") && type !== "tool_result") {
        add(`${path}.tool_use_id`, only(block, "tool_use_id"), PROTOCOL_ID);
        if (type === "web_search_tool_result") each(only(block, "content"), (item, index) => {
          if (text(only(item, "type")) === "web_search_result") add(`${path}.content.${index}.encrypted_content`, only(item, "encrypted_content"));
        });
      } else if (type === "text") each(only(block, "citations"), (citation, index) => {
        if (text(only(citation, "type")) === "web_search_result_location") add(`${path}.citations.${index}.encrypted_index`, only(citation, "encrypted_index"));
      });
    });
  });
  return found;
}

function validateOpaqueValues(before, after) {
  const compare = (was, now) => {
    for (let index = 0; index < Math.max(was.length, now.length); index += 1) {
      if (was[index]?.path !== now[index]?.path || was[index]?.node.value !== now[index]?.node.value) {
        throw signedMutation("-", (was[index] ?? now[index]).path.split(".", 2).join("."));
      }
    }
  };
  compare(before.entries, after.entries);
  compare(before.passthrough.entries, after.passthrough.entries);
}

// Names where the signed-block rule tripped as label:messageIndex.blockIndex; never any text.
function signedMutation(label, at) {
  return graphError("signed block mutation", `signed:${label}:${at}`);
}

function validateSourceProvenance(scan, canonical) {
  if (!Array.isArray(scan.sources) || scan.sources.length !== canonical.sources.length
    || scan.text !== canonical.text || !Array.isArray(scan.map) || scan.map.length !== canonical.map.length) throw new Error("invalid source provenance");
  for (const [index, source] of scan.sources.entries()) {
    const expected = canonical.sources[index];
    const node = source?.node;
    if (source?.start !== expected.start || source?.end !== expected.end || !node
      || node.type !== expected.node.type || node.value !== expected.node.value
      || node.start !== expected.node.start || node.end !== expected.node.end
      || !Array.isArray(node.map) || node.map.length !== expected.node.map.length) throw new Error("invalid source provenance");
    for (const [offset, entry] of node.map.entries()) {
      const actual = expected.node.map[offset];
      if (entry?.start !== actual.start || entry?.end !== actual.end) throw new Error("invalid source provenance");
    }
  }
  for (const [index, entry] of scan.map.entries()) {
    const expected = canonical.map[index];
    if (expected === null) {
      if (entry !== null) throw new Error("invalid source provenance");
    } else {
      if (!entry) throw new Error("unmapped span");
      if (entry.start !== expected.start || entry.end !== expected.end) throw new Error("cross-field span");
    }
  }
}

function validateAllValues(values, expected) {
  if (!Array.isArray(values) || values.length !== expected.length) throw new Error("invalid source provenance");
  for (const [index, node] of values.entries()) {
    const original = expected[index];
    if (node?.type !== original.type || node?.value !== original.value || node?.start !== original.start
      || node?.end !== original.end || node?.protocolId !== original.protocolId
      || !Array.isArray(node?.map) || node.map.length !== original.map.length
      || node.map.some((entry, offset) => entry?.start !== original.map[offset].start || entry?.end !== original.map[offset].end)) throw new Error("invalid source provenance");
  }
}

// Names which control field tripped, from fixed vocabularies only; anything else is reported as "other".
export const CONTROL_RULES = ["value", "key", "type", "selector"];
export const CONTROL_CONTEXTS = ["request", "messages", "message", "block", "tools", "tool", "content", "data", "control", "thinking", "cache", "choice", "output", "schema", "schemas", "fields", "literal"];
export const CONTROL_KEYS = ["model", "messages", "system", "tools", "tool_choice", "max_tokens", "stream", "metadata", "temperature", "top_p", "top_k",
  "stop_sequences", "thinking", "output_config", "service_tier", "mcp_servers", "context_management", "container", "cache_control", "role", "content",
  "type", "text", "id", "tool_use_id", "name", "input", "is_error", "source", "signature", "data", "citations", "transformations", "file_id",
  "defer_loading", "strict", "max_uses", "budget_tokens", "ttl", "disable_parallel_tool_use", "effort", "input_schema", "description", "title",
  "properties", "items", "enum", "required", "const", "default", "pattern", "format", "examples", "url", "media_type"];
function controlMutation(rule, context, key) {
  const part = (value, allowed) => allowed.includes(value) ? value : "other";
  const defect = `control:${part(rule, CONTROL_RULES)}:${part(context, CONTROL_CONTEXTS)}:${key === null ? "-" : part(key, CONTROL_KEYS)}`;
  return Object.assign(new Error("protocol control mutation"), { graphDefect: defect });
}

// pinned, when given, collects the typed control and selector scalars of `before`.
function validateJsonShape(before, after, context = before.type === "object"
  && before.children.some(({ key, value }) => key === "messages" && value.type === "array") ? "request" : "data", pinned, field = null) {
  const container = (node) => node.type === "object" || node.type === "array";
  const control = ["control", "thinking", "cache", "choice", "output", "schema", "schemas", "fields", "literal"].includes(context);
  if (control && (before.type !== after.type || !container(before) && before.value !== after.value)) throw controlMutation("value", context, typeof field === "string" && /^[a-z_]+$/.test(field) ? field : null);
  if (container(before) !== container(after) || (container(before) && before.type !== after.type)) throw new Error("invalid JSON topology");
  if (!container(before)) return;
  if (before.children.length !== after.children.length) throw new Error("invalid JSON topology");
  const fixed = {
    request: ["model", "messages", "system", "tools", "tool_choice", "max_tokens", "stream", "metadata", "temperature", "top_p", "top_k", "stop_sequences", "thinking", "output_config", "service_tier", "mcp_servers", "context_management", "container", "cache_control"],
    message: ["role", "content"],
    block: ["type", "text", "id", "tool_use_id", "name", "input", "content", "is_error", "source", "thinking", "signature", "data", "cache_control", "citations", "transformations", "file_id"],
  };
  const keys = new Map();
  for (const [index, entry] of before.children.entries()) {
    const candidate = after.children[index];
    if (before.type === "object") {
      if (keys.has(candidate.key) && keys.get(candidate.key) !== entry.key) throw new Error("JSON key collision");
      keys.set(candidate.key, entry.key);
      if ((control || ["tool", "citation", "source"].includes(context) || fixed[context]?.includes(entry.key))
        && candidate.key !== entry.key) throw controlMutation("key", context, entry.key);
      const requiredTypes = {
        request: { model: "string", max_tokens: "number", temperature: "number", top_p: "number", top_k: "number", stream: "boolean",
          thinking: "object", tool_choice: "object", output_config: "object" },
        message: { role: "string" },
        block: { type: "string", is_error: "boolean" },
        tool: { name: "string", type: "string", defer_loading: "boolean", strict: "boolean", max_uses: "number" },
        thinking: { type: "string", budget_tokens: "number" },
        cache: { type: "string", ttl: "string" },
        choice: { type: "string", name: "string", disable_parallel_tool_use: "boolean" },
        output: { effort: "string" },
      };
      const required = requiredTypes[context]?.[entry.key];
      if (required && [entry.value, candidate.value].some((node) => required === "number"
        ? node.type !== "literal" || !/^-?\d/.test(node.value) || !Number.isFinite(Number(node.value))
        : required === "boolean" ? node.type !== "literal" || !["true", "false"].includes(node.value)
          : node.type !== required)) throw controlMutation("type", context, entry.key);
      const selector = context === "request" && entry.key === "model"
        || context === "message" && entry.key === "role"
        || context === "block" && entry.key === "type"
        || context === "block" && entry.key === "name" && before.children.some(({ key, value }) => key === "type" && ["tool_use", "server_tool_use"].includes(value.value));
      if (selector && (entry.value.type !== candidate.value.type || entry.value.value !== candidate.value.value)) throw controlMutation("selector", context, entry.key);
      if ((required || selector) && !container(entry.value)) pinned?.add(entry.value);
    }
    let childContext = control ? "control" : "data";
    if (context === "request") childContext = { messages: "messages", tools: "tools", tool_choice: "choice", system: "content",
      thinking: "thinking", cache_control: "cache", output_config: "output", metadata: "data" }[entry.key]
      ?? (fixed.request.includes(entry.key) ? "control" : "data");
    else if (context === "messages") childContext = "message";
    else if (context === "tools") childContext = "tool";
    else if (context === "tool") childContext = { description: "data", cache_control: "cache", input_schema: "schema" }[entry.key] ?? "control";
    // Schema prose is only documentation the API accepts back altered. Every other schema value (type, required,
    // pattern, property names) constrains the tool call and stays locked. Only keywords known to hold subschemas
    // are walked as schemas; anything else (enum, const, default, examples, discriminator, extensions) is a
    // literal, locked whole even under prose-shaped keys, and keyword maps hold property names, not prose.
    else if (context === "schema") childContext = schemaChildContext(before, entry);
    else if (context === "schemas" || context === "fields") childContext = "schema";
    else if (context === "literal") childContext = "literal";
    else if (context === "message" && entry.key === "content" || context === "block" && entry.key === "content") childContext = "content";
    else if (context === "content") childContext = "block";
    else if (context === "block" && entry.key === "cache_control") childContext = "cache";
    // Quoted prose the API accepts back altered: citation excerpts and titles, and plain-text document bodies.
    // Everything else in a citation or source (type, url, encrypted index, offsets, media type) stays locked.
    else if (context === "block" && entry.key === "citations") childContext = entry.value.type === "array" ? "citations" : "control";
    else if (context === "citations") childContext = "citation";
    else if (context === "citation") childContext = ["cited_text", "title", "document_title"].includes(entry.key) ? "data" : "control";
    else if (context === "block" && entry.key === "source") childContext = "source";
    else if (context === "source") {
      const textSource = before.children.some(({ key, value }) => key === "type" && value.type === "string" && value.value === "text");
      childContext = textSource && entry.key === "data" ? "data" : "control";
    }
    else if (context === "block" && fixed.block.includes(entry.key) && !["type", "id", "tool_use_id", "name", "text", "input"].includes(entry.key)) childContext = "control";
    validateJsonShape(entry.value, candidate.value, childContext, pinned, before.type === "array" ? field : entry.key);
  }
}

const SCHEMA_PROSE = ["description", "title"];
const SUBSCHEMA = ["items", "additionalItems", "additionalProperties", "unevaluatedItems", "unevaluatedProperties", "contains",
  "propertyNames", "not", "if", "then", "else", "contentSchema"];
const SUBSCHEMA_LISTS = ["anyOf", "oneOf", "allOf", "prefixItems", "items"];
const SUBSCHEMA_MAPS = ["properties", "patternProperties", "$defs", "definitions", "dependentSchemas"];
const SCHEMA_LITERALS = ["enum", "const", "default", "examples", "example"];

// Default-deny: a schema object's value is walked as a schema only under a keyword known to hold one. Scalars stay
// in schema context so a mutation names its keyword; any other container is a literal.
function schemaChildContext(schema, { key, value }) {
  if (schema.type !== "object") return value.type === "object" || value.type === "array" ? "literal" : "schema";
  if (SCHEMA_PROSE.includes(key) && value.type === "string") return "data";
  if (SCHEMA_LITERALS.includes(key)) return "literal";
  if (value.type === "object" && SUBSCHEMA.includes(key)) return "schema";
  if (value.type === "array" && SUBSCHEMA_LISTS.includes(key)) return "schemas";
  if (value.type === "object" && SUBSCHEMA_MAPS.includes(key)) return "fields";
  return value.type === "object" || value.type === "array" ? "literal" : "schema";
}

const GRAPH_DEFECTS = new Set(["orphan", "duplicate", "role", "id", "limit"]);

function graphError(message, defect) {
  return Object.assign(new Error(message), { graphDefect: defect });
}

function collectProtocolIds(root) {
  // invalid holds the first GRAPH_DEFECTS entry seen, never request content.
  const graph = { nodes: [], invalid: false, overLimit: false };
  const reject = (defect) => { graph.invalid ||= defect; };
  const field = (node, name) => {
    if (node?.type !== "object") return undefined;
    const matches = node.children.filter(({ key }) => key === name);
    if (matches.length > 1) reject("duplicate");
    return matches[0]?.value;
  };
  const messages = field(root, "messages");
  if (messages?.type !== "array") return graph;
  const calls = new Map();
  const results = new Set();
  for (const [messageIndex, { value: message }] of messages.children.entries()) {
    const role = field(message, "role");
    const content = field(message, "content");
    if (content?.type !== "array") continue;
    for (const [blockIndex, { value: block }] of content.children.entries()) {
      const type = field(block, "type");
      if (type?.type !== "string" || !["tool_use", "tool_result"].includes(type.value)) continue;
      const call = type.value === "tool_use";
      const id = field(block, call ? "id" : "tool_use_id");
      if (role?.type !== "string" || role.value !== (call ? "assistant" : "user")) { reject("role"); continue; }
      if (id?.type !== "string" || !PROTOCOL_ID.test(id.value)) { reject("id"); continue; }
      if (graph.nodes.length >= MAX_PROTOCOL_IDS) { graph.overLimit = true; continue; }
      const index = graph.nodes.length;
      const reference = call ? undefined : calls.get(id.value);
      if (call ? calls.has(id.value) : results.has(id.value)) reject("duplicate");
      else if (!call && reference === undefined) reject("orphan");
      if (call) calls.set(id.value, index);
      else results.add(id.value);
      id.protocolId = id.value;
      graph.nodes.push({ value: id.value, path: `${messageIndex}:${blockIndex}:${type.value}`, reference });
    }
  }
  return graph;
}

function validateProtocolIds(before, after) {
  if (after.overLimit) throw graphError("protocol id limit", "limit");
  if (after.nodes.length !== before.nodes.length) throw new Error("protocol graph mutation");
  const forward = new Map();
  const reverse = new Map();
  for (const [index, original] of before.nodes.entries()) {
    const candidate = after.nodes[index];
    if (candidate.path !== original.path || !PROTOCOL_ID.test(candidate.value)) throw new Error("protocol graph mutation");
    if (forward.has(original.value) && forward.get(original.value) !== candidate.value) throw new Error("protocol graph mutation");
    if (reverse.has(candidate.value) && reverse.get(candidate.value) !== original.value) throw new Error("protocol id collision");
    forward.set(original.value, candidate.value);
    reverse.set(candidate.value, original.value);
    if (original.reference !== undefined && candidate.value !== after.nodes[original.reference].value) throw new Error("protocol graph mutation");
  }
  if (after.invalid) throw new Error("protocol graph mutation");
}

function alphabeticOrdinal(ordinal) {
  let result = "";
  do {
    result = String.fromCharCode(97 + ordinal % 26) + result;
    ordinal = Math.floor(ordinal / 26) - 1;
  } while (ordinal >= 0);
  return result;
}

function byteOffsets(source) {
  const result = Array(source.length + 1).fill(-1);
  let bytes = 0;
  for (let at = 0; at < source.length;) {
    result[at] = bytes;
    const point = source.codePointAt(at);
    const width = point > 0xffff ? 2 : 1;
    bytes += Buffer.byteLength(String.fromCodePoint(point));
    at += width;
  }
  result[source.length] = bytes;
  return result;
}
