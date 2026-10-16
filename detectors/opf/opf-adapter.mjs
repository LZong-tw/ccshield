const LABELS = new Set([
  "account_number", "private_address", "private_email", "private_person",
  "private_phone", "private_url", "private_date", "secret",
]);
const MAX_BODY_BYTES = 1_048_576;
const MAX_PROJECTED_RANGES = 8192;
const MAX_PROOF_RANGES = 8192;
const MAX_PROOF_BATCH = 1024;
const MAX_PROOF_ENTRIES = 128;
const MAX_PROTOCOL_IDS = 4096;
const MAX_ID_ALIASES = 1024;
const PROTOCOL_ID = /^[a-zA-Z0-9_-]+$/;
const OPAQUE_VALUE = /^[A-Za-z0-9+/=_-]{16,}$/;
export const UNKNOWN_REASONS = new Map([
  ["invalid prediction", "invalid-prediction"],
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
      || result.detected_spans.length > 1024 || result.summary.span_count !== result.detected_spans.length) throw new Error("invalid prediction");
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
    const replacementsByRange = new Map();
    const fragments = new Map();
    const projectedRanges = new Set();
    let kept = 0;
    for (const span of result.detected_spans) {
      if (!LABELS.has(span.label) || !Number.isInteger(span.start) || !Number.isInteger(span.end)
        || span.start < 0 || span.end <= span.start || span.end > chars.length
        || chars.slice(span.start, span.end).join("") !== span.text) throw new Error("invalid span");
      // A detector hit wholly inside a typed control or selector value (model, role, block type, tool name, ...)
      // is a false positive the API cannot accept altered; drop it. Spans reaching past that value stay fail-closed.
      const home = scan.sources.findIndex((source) => source.start <= span.start && span.end <= source.end);
      if (home >= 0 && pinned.has(canonical.sources[home].node)) continue;
      kept += 1;
      let projected = false;
      for (const source of scan.sources) {
        const start = Math.max(source.start, span.start);
        const end = Math.min(source.end, span.end);
        if (end <= start) continue;
        projected = true;
        const key = `${span.label}:${source.node.map[start - source.start].start}:${source.node.map[end - source.start - 1].end}`;
        if (projectedRanges.has(key)) continue;
        if (projectedRanges.size >= MAX_PROJECTED_RANGES) throw new Error("redaction projection limit");
        projectedRanges.add(key);
        const text = chars.slice(start, end).join("");
        fragments.set(`${span.label}:${text}`, { label: span.label, text });
      }
      if (!projected) throw new Error("unmapped span");
    }
    if (fragments.size && canonical.protocolIds.invalid) throw graphError("invalid protocol graph", canonical.protocolIds.invalid);
    if (fragments.size && canonical.protocolIds.overLimit) throw graphError("protocol id limit", "limit");
    const projectedIds = new Set();
    const keyNodes = collectKeyNodes(canonical.root);
    const characterOffsets = new WeakMap();
    for (const fragment of fragments.values()) {
      for (const node of canonical.allValues) {
        if (canonical.opaque.nodes.has(node)) continue;
        let match = node.value.indexOf(fragment.text);
        if (match < 0) continue;
        if (canonical.opaque.signedText.has(node)) throw new Error("signed block mutation");
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
        for (; match >= 0; match = node.value.indexOf(fragment.text, match + 1)) {
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
    }
    const replacements = [...replacementsByRange.values()].sort((a, b) => a.start - b.start || a.end - b.end);
    if (kept && !replacements.length) throw new Error("unmapped finding");
    if (!replacements.length) return { status: "ok", findings: [] };
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
    const decodedFragments = [...new Set([...fragments.values()].map(({ text }) => text))];
    const originalFragments = [...new Map(replacements.map(({ start, end }) => {
      const bytes = original.subarray(start, end);
      return [bytes.toString("base64"), bytes];
    })).values()];
    const safeReplacement = (value) => {
      if (decodedFragments.some((text) => containsFragment(value, text))) return false;
      const bytes = Buffer.from(JSON.stringify(value));
      return !originalFragments.some((fragment) => bytes.includes(fragment));
    };
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
    const opaqueRanges = candidate.opaque.entries.map(({ node }) => ({ start: node.map[0].start - 1, end: node.map.at(-1).end + 1 }));
    for (const span of replacements) {
      if (includesOutside(redacted, original.subarray(span.start, span.end), opaqueRanges)) throw new Error("value survived");
    }
    if (hasDecodedResidual(candidate.root, decodedFragments, candidate.opaque.nodes)) throw new Error("value survived");
    validateProtocolIds(canonical.protocolIds, candidate.protocolIds);
    validateJsonShape(canonical.root, candidate.root);
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
    return { status: "ok", findings, redactions, redactedBody: redacted.toString("base64") };
  } catch (error) {
    const reason = error instanceof Error && !(error instanceof SyntaxError)
      ? UNKNOWN_REASONS.get(error.message) ?? "adapter-error" : "adapter-error";
    const detail = reason === "adapter-error" ? undefined : error.graphDefect;
    return GRAPH_DEFECTS.has(detail) ? { status: "unknown", findings: [], reason, detail } : { status: "unknown", findings: [], reason };
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

function containsFragment(value, fragment) {
  const boundary = (offset) => !(offset > 0 && value.charCodeAt(offset - 1) >= 0xd800
    && value.charCodeAt(offset - 1) <= 0xdbff && value.charCodeAt(offset) >= 0xdc00 && value.charCodeAt(offset) <= 0xdfff);
  for (let at = value.indexOf(fragment); at >= 0; at = value.indexOf(fragment, at + 1)) {
    if (boundary(at) && boundary(at + fragment.length)) return true;
  }
  return false;
}

function hasDecodedResidual(node, fragments, opaque) {
  if (opaque.has(node)) return false;
  if (node.type === "string" || node.type === "literal") return fragments.some((text) => containsFragment(node.value, text));
  return node.children.some(({ keyNode, value }) => keyNode && hasDecodedResidual(keyNode, fragments, opaque)
    || hasDecodedResidual(value, fragments, opaque));
}

function includesOutside(buffer, needle, ranges) {
  for (let at = buffer.indexOf(needle); at >= 0; at = buffer.indexOf(needle, at + 1)) {
    if (!ranges.some(({ start, end }) => at >= start && at + needle.length <= end)) return true;
  }
  return false;
}

// Provider-issued values the API verifies byte for byte. Only these exact structural paths qualify, and a
// duplicated key anywhere on the path disqualifies it, so a look-alike field elsewhere is still scanned.
function collectOpaqueValues(root) {
  const found = { entries: [], nodes: new Set(), signedText: new Set() };
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
        add(`${path}.signature`, only(block, "signature"));
        const thinking = only(block, "thinking");
        if (thinking?.type === "string") found.signedText.add(thinking);
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
  if (before.entries.length !== after.entries.length) throw new Error("signed block mutation");
  for (const [index, { path, node }] of before.entries.entries()) {
    if (after.entries[index].path !== path || after.entries[index].node.value !== node.value) throw new Error("signed block mutation");
  }
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

// pinned, when given, collects the typed control and selector scalars of `before`.
function validateJsonShape(before, after, context = before.type === "object"
  && before.children.some(({ key, value }) => key === "messages" && value.type === "array") ? "request" : "data", pinned) {
  const container = (node) => node.type === "object" || node.type === "array";
  const control = ["control", "thinking", "cache", "choice", "output"].includes(context);
  if (control && (before.type !== after.type || !container(before) && before.value !== after.value)) throw new Error("protocol control mutation");
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
        && candidate.key !== entry.key) throw new Error("protocol control mutation");
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
          : node.type !== required)) throw new Error("protocol control mutation");
      const selector = context === "request" && entry.key === "model"
        || context === "message" && entry.key === "role"
        || context === "block" && entry.key === "type"
        || context === "block" && entry.key === "name" && before.children.some(({ key, value }) => key === "type" && ["tool_use", "server_tool_use"].includes(value.value));
      if (selector && (entry.value.type !== candidate.value.type || entry.value.value !== candidate.value.value)) throw new Error("protocol control mutation");
      if ((required || selector) && !container(entry.value)) pinned?.add(entry.value);
    }
    let childContext = control ? "control" : "data";
    if (context === "request") childContext = { messages: "messages", tools: "tools", tool_choice: "choice", system: "content",
      thinking: "thinking", cache_control: "cache", output_config: "output", metadata: "data" }[entry.key]
      ?? (fixed.request.includes(entry.key) ? "control" : "data");
    else if (context === "messages") childContext = "message";
    else if (context === "tools") childContext = "tool";
    else if (context === "tool") childContext = entry.key === "description" ? "data" : entry.key === "cache_control" ? "cache" : "control";
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
    validateJsonShape(entry.value, candidate.value, childContext, pinned);
  }
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
