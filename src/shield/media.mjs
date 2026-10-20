// Finds image and document blocks in a Messages request body, with the raw
// byte offsets of each image's base64 payload so a later stage can splice in
// a replacement without re-serialising the request.

const MAX_DEPTH = 512;
const QUOTE = 0x22;
const BACKSLASH = 0x5c;

const UNSUPPORTED_TYPES = new Set(["input_file", "file", "container_upload", "input_audio", "audio"]);
const TOOL_CALL_TYPES = new Set(["tool_use", "server_tool_use", "mcp_tool_use"]);
const THINKING_TYPES = new Set(["thinking", "redacted_thinking"]);
const BASE64_SOURCE_KEYS = new Set(["type", "media_type", "data"]);
const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

const MAGIC = {
  "image/png": (bytes) => startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  "image/jpeg": (bytes) => startsWith(bytes, [0xff, 0xd8, 0xff]),
  "image/gif": (bytes) => ["GIF87a", "GIF89a"].includes(bytes.subarray(0, 6).toString("latin1")),
  "image/webp": (bytes) => bytes.subarray(0, 4).toString("latin1") === "RIFF" && bytes.subarray(8, 12).toString("latin1") === "WEBP",
};

function startsWith(bytes, prefix) {
  return bytes.length >= prefix.length && prefix.every((byte, index) => bytes[index] === byte);
}

function scanError(message) {
  const error = new Error(message);
  error.code = "CCSHIELD_MEDIA_SCAN";
  return error;
}

// A minimal parser over bytes. JSON.parse has already accepted the body, so
// this only needs to locate values, not validate grammar. It records each
// string's raw span and whether it contained escapes, and flags duplicate keys.
function parseRaw(raw) {
  let position = 0;
  let duplicateKey = false;

  const skipSpace = () => {
    while (position < raw.length && (raw[position] === 0x20 || raw[position] === 0x0a || raw[position] === 0x0d || raw[position] === 0x09)) position += 1;
  };

  const readString = () => {
    const start = position + 1;
    let end = start;
    let escaped = false;
    while (raw[end] !== QUOTE) {
      if (end >= raw.length) throw scanError("shield media scan found an unterminated string");
      if (raw[end] === BACKSLASH) {
        escaped = true;
        end += 2;
      } else {
        end += 1;
      }
    }
    position = end + 1;
    const value = escaped ? JSON.parse(raw.subarray(start - 1, end + 1).toString("utf8")) : raw.subarray(start, end).toString("utf8");
    return { kind: "string", value, start, end, escaped };
  };

  const readValue = (depth) => {
    if (depth > MAX_DEPTH) throw scanError("shield media scan exceeded the nesting limit");
    skipSpace();
    const byte = raw[position];
    if (byte === QUOTE) return readString();
    if (byte === 0x7b) {
      position += 1;
      const entries = new Map();
      skipSpace();
      if (raw[position] === 0x7d) {
        position += 1;
        return { kind: "object", entries };
      }
      for (;;) {
        skipSpace();
        const key = readString().value;
        skipSpace();
        position += 1; // colon
        const value = readValue(depth + 1);
        if (entries.has(key)) duplicateKey = true;
        entries.set(key, value);
        skipSpace();
        if (raw[position++] === 0x7d) return { kind: "object", entries };
      }
    }
    if (byte === 0x5b) {
      position += 1;
      const items = [];
      skipSpace();
      if (raw[position] === 0x5d) {
        position += 1;
        return { kind: "array", items };
      }
      for (;;) {
        items.push(readValue(depth + 1));
        skipSpace();
        if (raw[position++] === 0x5d) return { kind: "array", items };
      }
    }
    while (position < raw.length && !",]} \n\r\t".includes(String.fromCharCode(raw[position]))) position += 1;
    return { kind: "primitive" };
  };

  const root = readValue(0);
  return { root, duplicateKey };
}

const typeOf = (node) => {
  const type = node?.kind === "object" ? node.entries.get("type") : undefined;
  return type?.kind === "string" ? type.value : undefined;
};

export function extractMedia(raw) {
  if (!Buffer.isBuffer(raw)) throw new TypeError("shield media scan requires a Buffer");
  const result = { images: [], documents: [], imageCount: 0, documentCount: 0, reasonCodes: [] };
  try {
    JSON.parse(raw.toString("utf8"));
  } catch {
    return result;
  }

  const { root, duplicateKey } = parseRaw(raw);
  const reasons = new Set();
  if (duplicateKey) reasons.add("media_duplicate_key");

  const addDocument = (path) => {
    result.documentCount += 1;
    result.documents.push({ path });
    reasons.add("media_document_blocked");
  };

  const addImage = (block, path) => {
    result.imageCount += 1;
    const source = block.entries.get("source");
    if (
      source?.kind !== "object" ||
      typeOf(source) !== "base64" ||
      [...source.entries.keys()].some((key) => !BASE64_SOURCE_KEYS.has(key))
    ) {
      reasons.add("media_image_source_blocked");
      return;
    }
    const data = source.entries.get("data");
    if (data?.kind !== "string" || data.escaped || data.value === "" || !CANONICAL_BASE64.test(data.value)) {
      reasons.add("media_image_encoding_blocked");
      return;
    }
    const bytes = Buffer.from(data.value, "base64");
    if (bytes.toString("base64") !== data.value) {
      reasons.add("media_image_encoding_blocked");
      return;
    }
    const mediaType = source.entries.get("media_type");
    const mime = mediaType?.kind === "string" ? mediaType.value : undefined;
    if (!Object.hasOwn(MAGIC, mime ?? "") || !MAGIC[mime](bytes)) {
      reasons.add("media_image_type_blocked");
      return;
    }
    result.images.push({ path, mime, bytes, rawOffset: data.start, rawLength: data.end - data.start });
  };

  // Anything outside the known image positions: media here is denied, not
  // extracted. Tool-call arguments and thinking blocks are opaque to us.
  const denyScan = (node, path) => {
    if (node.kind === "array") {
      node.items.forEach((item, index) => denyScan(item, `${path}[${index}]`));
      return;
    }
    if (node.kind !== "object") return;
    const type = typeOf(node);
    if (type === "document") return addDocument(path);
    if (type === "image") {
      result.imageCount += 1;
      reasons.add("media_path_blocked");
      return;
    }
    if (THINKING_TYPES.has(type)) return;
    if (UNSUPPORTED_TYPES.has(type) || node.entries.has("file_id")) reasons.add("media_unsupported_blocked");
    if (node.entries.get("source")?.kind === "object") reasons.add("media_path_blocked");
    for (const [key, value] of node.entries) {
      if (key === "input" && TOOL_CALL_TYPES.has(type)) continue;
      denyScan(value, `${path}.${key}`);
    }
  };

  const walkBlocks = (content, path, allowNested) => {
    content.items.forEach((block, index) => {
      const blockPath = `${path}[${index}]`;
      const type = typeOf(block);
      if (type === "image") return addImage(block, blockPath);
      if (type === "document") return addDocument(blockPath);
      const nested = block.kind === "object" ? block.entries.get("content") : undefined;
      if (type === "tool_result" && allowNested && nested?.kind === "array") {
        walkBlocks(nested, `${blockPath}.content`, false);
        for (const [key, value] of block.entries) if (key !== "content") denyScan(value, `${blockPath}.${key}`);
        return;
      }
      denyScan(block, blockPath);
    });
  };

  if (root.kind === "object") {
    const system = root.entries.get("system");
    if (system) denyScan(system, "system");
    const messages = root.entries.get("messages");
    if (messages?.kind === "array") {
      messages.items.forEach((message, index) => {
        const content = message.kind === "object" ? message.entries.get("content") : undefined;
        if (content?.kind === "array") walkBlocks(content, `messages[${index}].content`, true);
      });
    }
  }

  result.reasonCodes = [...reasons];
  return result;
}

// Published in the daemon identity so status reports what this build does,
// not what a newer build on disk would do.
export const MEDIA_COVERAGE = Object.freeze({ documents: "blocked", images: "unscanned" });

export function mediaOutcomeFor(reasonCodes) {
  if (reasonCodes.length === 0) return null;
  return reasonCodes.includes("media_document_blocked") ? "blocked_document" : "blocked_source";
}

export function patchMedia(raw, replacements) {
  const ordered = [...replacements].sort((left, right) => left.rawOffset - right.rawOffset);
  const parts = [];
  let cursor = 0;
  for (const { rawOffset, rawLength, text } of ordered) {
    if (typeof text !== "string" || !/^[A-Za-z0-9+/=]*$/.test(text)) throw new TypeError("shield media replacement must be base64 text");
    if (!Number.isInteger(rawOffset) || !Number.isInteger(rawLength) || rawOffset < cursor || rawLength < 0 || rawOffset + rawLength > raw.length) {
      throw new RangeError("shield media replacement is out of range or overlaps another");
    }
    parts.push(raw.subarray(cursor, rawOffset), Buffer.from(text, "latin1"));
    cursor = rawOffset + rawLength;
  }
  parts.push(raw.subarray(cursor));
  return Buffer.concat(parts);
}
