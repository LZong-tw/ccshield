import assert from "node:assert/strict";
import test from "node:test";

import { extractMedia, mediaOutcomeFor, patchImages, patchMedia } from "../src/shield/media.mjs";
import { opaqueValues } from "../src/shield/privacy.mjs";

const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(24, 7)]);
const JPEG = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(24, 3)]);
const GIF = Buffer.concat([Buffer.from("GIF89a"), Buffer.alloc(24, 1)]);
const WEBP = Buffer.concat([Buffer.from("RIFF"), Buffer.alloc(4, 0), Buffer.from("WEBP"), Buffer.alloc(20, 2)]);

const image = (bytes = PNG, mediaType = "image/png") => ({ type: "image", source: { type: "base64", media_type: mediaType, data: bytes.toString("base64") } });
const document = (source) => ({ type: "document", source });
const body = (value) => Buffer.from(JSON.stringify(value));
const userTurn = (...content) => body({ model: "claude-sonnet-5", max_tokens: 16, messages: [{ role: "user", content }] });

function assertBlocked(result, code, outcome = "blocked_source") {
  assert.ok(result.reasonCodes.includes(code), `expected ${code}, got ${JSON.stringify(result.reasonCodes)}`);
  assert.equal(mediaOutcomeFor(result.reasonCodes), outcome);
}

test("a clean base64 image is extracted with its raw offsets and decoded bytes", () => {
  const raw = userTurn({ type: "text", text: "look" }, image());
  const result = extractMedia(raw);
  assert.deepEqual(result.reasonCodes, []);
  assert.equal(result.imageCount, 1);
  assert.equal(result.documentCount, 0);
  const [found] = result.images;
  assert.equal(found.path, "messages[0].content[1]");
  assert.equal(found.mime, "image/png");
  assert.deepEqual(found.bytes, PNG);
  assert.equal(raw.subarray(found.rawOffset, found.rawOffset + found.rawLength).toString(), PNG.toString("base64"));
  assert.equal(mediaOutcomeFor(result.reasonCodes), null);
});

test("every allowed image format passes when its magic bytes match the declared type", () => {
  for (const [bytes, mime] of [[PNG, "image/png"], [JPEG, "image/jpeg"], [GIF, "image/gif"], [WEBP, "image/webp"]]) {
    const result = extractMedia(userTurn(image(bytes, mime)));
    assert.deepEqual(result.reasonCodes, [], mime);
    assert.equal(result.images[0].mime, mime);
  }
});

test("documents block whatever their source", () => {
  for (const source of [
    { type: "base64", media_type: "application/pdf", data: Buffer.from("%PDF-1.7 fake").toString("base64") },
    { type: "text", media_type: "text/plain", data: "plain text document" },
    { type: "url", url: "https://example.invalid/a.pdf" },
    { type: "file", file_id: "file_abc" },
  ]) {
    const result = extractMedia(userTurn(document(source)));
    assertBlocked(result, "media_document_blocked", "blocked_document");
    assert.equal(result.documentCount, 1);
    assert.deepEqual(result.images, []);
  }
});

test("input_file, file, container_upload and audio blocks are unsupported media", () => {
  for (const block of [
    { type: "input_file", file_data: "AAAA" },
    { type: "file", file: { file_id: "file_abc" } },
    { type: "container_upload", file_id: "file_abc" },
    { type: "input_audio", input_audio: { data: "AAAA", format: "wav" } },
    { type: "audio", source: { type: "base64", media_type: "audio/wav", data: "AAAA" } },
  ]) {
    assertBlocked(extractMedia(userTurn(block)), "media_unsupported_blocked");
  }
});

test("image url, file and unknown source types are blocked, not fetched", () => {
  for (const source of [
    { type: "url", url: "https://example.invalid/a.png" },
    { type: "file", file_id: "file_abc" },
    { type: "mystery", data: PNG.toString("base64") },
    { type: "base64", media_type: "image/png", data: PNG.toString("base64"), url: "https://example.invalid/a.png" },
  ]) {
    const result = extractMedia(userTurn({ type: "image", source }));
    assertBlocked(result, "media_image_source_blocked");
    assert.equal(result.imageCount, 1);
    assert.deepEqual(result.images, []);
  }
});

test("an unknown MIME or magic bytes that contradict the declared type block", () => {
  assertBlocked(extractMedia(userTurn(image(PNG, "image/svg+xml"))), "media_image_type_blocked");
  assertBlocked(extractMedia(userTurn(image(JPEG, "image/png"))), "media_image_type_blocked");
  assertBlocked(extractMedia(userTurn(image(Buffer.from("%PDF-1.7 not an image"), "image/png"))), "media_image_type_blocked");
});

test("non-canonical base64 blocks: whitespace, \\u escapes, url-safe alphabet, bad padding", () => {
  const data = PNG.toString("base64");
  const withData = (raw) => Buffer.from(JSON.stringify({ messages: [{ role: "user", content: [{ type: "image", source: { type: "base64", media_type: "image/png", data: "@@" } }] }] }).replace('"@@"', raw));
  for (const raw of [
    JSON.stringify(`${data.slice(0, 8)}\n${data.slice(8)}`),
    JSON.stringify(` ${data}`),
    `"\\u${data.charCodeAt(0).toString(16).padStart(4, "0")}${data.slice(1)}"`,
    JSON.stringify(`${data.slice(0, 4)}-_${data.slice(6)}`),
    JSON.stringify(data.replace(/=+$/, "")),
    JSON.stringify(""),
  ]) {
    assertBlocked(extractMedia(withData(raw)), "media_image_encoding_blocked");
  }
});

test("duplicate keys block, because parsers disagree about which value wins", () => {
  const raw = Buffer.from(`{"messages":[{"role":"user","content":[{"type":"text","type":"image","source":{"type":"base64","media_type":"image/png","data":"${PNG.toString("base64")}"}}]}]}`);
  assertBlocked(extractMedia(raw), "media_duplicate_key");
  const nested = Buffer.from(`{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"url","type":"base64","media_type":"image/png","data":"${PNG.toString("base64")}"}}]}]}`);
  assertBlocked(extractMedia(nested), "media_duplicate_key");
});

test("images in assistant turns and user tool results are extracted like opaqueValues does", () => {
  const raw = body({ messages: [
    { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_1", content: [{ type: "text", text: "shot" }, image(JPEG, "image/jpeg")] }] },
    { role: "assistant", content: [image(GIF, "image/gif")] },
  ] });
  const result = extractMedia(raw);
  assert.deepEqual(result.reasonCodes, []);
  assert.deepEqual(result.images.map(({ path }) => path), ["messages[0].content[0].content[1]", "messages[1].content[0]"]);
});

test("media in system, a server tool result, or nested deeper than a known path is default-denied", () => {
  const systemImage = body({ system: [{ type: "text", text: "x" }, image()], messages: [] });
  assertBlocked(extractMedia(systemImage), "media_path_blocked");
  const serverResult = body({ messages: [{ role: "assistant", content: [{ type: "web_fetch_tool_result", tool_use_id: "srvtoolu_1", content: { type: "web_fetch_result", url: "https://example.invalid", content: document({ type: "text", media_type: "text/plain", data: "x" }) } }] }] });
  assertBlocked(extractMedia(serverResult), "media_document_blocked", "blocked_document");
  const deep = userTurn({ type: "tool_result", tool_use_id: "toolu_1", content: [{ type: "tool_result", content: [image()] }] });
  assertBlocked(extractMedia(deep), "media_path_blocked");
  const orphanSource = userTurn({ type: "text", text: "x", source: { type: "base64", data: "AAAA" } });
  assertBlocked(extractMedia(orphanSource), "media_path_blocked");
  const fileId = body({ messages: [{ role: "assistant", content: [{ type: "code_execution_tool_result", tool_use_id: "srvtoolu_1", content: { type: "code_execution_result", content: [{ type: "code_execution_output", file_id: "file_abc" }] } }] }] });
  assertBlocked(extractMedia(fileId), "media_unsupported_blocked");
});

test("a request shaped like real Claude Code traffic extracts nothing and blocks nothing", () => {
  const raw = body({
    model: "claude-sonnet-5",
    max_tokens: 32000,
    metadata: { user_id: "user_abc" },
    system: [{ type: "text", text: "You are Claude Code.", cache_control: { type: "ephemeral" } }],
    tools: [
      { name: "Read", description: "read", input_schema: { type: "object", properties: { file_path: { type: "string" }, source: { type: "object", properties: { type: { type: "string", enum: ["file", "image"] } } } } } },
      { name: "Upload", input_schema: { type: "object", properties: { type: { const: "document" }, file_id: { type: "string" } } } },
    ],
    tool_choice: { type: "auto" },
    output_format: { type: "json_schema", schema: { properties: { source: { type: "object" } } } },
    messages: [
      { role: "user", content: "hello" },
      { role: "assistant", content: [
        { type: "thinking", thinking: "plan", signature: "sig".repeat(10) },
        { type: "redacted_thinking", data: "ZW5jcnlwdGVkLXRoaW5raW5nLWJsb2I=" },
        { type: "tool_use", id: "toolu_1", name: "Upload", input: { type: "document", source: { type: "url", url: "x" }, file_id: "file_abc" } },
        { type: "server_tool_use", id: "srvtoolu_1", name: "web_search", input: { query: "q", source: { type: "image" } } },
        { type: "web_search_tool_result", tool_use_id: "srvtoolu_1", content: [{ type: "web_search_result", url: "https://example.invalid", title: "t", encrypted_content: "abc", page_age: null }] },
        { type: "text", text: "done", citations: [{ type: "char_location", document_index: 0, document_title: null, cited_text: "x" }] },
      ] },
      { role: "user", content: [
        { type: "tool_result", tool_use_id: "toolu_1", content: [{ type: "text", text: "ok" }, { type: "search_result", source: "https://example.invalid", title: "t", content: [{ type: "text", text: "r" }] }] },
      ] },
    ],
  });
  const result = extractMedia(raw);
  assert.deepEqual(result, { images: [], documents: [], imageCount: 0, documentCount: 0, reasonCodes: [] });
});

test("redacted_thinking passes through even when its blob looks like base64", () => {
  const raw = body({ messages: [{ role: "assistant", content: [{ type: "redacted_thinking", data: PNG.toString("base64") }] }] });
  assert.deepEqual(extractMedia(raw).reasonCodes, []);
});

test("non-JSON bodies carry no media; nesting past the walk limit fails closed", () => {
  assert.deepEqual(extractMedia(Buffer.from("not json")).reasonCodes, []);
  assert.throws(() => extractMedia(Buffer.from(`${"[".repeat(600)}${"]".repeat(600)}`)), { code: "CCSHIELD_MEDIA_SCAN" });
});

test("differential: every image and document opaqueValues sees is extracted or blocked", () => {
  const raw = body({ messages: [
    { role: "user", content: [image(), document({ type: "base64", media_type: "application/pdf", data: Buffer.from("%PDF-1.7 a fake pdf").toString("base64") }),
      { type: "tool_result", tool_use_id: "toolu_1", content: [image(JPEG, "image/jpeg"), document({ type: "base64", media_type: "application/pdf", data: Buffer.from("%PDF-1.7 nested fake").toString("base64") })] }] },
    { role: "assistant", content: [image(WEBP, "image/webp")] },
  ] });
  const covered = new Set(extractMedia(raw).images.concat(extractMedia(raw).documents).map(({ path }) => path));
  const expected = opaqueValues(raw)
    .filter(([path]) => path.endsWith(".source.data"))
    .map(([path]) => {
      const [message, block, ...rest] = path.replace(/\.source\.data$/, "").split(".");
      return `messages[${message}].content[${block}]${rest.length ? `.content[${rest[1]}]` : ""}`;
    });
  assert.equal(expected.length, 5);
  for (const path of expected) assert.ok(covered.has(path), `${path} not covered`);
});

test("patchMedia splices replacements at recorded offsets and leaves every other byte alone", () => {
  const raw = userTurn({ type: "text", text: "før" }, image(JPEG, "image/jpeg"), { type: "text", text: "after" }, image(GIF, "image/gif"));
  const { images } = extractMedia(raw);
  const replacements = images.map((found) => ({ rawOffset: found.rawOffset, rawLength: found.rawLength, text: PNG.toString("base64") }));
  const patched = patchMedia(raw, replacements);
  const parsed = JSON.parse(patched.toString("utf8"));
  const original = JSON.parse(raw.toString("utf8"));
  assert.equal(parsed.messages[0].content[1].source.data, PNG.toString("base64"));
  assert.equal(parsed.messages[0].content[3].source.data, PNG.toString("base64"));
  original.messages[0].content[1].source.data = PNG.toString("base64");
  original.messages[0].content[3].source.data = PNG.toString("base64");
  assert.deepEqual(parsed, original);
  const head = images[0].rawOffset;
  assert.deepEqual(patched.subarray(0, head), raw.subarray(0, head));
  assert.throws(() => patchMedia(raw, [{ rawOffset: head, rawLength: 4, text: 'a"b' }]), TypeError);
  assert.throws(() => patchMedia(raw, [replacements[0], replacements[0]]), RangeError);
  assert.throws(() => patchMedia(raw, [{ rawOffset: raw.length - 2, rawLength: 8, text: "AAAA" }]), RangeError);
});

test("images record their media_type offsets and whether they sit in the last user turn", () => {
  const raw = body({ messages: [
    { role: "user", content: [image(JPEG, "image/jpeg")] },
    { role: "assistant", content: [{ type: "text", text: "ok" }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "t", content: [image(GIF, "image/gif")] }, image()] },
  ] });
  const { images } = extractMedia(raw);
  assert.deepEqual(images.map((found) => found.lastTurn), [false, true, true]);
  for (const found of images) {
    assert.equal(raw.subarray(found.mediaTypeOffset, found.mediaTypeOffset + found.mediaTypeLength).toString(), found.mime);
  }
});

test("patchImages swaps bytes and media_type, then re-extracts to prove the splice", () => {
  const raw = userTurn({ type: "text", text: "før" }, image(JPEG, "image/jpeg"), image(GIF, "image/gif"));
  const { images } = extractMedia(raw);
  const masked = [Buffer.concat([PNG, Buffer.from([1])]), Buffer.concat([PNG, Buffer.from([2])])];
  const patched = patchImages(raw, images.map((found, index) => ({ image: found, bytes: masked[index] })));
  const parsed = JSON.parse(patched.toString("utf8"));
  const original = JSON.parse(raw.toString("utf8"));
  original.messages[0].content[1].source = { type: "base64", media_type: "image/png", data: masked[0].toString("base64") };
  original.messages[0].content[2].source = { type: "base64", media_type: "image/png", data: masked[1].toString("base64") };
  assert.deepEqual(parsed, original);
  assert.throws(() => patchImages(raw, [{ image: images[0], bytes: JPEG }]), /PNG/);
});
