import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { EventEmitter, once } from "node:events";
import { existsSync } from "node:fs";
import { copyFile, mkdtemp, mkdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { test } from "node:test";
import { pathToFileURL } from "node:url";

import { prepareOpfScan, adaptOpfPrediction, UNKNOWN_REASONS } from "../detectors/opf/opf-adapter.mjs";
import { buildOpfWorkerArgs } from "../src/shield/opf-args.mjs";
import { createPrivacyFilter, isVerifiedRedaction } from "../src/shield/privacy.mjs";

const sourceOf = (name) => resolve(import.meta.dirname, name.endsWith(".py") ? "../detectors/opf/python" : "../detectors/opf", name);

function prediction(text, label, value) {
  const start = Array.from(text.slice(0, text.indexOf(value))).length;
  return {
    schema_version: 1,
    summary: { output_mode: "typed", span_count: 1, by_label: { [label]: 1 }, decoded_mismatch: false },
    text,
    detected_spans: [{ label, start, end: start + Array.from(value).length, text: value, placeholder: "<PRIVATE>" }],
    redacted_text: text.replace(value, "<PRIVATE>"),
  };
}

function multiplePredictions(text, matches) {
  const spans = matches.flatMap(([label, value]) => prediction(text, label, value).detected_spans);
  const byLabel = {};
  for (const { label } of spans) byLabel[label] = (byLabel[label] ?? 0) + 1;
  return { ...prediction(text, ...matches[0]), detected_spans: spans,
    summary: { output_mode: "typed", span_count: spans.length, by_label: byLabel, decoded_mismatch: false } };
}

function verifiedResult(original, result) {
  assert.equal(result.status, "ok");
  const redactedBody = Buffer.from(result.redactedBody, "base64");
  assert.equal(isVerifiedRedaction({ original, result: { ...result, redactedBody } }), true);
  return JSON.parse(redactedBody);
}

function toolMessages(ids) {
  return [
    { role: "assistant", content: ids.map((id) => ({ type: "tool_use", id, name: "inspect", input: {} })) },
    { role: "user", content: ids.map((id) => ({ type: "tool_result", tool_use_id: id, content: "safe" })) },
  ];
}

const OPAQUE = "EqQBCkYIBxgCKkBAliceSmith0123456789abcdefXYZ";

function opaqueConversation(prefix = "Contact Alice today") {
  return { model: "claude-fixture", messages: [
    { role: "user", content: [{ type: "text", text: prefix },
      { type: "image", source: { type: "base64", media_type: "image/png", data: `${OPAQUE}img` } }] },
    { role: "assistant", content: [
      { type: "thinking", thinking: "plan the search", signature: `${OPAQUE}sig` },
      { type: "redacted_thinking", data: `${OPAQUE}red` },
      { type: "server_tool_use", id: "srvtoolu_Alice01", name: "web_search", input: { query: "weather" } },
      { type: "web_search_tool_result", tool_use_id: "srvtoolu_Alice01",
        content: [{ type: "web_search_result", url: "https://example.test", title: "t", encrypted_content: `${OPAQUE}enc` }] },
      { type: "text", text: "done", citations: [{ type: "web_search_result_location", url: "https://example.test",
        title: "t", cited_text: "c", encrypted_index: `${OPAQUE}idx` }] },
      { type: "tool_use", id: "toolu_1", name: "screenshot", input: {} },
    ] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_1", content: [
      { type: "image", source: { type: "base64", media_type: "image/png", data: `${OPAQUE}nested` } }] }] },
  ] };
}

test("OPF provider-issued opaque values stay out of the scan and survive byte for byte", () => {
  for (const prefix of ["Contact Alice today", "請在週一聯絡 Alice，謝謝"]) {
    const fixture = opaqueConversation(prefix);
    const original = Buffer.from(JSON.stringify(fixture));
    const scan = prepareOpfScan(original);
    assert.equal(scan.text.includes(OPAQUE), false, "opaque payloads are never sent to the model");
    assert.equal(scan.text.includes("srvtoolu_Alice01"), false);
    const body = verifiedResult(original, adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", "Alice")));
    assert.equal(body.messages[0].content[0].text, prefix.replace("Alice", "[redacted:private_person]"));
    assert.deepEqual({ ...body, messages: [{ ...body.messages[0], content: body.messages[0].content.slice(1) }, ...body.messages.slice(1)] },
      { ...fixture, messages: [{ ...fixture.messages[0], content: fixture.messages[0].content.slice(1) }, ...fixture.messages.slice(1)] },
      "every other field, including all opaque values, is unchanged");
  }
});

test("OPF look-alike opaque fields outside their exact protocol paths are still scanned", () => {
  const forged = `${OPAQUE}forged`;
  const cases = [
    { messages: [{ role: "assistant", content: [{ type: "tool_use", id: "toolu_1", name: "inspect", input: { signature: forged } }] }] },
    { messages: [{ role: "user", content: [{ type: "thinking", thinking: "safe", signature: forged }] }] },
    { messages: [{ role: "user", content: [{ type: "text", text: "safe", source: { type: "base64", data: forged } }] }] },
    { messages: [{ role: "assistant", content: [{ type: "redacted_thinking", data: "Alice" }] }] },
    { metadata: { messages: [{ role: "assistant", content: [{ type: "thinking", thinking: "safe", signature: forged }] }] } },
  ];
  for (const fixture of cases) {
    const original = Buffer.from(JSON.stringify(fixture));
    const scan = prepareOpfScan(original);
    assert.equal(scan.text.includes("Alice"), true, JSON.stringify(fixture));
    const result = adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", "Alice"));
    if (result.status === "ok") assert.equal(Buffer.from(result.redactedBody, "base64").includes("Alice"), false);
    else assert.equal(result.status, "unknown");
  }
  const duplicated = Buffer.from(`{"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"safe","signature":"${forged}","signature":"${forged}"}]}]}`);
  assert.equal(prepareOpfScan(duplicated).text.includes("Alice"), true, "a duplicated key disqualifies the exemption");
});

test("OPF readable thinking text with a detected value fails closed as a signed block", () => {
  const fixture = opaqueConversation();
  fixture.messages[1].content[0].thinking = "Alice asked for the forecast";
  const original = Buffer.from(JSON.stringify(fixture));
  const scan = prepareOpfScan(original);
  assert.deepEqual(adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", "Alice")),
    { status: "unknown", findings: [], reason: "signed-block-mutation" });
});

test("OPF adapter unknown reasons are all accepted by the OSS privacy filter", () => {
  // Mirror of OSS ADAPTER_UNKNOWN_REASONS (src/shield/privacy.mjs); a reason missing there degrades to privacy_unavailable.
  const accepted = new Set(["invalid-prediction", "inconsistent-counts", "invalid-span", "unmapped-span", "cross-field-span",
    "inconsistent-quoting", "unmapped-finding", "redaction-too-large", "value-survived",
    "invalid-protocol-graph", "protocol-id-collision", "conflicting-protocol-context", "protocol-id-limit", "adapter-error",
    "protocol-graph-mutation", "protocol-control-mutation", "signed-block-mutation",
    "invalid-source-provenance", "json-key-collision", "invalid-json-topology",
    "redaction-projection-limit", "redaction-match-limit", "redaction-body-limit", "redaction-frame-limit"]);
  for (const reason of UNKNOWN_REASONS.values()) assert.ok(accepted.has(reason), reason);
});

test("OPF account findings preserve legal paired Messages IDs and accepted privacy evidence", () => {
  const original = Buffer.from(JSON.stringify({ messages: toolMessages(["toolu_9182736450"]) }));
  const scan = prepareOpfScan(original);
  assert.equal(scan.text.split("toolu_9182736450").length - 1, 2, "both native IDs remain scanned");
  const result = adaptOpfPrediction(original, scan, prediction(scan.text, "account_number", "toolu_9182736450"));
  assert.equal(result.status, "ok");
  const body = JSON.parse(Buffer.from(result.redactedBody, "base64"));
  assert.match(body.messages[0].content[0].id, /^[a-zA-Z0-9_-]+$/);
  assert.match(body.messages[0].content[0].id, /^[a-zA-Z_]+$/);
  assert.equal(body.messages[0].content[0].id, body.messages[1].content[0].tool_use_id);
  assert.equal(Buffer.from(result.redactedBody, "base64").includes(Buffer.from("toolu_9182736450")), false);
  assert.deepEqual(result.findings, [{ label: "account_number", count: 2 }]);
  verifiedResult(original, result);
});

test("OPF distinct full IDs do not collapse under one finding label", () => {
  const original = Buffer.from(JSON.stringify({ messages: toolMessages(["toolu_9182736450", "toolu_5647382910"]) }));
  const scan = prepareOpfScan(original);
  const result = adaptOpfPrediction(original, scan, multiplePredictions(scan.text,
    [["account_number", "toolu_9182736450"], ["account_number", "toolu_5647382910"]]));
  const body = verifiedResult(original, result);
  const calls = body.messages[0].content.map(({ id }) => id);
  const references = body.messages[1].content.map(({ tool_use_id }) => tool_use_id);
  assert.notEqual(calls[0], calls[1]);
  assert.deepEqual(references, calls);
  for (const id of calls) assert.match(id, /^[a-zA-Z_]+$/);
  assert.deepEqual(result.findings, [{ label: "account_number", count: 4 }]);
});

test("OPF partial ID findings keep uncovered bytes and redact ordinary repeated data normally", () => {
  const messages = toolMessages(["toolu_9182736450_tail"]);
  messages[0].content[0].input.id = "9182736450";
  messages[1].content[0].content = "9182736450";
  const original = Buffer.from(JSON.stringify({ messages, metadata: { id: "9182736450" },
    text: '{"type":"tool_use","id":"9182736450"}' }));
  const scan = prepareOpfScan(original);
  assert.equal(scan.text.split("9182736450").length - 1, 6);
  const result = adaptOpfPrediction(original, scan, prediction(scan.text, "account_number", "9182736450"));
  const body = verifiedResult(original, result);
  assert.match(body.messages[0].content[0].id, /^toolu_[a-zA-Z_]+_tail$/);
  assert.equal(body.messages[0].content[0].id, body.messages[1].content[0].tool_use_id);
  assert.equal(body.messages[0].content[0].input.id, "[redacted:account_number]");
  assert.equal(body.messages[1].content[0].content, "[redacted:account_number]");
  assert.equal(body.metadata.id, "[redacted:account_number]");
  assert.equal(body.text, '{"type":"tool_use","id":"[redacted:account_number]"}');
  assert.equal(Buffer.from(result.redactedBody, "base64").includes(Buffer.from("9182736450")), false);
  for (const { start, end } of result.redactions[0].spans) assert.equal(original.subarray(start, end).toString(), "9182736450");
});

test("OPF ID overlap unions and duplicate findings preserve every original label and escaped byte span", () => {
  const original = Buffer.from('{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"toolu_\\u0039\\u0031\\u0038\\u0032_tail","name":"inspect","input":{"text":"\\u9673 😀"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_9182_tail","content":"safe"}]}]}');
  const scan = prepareOpfScan(original);
  const matches = [["account_number", "918"], ["secret", "182"], ["account_number", "918"]];
  const result = adaptOpfPrediction(original, scan, multiplePredictions(scan.text, matches));
  const reversed = adaptOpfPrediction(original, scan, multiplePredictions(scan.text, [...matches].reverse()));
  const body = verifiedResult(original, result);
  assert.equal(result.redactedBody, reversed.redactedBody);
  assert.match(body.messages[0].content[0].id, /^toolu_[a-zA-Z_]+_tail$/);
  assert.equal(body.messages[0].content[0].id, body.messages[1].content[0].tool_use_id);
  assert.equal(body.messages[0].content[0].input.text, "陳 😀");
  assert.deepEqual(result.findings, [{ label: "account_number", count: 2 }, { label: "secret", count: 2 }]);
  assert.deepEqual(result.redactions.map(({ spans }) => spans.map(({ start, end }) => original.subarray(start, end).toString())),
    [["\\u0039\\u0031\\u0038", "918"], ["\\u0031\\u0038\\u0032", "182"]]);
});

test("OPF adjacent ID spans preserve equality without extending redaction coverage", () => {
  const original = Buffer.from(JSON.stringify({ messages: toolMessages(["toolu_918273_tail"]) }));
  const scan = prepareOpfScan(original);
  const result = adaptOpfPrediction(original, scan, multiplePredictions(scan.text,
    [["account_number", "918"], ["secret", "273"]]));
  const body = verifiedResult(original, result);
  assert.match(body.messages[0].content[0].id, /^toolu_[a-zA-Z_]+_tail$/);
  assert.equal(body.messages[0].content[0].id, body.messages[1].content[0].tool_use_id);
  assert.equal(result.redactions.reduce((count, { spans }) => count + spans.length, 0), 4);
});

test("OPF aliases reserve unchanged protocol IDs", () => {
  const original = Buffer.from(JSON.stringify({ messages: toolMessages(["toolu_9182736450", "airkit_id_a"]) }));
  const scan = prepareOpfScan(original);
  const result = adaptOpfPrediction(original, scan, prediction(scan.text, "account_number", "toolu_9182736450"));
  const body = verifiedResult(original, result);
  const [changed, unchanged] = body.messages[0].content;
  assert.equal(unchanged.id, "airkit_id_a");
  assert.match(changed.id, /^[a-zA-Z_]+$/);
  assert.notEqual(changed.id, unchanged.id);
  assert.equal(body.messages[1].content[0].tool_use_id, changed.id);
  assert.equal(body.messages[1].content[1].tool_use_id, unchanged.id);
});

test("OPF assembled partial alias collisions fail closed instead of changing uncovered IDs", () => {
  const original = Buffer.from(JSON.stringify({ messages: toolMessages(["toolu_9182_tail", "toolu_airkit_id_a_tail"]) }));
  const scan = prepareOpfScan(original);
  assert.deepEqual(adaptOpfPrediction(original, scan, prediction(scan.text, "account_number", "9182")),
    { status: "unknown", findings: [], reason: "protocol-id-collision" });
});

test("OPF malformed tool ID graphs and unsafe roles fail closed with bounded reasons", () => {
  const cases = [
    [{ messages: toolMessages([9182736450]) }, "9182736450", "id"],
    [{ messages: toolMessages(["bad:id"]) }, "bad:id", "id"],
    [{ messages: [{ role: "assistant", content: [{ type: "tool_use", name: "inspect", input: { text: "9182" } }] }] }, "9182", "id"],
    [{ messages: [...toolMessages(["toolu_9182"]), { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_other", content: "9182" }] }] }, "9182", "orphan"],
    [{ messages: [{ role: "user", content: [{ type: "tool_use", id: "toolu_9182", name: "inspect", input: {} }] }] }, "9182", "role"],
    [{ messages: [{ role: "assistant", content: [{ type: "tool_result", tool_use_id: "toolu_9182", content: "safe" }] }] }, "9182", "role"],
    [{ messages: toolMessages(["toolu_9182", "toolu_9182"]) }, "9182", "duplicate"],
    [{ messages: [{ role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_9182", content: "safe" }] }, ...toolMessages(["toolu_9182"])] }, "9182", "orphan"],
  ];
  for (const [fixture, value, detail] of cases) {
    const original = Buffer.from(JSON.stringify(fixture));
    const scan = prepareOpfScan(original);
    const result = adaptOpfPrediction(original, scan, prediction(scan.text, "account_number", value));
    // The sub-reason is a bare enum: it carries no request content.
    assert.deepEqual(result, { status: "unknown", findings: [], reason: "invalid-protocol-graph", detail }, JSON.stringify(fixture));
  }
});

test("OPF conflicting protocol span contexts fail closed", () => {
  const original = Buffer.from(JSON.stringify({ messages: toolMessages(["toolu_9182"]) }));
  const scan = prepareOpfScan(original);
  const node = scan.allValues.find(({ value }) => value === "toolu_9182");
  const conflicting = { ...scan, allValues: [...scan.allValues, { ...node, protocolId: undefined }] };
  // Replacement walks the adapter's own parse, so a forged value is rejected before any range is built.
  assert.deepEqual(adaptOpfPrediction(original, conflicting, prediction(scan.text, "account_number", "9182")),
    { status: "unknown", findings: [], reason: "invalid-source-provenance" });
});

test("OPF duplicate structural keys and redacted discriminators cannot evade ID graph validation", () => {
  const originals = [
    Buffer.from('{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"toolu_9182","id":"toolu_other","input":{}}]}]}'),
    Buffer.from('{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"toolu_9182","input":{}}]}],"messages":[]}'),
    // The prose hit comes first; its fragment would also rewrite the tool_use discriminator below it.
    Buffer.from(JSON.stringify({ messages: [{ role: "user", content: [{ type: "text", text: "see tool_use" }] },
      ...toolMessages(["toolu_9182"])] })),
  ];
  for (const [index, original] of originals.entries()) {
    const scan = prepareOpfScan(original);
    // Malformed input graphs keep their own reason; masking a tool_use discriminator mutates a valid graph.
    assert.deepEqual(adaptOpfPrediction(original, scan, prediction(scan.text, "secret", index === 2 ? "tool_use" : "9182")),
      index === 2 ? { status: "unknown", findings: [], reason: "protocol-graph-mutation" }
        : { status: "unknown", findings: [], reason: "invalid-protocol-graph", detail: "duplicate" });
  }  const original = Buffer.from(JSON.stringify({ messages: toolMessages(["toolu_9182"]) }));
  const scan = prepareOpfScan(original);
  // A hit confined to the discriminator itself is dropped rather than applied.
  assert.deepEqual(adaptOpfPrediction(original, scan, prediction(scan.text, "secret", "tool_use")), { status: "ok", findings: [] });
});

test("OPF nested imitation Messages objects receive ordinary redactions", () => {
  const original = Buffer.from(JSON.stringify({ messages: toolMessages(["toolu_9182"]),
    metadata: { messages: toolMessages(["toolu_9182"]) } }));
  const scan = prepareOpfScan(original);
  const body = verifiedResult(original, adaptOpfPrediction(original, scan, prediction(scan.text, "account_number", "toolu_9182")));
  assert.match(body.messages[0].content[0].id, /^[a-zA-Z_]+$/);
  assert.equal(body.metadata.messages[0].content[0].id, "[redacted:account_number]");
  assert.equal(body.metadata.messages[1].content[0].tool_use_id, "[redacted:account_number]");
});

test("OPF alphabetic aliases stay distinct past z and reset for each request", () => {
  const ids = Array.from({ length: 30 }, (_, index) => `toolu_${index}_9182`);
  const original = Buffer.from(JSON.stringify({ messages: toolMessages(ids) }));
  const scan = prepareOpfScan(original);
  const result = adaptOpfPrediction(original, scan, prediction(scan.text, "account_number", "9182"));
  const body = verifiedResult(original, result);
  const calls = body.messages[0].content.map(({ id }) => id);
  assert.equal(new Set(calls).size, 30);
  for (const id of calls) assert.match(id, /^[a-zA-Z0-9_-]+$/);
  assert.equal(calls[26], "toolu_26_airkit_id_aa");
  assert.deepEqual(body.messages[1].content.map(({ tool_use_id }) => tool_use_id), calls);
  const next = Buffer.from(JSON.stringify({ messages: toolMessages(["toolu_9182"]) }));
  const nextScan = prepareOpfScan(next);
  const nextBody = verifiedResult(next, adaptOpfPrediction(next, nextScan, prediction(nextScan.text, "secret", "toolu_9182")));
  assert.equal(nextBody.messages[0].content[0].id, "airkit_id_a");
});

test("OPF request-local ID allocation is bounded and pending calls remain valid", () => {
  for (const [count, status] of [[1024, "ok"], [1025, "unknown"]]) {
    const messages = toolMessages(Array.from({ length: count }, (_, index) => `toolu_${index}_9182`)).slice(0, 1);
    const original = Buffer.from(JSON.stringify({ messages }));
    const scan = prepareOpfScan(original);
    const result = adaptOpfPrediction(original, scan, prediction(scan.text, "account_number", "9182"));
    assert.equal(result.status, status);
    if (status === "unknown") assert.deepEqual(result, { status: "unknown", findings: [], reason: "protocol-id-limit" });
    else assert.equal(new Set(verifiedResult(original, result).messages[0].content.map(({ id }) => id)).size, 1024);
  }
  const messages = toolMessages(Array.from({ length: 4097 }, (_, index) => `toolu_${index}`)).slice(0, 1);
  const original = Buffer.from(JSON.stringify({ messages, text: "9182" }));
  const scan = prepareOpfScan(original);
  // Only the canonical graph count carries the "limit" sub-reason; alias exhaustion above stays bare.
  assert.deepEqual(adaptOpfPrediction(original, scan, prediction(scan.text, "account_number", "9182")),
    { status: "unknown", findings: [], reason: "protocol-id-limit", detail: "limit" });
});

test("OPF escaped alphabetic findings use aliases that cannot recreate decoded fragments", () => {
  const original = Buffer.from('{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"toolu_\\u0061\\u0069\\u0072\\u006b\\u0069\\u0074_tail","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_\\u0061\\u0069\\u0072\\u006b\\u0069\\u0074_tail","content":"safe"}]}]}');
  const scan = prepareOpfScan(original);
  const result = adaptOpfPrediction(original, scan, prediction(scan.text, "secret", "airkit"));
  const body = verifiedResult(original, result);
  assert.equal(body.messages[0].content[0].id, body.messages[1].content[0].tool_use_id);
  assert.match(body.messages[0].content[0].id, /^toolu_[a-zA-Z_]+_tail$/);
  assert.equal(body.messages[0].content[0].id.includes("airkit"), false);
});

test("OPF Unicode offsets become original UTF-8 byte spans through JSON escapes", () => {
  const original = Buffer.from('{"system":"noreply@example.org","messages":[{"role":"user","content":"Name: \\u9673\\u5c0f\\u660e 😀"}]}');
  const scan = prepareOpfScan(original);
  const result = adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", "陳小明"));
  assert.equal(result.status, "ok");
  assert.deepEqual(result.findings, [{ label: "private_person", count: 1 }]);
  const [span] = result.redactions[0].spans;
  assert.equal(original.subarray(span.start, span.end).toString(), "\\u9673\\u5c0f\\u660e");
  const replaced = Buffer.from(result.redactedBody, "base64");
  assert.equal(JSON.parse(replaced).messages[0].content, "Name: [redacted:private_person] 😀");
  assert.equal(JSON.parse(replaced).system, "noreply@example.org");
});

test("OPF secret keeps its label and a duplicate value is replaced everywhere", () => {
  const original = Buffer.from('{"system":"x","messages":[{"content":"token ABC123"}],"metadata":"ABC123"}');
  const scan = prepareOpfScan(original);
  const result = adaptOpfPrediction(original, scan, prediction(scan.text, "secret", "ABC123"));
  assert.equal(result.status, "ok");
  assert.deepEqual(result.findings, [{ label: "secret", count: 2 }]);
  assert.deepEqual(result.redactions, [{ label: "secret", count: 2, spans: [{ start: 44, end: 50 }, { start: 66, end: 72 }] }]);
  assert.equal(Buffer.from(result.redactedBody, "base64").includes(Buffer.from("ABC123")), false);
});

test("client preamble, tools and complete reminder are absent from model input", () => {
  const original = Buffer.from(JSON.stringify({
    system: "noreply@example.org",
    tools: [{ description: "tool@example.org" }],
    messages: [{ content: [
      { type: "text", text: "<system-reminder>account@example.org</system-reminder>" },
      { type: "text", text: "my mail is user@example.org" },
    ] }],
  }));
  const scan = prepareOpfScan(original);
  assert.equal(scan.text.includes("noreply@example.org"), false);
  assert.equal(scan.text.includes("tool@example.org"), false);
  assert.equal(scan.text.includes("account@example.org"), false);
  assert.equal(scan.text.includes("user@example.org"), true);
});

test("personal data in a non-exempt JSON key is scanned and redacted", () => {
  const original = Buffer.from('{"system":"client preamble","messages":[{"content":"safe"}],"metadata":{"alice@example.org":"safe"}}');
  const scan = prepareOpfScan(original);
  assert.equal(scan.text.includes("alice@example.org"), true);
  const result = adaptOpfPrediction(original, scan, prediction(scan.text, "private_email", "alice@example.org"));
  assert.equal(result.status, "ok");
  assert.deepEqual(result.findings, [{ label: "private_email", count: 1 }]);
  assert.deepEqual(JSON.parse(Buffer.from(result.redactedBody, "base64")).metadata, {
    "[redacted:private_email]": "safe",
  });
});

test("OPF mismatches, unsupported labels, and crossing spans fail closed", () => {
  const original = Buffer.from('{"content":"Alice Smith"}');
  const scan = prepareOpfScan(original);
  const good = prediction(scan.text, "private_person", "Alice Smith");
  for (const bad of [
    { ...good, summary: { ...good.summary, decoded_mismatch: true } },
    { ...good, detected_spans: [{ ...good.detected_spans[0], label: "email" }] },
    { ...good, detected_spans: [{ ...good.detected_spans[0], end: 999 }] },
    { ...good, detected_spans: [{ ...good.detected_spans[0], text: "Bob" }] },
    { ...good, detected_spans: [] },
    { ...good, summary: { ...good.summary, by_label: {} } },
  ]) assert.equal(adaptOpfPrediction(original, scan, bad).status, "unknown");
});

test("OPF unknown predictions report static reasons without exposing input or spans", () => {
  const original = Buffer.from('{"content":"Sensitive Alice Smith"}');
  const scan = prepareOpfScan(original);
  const good = prediction(scan.text, "private_person", "Sensitive Alice Smith");
  const cases = [
    ["invalid-prediction", { ...good, text: "private upstream response" }, scan],
    ["inconsistent-counts", { ...good, summary: { ...good.summary, by_label: {} } }, scan],
    ["invalid-span", { ...good, detected_spans: [{ ...good.detected_spans[0], text: "private span" }] }, scan],
    ["unmapped-span", good, { ...scan, map: scan.map.map((entry, index) => index === good.detected_spans[0].start ? null : entry) }],
    ["cross-field-span", good, { ...scan, map: scan.map.map((entry, index) => index === good.detected_spans[0].start + 1 ? { start: entry.start + 1, end: entry.end + 1 } : entry) }],
    ["invalid-source-provenance", good, { ...scan, allValues: [] }],
  ];
  for (const [reason, result, prepared] of cases) {
    const adapted = adaptOpfPrediction(original, prepared, result);
    assert.deepEqual(adapted, { status: "unknown", findings: [], reason });
    assert.doesNotMatch(JSON.stringify(adapted), /Sensitive|Alice|Smith|private upstream response|private span/);
  }
  const survived = Buffer.from('{"content":"a","flag":false}');
  const prepared = prepareOpfScan(survived);
  assert.deepEqual(adaptOpfPrediction(survived, prepared, prediction(prepared.text, "private_person", "a")),
    { status: "unknown", findings: [], reason: "value-survived" });
  const maximumBody = Buffer.concat([original, Buffer.alloc(1_048_576 - original.length, " ")]);
  assert.deepEqual(adaptOpfPrediction(maximumBody, scan, good),
    { status: "unknown", findings: [], reason: "redaction-body-limit" });
  assert.equal(Object.hasOwn(adaptOpfPrediction(original, scan, good), "reason"), false,
    "successful predictions must retain their existing result shape");
});

test("OPF duplicate-text propagation unions nested byte overlaps and retains each label's original ranges", () => {
  const original = Buffer.from('{"content":"Alice","metadata":"Alice@example.org"}');
  const scan = prepareOpfScan(original);
  const result = adaptOpfPrediction(original, scan, multiplePredictions(scan.text,
    [["private_person", "Alice"], ["private_email", "Alice@example.org"]]));
  assert.deepEqual(verifiedResult(original, result), { content: "[redacted:private_person]", metadata: "[redacted:private_email]" });
  assert.deepEqual(result.findings, [{ label: "private_person", count: 2 }, { label: "private_email", count: 1 }]);
  assert.deepEqual(result.redactions.map(({ label, spans }) => [label, spans.map(({ start, end }) => original.subarray(start, end).toString())]),
    [["private_person", ["Alice", "Alice"]], ["private_email", ["Alice@example.org"]]]);
});

test("OPF connected partial overlaps form one replacement but adjacent intervals stay separate", () => {
  const original = Buffer.from('{"content":"ABCDEFGH abcXYZ"}');
  const scan = prepareOpfScan(original);
  const result = adaptOpfPrediction(original, scan, multiplePredictions(scan.text,
    [["private_person", "ABCD"], ["private_address", "CDEF"], ["private_url", "EFGH"],
      ["private_person", "abc"], ["private_email", "XYZ"]]));
  assert.deepEqual(verifiedResult(original, result), { content: "[redacted:private_address] [redacted:private_person][redacted:private_email]" });
  assert.deepEqual(result.findings, [{ label: "private_person", count: 2 }, { label: "private_address", count: 1 },
    { label: "private_url", count: 1 }, { label: "private_email", count: 1 }]);
});

test("OPF exact-range multiple labels retain secret facts and use a deterministic secret placeholder", () => {
  const original = Buffer.from('{"content":"Alice@example.org","duplicate":"Alice@example.org"}');
  const scan = prepareOpfScan(original);
  const matches = [["private_email", "Alice@example.org"], ["secret", "Alice"], ["private_person", "Alice@example.org"]];
  const result = adaptOpfPrediction(original, scan, multiplePredictions(scan.text, matches));
  const reversed = adaptOpfPrediction(original, scan, multiplePredictions(scan.text, [...matches].reverse()));
  assert.deepEqual(verifiedResult(original, result), { content: "[redacted:secret]", duplicate: "[redacted:secret]" });
  assert.equal(result.redactedBody, reversed.redactedBody);
  assert.deepEqual(result.findings.map(({ label, count }) => [label, count]).sort(),
    [["private_email", 2], ["private_person", 2], ["secret", 2]]);
  const piiFindings = result.findings.map(({ label, count }) => ({ category: label, count }));
  const decision = spawnSync("opa", ["eval", "--format=json", "--data",
    resolve(import.meta.dirname, "../policy/baseline.rego"), "--stdin-input", "data.ccshield.shield.decision"], {
    encoding: "utf8", input: JSON.stringify({ destinationClass: "subscription", lane: "subscription", interactive: false,
      repositoryClass: "unknown", pathClasses: ["unknown"], secretFindings: [], piiFindings }),
  });
  assert.equal(decision.status, 0, decision.stderr);
  assert.deepEqual(JSON.parse(decision.stdout).result[0].expressions[0].value,
    { action: "redact", reasonCodes: ["subscription-pii"], approvalEligible: false, redactions: [] });
});

test("OPF unions preserve escaped Unicode JSON and numeric replacement quoting", () => {
  const original = Buffer.from('{"content":"\\u9673\\u5c0f\\u660e 😀","account":1234567890}');
  const scan = prepareOpfScan(original);
  const result = adaptOpfPrediction(original, scan, multiplePredictions(scan.text,
    [["private_person", "陳小明"], ["private_address", "小明"], ["account_number", "1234567890"], ["secret", "3456"]]));
  assert.deepEqual(verifiedResult(original, result), { content: "[redacted:private_address] 😀", account: "[redacted:secret]" });
});

test("OPF overlapping ranges with inconsistent JSON quoting fail closed", () => {
  const original = Buffer.from('{"content":"Alice"}');
  const scan = prepareOpfScan(original);
  const node = scan.allValues.find(({ value }) => value === "Alice");
  const inconsistent = { ...scan, allValues: [...scan.allValues, { ...node, type: "literal" }] };
  assert.deepEqual(adaptOpfPrediction(original, inconsistent, multiplePredictions(scan.text,
    [["private_person", "Alice"], ["secret", "Alice"]])),
    { status: "unknown", findings: [], reason: "invalid-source-provenance" });
});

test("OPF partial numeric replacements remain fail closed", () => {
  const numeric = Buffer.from('{"account":1234567890}');
  const numericScan = prepareOpfScan(numeric);
  assert.deepEqual(adaptOpfPrediction(numeric, numericScan, prediction(numericScan.text, "account_number", "12345")),
    { status: "unknown", findings: [], reason: "adapter-error" });
});

test("OPF markers avoid every detected fragment including labels and short punctuation", async () => {
  for (const [label, value] of [["secret", "secret"], ["private_person", "private"],
    ["private_person", "private_person"], ["private_person", "redact"], ["private_person", "a"],
    ["private_person", ":"], ["private_person", '"']]) {
    const original = Buffer.from(JSON.stringify([value]));
    const scan = prepareOpfScan(original);
    const result = adaptOpfPrediction(original, scan, prediction(scan.text, label, value));
    const body = verifiedResult(original, result);
    assert.equal(body[0].includes(value), false, value);
    assert.deepEqual(result.findings, [{ label, count: 1 }]);
    await normalizedResult(original, result);
  }
});

test("OPF escaped ordinary fragments cannot survive decoded in generated markers", () => {
  for (const original of [Buffer.from('{"content":"\\u0070rivate_person"}'),
    Buffer.from('{"content":"\\u0072edact"}')]) {
    const scan = prepareOpfScan(original);
    const value = scan.allValues.find(({ value }) => value !== "content").value;
    const body = verifiedResult(original, adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", value)));
    assert.equal(body.content.includes(value), false);
  }
});

test("OPF decoded fragments reconstructed at replacement edges remain fail closed", () => {
  const original = Buffer.from('["aX","\\u0061["]');
  const scan = prepareOpfScan(original);
  assert.deepEqual(adaptOpfPrediction(original, scan, multiplePredictions(scan.text,
    [["private_person", "X"], ["secret", "a["]])),
    { status: "unknown", findings: [], reason: "value-survived" });
});

test("OPF partial alias edges cannot reconstruct another escaped detected fragment", () => {
  const messages = toolMessages(["xAIR"]);
  messages[0].content[0].input = ["airkit", "xa"];
  const original = Buffer.from(JSON.stringify({ messages }).replace('"xa"', '"\\u0078a"'));
  const scan = prepareOpfScan(original);
  assert.deepEqual(adaptOpfPrediction(original, scan, multiplePredictions(scan.text,
    [["secret", "AIR"], ["secret", "airkit"], ["secret", "xa"]])),
    { status: "unknown", findings: [], reason: "value-survived" });
});

test("OPF collision-safe aliases preserve uniqueness at the existing allocation limit", () => {
  for (const [count, status] of [[1024, "ok"], [1025, "unknown"]]) {
    const original = Buffer.from(JSON.stringify({ messages: toolMessages(Array.from({ length: count }, (_, index) => `airkit_${index}`)).slice(0, 1) }));
    const scan = prepareOpfScan(original);
    const result = adaptOpfPrediction(original, scan, prediction(scan.text, "secret", "airkit"));
    assert.equal(result.status, status);
    if (status === "unknown") assert.equal(result.reason, "protocol-id-limit");
    else {
      const ids = verifiedResult(original, result).messages[0].content.map(({ id }) => id);
      assert.equal(new Set(ids).size, 1024);
      for (const id of ids) {
        assert.match(id, /^[a-zA-Z0-9_-]+$/);
        assert.equal(id.includes("airkit"), false);
      }
    }
  }
});

test("OPF collision-safe markers remain deterministic across finding order and overlaps", () => {
  const original = Buffer.from('["private_person","redact","█"]');
  const scan = prepareOpfScan(original);
  const matches = [["private_person", "private_person"], ["secret", "private"],
    ["private_person", "redact"], ["secret", "█"]];
  const result = adaptOpfPrediction(original, scan, multiplePredictions(scan.text, matches));
  const reversed = adaptOpfPrediction(original, scan, multiplePredictions(scan.text, [...matches].reverse()));
  verifiedResult(original, result);
  assert.equal(result.redactedBody, reversed.redactedBody);
  assert.deepEqual(result.findings.map(({ label, count }) => [label, count]).sort(),
    [["private_person", 2], ["secret", 2]]);
});

test("OPF marker candidate exhaustion is bounded and fails closed", () => {
  const original = Buffer.from(JSON.stringify(["redact", "█", ...Array.from({ length: 256 }, (_, index) => String.fromCharCode(0xe000 + index))]));
  const scan = prepareOpfScan(original);
  assert.deepEqual(adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", scan.text)),
    { status: "unknown", findings: [], reason: "value-survived" });
});

test("OPF collision-safe proof still rejects restored content and tampered counts", () => {
  const original = Buffer.from('["private_person"]');
  const scan = prepareOpfScan(original);
  const result = adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", "private_person"));
  verifiedResult(original, result);
  assert.equal(isVerifiedRedaction({ original, result: { ...result, redactedBody: original } }), false);
  assert.equal(isVerifiedRedaction({ original, result: { ...result, redactedBody: Buffer.from(result.redactedBody, "base64"),
    redactions: result.redactions.map((redaction) => ({ ...redaction, spans: [] })) } }), false);
});

test("OPF arbitrary JSON parser and runtime errors use a generic nonsecret reason", () => {
  const original = Buffer.from('{"content":"Sensitive Alice Smith", "private_json_fragment"}');
  const prepared = prepareOpfScan(Buffer.from('{"content":"Sensitive Alice Smith"}'));
  const result = adaptOpfPrediction(original, prepared, prediction(prepared.text, "private_person", "Sensitive Alice Smith"));
  assert.deepEqual(result, { status: "unknown", findings: [], reason: "adapter-error" });
  const broken = { get schema_version() { throw new Error("private runtime error Sensitive Alice Smith"); } };
  assert.deepEqual(adaptOpfPrediction(original, prepared, broken), result);
  const syntax = { get schema_version() { throw new SyntaxError("invalid prediction"); } };
  assert.deepEqual(adaptOpfPrediction(original, prepared, syntax), result,
    "JSON parser errors must remain generic even if their message matches an allowed static error");
  assert.doesNotMatch(JSON.stringify(result), /Sensitive|Alice|Smith|private_json_fragment|private runtime error/);
});

test("a numeric account finding cannot silently become allow", () => {
  const original = Buffer.from('{"account":1234567890}');
  const scan = prepareOpfScan(original);
  const result = adaptOpfPrediction(original, scan, prediction(scan.text, "account_number", "1234567890"));
  assert.equal(result.status, "ok");
  assert.deepEqual(result.findings, [{ label: "account_number", count: 1 }]);
  assert.equal(JSON.parse(Buffer.from(result.redactedBody, "base64")).account, "[redacted:account_number]");
});

test("repeated model findings redact each occurrence once", () => {
  const original = Buffer.from('{"content":"person@example.org and person@example.org"}');
  const scan = prepareOpfScan(original);
  const first = prediction(scan.text, "private_email", "person@example.org");
  const second = { ...first.detected_spans[0], start: first.detected_spans[0].start + 23, end: first.detected_spans[0].end + 23 };
  const result = adaptOpfPrediction(original, scan, {
    ...first,
    summary: { ...first.summary, span_count: 2, by_label: { private_email: 2 } },
    detected_spans: [first.detected_spans[0], second],
  });
  assert.equal(result.status, "ok");
  assert.deepEqual(result.findings, [{ label: "private_email", count: 2 }]);
  assert.equal(JSON.parse(Buffer.from(result.redactedBody, "base64")).content,
    "[redacted:private_email] and [redacted:private_email]");
});

test("OPF synthetic joins project each array scalar without covering JSON syntax", () => {
  const original = Buffer.from('["Alice","Smith"]');
  const scan = prepareOpfScan(original);
  assert.equal(scan.text, "Alice\nSmith");
  const result = adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", "Alice\nSmith"));
  assert.deepEqual(verifiedResult(original, result), ["[redacted:private_person]", "[redacted:private_person]"]);
  assert.deepEqual(result.redactions[0].spans.map(({ start, end }) => original.subarray(start, end).toString()), ["Alice", "Smith"]);
});

test("OPF synthetic key/value joins preserve properties and propagate every fragment", () => {
  const original = Buffer.from('{"Alice":"Smith","copy":["Alice","Smith"],"safe":{"nested":[]}}');
  const scan = prepareOpfScan(original);
  const result = adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", "Alice\nSmith"));
  assert.deepEqual(verifiedResult(original, result), { "[redacted:private_person]": "[redacted:private_person]",
    copy: ["[redacted:private_person]", "[redacted:private_person]"], safe: { nested: [] } });
  assert.deepEqual(result.findings, [{ label: "private_person", count: 4 }]);
});

test("OPF field newlines and escaped codepoints remain detected source characters", () => {
  const original = Buffer.from('["\\u9673\\n😀","\\u5c0f\\u660e",918273]');
  const scan = prepareOpfScan(original);
  const result = adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", "陳\n😀\n小明\n918273"));
  assert.deepEqual(verifiedResult(original, result), Array(3).fill("[redacted:private_person]"));
  assert.deepEqual(result.redactions[0].spans.map(({ start, end }) => original.subarray(start, end).toString()),
    ["\\u9673\\n😀", "\\u5c0f\\u660e", "918273"]);
  const actual = Buffer.from('["Alice\\nSmith"]');
  const actualScan = prepareOpfScan(actual);
  const actualResult = adaptOpfPrediction(actual, actualScan, prediction(actualScan.text, "private_person", "Alice\nSmith"));
  assert.deepEqual(verifiedResult(actual, actualResult), ["[redacted:private_person]"]);
  assert.equal(actualResult.redactions[0].spans.length, 1);
});

test("OPF empty scalars and separator edges never discard a detected fragment", () => {
  const original = Buffer.from('["","Alice","","Smith",""]');
  const scan = prepareOpfScan(original);
  assert.equal(scan.text, "\nAlice\n\nSmith\n");
  const result = adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", scan.text));
  assert.deepEqual(verifiedResult(original, result), ["", "[redacted:private_person]", "", "[redacted:private_person]", ""]);
  assert.deepEqual(adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", "\n")),
    { status: "unknown", findings: [], reason: "unmapped-span" });
});

test("OPF cross-field overlaps retain labels and stable paired partial tool aliases", () => {
  const messages = toolMessages(["toolu_9182_tail"]);
  messages[0].content[0].input = ["Alice", "Smith", "9182"];
  const original = Buffer.from(JSON.stringify({ messages }));
  const scan = prepareOpfScan(original);
  const result = adaptOpfPrediction(original, scan, multiplePredictions(scan.text,
    [["private_person", "Alice\nSmith\n9182"], ["secret", "Smith\n9182"]]));
  const body = verifiedResult(original, result);
  assert.deepEqual(body.messages[0].content[0].input,
    ["[redacted:private_person]", "[redacted:secret]", "[redacted:secret]"]);
  assert.equal(body.messages[0].content[0].id, body.messages[1].content[0].tool_use_id);
  assert.match(body.messages[0].content[0].id, /^toolu_[a-zA-Z_]+_tail$/);
  assert.deepEqual(result.findings, [{ label: "private_person", count: 5 }, { label: "secret", count: 4 }]);
});

test("OPF redacted sibling keys get distinct markers per distinct value", () => {
  for (const [fixture, pick] of [
    [{ "alice@example.org": 1, "bob@example.org": 2, "alice@example.org ": 3 }, (body) => body],
    [{ metadata: { "alice@example.org": [], "bob@example.org": {} } }, (body) => body.metadata],
  ]) {
    const original = Buffer.from(JSON.stringify(fixture));
    const scan = prepareOpfScan(original);
    const result = adaptOpfPrediction(original, scan,
      multiplePredictions(scan.text, [["private_email", "alice@example.org"], ["private_email", "bob@example.org"]]));
    assert.equal(result.status, "ok");
    const keys = Object.keys(pick(JSON.parse(Buffer.from(result.redactedBody, "base64"))));
    assert.equal(keys.some((key) => key.includes("@example.org")), false);
    assert.ok(keys.includes("[redacted:private_email]"));
    assert.ok(keys.includes("[redacted:private_email#2]"));
  }
});

test("OPF key redaction that collides with an existing sibling key fails closed", () => {
  const original = Buffer.from(JSON.stringify({ "alice@example.org": 1, "[redacted:private_email]": 2 }));
  const scan = prepareOpfScan(original);
  assert.deepEqual(adaptOpfPrediction(original, scan, multiplePredictions(scan.text, [["private_email", "alice@example.org"]])),
    { status: "unknown", findings: [], reason: "json-key-collision" });
});

test("OPF fixed Messages keys stay locked while spans wholly inside selector values are dropped", () => {
  const fixture = { model: "claude-fixture", messages: [{ role: "user", content: [{ type: "text", text: "safe" }] }],
    tool_choice: { type: "tool", name: "inspect" }, tools: [{ name: "inspect", input_schema: { type: "object" } }] };
  // "tool" first occurs inside the tool_choice key, so it is a key mutation rather than a selector value.
  for (const value of ["messages", "model", "role", "content", "type", "tool_choice", "tool"]) {
    const original = Buffer.from(JSON.stringify(fixture));
    const scan = prepareOpfScan(original);
    const result = adaptOpfPrediction(original, scan, prediction(scan.text, "secret", value));
    assert.equal(result.status, "unknown", `unsafe protocol change for ${value}`);
    assert.equal(result.reason, "protocol-control-mutation");
  }
  for (const value of ["claude-fixture", "fixture", "user", "text", "inspect"]) {
    const original = Buffer.from(JSON.stringify(fixture));
    const scan = prepareOpfScan(original);
    assert.deepEqual(adaptOpfPrediction(original, scan, prediction(scan.text, "secret", value)),
      { status: "ok", findings: [] }, value);
  }
  const original = Buffer.from(JSON.stringify({ messages: toolMessages(["toolu_9182"]) }));
  const scan = prepareOpfScan(original);
  assert.deepEqual(adaptOpfPrediction(original, scan, prediction(scan.text, "secret", "inspect")),
    { status: "ok", findings: [] });
});

test("OPF spans wholly inside typed Messages control scalars are dropped", () => {
  for (const [extra, content, selected] of [
    [{ max_tokens: 918273 }, "safe", "918273"],
    [{ thinking: { type: "enabled", budget_tokens: 1024 } }, "safe", "enabled"],
    [{}, [{ type: "text", text: "safe", cache_control: { type: "ephemeral" } }], "ephemeral"],
  ]) {
    const original = Buffer.from(JSON.stringify({ model: "claude-fixture", messages: [{ role: "user", content }], ...extra }));
    const scan = prepareOpfScan(original);
    assert.equal(scan.text.includes(selected), true, "protocol controls remain scanned");
    assert.deepEqual(adaptOpfPrediction(original, scan, prediction(scan.text, "secret", selected)),
      { status: "ok", findings: [] }, selected);
  }
});

test("OPF drops control-value spans but still redacts real findings in the same request", () => {
  const fixture = { model: "claude-sonnet-5", messages: [
    { role: "user", content: [{ type: "text", text: "Alice wrote" }] },
    { role: "assistant", content: [{ type: "tool_use", id: "toolu_1", name: "lookup_tool", input: {} },
      { type: "server_tool_use", id: "srvtoolu_1", name: "web_search", input: {} }] },
  ] };
  const original = Buffer.from(JSON.stringify(fixture));
  const scan = prepareOpfScan(original);
  const result = adaptOpfPrediction(original, scan, multiplePredictions(scan.text, [["private_person", "claude-sonnet-5"],
    ["private_person", "user"], ["secret", "text"], ["private_person", "lookup_tool"], ["private_person", "web_search"],
    ["private_person", "Alice"]]));
  assert.deepEqual(result.findings, [{ label: "private_person", count: 1 }]);
  const body = verifiedResult(original, result);
  assert.deepEqual(body, { ...fixture, messages: [
    { role: "user", content: [{ type: "text", text: "[redacted:private_person] wrote" }] }, fixture.messages[1]] });
});

test("OPF spans crossing a control value boundary, malformed controls and thinking text stay fail-closed", () => {
  const base = { model: "claude-fixture", messages: [{ role: "user", content: "Alice" }] };
  for (const [fixture, selected, reason] of [
    [base, "fixture\nmessages", "protocol-control-mutation"],
    [base, "user\ncontent\nAlice", "protocol-control-mutation"],
    [{ ...base, max_tokens: "4096" }, "4096", "protocol-control-mutation"],
    [{ ...base, messages: [{ role: "assistant", content: [{ type: "thinking", thinking: "Alice planned", signature: "opaque" }] }] },
      "Alice", "signed-block-mutation"],
  ]) {
    const original = Buffer.from(JSON.stringify(fixture));
    const scan = prepareOpfScan(original);
    assert.deepEqual(adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", selected)),
      { status: "unknown", findings: [], reason }, selected);
  }
  // A dropped selector span must not mask the signed-block failure of another span.
  const original = Buffer.from(JSON.stringify({ ...base,
    messages: [{ role: "assistant", content: [{ type: "thinking", thinking: "Alice planned", signature: "opaque" }] }] }));
  const scan = prepareOpfScan(original);
  assert.deepEqual(adaptOpfPrediction(original, scan, multiplePredictions(scan.text,
    [["private_person", "claude-fixture"], ["private_person", "Alice"]])),
  { status: "unknown", findings: [], reason: "signed-block-mutation" });
});

test("OPF known scalar and nested control knobs remain protocol controls in their own contexts", () => {
  const base = { model: "claude-fixture", messages: [{ role: "user", content: "safe" }] };
  const dropped = { status: "ok", findings: [] };
  const locked = (reason = "protocol-control-mutation") => ({ status: "unknown", findings: [], reason });
  const cases = [
    [{ ...base, top_k: 918273 }, "918273", dropped],
    [{ ...base, top_p: 0.918273 }, "0.918273", dropped],
    [{ ...base, temperature: 0.918273 }, "0.918273", dropped],
    [{ ...base, thinking: { type: "enabled", budget_tokens: 918273 } }, "918273", dropped],
    [{ ...base, thinking: { type: "adaptive" } }, "adaptive", dropped],
    [{ ...base, cache_control: { type: "ephemeral", ttl: "1h" } }, "1h", dropped],
    [{ ...base, output_config: { effort: "high", format: { type: "json_schema", schema: { type: "object" } } } }, "high", dropped],
    [{ ...base, output_config: { effort: "high", format: { type: "json_schema", schema: { type: "object" } } } }, "json_schema", locked()],
    [{ ...base, tool_choice: { type: "tool", name: "inspect", disable_parallel_tool_use: true } }, "disable_parallel_tool_use", locked()],
    [{ ...base, tools: [{ type: "web_search_20250305", name: "web_search", max_uses: 918273 }] }, "918273", dropped],
    [{ ...base, tools: [{ name: "inspect", input_schema: { type: "object" }, cache_control: { type: "ephemeral" } }] }, "ephemeral", dropped],
    [{ ...base, context_management: { edits: [{ type: "clear_tool_uses_20250919", trigger: { type: "input_tokens", value: 918273 } }] } }, "918273", locked()],
    [{ ...base, messages: [{ role: "assistant", content: [{ type: "thinking", thinking: "Alice", signature: "opaque" }] }] }, "Alice", locked("signed-block-mutation")],
    [{ ...base, messages: [{ role: "user", content: [{ type: "image", source: { type: "base64", media_type: "image/png", data: "QUJDRA==" } }] }] }, "base64", locked()],
  ];
  for (const [fixture, selected, expected] of cases) {
    const original = Buffer.from(JSON.stringify(fixture));
    const scan = prepareOpfScan(original);
    assert.deepEqual(adaptOpfPrediction(original, scan, prediction(scan.text, "secret", selected)), expected, selected);
  }
});

test("OPF citation excerpts and titles and plain-text document bodies are redactable prose", () => {
  // The API accepts replayed web_search citations whose cited_text/title were altered (probed 2026-10-15).
  const citation = (extra) => ({ model: "claude-fixture", messages: [{ role: "user", content: "q" }, { role: "assistant", content: [
    { type: "text", text: "answer", citations: [{ type: "web_search_result_location", url: "https://example.com/a",
      title: "Benchmarks", encrypted_index: "QUJDREVGR0hJSktMTU5PUA==", cited_text: "measured today", ...extra }] }] }] });
  const document = (data) => ({ model: "claude-fixture", messages: [{ role: "user", content: [
    { type: "document", source: { type: "text", media_type: "text/plain", data } }] }] });
  const toolDocument = (data) => ({ model: "claude-fixture", messages: [
    { role: "assistant", content: [{ type: "tool_use", id: "toolu_fixture", name: "Read", input: {} }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_fixture", content: [document(data).messages[0].content[0]] }] }] });
  for (const fixture of [citation({ cited_text: "measured by Alice today" }), citation({ title: "Alice blog" }),
    document("written by Alice"), toolDocument("written by Alice")]) {
    const original = Buffer.from(JSON.stringify(fixture));
    const scan = prepareOpfScan(original);
    const result = adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", "Alice"));
    assert.equal(result.status, "ok", JSON.stringify(fixture));
    const redacted = JSON.parse(Buffer.from(result.redactedBody, "base64"));
    assert.equal(JSON.stringify(redacted).includes("Alice"), false);
    const locked = (body) => JSON.stringify(body, (key, value) => ["cited_text", "title", "data"].includes(key) ? undefined : value);
    assert.equal(locked(redacted), locked(fixture), "only the prose fields change");
  }
});

test("OPF citation and document-source controls stay locked", () => {
  const citation = (extra) => ({ model: "claude-fixture", messages: [{ role: "user", content: "q" }, { role: "assistant", content: [
    { type: "text", text: "answer", citations: [{ type: "web_search_result_location", url: "https://example.com/a",
      title: "t", encrypted_index: "QUJDREVGR0hJSktMTU5PUA==", cited_text: "x", ...extra }] }] }] });
  const source = (value) => ({ model: "claude-fixture", messages: [{ role: "user", content: [{ type: "document", source: value }] }] });
  for (const fixture of [citation({ url: "https://example.com/Alice" }), citation({ type: "Alice" }),
    source({ type: "url", url: "https://example.com/Alice" }), source({ type: "base64", media_type: "Alice", data: "QUJD" }),
    source({ type: "text", media_type: "Alice", data: "x" })]) {
    const original = Buffer.from(JSON.stringify(fixture));
    const scan = prepareOpfScan(original);
    assert.deepEqual(adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", "Alice")),
      { status: "unknown", findings: [], reason: "protocol-control-mutation" }, JSON.stringify(fixture));
  }
});

test("OPF known primitive control types cannot be passed through as malformed Messages values", () => {
  for (const extra of [{ max_tokens: "4096" }, { stream: "true" }, { temperature: "0.5" }, { top_k: true }]) {
    const original = Buffer.from(JSON.stringify({ model: "claude-fixture", messages: [{ role: "user", content: "Alice" }], ...extra }));
    const scan = prepareOpfScan(original);
    assert.deepEqual(adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", "Alice")),
      { status: "unknown", findings: [], reason: "protocol-control-mutation" });
  }
});

test("OPF protocol lookalikes in input metadata and generic JSON still mask with real proof", () => {
  const lookalike = { max_tokens: 918273, thinking: { type: "enabled", budget_tokens: 918273 },
    cache_control: { type: "ephemeral", ttl: "1h" }, name: "Alice" };
  const masked = { max_tokens: "[redacted:secret]", thinking: { type: "[redacted:secret]", budget_tokens: "[redacted:secret]" },
    cache_control: { type: "[redacted:secret]", ttl: "[redacted:secret]" }, name: "[redacted:private_person]" };
  const messages = toolMessages(["toolu_safe"]);
  messages[0].content[0].input = lookalike;
  for (const fixture of [lookalike, { model: "claude-fixture", max_tokens: 4096, stream: true, messages, metadata: lookalike }]) {
    const original = Buffer.from(JSON.stringify(fixture));
    const scan = prepareOpfScan(original);
    const body = verifiedResult(original, adaptOpfPrediction(original, scan, multiplePredictions(scan.text,
      [["secret", "918273"], ["secret", "enabled"], ["secret", "ephemeral"], ["secret", "1h"], ["private_person", "Alice"]])));
    if (fixture === lookalike) assert.deepEqual(body, masked);
    else {
      assert.deepEqual(body.messages[0].content[0].input, masked);
      assert.deepEqual(body.metadata, masked);
      assert.equal(body.max_tokens, 4096);
      assert.equal(body.stream, true);
      assert.equal(body.messages[0].content[0].id, body.messages[1].content[0].tool_use_id);
    }
  }
});

test("OPF unknown JSON shapes and nested imitation selectors receive ordinary masking", () => {
  const original = Buffer.from(JSON.stringify({ messages: "Alice", metadata: { role: "Alice", type: "Alice", name: "Alice" } }));
  const scan = prepareOpfScan(original);
  assert.deepEqual(verifiedResult(original, adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", "Alice"))),
    { messages: "[redacted:private_person]", metadata: { role: "[redacted:private_person]", type: "[redacted:private_person]", name: "[redacted:private_person]" } });
});

test("OPF broken source provenance cannot reclassify detected characters as separators", () => {
  const original = Buffer.from('["Alice","Smith"]');
  const scan = prepareOpfScan(original);
  const good = prediction(scan.text, "private_person", scan.text);
  assert.ok(Array.isArray(scan.sources));
  for (const sources of [undefined, [], scan.sources.slice(1), scan.sources.map((source, index) => index ? source : { ...source, end: source.end - 1 }),
    scan.sources.map((source, index) => index ? source : { ...source, node: { ...source.node, value: "Alicx" } })]) {
    assert.deepEqual(adaptOpfPrediction(original, { ...scan, sources }, good),
      { status: "unknown", findings: [], reason: "invalid-source-provenance" });
  }
});

test("OPF projection and propagated ranges are bounded without truncation", () => {
  for (const [count, status] of [[8192, "ok"], [8193, "unknown"]]) {
    const original = Buffer.from(JSON.stringify(Array(count).fill("Alice")));
    const scan = prepareOpfScan(original);
    const result = adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", scan.text));
    assert.equal(result.status, status);
    if (status === "ok") assert.equal(verifiedResult(original, result).length, 8192);
    else assert.equal(result.reason, "redaction-projection-limit");
    const repeated = adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", "Alice"));
    assert.equal(repeated.status, status);
    if (status === "unknown") assert.equal(repeated.reason, "redaction-match-limit");
  }
});

test("OPF duplicate cross-field predictions count distinct source coverage once", () => {
  const original = Buffer.from('["Alice","Smith"]');
  const scan = prepareOpfScan(original);
  const result = adaptOpfPrediction(original, scan, multiplePredictions(scan.text,
    Array(1024).fill(["private_person", scan.text])));
  assert.deepEqual(verifiedResult(original, result), ["[redacted:private_person]", "[redacted:private_person]"]);
  assert.deepEqual(result.findings, [{ label: "private_person", count: 2 }]);
  const excess = multiplePredictions(scan.text, Array(1025).fill(["private_person", scan.text]));
  assert.deepEqual(adaptOpfPrediction(original, scan, excess), { status: "unknown", findings: [], reason: "invalid-prediction" });
});

function paddedBody(fixture, bytes = 549102) {
  const body = Buffer.from(JSON.stringify(fixture));
  return Buffer.concat([body, Buffer.alloc(bytes - body.length, 32)]);
}

async function normalizedResult(original, result) {
  const worker = new EventEmitter();
  worker.stdout = new EventEmitter();
  worker.stderr = new EventEmitter();
  worker.kill = () => {};
  worker.stdin = { write(frame) {
    const request = JSON.parse(frame);
    const reply = request.type === "health"
      ? { protocol: "airkit-privacy-ndjson-v1", version: "capacity-test" } : result;
    queueMicrotask(() => worker.stdout.emit("data", Buffer.from(`${JSON.stringify({ ...reply, id: request.id, type: request.type })}\n`)));
  } };
  const filter = await createPrivacyFilter({ provision: { privacy: { version: "capacity-test",
    worker: { command: "/private/tmp/capacity-test-worker", args: [], sha256: "0".repeat(64) } } },
    spawnWorker: () => worker, validateWorker: async () => {}, timeoutMs: 1000 });
  try {
    const normalized = await filter.scan(original);
    assert.equal(normalized.status, "ok", normalized.reason);
    assert.equal(isVerifiedRedaction({ original, result: normalized }), true);
    return normalized;
  } finally { filter.close(); }
}

test("OPF 549102-byte single-field repeats preserve all batched proof through the real OSS parser", async () => {
  const original = paddedBody({ content: "Alice ".repeat(1025) });
  const scan = prepareOpfScan(original);
  const result = adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", "Alice"));
  assert.equal(result.status, "ok", result.reason);
  assert.deepEqual(result.findings, [{ label: "private_person", count: 1024 }, { label: "private_person", count: 1 }]);
  assert.equal(result.redactions.flatMap(({ spans }) => spans).length, 1025);
  for (const { spans } of result.redactions) for (const { start, end } of spans) assert.equal(original.subarray(start, end).toString(), "Alice");
  await normalizedResult(original, result);
});

test("OPF long decoded fields avoid call argument limits while preserving every repeated range", () => {
  const original = Buffer.from(JSON.stringify({ content: "Alice ".repeat(1025) + "x".repeat(540000) }));
  const scan = prepareOpfScan(original);
  const result = adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", "Alice"));
  const body = verifiedResult(original, result);
  assert.equal(body.content.endsWith("x".repeat(540000)), true);
  assert.equal(result.redactions.reduce((count, { count: value }) => count + value, 0), 1025);
});

test("OPF output body cap remains one MiB with an independent bounded reason", () => {
  const original = paddedBody({ content: "Alice" }, 1048576);
  const scan = prepareOpfScan(original);
  assert.deepEqual(adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", "Alice")),
    { status: "unknown", findings: [], reason: "redaction-body-limit" });
});

test("OPF exact propagation preserves overlapping surrogate pairs and distinct lone surrogates", () => {
  const original = Buffer.from(JSON.stringify(["😀😀😀", "\ud83d", "\ude00"]));
  const scan = prepareOpfScan(original);
  const overlap = adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", "😀😀"));
  assert.deepEqual(verifiedResult(original, overlap), ["[redacted:private_person]", "\ud83d", "\ude00"]);
  assert.equal(overlap.redactions[0].count, 2);
  for (const value of ["\ud83d", "\ude00"]) {
    const expected = prediction(scan.text, "secret", value);
    const start = Array.from(scan.text).indexOf(value);
    expected.detected_spans[0] = { ...expected.detected_spans[0], start, end: start + 1 };
    const result = adaptOpfPrediction(original, scan, expected);
    const body = verifiedResult(original, result);
    assert.equal(body[0], "😀😀😀", "a lone surrogate must never match one half of a surrogate pair");
    assert.deepEqual(result.findings, [{ label: "secret", count: 1 }]);
  }
});

test("OPF batched propagation removes every occurrence from excluded client contexts", async () => {
  const original = paddedBody({ system: Array(1025).fill("Alice"), tools: [{ description: "Alice" }],
    messages: [{ content: [{ type: "text", text: "<system-reminder>Alice</system-reminder>" }, { type: "text", text: "Alice" }] }] });
  const scan = prepareOpfScan(original);
  assert.equal(scan.text.split("Alice").length - 1, 1);
  const result = adaptOpfPrediction(original, scan, prediction(scan.text, "private_person", "Alice"));
  assert.deepEqual(result.findings, [{ label: "private_person", count: 1024 }, { label: "private_person", count: 4 }]);
  const normalized = await normalizedResult(original, result);
  assert.equal(normalized.redactedBody.includes("Alice"), false);
  const body = JSON.parse(normalized.redactedBody);
  assert.equal(body.system.length, 1025);
  assert.equal(body.tools[0].description, "[redacted:private_person]");
  assert.equal(body.messages[0].content[0].text, "<system-reminder>[redacted:private_person]</system-reminder>");
});

test("OPF altered propagation and protocol metadata cannot drop a projected finding", () => {
  const original = Buffer.from('["Alice","Smith"]');
  const scan = prepareOpfScan(original);
  const result = prediction(scan.text, "private_person", scan.text);
  for (const allValues of [scan.allValues.slice(0, 1), scan.allValues.map((node, index) => index ? { ...node, map: scan.allValues[0].map } : node)]) {
    assert.equal(adaptOpfPrediction(original, { ...scan, allValues }, result).status, "unknown");
  }
  const malformed = Buffer.from(JSON.stringify({ messages: [{ role: "user", content: [{ type: "tool_use", id: "toolu_9182", name: "inspect", input: {} }] }] }));
  const prepared = prepareOpfScan(malformed);
  assert.deepEqual(adaptOpfPrediction(malformed, { ...prepared, protocolIds: { nodes: [], invalid: false, overLimit: false } },
    prediction(prepared.text, "account_number", "9182")), { status: "unknown", findings: [], reason: "invalid-protocol-graph", detail: "role" });
});

test("OPF multi-label propagated ranges retain overlapping and disjoint proof in bounded batches", async () => {
  for (const [fixture, matches] of [
    [[...Array(1025).fill("Alice"), ...Array(1025).fill("Smith")], [["private_person", "Alice"], ["secret", "Smith"]]],
    [Array(1025).fill("Alice"), [["private_person", "Alice"], ["secret", "Alice"]]],
  ]) {
    const original = Buffer.from(JSON.stringify(fixture));
    const scan = prepareOpfScan(original);
    const result = adaptOpfPrediction(original, scan, multiplePredictions(scan.text, matches));
    assert.equal(result.status, "ok", result.reason);
    assert.equal(result.redactions.reduce((count, { count: value }) => count + value, 0), 2050);
    assert.deepEqual(result.redactions.map(({ count }) => count), [1024, 1, 1024, 1]);
    await normalizedResult(original, result);
  }
});

test("OPF propagation budget counts all labels together at 8192 and 8193", () => {
  for (const [smithCount, status] of [[4096, "ok"], [4097, "unknown"]]) {
    const original = Buffer.from(JSON.stringify([...Array(4096).fill("Alice"), ...Array(smithCount).fill("Smith")]));
    const scan = prepareOpfScan(original);
    const result = adaptOpfPrediction(original, scan, multiplePredictions(scan.text,
      [["private_person", "Alice"], ["secret", "Smith"]]));
    assert.equal(result.status, status);
    if (status === "unknown") assert.deepEqual(result, { status: "unknown", findings: [], reason: "redaction-match-limit" });
    else {
      assert.equal(result.redactions.reduce((count, { count: value }) => count + value, 0), 8192);
      assert.equal(result.redactions.length, 8);
      verifiedResult(original, result);
    }
  }
});

const opfRoot = process.env.CCSHIELD_TEST_OPF_ROOT
  ?? (process.env.CCSHIELD_LIVE_INSTALL_TEST === "1" ? join(homedir(), ".local/share/airkit-shield/opf-2026-09-29") : undefined);
test("deadline Viterbi returns the pinned upstream paths with real torch", { skip: !(opfRoot && existsSync(join(opfRoot, ".venv/bin/python"))) && "provisioned OPF venv not present" }, () => {
  const result = spawnSync(join(opfRoot, ".venv/bin/python"), ["-I", "-B", sourceOf("opf-viterbi-deadline.py"),
    "--self-test", join(opfRoot, "src/opf"), join(opfRoot, "checkpoint/original")], { encoding: "utf8", timeout: 120_000 });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /^ok: /);
});

test("exact OPF window cache preserves bounded cooperative retry progress", () => {
  const script = String.raw`
import importlib.util
import json
import math
import struct
import sys
import types
import unittest

class Module:
    training = False
    def modules(self): return [self]
    def parameters(self): return []
    def buffers(self): return []

class Tensor:
    device = types.SimpleNamespace(type="cpu")
    layout = "strided"
    def __init__(self, value, shape=(1, 1), dtype="int32", size=None):
        self.value, self.shape, self.dtype, self.size = value, shape, dtype, size
    def dim(self): return len(self.shape)
    def detach(self): return self
    def contiguous(self): return self
    def numpy(self): return self
    def tobytes(self): return struct.pack("<i", self.value)
    def clone(self): return Tensor(self.value, self.shape, self.dtype, self.size)
    def numel(self): return self.size if self.size is not None else math.prod(self.shape)
    def element_size(self): return 4

torch = types.ModuleType("torch")
torch.nn = types.SimpleNamespace(Module=Module)
torch.Tensor, torch.strided = Tensor, "strided"
torch.int32, torch.int64, torch.bool = "int32", "int64", "bool"
torch.is_grad_enabled = lambda: False
torch.is_autocast_enabled = lambda device: False
sys.modules["torch"] = torch
spec = importlib.util.spec_from_file_location("cache", sys.argv[1])
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

class Clock:
    value = 0.0
    def __call__(self): return self.value

class Model(Module):
    def __init__(self, clock=None, cost=0.0, size=None):
        self.clock, self.cost, self.size, self.calls, self.fail = clock, cost, size, 0, False
    def forward(self, tokens, attention_mask=None):
        self.calls += 1
        self.last = tokens.value
        if self.fail: raise RuntimeError("synthetic failed compute")
        if self.clock: self.clock.value += self.cost
        return Tensor(tokens.value, size=self.size)

class CacheTests(unittest.TestCase):
    def make_cache(self, **kwargs):
        clock = Clock()
        model = Model(clock)
        return clock, model, helper.ExactWindowLogitsCache(model, namespace="synthetic", clock=clock, **kwargs)

    def test_more_than_32_exact_windows_remain_available_under_byte_cap(self):
        model = Model()
        cache = helper.ExactWindowLogitsCache(model, namespace="synthetic")
        for _ in range(2):
            for value in range(40): cache.forward(Tensor(value))
        self.assertEqual(model.calls, 40)
        self.assertEqual(cache.snapshot()["hits"], 40)
        self.assertLessEqual(cache.snapshot()["bytes"], 64*1024*1024)

    def test_expired_hits_and_misses_do_not_return_or_compute(self):
        clock, model, cache = self.make_cache()
        cache.forward(Tensor(1))
        cache.begin_scan(1.0)
        clock.value = 1.0
        for value in [1, 2]:
            with self.assertRaises(helper.CooperativeScanTimeout): cache.forward(Tensor(value))
        self.assertEqual(model.calls, 1)
        self.assertEqual(cache.snapshot()["hits"], 0)
        cache.end_scan()
        cache.forward(Tensor(1))
        self.assertEqual(cache.snapshot()["hits"], 1)

    def test_completed_logits_survive_exhaustion_and_retry_is_exact(self):
        clock, model, cache = self.make_cache()
        model.cost = 2.0
        cache.begin_scan(1.0)
        with self.assertRaises(helper.CooperativeScanTimeout): cache.forward(Tensor(17))
        self.assertEqual(cache.snapshot()["entries"], 1)
        cache.end_scan()
        cache.begin_scan(1.0)
        self.assertEqual(cache.forward(Tensor(17)).value, 17)
        cache.check_deadline()
        cache.end_scan()
        self.assertEqual(model.calls, 1)

    def test_failed_compute_and_invalid_logits_are_not_cached(self):
        clock, model, cache = self.make_cache()
        cache.begin_scan(1.0)
        model.fail = True
        with self.assertRaises(RuntimeError): cache.forward(Tensor(1))
        self.assertEqual(cache.snapshot()["entries"], 0)
        cache.end_scan()
        model.fail = False
        model.forward = lambda *args, **kwargs: None
        invalid = helper.ExactWindowLogitsCache(model, namespace="synthetic", clock=clock)
        with self.assertRaises(RuntimeError): invalid.forward(Tensor(1))
        self.assertEqual(invalid.snapshot()["entries"], 0)

    def test_keys_and_namespace_remain_exact(self):
        clock, model, cache = self.make_cache()
        for tokens, mask in [(Tensor(1), None), (Tensor(2), None),
                             (Tensor(1, dtype="int64"), None), (Tensor(1, shape=(1, 2)), None),
                             (Tensor(1), Tensor(1, dtype="bool")), (Tensor(1), Tensor(0, dtype="bool"))]:
            cache.forward(tokens, attention_mask=mask)
        cache.set_namespace("other-checkpoint")
        cache.forward(Tensor(1))
        self.assertEqual(model.calls, 7)
        self.assertEqual(cache.snapshot()["entries"], 1)

    def test_entry_and_default_byte_caps_remain_bounded(self):
        model = Model()
        cache = helper.ExactWindowLogitsCache(model, namespace="synthetic")
        for value in range(257): cache.forward(Tensor(value))
        self.assertEqual(cache.snapshot()["entries"], 256)
        self.assertEqual(cache.snapshot()["evictions"], 1)
        large = Model(size=8*1024*1024)
        cache = helper.ExactWindowLogitsCache(large, namespace="synthetic")
        for value in range(3): cache.forward(Tensor(value))
        self.assertEqual(cache.snapshot()["entries"], 1)
        self.assertEqual(cache.snapshot()["evictions"], 2)
        self.assertLessEqual(cache.snapshot()["bytes"], 64*1024*1024)

    def test_cooperative_retry_can_progress_or_fail_to_converge_with_eviction(self):
        for windows, entries, expected in [(40, 256, [11, 22, 33, 40]), (80, 32, [11, 22, 33, 11])]:
            clock, model, cache = self.make_cache(max_entries=entries)
            model.cost = 1.0
            progress = []
            for _ in range(4):
                cache.begin_scan(10.5)
                try:
                    for value in range(windows): cache.forward(Tensor(value))
                    progress.append(windows)
                except helper.CooperativeScanTimeout:
                    progress.append(model.last + 1)
                finally: cache.end_scan()
            self.assertEqual(progress, expected)
            self.assertLessEqual(cache.snapshot()["entries"], entries)
            self.assertLessEqual(cache.snapshot()["bytes"], 64*1024*1024)

    def test_budget_validation_and_request_reset(self):
        clock, model, cache = self.make_cache()
        for budget in [0, -1, True, float("nan"), float("inf")]:
            with self.assertRaises((ValueError, TypeError)): cache.begin_scan(budget)
        cache.begin_scan(1.0)
        clock.value = 2.0
        with self.assertRaises(helper.CooperativeScanTimeout): cache.check_deadline()
        cache.end_scan()
        cache.begin_scan(1.0)
        cache.check_deadline()
        cache.end_scan()

result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CacheTests))
raise SystemExit(0 if result.wasSuccessful() else 1)
`;
  const result = spawnSync("python3", ["-I", "-B", "-c", script,
    sourceOf("opf-window-cache.py")], { encoding: "utf8", timeout: 60_000 });
  assert.equal(result.status, 0, result.stderr);
});

function parseReplies(run, status = 0) {
  const detail = `status=${run.status} signal=${run.signal} error=${run.error?.code ?? run.error?.message}`
    + ` stdoutBytes=${Buffer.byteLength(run.stdout ?? "")} stderr=${String(run.stderr ?? "").slice(0, 2000)}`;
  assert.equal(run.error, undefined, `worker run failed: ${detail}`);
  if (status === "failure") assert.notEqual(run.status, 0, `worker must fail: ${detail}`);
  else assert.equal(run.status, status, `worker exit status: ${detail}`);
  assert.ok(typeof run.stdout === "string" && run.stdout.length > 0 && run.stdout.endsWith("\n"), `worker emitted no complete frame: ${detail}`);
  return run.stdout.slice(0, -1).split("\n").map((line) => JSON.parse(line));
}

test("worker reply parser names the failed run instead of throwing a JSON SyntaxError", () => {
  for (const [run, pattern] of [
    [{ status: 1, signal: null, stdout: "", stderr: "" }, /worker exit status: status=1 .*stdoutBytes=0/],
    [{ status: 0, signal: null, stdout: "", stderr: "" }, /worker emitted no complete frame: .*stdoutBytes=0/],
    [{ status: null, signal: null, error: Object.assign(new Error("write EPIPE"), { code: "EPIPE" }), stdout: "", stderr: "" },
      /worker run failed: status=null signal=null error=EPIPE stdoutBytes=0/],
    [{ status: 0, signal: null, stdout: '{"type":"health"}', stderr: "" }, /worker emitted no complete frame: .*stdoutBytes=17/],
  ]) {
    assert.throws(() => parseReplies(run), (error) => error instanceof assert.AssertionError && pattern.test(error.message));
  }
  assert.deepEqual(parseReplies({ status: 2, stdout: '{"a":1}\n{"b":2}\n' }, "failure"), [{ a: 1 }, { b: 2 }]);
});

test("pinned local OPF worker keeps raw predictions inside the adapter", async (t) => {
  const python = spawnSync("python3", ["-c", "import sys; print(sys.executable)"], { encoding: "utf8" });
  assert.equal(python.status, 0, "Python 3 is required for the OPF worker test");
  const pythonPath = python.stdout.trim();
  const temp = await realpath(await mkdtemp(join(tmpdir(), "ccshield-opf-test-")));
  try {
    const checkpoint = join(temp, "checkpoint");
    await mkdir(checkpoint);
    const header = Buffer.from(JSON.stringify({ weight: { dtype: "BF16", shape: [2], data_offsets: [0, 4] } }));
    const headerLength = Buffer.alloc(8);
    headerLength.writeBigUInt64LE(BigInt(header.length));
    const modelBytes = Buffer.concat([headerLength, header, Buffer.from([1, 2, 3, 4])]);
    await writeFile(join(checkpoint, "model.safetensors"), modelBytes);
    const tokenizerDir = join(temp, "tiktoken-cache");
    await mkdir(tokenizerDir);
    const tokenizer = join(tokenizerDir, "fb374d419588a4632f3f557e76b4b70aebbca790");
    const tokenizerBytes = Buffer.from("synthetic local encoding");
    await writeFile(tokenizer, tokenizerBytes);
    const tokenizerDigest = createHash("sha256").update(tokenizerBytes).digest("hex");
    const source = join(temp, "opf");
    await mkdir(source);
    const sourceBytes = Buffer.from(`
import json
import os
import signal
import struct
import sys
import time
import types
cooperative_mode = os.getenv("CCSHIELD_TEST_COOPERATIVE_MODE")
scan_ms = int(sys.argv[6])
budget = (scan_ms - min(5000, scan_ms / 5)) / 1000
clock = [0.0]
if cooperative_mode:
    time.monotonic = lambda: clock[0]
pid_marker = os.getenv("CCSHIELD_TEST_PID_MARKER")
if os.getenv("CCSHIELD_TEST_IGNORE_TERM"):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
if pid_marker:
    with open(pid_marker, "w") as file:
        file.write(str(os.getpid()) + ":startup")
if os.getenv("CCSHIELD_TEST_STALL"):
    time.sleep(10)
restart_fail = os.getenv("CCSHIELD_TEST_RESTART_FAIL_ONCE_MARKER")
exit_once = os.getenv("CCSHIELD_TEST_SCAN_EXIT_ONCE_MARKER")
if restart_fail and exit_once and os.path.exists(exit_once) and not os.path.exists(restart_fail):
    with open(restart_fail, "w") as file:
        file.write("failed")
    raise RuntimeError("synthetic restart failure")
exit_after_reply = os.getenv("CCSHIELD_TEST_EXIT_AFTER_REPLY_MARKER")
if exit_after_reply:
    import builtins
    if os.path.exists(exit_after_reply):
        time.sleep(4)
    reply_print = builtins.print
    def print_then_exit(*args, **kwargs):
        reply_print(*args, **kwargs)
        if '"prediction"' in str(args[0]) and not os.path.exists(exit_after_reply):
            with open(exit_after_reply, "w") as file:
                file.write("exited")
            os._exit(3)
    builtins.print = print_then_exit
scan_number = [0]
block_calls = [0]
class Module:
    training = False
    def modules(self): return [self]
    def parameters(self): return []
    def named_parameters(self): return iter([])
    def buffers(self): return []
    def register_forward_pre_hook(self, hook):
        self.__dict__.setdefault("pre_hooks", []).append(hook)
    def __call__(self, *args, **kwargs):
        for hook in self.__dict__.get("pre_hooks", []): hook(self, args)
        return self.forward(*args, **kwargs)
    def eval(self):
        return self
class MLPBlock(Module):
    forward = None
    # The worker swaps forward for the real grouped kernel, so only the hook half of __call__ runs here.
    def __call__(self, tokens):
        for hook in self.__dict__.get("pre_hooks", []): hook(self, (tokens,))
        return tokens
class Linear:
    def __init__(self): self.dtype = "bfloat16"
    def float(self):
        self.dtype = "float32"
        return self
class AttentionBlock(Module):
    def __init__(self): self.qkv, self.out = Linear(), Linear()
class TransformerBlock(Module):
    def __init__(self, index): self.index, self.attn, self.mlp = index, AttentionBlock(), MLPBlock()
    def forward(self, tokens):
        # Warm-up probes use -1 so scan progress counts stay exact.
        if tokens.value >= 0: block_calls[0] += 1
        if cooperative_mode == "blocks" and self.index == 0 and (tokens.value == 0 or scan_number[0] == 2 and tokens.value == 2):
            clock[0] += 1.25 * budget
        return self.mlp(tokens)
class Parameter:
    dtype, shape = "bfloat16", (2,)
    data = "loaded"
    def numel(self): return 2
    def element_size(self): return 2
class Transformer(Module):
    def __init__(self): self.block, self.weight = [TransformerBlock(0), TransformerBlock(1)], Parameter()
    def named_parameters(self): return iter([("weight", self.weight)])
    def modules(self): return [self, *(module for block in self.block for module in (block, block.attn, block.mlp))]
    def forward(self, tokens, attention_mask=None):
        if cooperative_mode:
            self.forward_calls = getattr(self, "forward_calls", 0) + 1
            for block in self.block: block(tokens)
            if cooperative_mode == "windows": clock[0] += 0.75 * budget
            return tokens.clone()
        raise AssertionError("fixture does not run tensor inference")
class Tensor:
    device = types.SimpleNamespace(type="cpu")
    shape, layout, dtype = (1, 1), "strided", "int32"
    def __init__(self, value): self.value = value
    def dim(self): return 2
    def detach(self): return self
    def contiguous(self): return self
    def numpy(self): return self
    def tobytes(self): return struct.pack("<i", self.value)
    def clone(self): return Tensor(self.value)
    def numel(self): return 1
    def element_size(self): return 4
torch = types.ModuleType("torch")
torch.nn = types.ModuleType("torch.nn")
torch.nn.Module = Module
torch.Tensor, torch.strided = Tensor, "strided"
torch.int32, torch.int64, torch.bool = "int32", "int64", "bool"
torch.bfloat16, torch.float16, torch.float32 = "bfloat16", "float16", "float32"
# The mmap helper maps tensor bytes straight out of the safetensors file; record them so the warm-up can check the offset.
torch.frombuffer = lambda mapping, dtype, count, offset: types.SimpleNamespace(
    view=lambda shape: ("mapped", dtype, bytes(mapping[offset:offset + 2 * count]), shape))
torch.nn.functional = types.ModuleType("torch.nn.functional")
torch.set_num_threads = lambda count: setattr(torch, "threads", count)
torch.get_num_threads = lambda: torch.threads
torch.is_autocast_enabled = lambda device: False
torch.is_grad_enabled = lambda: False
env_module = types.ModuleType("opf._common.env")
env_module.get_env_bool = lambda name, default=False: default
architecture = types.ModuleType("opf._model.model")
architecture.AttentionBlock, architecture.MLPBlock, architecture.TransformerBlock = AttentionBlock, MLPBlock, TransformerBlock
architecture.swiglu = lambda x, **kwargs: x
weights = types.ModuleType("opf._model.weights")
weights.PARAM_NAME_MAP = {}
class Checkpoint:
    def __init__(self, files): self.tensor_name_to_file = files
    def _get_tensor(self, name): return "private copy"
weights.Checkpoint = Checkpoint
decoding = types.ModuleType("opf._core.decoding")
class ViterbiCRFDecoder:
    def decode(self, token_logprobs): return "upstream"
decoding.ViterbiCRFDecoder = ViterbiCRFDecoder
class EmptyScores:
    ndim, shape = 2, (0, 33)
torch.empty = lambda shape, dtype: types.SimpleNamespace(element_size=lambda: {"bfloat16": 2, "float16": 2, "float32": 4}[dtype])
for name, module in {"torch": torch, "torch.nn": torch.nn,
        "torch.nn.functional": torch.nn.functional, "opf._common": types.ModuleType("opf._common"),
        "opf._common.env": env_module, "opf._model": types.ModuleType("opf._model"),
        "opf._model.model": architecture, "opf._model.weights": weights,
        "opf._core": types.ModuleType("opf._core"), "opf._core.decoding": decoding}.items():
    sys.modules[name] = module
# The worker passes its thread count in the cache namespace; a test may pin the value it must be.
def expected_threads():
    threads = json.loads(sys.argv[5])["threads"]
    pinned = os.getenv("CCSHIELD_TEST_EXPECT_THREADS")
    assert pinned is None or threads == int(pinned)
    return threads
class Result:
    def __init__(self, text):
        selected = os.getenv("CCSHIELD_TEST_PREDICTION_VALUE")
        value = selected if selected and selected in text else "alice@example.com" if "alice@example.com" in text else "person@example.org"
        start = text.index(value)
        self.payload = {
            "schema_version": 1,
            "summary": {"output_mode": "typed", "span_count": 1, "by_label": {"private_email": 1}, "decoded_mismatch": False},
            "text": text,
            "detected_spans": [{"label": "private_email", "start": start, "end": start + len(value), "text": value, "placeholder": "<PRIVATE_EMAIL>"}],
            "redacted_text": text.replace(value, "<PRIVATE_EMAIL>"),
        }
    def to_dict(self):
        marker = os.getenv("CCSHIELD_TEST_EMPTY_PREDICTION_ONCE_MARKER")
        if marker and not os.path.exists(marker) and self.payload["text"] != "alice@example.com":
            with open(marker, "w") as file:
                file.write("empty")
            return None
        return self.payload
class OPF:
    def __init__(self, *, model, device, output_mode, output_text_only, context_window_length=None):
        assert model and device == "cpu" and output_mode == "typed" and output_text_only is False
        assert context_window_length == 4096
        assert torch.get_num_threads() == expected_threads()
        assert not any(name.startswith("OPF_") for name in os.environ)
        assert os.environ["TIKTOKEN_CACHE_DIR"].endswith("/tiktoken-cache")
        self.model = model
        served = Checkpoint({"weight": os.path.join(model, "model.safetensors")})
        assert served._get_tensor("weight") == ("mapped", "bfloat16", bytes([1, 2, 3, 4]), (2,))
        assert Checkpoint({"weight": os.path.join(model, "..", "elsewhere.safetensors")})._get_tensor("weight") == "private copy"
        self.calls = 0
        self.runtime = types.SimpleNamespace(model=Transformer(), n_ctx=4096)
        self.decoder = ViterbiCRFDecoder()
    def get_runtime(self):
        return self.runtime
    def get_prediction_components(self):
        return self.runtime, self.decoder
    def redact(self, text):
        assert MLPBlock.forward.__name__ == "grouped_forward"
        cache = self.runtime.model.forward.__self__
        assert type(cache).__name__ == "ExactWindowLogitsCache"
        assert f"cpu:threads{expected_threads()}:" in cache._namespace and "ctx4096" in cache._namespace
        assert "adb9dd7d6f47e482ccb0925e621a1375461b997833dfa5be6dfc67b9d58b6f0e" in cache._namespace
        assert "e5c38fa18d71767b939c659ededbc063ea40a1d6fa235ec920a8d718bc832f9b" in cache._namespace
        self.calls += 1
        scan_number[0] = self.calls
        if self.calls == 1:
            assert text == "alice@example.com"
            assert self.runtime.model.weight.data == ("mapped", "bfloat16", bytes([1, 2, 3, 4]), (2,))
            # Attention runs in fp32 while the mapped MLP weights stay bf16.
            assert all(layer.dtype == "float32" for block in self.runtime.model.block for layer in (block.attn.qkv, block.attn.out))
            # Global Viterbi now runs the deadline-aware copy; an empty sequence returns before any torch op.
            if not os.getenv("CCSHIELD_TEST_SKIP_WARMUP_DECODE"):
                assert self.decoder.decode(EmptyScores()) == []
            hooks = [len(module.__dict__.get("pre_hooks", [])) for module in self.runtime.model.modules()
                     if isinstance(module, (TransformerBlock, MLPBlock))]
            assert hooks == [1, 1, 1, 1], "every transformer and MLP block needs exactly one deadline hook"
            if cooperative_mode == "blocks": cache.forward(Tensor(0))
            elif not os.getenv("CCSHIELD_TEST_SKIP_WARMUP_BLOCKS"):
                for block in self.runtime.model.block: block(Tensor(-1))
        if cooperative_mode and self.calls > 1:
            marker = os.getenv("CCSHIELD_TEST_COOPERATIVE_MARKER")
            try:
                if cooperative_mode == "preprocess" and self.calls == 2: clock[0] += 1.25 * budget
                for value in [1, 2]: cache.forward(Tensor(value))
                if cooperative_mode == "postprocess" and self.calls == 2: clock[0] += 1.25 * budget
                return Result(text)
            finally:
                with open(marker, "a") as file:
                    file.write(str(os.getpid()) + ":" + str(self.calls) + ":" + str(getattr(self.runtime.model, "forward_calls", 0)) + ":" + str(cache.snapshot()["entries"]) + ":" + str(block_calls[0]) + "\\n")
        if self.calls > 1 and pid_marker:
            with open(pid_marker, "w") as file:
                file.write(str(os.getpid()) + ":scan")
        error_marker = os.getenv("CCSHIELD_TEST_SCAN_ERROR_ONCE_MARKER")
        if self.calls > 1 and error_marker and not os.path.exists(error_marker):
            with open(error_marker, "w") as file:
                file.write("error")
            raise RuntimeError("synthetic private model failure person@example.org")
        if self.calls > 1 and os.getenv("CCSHIELD_TEST_SCAN_STALL"):
            time.sleep(10)
        slow_marker = os.getenv("CCSHIELD_TEST_SCAN_SLOW_MARKER")
        if self.calls > 1 and slow_marker:
            with open(slow_marker, "w") as file:
                file.write("scanning")
            time.sleep(0.4)
        exit_marker = os.getenv("CCSHIELD_TEST_SCAN_EXIT_ONCE_MARKER")
        if self.calls > 1 and exit_marker and not os.path.exists(exit_marker):
            with open(exit_marker, "w") as file:
                file.write("exited")
            os._exit(2)
        held_pipe_marker = os.getenv("CCSHIELD_TEST_SCAN_EXIT_HELD_PIPE_MARKER")
        if self.calls > 1 and held_pipe_marker and not os.path.exists(held_pipe_marker):
            descendant = os.fork()
            if descendant == 0:
                time.sleep(10)
                os._exit(0)
            with open(held_pipe_marker, "w") as file:
                file.write(str(descendant))
            os._exit(2)
        marker = os.getenv("CCSHIELD_TEST_SCAN_STALL_ONCE_MARKER")
        if self.calls > 1 and marker and not os.path.exists(marker):
            with open(marker, "w") as file:
                file.write("stalled")
            if os.getenv("CCSHIELD_TEST_MUTATE_AFTER_STALL"):
                with open(os.path.join(self.model, "model.safetensors"), "ab") as file:
                    file.write(b"changed")
            helper = os.getenv("CCSHIELD_TEST_MUTATE_HELPER_AFTER_STALL")
            if helper:
                with open(helper, "ab") as file:
                    file.write(b"\\n# drift\\n")
            time.sleep(10)
        return Result(text)
`);
    await writeFile(join(source, "__init__.py"), sourceBytes);
    const digest = createHash("sha256").update("model.safetensors\0").update(String(modelBytes.length)).update("\0").update(modelBytes).update("\0").digest("hex");
    const sourceDigest = createHash("sha256").update("__init__.py\0").update(String(sourceBytes.length)).update("\0").update(sourceBytes).update("\0").digest("hex");
    const adapter = sourceOf("opf-adapter.mjs");
    const adapterDigest = createHash("sha256").update(await readFile(adapter)).digest("hex");
    const workerDir = join(temp, "worker");
    await mkdir(workerDir);
    for (const name of ["privacy-opf-worker.mjs", "opf-adapter.mjs", "opf-cpu-grouped.py", "opf-window-cache.py", "opf-mmap-weights.py", "opf-viterbi-deadline.py"]) {
      await copyFile(sourceOf(name), join(workerDir, name));
    }
    const worker = join(workerDir, "privacy-opf-worker.mjs");
    // Preloaded into the worker only: logs checkpoint digests and Python spawns, and can hold
    // the first Python's exit/close events back to simulate a reap slower than stopPython's deadline.
    const spy = join(temp, "worker-spy.mjs");
    await writeFile(spy, `
import childProcess from "node:child_process";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import os from "node:os";
if (process.env.CCSHIELD_TEST_PARALLELISM) os.availableParallelism = () => Number(process.env.CCSHIELD_TEST_PARALLELISM);
const note = (event) => fs.appendFileSync(process.env.CCSHIELD_TEST_SPY_LOG, event + " " + Date.now() + "\\n");
const createReadStream = fs.createReadStream;
fs.createReadStream = function (path, ...rest) {
  if (String(path).endsWith("/model.safetensors")) note("digest");
  return createReadStream.call(this, path, ...rest);
};
const spawn = childProcess.spawn;
let pythons = 0;
childProcess.spawn = function (...args) {
  const child = spawn.apply(this, args);
  const index = pythons++;
  note("spawn-" + index);
  const delay = index === 0 ? Number(process.env.CCSHIELD_TEST_DELAY_REAP_MS || 0) : 0;
  if (!delay) { child.once("exit", () => note("exit-" + index)); return child; }
  const codes = { exitCode: null, signalCode: null };
  let released = false;
  for (const name of Object.keys(codes)) Object.defineProperty(child, name, { configurable: true,
    get: () => released ? codes[name] : null, set: (value) => { codes[name] = value; } });
  const emit = child.emit;
  const held = [];
  child.emit = function (event, ...rest) {
    if (released || (event !== "exit" && event !== "close")) return emit.call(this, event, ...rest);
    held.push(event);
    if (event === "exit") {
      note("exit-" + index);
      setTimeout(() => {
        released = true;
        note("released-" + index);
        for (const name of held) emit.call(child, name, codes.exitCode, codes.signalCode);
      }, delay);
    }
    return true;
  };
  return child;
};
syncBuiltinESMExports();
`);
    const spyArgs = (workerArgv) => ["--import", pathToFileURL(spy).href, ...workerArgv];
    const spyEvents = async (log) => (await readFile(log, "utf8")).trim().split("\n").map((line) => line.split(" "))
      .map(([event, time]) => ({ event, time: Number(time) }));
    const body = Buffer.from('{"content":"person@example.org"}');
    const input = [
      { protocol: "airkit-privacy-ndjson-v1", id: "h", type: "health" },
      { protocol: "airkit-privacy-ndjson-v1", id: "s", type: "scan", body: body.toString("base64") },
    ].map((entry) => JSON.stringify(entry)).join("\n") + "\n";
    // Budget classes keyed by what must expire; spawnSync bounds stay above budget plus restart and shutdown.
    const workerArgs = ({ startup, scan }) => {
      const args = buildOpfWorkerArgs({ python: pythonPath, checkpoint: { path: checkpoint, sha256: digest, version: "test-1" },
        source: { path: source, sha256: sourceDigest }, adapter: { sha256: adapterDigest },
        tokenizer: { path: tokenizer, sha256: tokenizerDigest }, scanTimeoutMs: scan });
      args[args.indexOf("--startup-timeout-ms") + 1] = String(startup);
      return [worker, ...args];
    };
    const args = workerArgs({ startup: 30_000, scan: 30_000 });
    const scanExpiryArgs = workerArgs({ startup: 30_000, scan: 2_000 });
    const startupExpiryArgs = workerArgs({ startup: 1_000, scan: 2_000 });
    const runTimeout = 45_000;
    const run = spawnSync(process.execPath, args, { input, encoding: "utf8", timeout: runTimeout,
      env: { ...process.env, OPF_EXPERTS_PER_TOKEN: "1", OPF_ATTN_LOW_PRECISION: "1", OPF_MOE_TRITON: "1" } });
    const replies = parseReplies(run);
    assert.deepEqual(replies[0], { type: "health", id: "h", protocol: "airkit-privacy-ndjson-v1", version: "opf-1-client-exempt",
      capabilities: ["cooperative-timeout"] }, "OSS keeps a session ready across model_timeout only for this advertised capability");
    assert.equal(replies[1].status, "ok");
    assert.deepEqual(replies[1].findings, [{ label: "private_email", count: 1 }]);
    // Fewer CPUs lower the thread count; more never raise it past 4. Both must survive warm-up and a scan.
    for (const [parallelism, expected] of [[2, 2], [8, 4]]) {
      const threadRun = spawnSync(process.execPath, spyArgs(args), { input, encoding: "utf8", timeout: runTimeout,
        env: { ...process.env, CCSHIELD_TEST_SPY_LOG: join(temp, `threads-${parallelism}.log`),
          CCSHIELD_TEST_PARALLELISM: String(parallelism), CCSHIELD_TEST_EXPECT_THREADS: String(expected) } });
      const threadReplies = parseReplies(threadRun);
      assert.equal(threadReplies[1]?.status, "ok", `scan with ${parallelism} CPUs: ${threadRun.stderr}`);
    }
    assert.equal(JSON.parse(Buffer.from(replies[1].redactedBody, "base64")).content, "[redacted:private_email]");
    assert.equal(run.stdout.includes("person@example.org"), false);
    await t.test("worker returns a 549102-byte redaction inside the 4 MiB frame", () => {
      const fixture = { system: "", messages: [{ content: Array(8192).fill("Alice") }] };
      fixture.system = "x".repeat(549102 - Buffer.byteLength(JSON.stringify(fixture)));
      const largeBody = Buffer.from(JSON.stringify(fixture));
      assert.equal(largeBody.length, 549102);
      const request = JSON.stringify({ protocol: "airkit-privacy-ndjson-v1", id: "bounded-proof",
        type: "scan", body: largeBody.toString("base64") }) + "\n";
      const result = spawnSync(process.execPath, args, { input: request, encoding: "utf8", timeout: runTimeout, maxBuffer: 8 * 1048576,
        env: { ...process.env, CCSHIELD_TEST_PREDICTION_VALUE: "Alice" } });
      const [reply] = parseReplies(result);
      assert.equal(reply.status, "ok");
      assert.ok(Buffer.byteLength(result.stdout) <= 4 * 1048576);
      assert.doesNotMatch(Buffer.from(reply.redactedBody, "base64").toString(), /Alice/);
    });
    await t.test("worker exact serialized frame boundary includes newline and fails closed for hostile IDs", () => {
      const FRAME = 4 * 1048576;
      const envelope = { type: "health", id: "", protocol: "airkit-privacy-ndjson-v1", version: "opf-1-client-exempt",
        capabilities: ["cooperative-timeout"] };
      const overhead = Buffer.byteLength(JSON.stringify(envelope) + "\n");
      const slack = overhead - Buffer.byteLength(JSON.stringify({ type: "health", id: "", status: "unknown", findings: [],
        reason: "redaction-frame-limit" }) + "\n");
      for (const [extra, expected] of [[0, "health"], [1, "unknown"], [slack, "unknown"], [slack + 1, "closed"], [slack + 20, "closed"]]) {
        const id = "k".repeat(FRAME - overhead + extra);
        const request = JSON.stringify({ protocol: "airkit-privacy-ndjson-v1", id, type: "health" }) + "\n";
        assert.ok(Buffer.byteLength(request) - 1 <= FRAME, "the request itself must fit so only the reply can close the worker");
        const result = spawnSync(process.execPath, args, { input: request, encoding: "utf8", timeout: runTimeout, maxBuffer: 8 * 1048576 });
        assert.equal(result.error, undefined, "hostile IDs cannot hold the worker open");
        if (expected === "health") {
          assert.equal(Buffer.byteLength(result.stdout), FRAME);
          assert.deepEqual(parseReplies(result), [{ ...envelope, id }]);
        } else if (expected === "unknown") {
          assert.ok(Buffer.byteLength(result.stdout) <= FRAME);
          const [reply] = parseReplies(result);
          assert.equal(reply.id, id);
          assert.equal(reply.status, "unknown");
          assert.equal(reply.reason, "redaction-frame-limit");
        } else {
          assert.notEqual(result.status, 0);
          assert.equal(result.stdout, "", "no truncated JSON or oversized fallback may be emitted");
        }
      }
      const request = { protocol: "airkit-privacy-ndjson-v1", id: "hostile-type", type: "" };
      request.type = "k".repeat(FRAME - Buffer.byteLength(JSON.stringify(request)));
      const result = spawnSync(process.execPath, args, { input: JSON.stringify(request) + "\n", encoding: "utf8", timeout: runTimeout, maxBuffer: 8 * 1048576 });
      assert.ok(Buffer.byteLength(result.stdout) <= FRAME);
      const [reply] = parseReplies(result);
      assert.equal(reply.id, "hostile-type");
      assert.equal(reply.type, request.type);
      assert.equal(reply.status, "unknown");
    });
    const longBudget = spawnSync(process.execPath, workerArgs({ startup: 30_000, scan: 60_000 }), { input, encoding: "utf8", timeout: runTimeout });
    assert.equal(parseReplies(longBudget).length, 2, "worker must accept the finite 60-second cold scan budget");
    const overBudget = spawnSync(process.execPath, workerArgs({ startup: 30_000, scan: 60_001 }), { input, encoding: "utf8", timeout: runTimeout });
    assert.equal(overBudget.error, undefined);
    assert.notEqual(overBudget.status, 0, "worker must reject an unbounded scan budget");
    const malformed = spawnSync(process.execPath, args, { input: `${JSON.stringify({
      protocol: "airkit-privacy-ndjson-v1", id: "malformed", type: "scan", body: "bad!base64",
    })}\n`, encoding: "utf8", timeout: runTimeout });
    assert.deepEqual(parseReplies(malformed), [{ type: "scan", id: "malformed", status: "unknown" }]);
    const stalled = spawnSync(process.execPath, startupExpiryArgs,
    { input, encoding: "utf8", env: { ...process.env, CCSHIELD_TEST_STALL: "1" }, timeout: 5_000 });
    assert.equal(stalled.error, undefined, "a stalled model must not keep the worker alive");
    assert.notEqual(stalled.status, 0, "a startup timeout must not look like a clean exit");
    assert.equal(stalled.stdout, "", "a stalled model must not answer health");
    const unhooked = spawnSync(process.execPath, args,
      { input, encoding: "utf8", env: { ...process.env, CCSHIELD_TEST_SKIP_WARMUP_BLOCKS: "1" }, timeout: runTimeout });
    assert.equal(unhooked.error, undefined, "a model that bypasses the deadline hooks must not keep the worker alive");
    assert.doesNotMatch(unhooked.stdout, /opf-1-client-exempt|"ok"/, "a model whose blocks never reach the deadline hooks must not report ready");
    const undecoded = spawnSync(process.execPath, args,
      { input, encoding: "utf8", env: { ...process.env, CCSHIELD_TEST_SKIP_WARMUP_DECODE: "1" }, timeout: runTimeout });
    assert.equal(undecoded.error, undefined);
    assert.doesNotMatch(undecoded.stdout, /opf-1-client-exempt|"ok"/, "a prediction path that bypasses the deadline Viterbi must not report ready");
    // The warm-up probe finds only part of the address, as wrongly mapped weights would.
    const misread = spawnSync(process.execPath, args,
      { input, encoding: "utf8", env: { ...process.env, CCSHIELD_TEST_PREDICTION_VALUE: "alice" }, timeout: runTimeout });
    assert.equal(misread.error, undefined);
    assert.doesNotMatch(misread.stdout, /opf-1-client-exempt|"ok"/, "a model that misses the known warm-up answer must not report ready");
    const scanStalled = spawnSync(process.execPath, scanExpiryArgs,
    { input, encoding: "utf8", env: { ...process.env, CCSHIELD_TEST_SCAN_STALL: "1" }, timeout: runTimeout });
    const timeoutReplies = parseReplies(scanStalled);
    assert.equal(timeoutReplies[0].type, "health");
    assert.deepEqual(timeoutReplies[1], { type: "scan", id: "s", status: "unknown", reason: "model_killed" },
      "the hard watchdog reports a kill distinct from a cooperative timeout");
    const retryInput = [
      { protocol: "airkit-privacy-ndjson-v1", id: "first", type: "scan", body: body.toString("base64") },
      { protocol: "airkit-privacy-ndjson-v1", id: "after-timeout", type: "health" },
      { protocol: "airkit-privacy-ndjson-v1", id: "second", type: "scan", body: body.toString("base64") },
    ].map((entry) => JSON.stringify(entry)).join("\n") + "\n";
    for (const mode of ["windows", "blocks", "preprocess", "postprocess"]) {
      for (const scan of [30_000, 2_000]) await t.test(`cooperative ${mode} exhaustion at a ${scan}ms budget returns no prediction and retries in the same Python`, async () => {
        const marker = join(temp, `cooperative-${mode}-${scan}`);
        const result = spawnSync(process.execPath, workerArgs({ startup: 30_000, scan }), { input: retryInput, encoding: "utf8", timeout: runTimeout,
          // Warming off keeps the redact call sequence exact; the warming test below covers it separately.
          env: { ...process.env, CCSHIELD_TEST_COOPERATIVE_MODE: mode, CCSHIELD_TEST_COOPERATIVE_MARKER: marker, CCSHIELD_OPF_WARM_SECONDS: "0" } });
        const scans = parseReplies(result).filter(({ type }) => type === "scan");
        // Per-scan window cache counts show the retry reusing what the timed-out scan already computed.
        const counts = { windows: [[0, 2], [2, 0]], blocks: [[0, 2], [1, 1]], preprocess: [[0, 0], [0, 2]], postprocess: [[0, 2], [2, 0]] }[mode];
        assert.deepEqual(scans[0], { type: "scan", id: "first", status: "unknown", reason: "model_timeout", cache: { hits: counts[0][0], misses: counts[0][1] } });
        assert.equal(scans[1].id, "second");
        assert.deepEqual(scans[1].cache, { hits: counts[1][0], misses: counts[1][1] });
        assert.deepEqual(verifiedResult(body, scans[1]), { content: "[redacted:private_email]" });
        const progress = (await readFile(marker, "utf8")).trim().split("\n").map((line) => line.split(":").map(Number));
        assert.equal(progress.length, 2);
        assert.equal(progress[0][0], progress[1][0], "cooperative exhaustion must retain the same Python");
        assert.deepEqual(progress.map(([, call]) => call), [2, 3], "a replacement Python would repeat startup");
        if (mode === "windows") assert.deepEqual(progress.map(([, , calls, entries]) => [calls, entries]), [[2, 2], [2, 2]]);
        // Blocks: warm-up window 0 runs past the deadline with no scan active; scan one stops inside window 2
        // at its first block's MLP hook and caches only window 1; the retry hits window 1 and finishes window 2.
        if (mode === "blocks") assert.deepEqual(progress.map(([, , calls, entries, blocks]) => [calls, entries, blocks]), [[3, 2, 5], [4, 3, 7]]);
        assert.doesNotMatch(result.stdout, /person@example\.org|prediction/);
      });
    }
    const recovered = spawnSync(process.execPath, scanExpiryArgs,
      { input: retryInput, encoding: "utf8", env: { ...process.env, CCSHIELD_TEST_SCAN_STALL_ONCE_MARKER: join(temp, "stalled-once") }, timeout: runTimeout });
    const recoveredReplies = parseReplies(recovered)
      .sort((a, b) => ["first", "after-timeout", "second"].indexOf(a.id) - ["first", "after-timeout", "second"].indexOf(b.id));
    assert.deepEqual(recoveredReplies.map(({ id, status }) => [id, status]), [
      ["first", "unknown"], ["after-timeout", undefined], ["second", "ok"],
    ]);
    assert.deepEqual(recoveredReplies[2].findings, [{ label: "private_email", count: 1 }]);
    const exited = spawnSync(process.execPath, scanExpiryArgs,
      { input: retryInput, encoding: "utf8", env: { ...process.env, CCSHIELD_TEST_SCAN_EXIT_ONCE_MARKER: join(temp, "exited-once") }, timeout: runTimeout });
    const exitReplies = parseReplies(exited)
      .sort((a, b) => ["first", "after-timeout", "second"].indexOf(a.id) - ["first", "after-timeout", "second"].indexOf(b.id));
    assert.deepEqual(exitReplies.map(({ id, status }) => [id, status]), [
      ["first", "unknown"], ["after-timeout", undefined], ["second", "ok"],
    ]);
    const slowMarker = join(temp, "slow-scan");
    const concurrent = spawn(process.execPath, workerArgs({ startup: 30_000, scan: 1_000 }), {
      stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, CCSHIELD_TEST_SCAN_SLOW_MARKER: slowMarker },
    });
    const liveReplies = [];
    const liveOutput = createInterface({ input: concurrent.stdout });
    liveOutput.on("line", (line) => liveReplies.push(JSON.parse(line)));
    const waitFor = async (condition, timeout = 20_000) => {
      const deadline = Date.now() + timeout;
      while (!await condition()) {
        if (Date.now() > deadline) throw new Error("worker fixture condition timed out");
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
    };
    const send = (child, id, type = "scan") => child.stdin.write(`${JSON.stringify({
      protocol: "airkit-privacy-ndjson-v1", id, type, ...(type === "scan" ? { body: body.toString("base64") } : {}),
    })}\n`);
    await t.test("a stable timed-out model reports a bounded reason and recovers", () => {
      assert.equal(recoveredReplies[0].reason, "model_killed");
      assert.equal(exitReplies[0].reason, "model_error");
    });
    await t.test("a restart with unchanged asset metadata reuses the boot digest", async () => {
      const log = join(temp, "restart-digest-log");
      const result = spawnSync(process.execPath, spyArgs(scanExpiryArgs), { input: retryInput, encoding: "utf8", timeout: runTimeout,
        env: { ...process.env, CCSHIELD_TEST_SPY_LOG: log, CCSHIELD_TEST_SCAN_STALL_ONCE_MARKER: join(temp, "restart-digest-stall") } });
      const scans = parseReplies(result).filter(({ type }) => type === "scan");
      assert.deepEqual(scans.map(({ id, status, reason }) => [id, status, reason]), [["first", "unknown", "model_killed"], ["second", "ok", undefined]]);
      const events = (await spyEvents(log)).map(({ event }) => event);
      assert.equal(events.filter((event) => event.startsWith("spawn-")).length, 2, "the hard kill must respawn Python once");
      assert.equal(events.filter((event) => event === "digest").length, 1, "only the boot attestation hashes the checkpoint");
    });
    const liveChild = (argv, env) => {
      const child = spawn(process.execPath, argv, { stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, ...env } });
      const replies = [];
      const output = createInterface({ input: child.stdout });
      output.on("line", (line) => replies.push(JSON.parse(line)));
      const reply = async (id) => {
        await waitFor(() => replies.some((entry) => entry.id === id) || child.exitCode !== null || child.signalCode !== null);
        const found = replies.find((entry) => entry.id === id);
        assert.ok(found, `worker exited (code=${child.exitCode}, signal=${child.signalCode}) before replying to ${id}`);
        return found;
      };
      return { child, replies, output, reply };
    };
    await t.test("an idle worker finishes a timed-out scan's windows so the retry is all cache hits", async () => {
      const marker = join(temp, "cooperative-warming");
      const { child, output, reply } = liveChild(workerArgs({ startup: 30_000, scan: 2_000 }),
        { CCSHIELD_TEST_COOPERATIVE_MODE: "blocks", CCSHIELD_TEST_COOPERATIVE_MARKER: marker });
      try {
        send(child, "first");
        // Scan one stops inside window 2 and caches only window 1 (see the blocks case above).
        assert.deepEqual(await reply("first"), { type: "scan", id: "first", status: "unknown", reason: "model_timeout", cache: { hits: 0, misses: 2 } });
        const lines = async () => existsSync(marker) ? (await readFile(marker, "utf8")).trim().split("\n").length : 0;
        // The idle worker re-runs the timed-out text once in the background; wait until that pass is recorded.
        await waitFor(async () => await lines() >= 2);
        send(child, "second");
        const second = await reply("second");
        assert.deepEqual(second.cache, { hits: 2, misses: 0 }, "warming must have cached every window of the timed-out text");
        assert.deepEqual(verifiedResult(body, second), { content: "[redacted:private_email]" });
        const progress = (await readFile(marker, "utf8")).trim().split("\n").map((line) => line.split(":").map(Number));
        assert.deepEqual(progress.map(([, call]) => call), [2, 3, 4]);
        assert.equal(new Set(progress.map(([pid]) => pid)).size, 1, "warming must stay in the same Python");
        assert.doesNotMatch(JSON.stringify(second), /person@example\.org|prediction/);
      } finally {
        child.stdin.end();
        output.close();
        await once(child, "exit");
      }
    });
    await t.test("a slow Python reap after a hard kill keeps the worker and never overlaps a second Python", async () => {
      const log = join(temp, "slow-reap-log");
      const { child, output, reply } = liveChild(spyArgs(scanExpiryArgs), { CCSHIELD_TEST_SPY_LOG: log,
        CCSHIELD_TEST_DELAY_REAP_MS: "4000", CCSHIELD_TEST_SCAN_STALL_ONCE_MARKER: join(temp, "slow-reap-stall") });
      try {
        send(child, "first");
        assert.deepEqual(await reply("first"), { type: "scan", id: "first", status: "unknown", reason: "model_killed" });
        send(child, "during-reap");
        assert.deepEqual(await reply("during-reap"), { type: "scan", id: "during-reap", status: "unknown", reason: "model_error" },
          "a scan during a slow reap is refused without stopping the worker");
        const before = (await spyEvents(log)).map(({ event }) => event);
        assert.equal(before.includes("released-0"), false, "the fixture must still hide the first Python's exit");
        assert.equal(before.includes("spawn-1"), false, "no second Python may start before the first is confirmed gone");
        send(child, "after-reap", "health");
        assert.deepEqual(await reply("after-reap"), { type: "health", id: "after-reap", protocol: "airkit-privacy-ndjson-v1",
          version: "opf-1-client-exempt", capabilities: ["cooperative-timeout"] }, "health waits a bounded time for the reap instead of reporting not ready");
        const events = await spyEvents(log);
        const at = (name) => events.find(({ event }) => event === name)?.time;
        assert.ok(at("released-0") !== undefined && at("spawn-1") >= at("released-0"), "the replacement Python started before the first was reaped");
        send(child, "second");
        assert.equal((await reply("second")).status, "ok");
        const exited = once(child, "exit");
        child.stdin.end();
        assert.deepEqual(await exited, [0, null]);
        const final = await spyEvents(log);
        assert.equal(final.filter(({ event }) => event.startsWith("spawn-")).length, 2);
        assert.equal(final.filter(({ event }) => event === "digest").length, 1);
      } finally {
        child.kill("SIGKILL");
        output.close();
      }
    });
    await t.test("a failed Python respawn backs off without stopping the worker", async () => {
      const log = join(temp, "respawn-fail-log");
      const { child, output, reply } = liveChild(spyArgs(scanExpiryArgs), { CCSHIELD_TEST_SPY_LOG: log,
        CCSHIELD_TEST_SCAN_EXIT_ONCE_MARKER: join(temp, "respawn-exit"), CCSHIELD_TEST_RESTART_FAIL_ONCE_MARKER: join(temp, "respawn-fail") });
      try {
        send(child, "first");
        assert.equal((await reply("first")).reason, "model_error");
        send(child, "backoff-health", "health");
        send(child, "during-backoff");
        assert.deepEqual(await reply("backoff-health"), { type: "health", id: "backoff-health", status: "unknown" });
        assert.deepEqual(await reply("during-backoff"), { type: "scan", id: "during-backoff", status: "unknown", reason: "model_error" });
        assert.equal(child.exitCode, null, "a failed respawn must not stop the worker");
        const spawns = async () => (await spyEvents(log)).filter(({ event }) => event.startsWith("spawn-")).length;
        assert.equal(await spawns(), 2, "the backoff must not retry Python for every request");
        await new Promise((resolve) => setTimeout(resolve, 1_500));
        send(child, "second");
        assert.equal((await reply("second")).status, "ok");
        assert.equal(await spawns(), 3);
        const exited = once(child, "exit");
        child.stdin.end();
        assert.deepEqual(await exited, [0, null]);
      } finally {
        child.kill("SIGKILL");
        output.close();
      }
    });
    await t.test("an ok reply never waits behind a Python restart", async () => {
      const pidMarker = join(temp, "exit-after-reply-pid");
      const { child, output, reply } = liveChild(args, { CCSHIELD_TEST_EXIT_AFTER_REPLY_MARKER: join(temp, "exit-after-reply"),
        CCSHIELD_TEST_PID_MARKER: pidMarker });
      try {
        send(child, "ready", "health");
        await reply("ready");
        send(child, "first");
        const first = await reply("first");
        assert.match(await readFile(pidMarker, "utf8"), /:scan$/, "the ok frame waited for a replacement Python");
        assert.deepEqual(verifiedResult(body, first), { content: "[redacted:private_email]" });
        send(child, "second");
        assert.equal((await reply("second")).status, "ok");
        const exited = once(child, "exit");
        child.stdin.end();
        assert.deepEqual(await exited, [0, null]);
      } finally {
        child.kill("SIGKILL");
        output.close();
      }
    });
    await t.test("an unexpected Python exit closes its inherited pipe before recovery completes", async () => {
      const marker = join(temp, "exited-held-pipe");
      const child = spawn(process.execPath, args, { stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env, CCSHIELD_TEST_SCAN_EXIT_HELD_PIPE_MARKER: marker } });
      const replies = [];
      const output = createInterface({ input: child.stdout });
      output.on("line", (line) => replies.push(JSON.parse(line)));
      let descendantPid;
      try {
        send(child, "first");
        await waitFor(() => replies.some(({ id }) => id === "first"));
        descendantPid = Number(await readFile(marker, "utf8"));
        assert.ok(Number.isInteger(descendantPid) && descendantPid > 1);
        send(child, "second");
        child.stdin.end();
        await waitFor(() => child.exitCode !== null);
        assert.equal(child.exitCode, 0, "inherited stdout must not outlive owned child cleanup");
        assert.deepEqual(replies.map(({ id, status, reason }) => [id, status, reason]),
          [["first", "unknown", "model_error"], ["second", "ok", undefined]]);
        process.kill(descendantPid, 0);
      } finally {
        child.kill("SIGKILL");
        if (!descendantPid) descendantPid = Number(await readFile(marker, "utf8").catch(() => ""));
        if (Number.isInteger(descendantPid) && descendantPid > 1) {
          try { process.kill(descendantPid, "SIGKILL"); }
          catch (error) { if (error.code !== "ESRCH") throw error; }
        }
        output.close();
      }
    });
    for (const variable of ["CCSHIELD_TEST_SCAN_ERROR_ONCE_MARKER", "CCSHIELD_TEST_EMPTY_PREDICTION_ONCE_MARKER"]) {
      await t.test(`${variable} reports model_error without losing recovery`, () => {
        const result = spawnSync(process.execPath, scanExpiryArgs, { input: retryInput, encoding: "utf8", timeout: runTimeout,
          env: { ...process.env, [variable]: join(temp, variable) } });
        const scans = parseReplies(result).filter(({ type }) => type === "scan");
        assert.equal(scans[0].reason, "model_error");
        assert.equal(scans[1].status, "ok");
        assert.doesNotMatch(result.stdout, /synthetic private model failure|person@example\.org/);
      });
    }
    for (const helper of ["opf-cpu-grouped.py", "opf-window-cache.py", "opf-mmap-weights.py", "opf-viterbi-deadline.py"]) {
      await t.test(`a timed-out scan stops on ${helper} drift with stdin held open`, async () => {
        const path = join(workerDir, helper);
        const helperBytes = await readFile(path);
        const child = spawn(process.execPath, scanExpiryArgs, { stdio: ["pipe", "pipe", "pipe"],
          env: { ...process.env, CCSHIELD_TEST_SCAN_STALL_ONCE_MARKER: join(temp, `held-${helper}`),
            CCSHIELD_TEST_MUTATE_HELPER_AFTER_STALL: path } });
        const replies = [];
        const output = createInterface({ input: child.stdout });
        output.on("line", (line) => replies.push(JSON.parse(line)));
        try {
          send(child, "held-timeout");
          await waitFor(() => replies.length > 0);
          await waitFor(() => child.exitCode !== null);
          assert.deepEqual(replies, [{ type: "scan", id: "held-timeout", status: "unknown", reason: "model_killed" }]);
          assert.notEqual(child.exitCode, 0);
        } finally {
          child.kill();
          output.close();
          await writeFile(path, helperBytes);
        }
      });
    }
    for (const phase of ["startup", "scan"]) {
      for (const signal of ["SIGTERM", "SIGINT"]) {
        await t.test(`${signal} during ${phase} waits for its TERM-resistant Python child to exit`, async () => {
          const marker = join(temp, `${phase}-${signal}-pid`);
          const child = spawn(process.execPath, args, { stdio: ["pipe", "pipe", "pipe"],
            env: { ...process.env, CCSHIELD_TEST_PID_MARKER: marker, CCSHIELD_TEST_IGNORE_TERM: "1",
              [phase === "startup" ? "CCSHIELD_TEST_STALL" : "CCSHIELD_TEST_SCAN_STALL"]: "1" } });
          const replies = [];
          const output = createInterface({ input: child.stdout });
          output.on("line", (line) => replies.push(JSON.parse(line)));
          let pythonPid;
          const pythonGone = () => {
            try { process.kill(pythonPid, 0); return false; }
            catch (error) { if (error.code === "ESRCH") return true; throw error; }
          };
          try {
            if (phase === "scan") send(child, "interrupted");
            await waitFor(async () => {
              const value = await readFile(marker, "utf8").catch(() => "");
              if (!value.endsWith(`:${phase}`)) return false;
              pythonPid = Number(value.split(":")[0]);
              return true;
            });
            child.kill(signal);
            await waitFor(() => child.exitCode !== null || child.signalCode !== null);
            assert.equal(pythonGone(), true, "worker must await owned Python exit before it exits");
            assert.deepEqual(replies, [], "shutdown must not emit interrupted scan results");
          } finally {
            child.kill("SIGKILL");
            if (pythonPid && !pythonGone()) process.kill(pythonPid, "SIGKILL");
            output.close();
          }
        });
      }
    }
    try {
      send(concurrent, "initial", "health");
      await waitFor(() => liveReplies.some(({ id }) => id === "initial"));
      send(concurrent, "slow-1");
      await waitFor(() => readFile(slowMarker).then(() => true, () => false));
      send(concurrent, "during-scan", "health");
      await waitFor(() => liveReplies.some(({ id }) => id === "during-scan"));
      assert.equal(liveReplies.some(({ id }) => id === "slow-1"), false,
        "attested health must respond before active Python inference finishes");
      for (let index = 2; index <= 5; index += 1) send(concurrent, `slow-${index}`);
      const finished = once(concurrent, "exit");
      concurrent.stdin.end();
      const [code] = await finished;
      assert.equal(code, 0);
      assert.equal(liveReplies.find(({ id }) => id === "slow-5").status, "unknown", "worker scan queue is bounded");
      for (let index = 1; index <= 4; index += 1) {
        assert.equal(liveReplies.find(({ id }) => id === `slow-${index}`).status, "ok",
          "queued scan timeout must begin at Python dispatch");
      }
    } finally {
      concurrent.kill();
      liveOutput.close();
    }
    for (const helper of ["opf-cpu-grouped.py", "opf-window-cache.py", "opf-mmap-weights.py", "opf-viterbi-deadline.py"]) {
      const path = join(workerDir, helper);
      const helperBytes = await readFile(path);
      const marker = join(temp, `drift-${helper}`);
      const child = spawn(process.execPath, args, {
        stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, CCSHIELD_TEST_SCAN_SLOW_MARKER: marker },
      });
      const output = [];
      const lines = createInterface({ input: child.stdout });
      lines.on("line", (line) => output.push(JSON.parse(line)));
      try {
        send(child, "before-drift", "health");
        await waitFor(() => output.some(({ id }) => id === "before-drift"));
        send(child, "drifting-scan");
        await waitFor(() => readFile(marker).then(() => true, () => false));
        const finished = once(child, "exit");
        await writeFile(path, Buffer.concat([helperBytes, Buffer.from("\n# drift\n")]));
        // Let the scan complete without another request: post-scan attestation
        // must close the worker rather than trusting its loaded helper copy.
        await waitFor(() => child.exitCode !== null);
        const [code] = await finished;
        assert.notEqual(code, 0, `${helper} drift must stop the worker`);
        assert.equal(output.some(({ id, status }) => id === "drifting-scan" && status === "ok"), false);
        const invalid = spawnSync(process.execPath, args, { input, encoding: "utf8", timeout: runTimeout });
        assert.equal(invalid.error, undefined);
        assert.notEqual(invalid.status, 0, "helper drift is rejected before Python import");
        assert.equal(invalid.stdout, "");
        await writeFile(path, helperBytes);
        const recovering = spawnSync(process.execPath, scanExpiryArgs, {
          input: retryInput, encoding: "utf8", timeout: runTimeout,
          env: { ...process.env, CCSHIELD_TEST_SCAN_STALL_ONCE_MARKER: join(temp, `recovery-${helper}`),
            CCSHIELD_TEST_MUTATE_HELPER_AFTER_STALL: path },
        });
        const scans = parseReplies(recovering, "failure").filter(({ type }) => type === "scan");
        assert.deepEqual(scans.map(({ id, status }) => [id, status]), [["first", "unknown"]]);
      } finally {
        child.kill();
        lines.close();
        await writeFile(path, helperBytes);
      }
    }
    const held = spawn(process.execPath, scanExpiryArgs, {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env,
        CCSHIELD_TEST_SCAN_STALL_ONCE_MARKER: join(temp, "held-mutated-once"), CCSHIELD_TEST_MUTATE_AFTER_STALL: "1" },
    });
    try {
      const output = createInterface({ input: held.stdout });
      const exited = once(held, "exit");
      held.stdin.write(`${JSON.stringify({ protocol: "airkit-privacy-ndjson-v1", id: "held-scan", type: "scan", body: body.toString("base64") })}\n`);
      const [firstLine] = await once(output, "line");
      assert.equal(JSON.parse(firstLine).status, "unknown");
      held.stdin.write(`${JSON.stringify({ protocol: "airkit-privacy-ndjson-v1", id: "held-health", type: "health" })}\n`);
      const [code] = await Promise.race([
        exited,
        new Promise((_, reject) => setTimeout(() => reject(new Error("worker kept stdin open after asset drift")), 10_000)),
      ]);
      assert.notEqual(code, 0);
    } finally {
      held.kill();
    }
    await writeFile(join(checkpoint, "model.safetensors"), modelBytes);
    const drifted = spawnSync(process.execPath, scanExpiryArgs,
      { input: retryInput, encoding: "utf8", env: { ...process.env,
        CCSHIELD_TEST_SCAN_STALL_ONCE_MARKER: join(temp, "mutated-once"), CCSHIELD_TEST_MUTATE_AFTER_STALL: "1" }, timeout: runTimeout });
    const driftedReplies = parseReplies(drifted, "failure").filter(({ type }) => type === "scan");
    assert.deepEqual(driftedReplies.map(({ id, status }) => [id, status]), [["first", "unknown"]], "asset drift must stop worker before later requests");
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});
