import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";

// Spawns the real privacy worker as a subprocess and speaks its NDJSON
// protocol over stdio. The version is read from the worker source so the
// contract is pinned once, not hardcoded in two files.

const repoRoot = resolve(import.meta.dirname, "..");
const workerPath = resolve(repoRoot, "detectors", "regex", "privacy-worker.mjs");
const MAX_BODY_BYTES = 1024 * 1024;

function ask(requests) {
  const input = `${requests.map((request) => JSON.stringify(request)).join("\n")}\n`;
  const result = spawnSync(process.execPath, [workerPath], { input, encoding: "utf8" });
  assert.equal(result.status, 0, `worker exited ${result.status}: ${result.stderr}`);
  const lines = result.stdout.split("\n").filter((line) => line.trim() !== "");
  assert.equal(lines.length, requests.length, "worker must answer every request exactly once");
  const replies = lines.map((line) => JSON.parse(line));
  return new Map(replies.map((reply) => [reply.id, reply]));
}

function scanReply(body) {
  return ask([{ id: "t", type: "scan", body }]).get("t");
}

function scanJson(value) {
  return scanReply(Buffer.from(JSON.stringify(value), "utf8").toString("base64"));
}

async function workerVersion() {
  const source = await readFile(workerPath, "utf8");
  const match = source.match(/const VERSION = "([^"]+)"/);
  assert.ok(match, "worker source must declare a VERSION");
  return match[1];
}

test("health handshake reports the protocol and the worker file's version", async () => {
  const reply = ask([{ id: "h1", type: "health" }]).get("h1");
  assert.equal(reply.type, "health");
  assert.equal(reply.protocol, "airkit-privacy-ndjson-v1");
  assert.equal(reply.version, await workerVersion());
  // Honesty markers: the scope gate exempts client-injected content (`system`,
  // `tools`, and the claudeMd envelope), and detection is still skeleton (probe
  // token + one email regex). A version bump must not drop either marker
  // without a deliberate decision.
  assert.match(reply.version, /client-exempt/);
  assert.match(reply.version, /skeleton/);
});

test("a preamble email in the system field is exempt (string form)", () => {
  const reply = scanJson({
    system: "You are Claude Code. Security contact: noreply@anthropic.com.",
    messages: [{ role: "user", content: "hi" }],
  });
  assert.equal(reply.status, "ok");
  assert.deepEqual(reply.findings, []);
  assert.equal("redactions" in reply, false);
  assert.equal("redactedBody" in reply, false);
});

test("a preamble email in the system field is exempt (content-block form)", () => {
  const reply = scanJson({
    system: [{ type: "text", text: "Sample mailbox: company@company.com" }],
    messages: [{ role: "user", content: "hi" }],
  });
  assert.equal(reply.status, "ok");
  assert.deepEqual(reply.findings, []);
  assert.equal("redactions" in reply, false);
  assert.equal("redactedBody" in reply, false);
});

test("a null system field with empty messages yields no findings", () => {
  const reply = scanJson({ system: null, messages: [] });
  assert.equal(reply.status, "ok");
  assert.deepEqual(reply.findings, []);
  assert.equal("redactions" in reply, false);
  assert.equal("redactedBody" in reply, false);
});

test("a user email in messages is detected, redacted, and verifiable across the whole body", () => {
  const original = Buffer.from(JSON.stringify({
    system: "You are Claude Code, a CLI agent.",
    messages: [{ role: "user", content: "reach me at person@example.org" }],
  }), "utf8");
  const reply = scanReply(original.toString("base64"));

  assert.equal(reply.status, "ok");
  assert.deepEqual(reply.findings, [{ label: "email", count: 1 }]);
  const redaction = reply.redactions.find((entry) => entry.label === "email");
  assert.equal(redaction.count, 1);
  assert.equal(redaction.spans.length, 1);

  const [span] = redaction.spans;
  assert.equal(original.subarray(span.start, span.end).toString("utf8"), "person@example.org");

  const redacted = Buffer.from(reply.redactedBody, "base64");
  assert.ok(redacted.byteLength > 0 && redacted.byteLength <= MAX_BODY_BYTES);
  assert.ok(!redacted.equals(original));
  // Full-body replacement: the untouched system text survives verbatim and the
  // envelope still parses, so the upstream can re-read it.
  const reparsed = JSON.parse(redacted.toString("utf8"));
  assert.equal(reparsed.system, "You are Claude Code, a CLI agent.");
  assert.match(JSON.stringify(reparsed.messages), /\[redacted:email\]/);
  assert.ok(redacted.includes(Buffer.from("[redacted:email]", "utf8")));
  // No span's original bytes may survive in the redacted body.
  for (const entry of reply.redactions) {
    for (const { start, end } of entry.spans) {
      assert.ok(!redacted.includes(original.subarray(start, end)));
    }
  }
});

test("a system boilerplate mailbox distinct from the user's mailbox is not counted", () => {
  const reply = scanJson({
    system: "Security contact: security@anthropic.com",
    messages: [{ role: "user", content: "my address is person@example.org" }],
  });
  assert.deepEqual(reply.findings, [{ label: "email", count: 1 }]);
  const redacted = JSON.parse(Buffer.from(reply.redactedBody, "base64").toString("utf8"));
  assert.equal(redacted.system, "Security contact: security@anthropic.com");
  assert.match(JSON.stringify(redacted.messages), /\[redacted:email\]/);
});

test("the same mailbox in both system and messages is user data: both occurrences replaced", () => {
  const original = Buffer.from(JSON.stringify({
    system: "User identity: person@example.org",
    messages: [{ role: "user", content: "I am person@example.org" }],
  }), "utf8");
  const reply = scanReply(original.toString("base64"));

  assert.deepEqual(reply.findings, [{ label: "email", count: 2 }]);
  const text = Buffer.from(reply.redactedBody, "base64").toString("utf8");
  assert.ok(!text.includes("person@example.org"));
  assert.equal(text.match(/\[redacted:email\]/g).length, 2);
  JSON.parse(text);
});

test("emails in non-exempt fields (metadata, tool results) stay in scope", () => {
  const reply = scanJson({
    system: "You are Claude Code.",
    messages: [{ role: "user", content: "hi" }, { role: "user", content: [{ type: "tool_result", content: "logged in as person@example.org" }] }],
    metadata: { user_id: "acct-person@example.org" },
    tools: [{ name: "mail", description: "sends from sender@example.org" }],
  });
  // tools[].description is now exempt; the tool_result and metadata emails are
  // user data and must still be found.
  assert.deepEqual(reply.findings, [{ label: "email", count: 2 }]);
  const text = Buffer.from(reply.redactedBody, "base64").toString("utf8");
  assert.ok(!text.includes("person@example.org"));
  assert.ok(text.includes("sender@example.org"));
});

test("tool boilerplate mailboxes (Bash Co-Authored-By, plugin placeholder) are exempt", () => {
  const reply = scanJson({
    system: "You are Claude Code.",
    messages: [{ role: "user", content: "hi" }],
    tools: [
      { name: "Bash", description: "End git commit messages with:\n\nCo-Authored-By: Claude Code <noreply@anthropic.com>" },
      { name: "mcp__plugin_slack_slack__slack_search_users", description: "Examples: john@company.com" },
    ],
  });
  assert.equal(reply.status, "ok");
  assert.deepEqual(reply.findings, []);
  assert.equal("redactions" in reply, false);
  assert.equal("redactedBody" in reply, false);
});

test("a user email inside a tool schema default or example stays in scope", () => {
  // The exemption drops the whole `tools` key only when the body is
  // messages-shaped; but a tools array entry that carries an email is exempt
  // as client boilerplate. What must stay in scope is anything the user's
  // tools emit at runtime — tool_result content — covered above. This case
  // pins that a bare email in tools with no other source yields no findings.
  const reply = scanJson({
    system: "You are Claude Code.",
    messages: [{ role: "user", content: "hi" }],
    tools: [{ name: "t", description: "contact ops@internal.example" }],
  });
  assert.deepEqual(reply.findings, []);
});

test("the claudeMd system-reminder envelope in a message is exempt, the prompt after it is not", () => {
  const envelope = "<system-reminder>\nAs you answer the user's questions, you can use the following context:\n\n# userEmail\nThe user's email address is account@gmail.com. Use it only to identify the user.\n\n</system-reminder>\n\n";
  const reply = scanJson({
    system: [{ type: "text", text: "You are Claude Code, a CLI agent." }],
    messages: [{ role: "user", content: [
      { type: "text", text: envelope },
      { type: "text", text: "Reply with exactly: SHIELD OK" },
    ] }],
  });
  assert.equal(reply.status, "ok");
  assert.deepEqual(reply.findings, []);
  assert.equal("redactions" in reply, false);
  assert.equal("redactedBody" in reply, false);

  // The prompt block after the envelope is user content and stays in scope.
  const withPrompt = scanJson({
    system: "You are Claude Code.",
    messages: [{ role: "user", content: [
      { type: "text", text: envelope },
      { type: "text", text: "reach me at person@example.org" },
    ] }],
  });
  assert.deepEqual(withPrompt.findings, [{ label: "email", count: 1 }]);
});

test("a system-reminder that is not one whole envelope stays in scope", () => {
  // Partial: text before the opening tag — real user content quoting a reminder.
  const partial = scanJson({
    system: "You are Claude Code.",
    messages: [{ role: "user", content: [
      { type: "text", text: "the reminder looks like <system-reminder>identity person@example.org</system-reminder>" },
    ] }],
  });
  assert.deepEqual(partial.findings, [{ label: "email", count: 1 }]);

  // Two reminders in one block — not the single claudeMd envelope shape.
  const two = scanJson({
    system: "You are Claude Code.",
    messages: [{ role: "user", content: [
      { type: "text", text: "<system-reminder>a</system-reminder><system-reminder>person@example.org</system-reminder>" },
    ] }],
  });
  assert.deepEqual(two.findings, [{ label: "email", count: 1 }]);

  // Unbalanced — not an envelope at all.
  const unbalanced = scanJson({
    system: "You are Claude Code.",
    messages: [{ role: "user", content: [
      { type: "text", text: "<system-reminder>person@example.org" },
    ] }],
  });
  assert.deepEqual(unbalanced.findings, [{ label: "email", count: 1 }]);
});

test("the same mailbox in the envelope and the prompt is user data: both replaced", () => {
  const envelope = "<system-reminder>\n# userEmail\nThe user's email address is person@example.org\n</system-reminder>\n";
  const original = Buffer.from(JSON.stringify({
    system: "You are Claude Code.",
    messages: [{ role: "user", content: [
      { type: "text", text: envelope },
      { type: "text", text: "I am person@example.org" },
    ] }],
  }), "utf8");
  const reply = scanReply(original.toString("base64"));
  // One mailbox, two original occurrences: matched once in the prompt, and
  // occurrences() replaces BOTH — the envelope copy included, because that
  // mailbox is user data wherever it appears.
  assert.deepEqual(reply.findings, [{ label: "email", count: 2 }]);
  const redacted = Buffer.from(reply.redactedBody, "base64").toString("utf8");
  // The envelope copy is exempt from scanning but the value matched in the
  // prompt replaces every occurrence in the ORIGINAL body — the envelope copy
  // too, because that mailbox is user data wherever it appears.
  assert.ok(!redacted.includes("person@example.org"));
  JSON.parse(redacted);
});

test("deeply nested messages content is scanned without falling back", () => {
  let value = "person@example.org";
  for (let i = 0; i < 24; i += 1) value = { nested: value };
  const reply = scanJson({
    system: "Preamble mailbox: security@anthropic.com",
    messages: [{ role: "user", content: [{ type: "text", text: "ok", attachment: value }] }],
  });
  // Count 1 proves the gate took the messages-shaped path (the preamble
  // mailbox is exempt) and the 25-level nesting did not knock it to fallback.
  assert.deepEqual(reply.findings, [{ label: "email", count: 1 }]);
});

test("a body without the messages shape falls back to a full-text scan", () => {
  const reply = scanJson({ content: "reach me at person@example.org" });
  assert.deepEqual(reply.findings, [{ label: "email", count: 1 }]);
});

test("non-messages shapes never gain the exemption: system email detected", () => {
  // messages present but not an array → the gate does not apply → the email
  // inside `system` is scanned (fail toward detection, never toward release).
  const notArray = scanJson({
    system: "Identity: person@example.org",
    messages: "not-an-array",
  });
  assert.deepEqual(notArray.findings, [{ label: "email", count: 1 }]);

  // No system key at all → nothing to exempt.
  const noSystem = scanJson({
    messages: [{ role: "user", content: "reach me at person@example.org" }],
  });
  assert.deepEqual(noSystem.findings, [{ label: "email", count: 1 }]);

  // Top-level array → fallback.
  const topLevelArray = scanJson([{ content: "reach me at person@example.org" }]);
  assert.deepEqual(topLevelArray.findings, [{ label: "email", count: 1 }]);
});

test("a non-JSON body with an email reports findings without a redaction", () => {
  const reply = scanReply(Buffer.from("plain text, contact person@example.org", "utf8").toString("base64"));
  assert.equal(reply.status, "ok");
  assert.deepEqual(reply.findings, [{ label: "email", count: 1 }]);
  // A redaction the daemon cannot verify (the body is not JSON) is withheld on
  // purpose; the policy still blocks on the finding.
  assert.equal("redactions" in reply, false);
  assert.equal("redactedBody" in reply, false);
});

test("the provisioning probe token is detected and redacted", () => {
  const reply = scanJson({ content: "AIRKIT_PRIVACY_PROTOCOL_PROBE_EMAIL" });
  assert.equal(reply.status, "ok");
  assert.deepEqual(reply.findings, [{ label: "email", count: 1 }]);
  const redacted = Buffer.from(reply.redactedBody, "base64");
  assert.ok(redacted.includes(Buffer.from("[redacted:email]", "utf8")));
});

test("malformed scan requests fail closed as unknown", () => {
  const replies = ask([
    { id: "m1", type: "scan", body: null },
    { id: "m2", type: "scan", body: 123 },
    { id: "m3", type: "scan", body: "" },
    { id: "m4", type: "nonsense" },
  ]);
  for (const id of ["m1", "m2", "m3", "m4"]) {
    assert.equal(replies.get(id).status, "unknown", `${id} must fail closed`);
  }
});
