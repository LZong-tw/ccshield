import assert from "node:assert/strict";
import { test } from "node:test";

import { prepareOpfScan, adaptOpfPrediction } from "../detectors/opf/opf-adapter.mjs";
import { withoutLocalFalsePositives } from "../detectors/opf/privacy-opf-worker.mjs";
import { isVerifiedRedaction } from "../src/shield/privacy.mjs";

const USER = "untionglim";

// Runs one request through the worker's exemption filter and the pinned adapter, as the worker does.
// `texts` become separate text blocks (separate sources); `hits` are [label, value, occurrence?] model spans.
function redact(texts, hits) {
  const fixture = { model: "claude-sonnet-5-5", messages: [{ role: "user", content: texts.map((text) => ({ type: "text", text })) }] };
  const original = Buffer.from(JSON.stringify(fixture));
  const scan = prepareOpfScan(original);
  const spans = hits.map(([label, value, occurrence = 0]) => {
    let at = -1;
    for (let seen = 0; seen <= occurrence; seen += 1) at = scan.text.indexOf(value, at + 1);
    assert.notEqual(at, -1, `${value} is in the scan text`);
    const start = Array.from(scan.text.slice(0, at)).length;
    return { label, start, end: start + Array.from(value).length, text: value, placeholder: "<PRIVATE>" };
  });
  const byLabel = {};
  for (const { label } of spans) byLabel[label] = (byLabel[label] ?? 0) + 1;
  const prediction = { schema_version: 1, text: scan.text, detected_spans: spans, redacted_text: scan.text,
    summary: { output_mode: "typed", span_count: spans.length, by_label: byLabel, decoded_mismatch: false } };
  const result = adaptOpfPrediction(original, scan, withoutLocalFalsePositives(scan, prediction, USER));
  assert.equal(result.status, "ok");
  if (!result.redactedBody) return texts;
  const redactedBody = Buffer.from(result.redactedBody, "base64");
  assert.equal(isVerifiedRedaction({ original, result: { ...result, redactedBody } }), true);
  return JSON.parse(redactedBody).messages[0].content.map((block) => block.text);
}

// Shapes taken from real transcripts where Claude reused a [redacted:...] placeholder in a tool call.
test("local false positives seen in real sessions pass through unredacted", () => {
  const cases = [
    ["private_person", "untionglim", "cat /Users/untionglim/projects/incident-docs/inventory.md"],
    ["private_person", "Users/untionglim", "cd /Users/untionglim/projects/mac-automation/"],
    ["private_person", "Users-untionglim", "~/.claude/projects/-Users-untionglim/memory/reference_kubectl.md"],
    ["private_person", "untionglim", "P=~/Library/LaunchAgents/com.untionglim.input-source-monitor.plist"],
    ["secret", "7230bbc0-13dd-4353-a160-ce527a889aea",
      "Output is being written to: /private/tmp/claude-501/-Users-untionglim/7230bbc0-13dd-4353-a160-ce527a889aea/tasks/bhz2fyfnb.output"],
    ["secret", "08b022c3-234a-449f-83de-ba4b48e3587d",
      "read /Users/untionglim/.claude/projects/-Users-untionglim-projects-web-ai-runtime-kit/08b022c3-234a-449f-83de-ba4b48e3587d.jsonl"],
    ["secret", "b97w7dv93", "Full output saved to: /Users/untionglim/.claude/projects/p/s/tool-results/b97w7dv93.txt"],
    ["account_number", "2139226119", "- [Dorami](https://kkcompany.atlassian.net/wiki/spaces/Web/pages/2139226119/Dorami)"],
    ["account_number", "2351267861", "\"history\": \"/rest/api/content/2351267861/history\""],
    ["account_number", "2351267861", "\"covered\": [\"content:2351267861\"]"],
    ["account_number", "2359033928", "space=ok\nCreated [live_doc]   2026-11-09   ID: 2359033928   Space ID: 1457192969"],
    ["account_number", "1457192969", "space=ok\nCreated [live_doc]   2026-11-09   ID: 2359033928   Space ID: 1457192969"],
    ["account_number", "1457192969", "{\n  \"type\": \"live_doc\",\n  \"spaceId\": \"1457192969\",\n  \"parentId\": \"1559298050\"\n}"],
    ["account_number", "2309652651", "- entityType: \"content\"\n  content:\n    id: \"2309652651\""],
  ];
  for (const [label, value, text] of cases) assert.deepEqual(redact([text], [[label, value]]), [text], `${label} ${value}`);
});

test("look-alikes of the exempt shapes stay redacted", () => {
  const cases = [
    // A real name, a different handle, and a span reaching past the login name.
    ["private_person", "Lim Un Tiong", "owner: Lim Un Tiong (/Users/untionglim)"],
    ["private_person", "untiongl", "cd /Users/untiongl/projects"],
    ["private_person", "Users/untionglim/projects", "cd /Users/untionglim/projects/x"],
    // UUIDs and short tokens outside Claude Code's own directories.
    ["secret", "7230bbc0-13dd-4353-a160-ce527a889aea", "export API_KEY=7230bbc0-13dd-4353-a160-ce527a889aea"],
    ["secret", "7230bbc0-13dd-4353-a160-ce527a889aea", "cat /tmp/7230bbc0-13dd-4353-a160-ce527a889aea/tasks/x"],
    ["secret", "sk-ant-api03-abcdef", "/Users/untionglim/.claude/projects/p/s/tool-results/x token=sk-ant-api03-abcdef"],
    // 12-digit AWS accounts, even inside Confluence output.
    ["account_number", "975050139402", "Confluence page: arn:aws:iam::975050139402:role/web-admin"],
    ["account_number", "579459883590", "[live_doc] MFA account ID: 579459883590"],
    ["account_number", "579459883590", "https://kkcompany.atlassian.net/wiki/spaces/Web/pages/579459883590"],
    // Field-shaped ids outside Confluence output.
    ["account_number", "12345678", "Bank transfer\nAccount ID: 12345678"],
    ["account_number", "2359033928", "{\"id\": \"2359033928\", \"type\": \"customer\"}"],
    // Other labels in an exempt position.
    ["private_email", "untionglim", "cat /Users/untionglim/x"],
  ];
  for (const [label, value, text] of cases) {
    assert.deepEqual(redact([text], [[label, value]]), [text.replaceAll(value, `[redacted:${label}]`)], `${label} ${value}`);
  }
});

test("Confluence output in one block does not exempt an id in another block", () => {
  const texts = ["Created [live_doc] ID: 2359033928", "Customer record\nID: 31415926"];
  assert.deepEqual(redact(texts, [["account_number", "2359033928"], ["account_number", "31415926"]]),
    ["Created [live_doc] ID: 2359033928", "Customer record\nID: [redacted:account_number]"]);
});

test("an exempt occurrence is still redacted when another occurrence of the same value is not exempt", () => {
  const texts = ["Daily Worklogs live under Work Logs (1559298050)", "https://kkcompany.atlassian.net/wiki/spaces/Web/pages/1559298050"];
  assert.deepEqual(redact(texts, [["account_number", "1559298050", 0], ["account_number", "1559298050", 1]]),
    ["Daily Worklogs live under Work Logs ([redacted:account_number])",
      "https://kkcompany.atlassian.net/wiki/spaces/Web/pages/[redacted:account_number]"]);
});

test("without a usable local username no private_person span is exempt", () => {
  const fixture = { model: "m", messages: [{ role: "user", content: "cd /Users/untionglim" }] };
  const scan = prepareOpfScan(Buffer.from(JSON.stringify(fixture)));
  const start = Array.from(scan.text).length - USER.length;
  const prediction = { schema_version: 1, text: scan.text, redacted_text: scan.text,
    detected_spans: [{ label: "private_person", start, end: start + USER.length, text: USER }],
    summary: { output_mode: "typed", span_count: 1, by_label: { private_person: 1 }, decoded_mismatch: false } };
  assert.equal(withoutLocalFalsePositives(scan, prediction, null), prediction);
  assert.equal(withoutLocalFalsePositives(scan, prediction, USER).detected_spans.length, 0);
});
