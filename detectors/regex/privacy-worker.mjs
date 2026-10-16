#!/usr/bin/env node
// ccshield privacy worker — regex fallback.
//
// Speaks airkit-privacy-ndjson-v1. This is the detector the daemon runs until
// the OPF model is downloaded and verified, and the one it falls back to when
// OPF is unavailable. It only covers what a regex can say with low false
// positives; `address` and `person` need the model.
//
// Read docs/superpowers/specs/2026-09-03-shield-privacy-worker-contract.md
// before changing anything here.
//
// Two things to know before you widen RULES:
//
//   1. The subscription policy redacts on any finding, so a false positive
//      silently rewrites what the user sent. Every rule here is scoped so that
//      hashes, git SHAs, loopback addresses, timestamps and version strings
//      in a coding session do not match. Gitleaks owns secrets.
//   2. The worker is digest-pinned. Editing this file changes its SHA-256 and
//      the next spawn refuses to start until it is re-pinned.
//
// Deploying it: the daemon spawns this file with `shell: false`
// (privacy.mjs:22), so the shebang is what execs, and the daemon runs under
// launchd, whose plist carries `EnvironmentVariables: {}` (service.mjs:31) —
// PATH is /usr/bin:/bin:/usr/sbin:/sbin. `/usr/bin/env node` cannot find a
// Homebrew or nvm node there and the worker dies with exit 127. Copy this file
// to its pinned location with the interpreter resolved to an absolute path:
//
//   sed "1s|^#!.*|#!$(readlink -f "$(command -v node)")|" \
//     tools/shield/privacy-worker.mjs > <pinned-path>
//   chmod 0755 <pinned-path>
//   shasum -a 256 <pinned-path>      # goes in the manifest
//
// Pin the script, not the interpreter: putting node in `worker.command` would
// aim validateAsset at the node binary instead of this logic, and every node
// upgrade would break provisioning. A node upgrade still invalidates the
// absolute shebang — that fails closed (exec fails, the lane blocks), and the
// fix is to redeploy and re-provision.

const PROTOCOL = "airkit-privacy-ndjson-v1";

// Must equal the manifest `version` and the policy manifest's
// detectorVersions.privacy. The daemon refuses to start if the three disagree.
//
// scan() skips the parts of an Anthropic messages-shaped body the client fills
// in before the user types anything — the `system` preamble, the `tools`
// descriptions, and the single claudeMd <system-reminder> envelope in the
// first message (see scanScope).
const VERSION = "regex-v1";

// ---------------------------------------------------------------------------
// The part you decide.
//
// `label` must be one of exactly these eight; anything else downgrades the
// whole reply to "unknown", which fails closed on every request:
//   address  credit-card  email  ip-address  person  phone  ssn  token
// ---------------------------------------------------------------------------
const RULES = [
  // Required. `ccshield privacy provision` scans a fixed probe body and
  // fails unless this exact token comes back labelled "email" and redacted.
  // The probe is not a syntactically valid address, so the rule below does not
  // cover it. Do not remove this entry.
  // The AIRKIT_ spelling is the probe older daemons send. TODO(P5): drop it.
  { label: "email", pattern: /(?:CCSHIELD|AIRKIT)_PRIVACY_PROTOCOL_PROBE_EMAIL/g },

  { label: "email", pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },

  // Public IPv4 only. Loopback, private, link-local, CGNAT, unspecified,
  // documentation and multicast ranges are infrastructure, not personal data.
  { label: "ip-address", pattern: /(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/g, accept: isPublicIpv4 },

  // 13-19 digits, optionally grouped by single spaces or hyphens, that pass
  // the Luhn check and start with a card-network prefix.
  { label: "credit-card", pattern: /(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])/g, accept: isCardNumber },

  // US SSN with its canonical separators; the invalid area/group/serial
  // values are excluded.
  { label: "ssn", pattern: /(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])/g },

  // A phone number must say it is one: a leading + country code, or a
  // parenthesised area code. Bare digit runs are timestamps and IDs.
  { label: "phone", pattern: /(?<![\w+])\+\d{1,3}[ -]?(?:\(\d{1,4}\)[ -]?)?\d{2,4}(?:[ -]?\d{2,4}){1,3}(?![\w-])|(?<![\w)])\(\d{2,4}\) ?\d{3,4}[ -]\d{4}(?![\w-])/g },

  // Bearer-style tokens with a recognisable issuer prefix that Gitleaks'
  // default rules do not already confirm. A generic long-string rule would
  // redact every hash in the transcript.
  { label: "token", pattern: /\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{36,}|xox[abpr]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/g },

  // `address` and `person` are not regex-shaped. They need the model.
];

// ---------------------------------------------------------------------------
// Protocol plumbing below this line.
// ---------------------------------------------------------------------------

const KNOWN_LABELS = new Set(["address", "credit-card", "email", "ip-address", "person", "phone", "ssn", "token"]);
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_ENTRIES = 128;
const MAX_COUNT = 1024;

for (const rule of RULES) {
  if (!KNOWN_LABELS.has(rule.label)) throw new Error(`unsupported privacy label: ${rule.label}`);
  if (!rule.pattern.global) throw new Error(`privacy rule for ${rule.label} needs the g flag`);
}

function isPublicIpv4(value) {
  const octets = value.split(".").map(Number);
  if (octets.some((octet, index) => octet > 255 || (octet > 0 && value.split(".")[index].startsWith("0")))) return false;
  const [a, b, c] = octets;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if ((a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) return false;
  return true;
}

function isCardNumber(value) {
  if (/[ -].*[ -]/.test(value) && new Set(value.match(/[ -]/g)).size > 1) return false;
  const digits = value.replace(/[ -]/g, "");
  if (!/^(?:4|5[1-5]|2[2-7]|3[47]|6(?:011|5)|35|3[0689])/.test(digits)) return false;
  let sum = 0;
  for (let index = 0; index < digits.length; index += 1) {
    let digit = Number(digits[digits.length - 1 - index]);
    if (index % 2 === 1) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
  }
  return sum % 10 === 0;
}

function scan(original) {
  const texts = scanScope(original);
  const seen = new Set();
  const byLabel = new Map();

  for (const rule of RULES) {
    for (const match of texts.flatMap((text) => [...text.matchAll(rule.pattern)])) {
      const value = match[0];
      if (!value || (rule.accept && !rule.accept(value))) continue;
      const key = `${rule.label} ${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      for (const span of occurrences(original, Buffer.from(value, "utf8"))) {
        if (!byLabel.has(rule.label)) byLabel.set(rule.label, []);
        byLabel.get(rule.label).push(span);
      }
    }
  }

  // Spans from different rules can overlap. Keep the earliest, drop the rest,
  // so every reported span is genuinely replaced in the redacted body.
  const all = [];
  for (const [label, spans] of byLabel) for (const span of spans) all.push({ label, ...span });
  all.sort((left, right) => left.start - right.start || right.end - left.end);
  const kept = [];
  let reach = 0;
  for (const span of all) {
    if (span.start < reach) continue;
    kept.push(span);
    reach = span.end;
  }
  if (kept.length === 0) return { status: "ok", findings: [] };

  const grouped = new Map();
  for (const span of kept) {
    if (!grouped.has(span.label)) grouped.set(span.label, []);
    const spans = grouped.get(span.label);
    if (spans.length < MAX_COUNT) spans.push({ start: span.start, end: span.end });
  }
  const labels = [...grouped.keys()].slice(0, MAX_ENTRIES);
  const findings = labels.map((label) => ({ label, count: grouped.get(label).length }));
  const redactions = labels.map((label) => ({ label, count: grouped.get(label).length, spans: grouped.get(label) }));

  const redacted = rebuild(original, kept);
  // A redaction ccshield cannot verify is worse than none: report the findings
  // and let the policy act on them. The subscription policy blocks either way.
  if (!verifiable(original, redacted, kept)) return { status: "ok", findings };
  return { status: "ok", findings, redactions, redactedBody: redacted.toString("base64") };
}

// Decides which text scan() matches rules against. Three parts of an Anthropic
// messages-shaped body are the client's, not the user's, and must never be the
// only reason a request is blocked:
//
//   1. `system` — the fixed preamble. Claude Code ships sample addresses like
//      noreply@anthropic.com there on every request.
//   2. `tools` — tool definitions. The built-in Bash description carries the
//      Co-Authored-By line and plugin tool descriptions carry their own
//      boilerplate (a company.com placeholder in the Slack search tool).
//   3. The claudeMd envelope — a message's leading text block when that block
//      is one complete <system-reminder>…</system-reminder>. Claude Code
//      assembles the first one from global/project CLAUDE.md, the memory
//      index, and the OAuth account address (# userEmail) before the user
//      types anything; the user's actual prompt is the block that follows it.
//
// Everything else — the prompt blocks, conversation history, tool results,
// metadata — stays in scope. A text block is only exempt as a whole envelope:
// starts with <system-reminder>, ends with </system-reminder>, and contains
// exactly one balanced pair, so a reminder quoted inside real user content does
// not gain the exemption.
//
// Rules run over the decoded string values in scope, not over JSON text. On
// JSON text a value after a newline arrives as `\nfoo@example.com`, the rule
// swallows the escape's `n`, and the redaction then cuts the escape in half —
// the body stops parsing and the request fails closed. Every rule matches a
// pure-ASCII sequence with no `"` or `\\`, which JSON.stringify never escapes,
// so a match in a decoded value exists verbatim in the original body, which is
// what occurrences() relies on. Re-check that before adding a rule that can
// match non-ASCII, quotes or backslashes.
function scanScope(original) {
  const raw = original.toString("utf8");
  let parsed;
  try { parsed = JSON.parse(raw); } catch { return [raw]; }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)
    || !Array.isArray(parsed.messages) || !("system" in parsed)) {
    return stringValues(parsed);
  }
  const { system: _exempt, tools: _exemptTools, messages, ...rest } = parsed;
  return stringValues({ ...rest, messages: messages.map(exemptEnvelope) });
}

function stringValues(value, out = []) {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const item of value) stringValues(item, out);
  else if (value !== null && typeof value === "object") for (const item of Object.values(value)) stringValues(item, out);
  return out;
}

function exemptEnvelope(message) {
  if (message === null || typeof message !== "object" || Array.isArray(message)
    || !Array.isArray(message.content)) {
    return message;
  }
  const [first, ...rest] = message.content;
  if (first === undefined || first.type !== "text" || typeof first.text !== "string") return message;
  const text = first.text;
  const OPEN = "<system-reminder>";
  const CLOSE = "</system-reminder>";
  // Exactly one balanced pair, and the block is nothing but that envelope.
  // Trim tolerates the leading blank line and trailing newline Claude Code
  // leaves around the tags; nothing may precede or follow them but whitespace.
  const trimmed = text.trim();
  const oneOpen = trimmed.startsWith(OPEN) && trimmed.indexOf(OPEN, OPEN.length) === -1;
  const oneClose = trimmed.endsWith(CLOSE)
    && trimmed.slice(0, -CLOSE.length).indexOf(CLOSE) === -1;
  if (!oneOpen || !oneClose) return message;
  return { ...message, content: rest };
}

function occurrences(haystack, needle) {
  const spans = [];
  let from = 0;
  for (;;) {
    const at = haystack.indexOf(needle, from);
    if (at === -1) return spans;
    spans.push({ start: at, end: at + needle.byteLength });
    from = at + needle.byteLength;
    if (spans.length >= MAX_COUNT) return spans;
  }
}

function rebuild(original, spans) {
  const parts = [];
  let cursor = 0;
  for (const span of spans) {
    parts.push(original.subarray(cursor, span.start));
    parts.push(Buffer.from(`[redacted:${span.label}]`, "utf8"));
    cursor = span.end;
  }
  parts.push(original.subarray(cursor));
  return Buffer.concat(parts);
}

function verifiable(original, redacted, spans) {
  if (redacted.byteLength === 0 || redacted.byteLength > MAX_BODY_BYTES || redacted.equals(original)) return false;
  // The replacement must not break the envelope; ccshield re-parses it.
  try { JSON.parse(redacted.toString("utf8")); } catch { return false; }
  return spans.every((span) => !redacted.includes(original.subarray(span.start, span.end)));
}

function handle(request) {
  if (request.type === "health") return { type: "health", id: request.id, protocol: PROTOCOL, version: VERSION };
  if (request.type !== "scan") return { type: request.type, id: request.id, status: "unknown" };
  let original;
  try {
    original = Buffer.from(request.body, "base64");
  } catch {
    return { type: "scan", id: request.id, status: "unknown" };
  }
  if (original.byteLength === 0 || original.byteLength > MAX_BODY_BYTES) {
    return { type: "scan", id: request.id, status: "unknown" };
  }
  try {
    return { type: "scan", id: request.id, ...scan(original) };
  } catch {
    // Never guess. "unknown" is the honest answer and it fails closed.
    return { type: "scan", id: request.id, status: "unknown" };
  }
}

let buffered = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffered += chunk;
  let newline = buffered.indexOf("\n");
  while (newline !== -1) {
    const line = buffered.slice(0, newline);
    buffered = buffered.slice(newline + 1);
    if (line.trim() !== "") {
      let request;
      try { request = JSON.parse(line); } catch { request = null; }
      if (request && typeof request.id === "string" && typeof request.type === "string") {
        process.stdout.write(`${JSON.stringify(handle(request))}\n`);
      }
    }
    newline = buffered.indexOf("\n");
  }
});
process.stdin.on("end", () => process.exit(0));
