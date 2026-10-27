import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";

import { envNamesFor, readEnv } from "../compat-env.mjs";
import { attestShieldCheckpoint } from "./checkpoint.mjs";
import { isValidOpfWorkerArgs } from "./opf-args.mjs";
import { laneWindowCachePath } from "./paths.mjs";
import { PRIVACY_PROTOCOL as PROTOCOL } from "./protocol.mjs";
const MAX_BODY_BYTES = 1_048_576;
const MAX_FRAME_BYTES = 4 * 1_048_576; // base64 redacted body (≤1 MiB → ~1.4 MiB) plus findings must fit
const DEFAULT_TIMEOUT_MS = 2_000;
const DEFAULT_STARTUP_TIMEOUT_MS = 30_000;
const MAX_ADMITTED_SCANS = 4;
const MAX_ATTACHED_WAITERS = 8;
const RECENT_SCANS = 32;
const MAX_WINDOW_COUNT = 65_536;
const MAX_TOTAL = 4_294_967_295;
// A fixed key set keeps the diagnostics payload bounded; everything else lands in "other".
const TOTAL_FAILURE_REASONS = ["admission_limit", "queue_timeout", "scan_timeout", "model_timeout", "model_error", "model_killed", "worker_unavailable"];
const REQUEST_FAILURE = Symbol("privacy request failure");
const GRAPH_REASONS = new Set(["invalid-protocol-graph", "protocol-id-limit"]);
const GRAPH_DETAILS = new Set(["orphan", "duplicate", "role", "id", "limit"]);
const ADAPTER_UNKNOWN_REASONS = new Set([
  "invalid-prediction", "inconsistent-counts", "invalid-span", "unmapped-span", "cross-field-span",
  "inconsistent-quoting", "unmapped-finding", "redaction-too-large", "value-survived",
  "invalid-protocol-graph", "protocol-id-collision", "conflicting-protocol-context", "protocol-id-limit", "adapter-error",
  "protocol-graph-mutation", "protocol-control-mutation", "signed-block-mutation",
  "invalid-source-provenance", "json-key-collision", "invalid-json-topology",
  "model_timeout", "model_error", "model_killed",
  "redaction-projection-limit", "redaction-match-limit", "redaction-body-limit", "redaction-frame-limit",
  "segment-coverage", "segment-cache-invalid",
]);
const OPAQUE_VALUE = /^[A-Za-z0-9+/=_-]{16,}$/;
const PROTOCOL_ID = /^[a-zA-Z0-9_-]+$/;
const KNOWN_LABELS = new Set([
  "address", "credit-card", "email", "ip-address", "person", "phone", "ssn", "token",
  "account_number", "private_address", "private_email", "private_person",
  "private_phone", "private_url", "private_date", "secret",
]);

export async function createPrivacyFilter({ provision, paths, spawnWorker = defaultSpawnWorker, validateWorker = validatePrivacyWorkerAsset, validateCheckpoint = attestShieldCheckpoint, validateFile = validatePrivacyPinnedFile, timeoutMs, startupTimeoutMs } = {}) {
  const privacy = assertPrivacyProvision(provision);
  // Without lane paths (the self-test) the OPF worker keeps its cache in memory.
  const windowCacheArgs = privacy.checkpoint && paths !== undefined ? ["--window-cache-dir", laneWindowCachePath(paths)] : [];
  const startupBudgetMs = startupTimeoutMs ?? (privacy.checkpoint ? 60_000 : DEFAULT_STARTUP_TIMEOUT_MS);
  const scanTimeoutMs = timeoutMs ?? (privacy.checkpoint ? Number(privacy.worker.args[21]) + 1_000 : DEFAULT_TIMEOUT_MS);
  if (typeof spawnWorker !== "function") throw new TypeError("shield privacy worker launcher is required");
  if (typeof validateWorker !== "function") throw new TypeError("shield privacy worker validator is required");
  if (typeof validateCheckpoint !== "function") throw new TypeError("shield privacy checkpoint validator is required");
  if (typeof validateFile !== "function") throw new TypeError("shield privacy file validator is required");
  if (!Number.isInteger(scanTimeoutMs) || scanTimeoutMs < 1 || scanTimeoutMs > (privacy.checkpoint ? 241_000 : 30_000)) throw new TypeError("shield privacy worker timeout is invalid");
  if (!Number.isInteger(startupBudgetMs) || startupBudgetMs < 1 || startupBudgetMs > 60_000) throw new TypeError("shield privacy startup timeout is invalid");

  let assertCheckpointUnchanged;
  let assertSourceUnchanged;
  let current = null;
  let starting = null;
  let readiness = null;
  let active = null;
  const queue = [];
  const inflight = new Map();
  const recent = [];
  const totals = {
    scans: 0, ok: 0, unknown: 0, unavailable: 0, coalesced: 0, aborted: 0,
    failuresByReason: Object.fromEntries([...TOTAL_FAILURE_REASONS, "other"].map((reason) => [reason, 0])),
  };
  const count = (counts, key) => { counts[key] = Math.min(MAX_TOTAL, counts[key] + 1); };
  const tally = (result) => {
    count(totals, "scans");
    if (["ok", "unknown", "unavailable"].includes(result.status)) count(totals, result.status);
    if (result.reason === "aborted") count(totals, "aborted");
    else if (result.status !== "ok") count(totals.failuresByReason, TOTAL_FAILURE_REASONS.includes(result.reason) ? result.reason : "other");
    return result;
  };
  let closed = false;
  // A caller that goes away stops waiting at once. Its queued scan is dropped only when nobody else
  // still waits on it; an active scan always runs to completion so the worker is never interrupted.
  const addWaiter = (entry, resolve, signal) => {
    const waiter = {
      release(result) {
        signal?.removeEventListener("abort", abandon);
        resolve(result);
      },
    };
    const abandon = () => {
      if (!entry.waiters.delete(waiter)) return;
      waiter.release(unavailable("aborted"));
      const index = queue.indexOf(entry);
      if (entry.waiters.size === 0 && index !== -1) {
        queue.splice(index, 1);
        entry.settle(unavailable("aborted"));
      }
    };
    entry.waiters.add(waiter);
    signal?.addEventListener("abort", abandon, { once: true });
  };
  const failScans = (reason = "worker_unavailable") => {
    active?.settle(unavailable(reason));
    active = null;
    for (const entry of queue.splice(0)) entry.settle(unavailable(reason === "scan_timeout" ? "worker_unavailable" : reason));
  };
  const stopWorker = (session, reason = "worker_unavailable") => {
    if (!session || session.stopped) return;
    session.stopped = true;
    if (current === session) {
      current = null;
      failScans(reason);
    }
    failPending(session.pending, reason);
    try { session.worker.kill?.(); } catch {}
  };
  const close = (reason = "worker_closed") => {
    closed = true;
    stopWorker(current, reason);
    failScans(reason);
  };
  const request = async (session, message, deadlineMs) => {
    if (closed || !session || session.stopped || current !== session) return requestFailure("worker_unavailable");
    const id = randomUUID();
    const payload = JSON.stringify({ ...message, id, protocol: PROTOCOL });
    if (Buffer.byteLength(payload) > MAX_FRAME_BYTES) return requestFailure("frame_limit");
    return await new Promise((resolve) => {
      const timer = setTimeout(() => {
        session.pending.delete(id);
        resolve(requestFailure(message.type === "scan" ? "scan_timeout" : "worker_unavailable"));
        if (message.type === "scan") stopWorker(session, "scan_timeout");
      }, deadlineMs);
      session.pending.set(id, { expectedType: message.type, resolve: (reply) => { clearTimeout(timer); resolve(reply); } });
      try { session.worker.stdin.write(`${payload}\n`); } catch { stopWorker(session); }
    });
  };
  const waitForHealth = async (session) => {
    const health = await request(session, { type: "health" }, startupBudgetMs);
    session.ready = !closed && !session.stopped && current === session && validHealth(health, privacy.version);
    session.cooperativeTimeout = session.ready && Array.isArray(health.capabilities) && health.capabilities.includes("cooperative-timeout");
    if (!session.ready && !(current === session && !closed && recoveringHealth(health))) stopWorker(session);
    return session.ready;
  };
  // The full tree digest runs once per filter; respawns re-attest against its metadata snapshot.
  const startWorker = async (attempt) => {
    try {
      try { await validateWorker(privacy.worker); } catch { throw new Error("shield privacy worker unavailable"); }
      if (privacy.checkpoint) {
        if (assertCheckpointUnchanged) {
          try {
            await assertCheckpointUnchanged();
            await assertSourceUnchanged();
          } catch { throw new Error("shield privacy checkpoint changed"); }
        } else {
          let checkpointUnchanged;
          let sourceUnchanged;
          try { checkpointUnchanged = await validateCheckpoint(privacy.checkpoint); } catch { throw new Error("shield privacy checkpoint unavailable"); }
          if (typeof checkpointUnchanged !== "function") throw new Error("shield privacy checkpoint unavailable");
          try { sourceUnchanged = await validateCheckpoint(privacy.source, { label: "source" }); } catch { throw new Error("shield privacy source unavailable"); }
          if (typeof sourceUnchanged !== "function") throw new Error("shield privacy source unavailable");
          if (!assertCheckpointUnchanged) {
            assertCheckpointUnchanged = checkpointUnchanged;
            assertSourceUnchanged = sourceUnchanged;
          }
        }
        try {
          await validateFile(privacy.adapter, { label: "adapter" });
          await validateFile(privacy.tokenizer, { label: "tokenizer" });
        } catch { throw new Error("shield privacy pinned file unavailable"); }
      }
    } catch (error) { if (!attempt.expired) close("assets_invalid"); throw error; }
    if (closed || attempt.expired) return false;
    let worker;
    try {
      worker = spawnWorker({
        command: privacy.checkpoint ? process.execPath : privacy.worker.command,
        args: privacy.checkpoint ? [privacy.worker.command, ...privacy.worker.args, ...windowCacheArgs] : privacy.worker.args,
        shell: false,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch { return false; }
    if (!worker?.stdin || !worker?.stdout || typeof worker.stdin.write !== "function" || typeof worker.stdout.on !== "function") {
      try { worker?.kill?.(); } catch {}
      return false;
    }
    const session = { worker, pending: new Map(), stopped: false };
    attempt.session = session;
    current = session;
    let remainder = Buffer.alloc(0);
    let stderrBytes = 0;
    const failWorker = () => stopWorker(session);
    worker.once?.("error", failWorker);
    worker.once?.("exit", failWorker);
    worker.stdin.on?.("error", failWorker);
    worker.stdout.on("data", (chunk) => {
      if (closed || session.stopped || current !== session) return;
      const incomingBytes = Buffer.isBuffer(chunk) || chunk instanceof Uint8Array ? chunk.byteLength : Buffer.byteLength(chunk);
      if (incomingBytes > MAX_FRAME_BYTES || remainder.byteLength > MAX_FRAME_BYTES - incomingBytes) { stopWorker(session, "frame_limit"); return; }
      const next = Buffer.concat([remainder, Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)]);
      const lines = next.toString("utf8").split("\n");
      remainder = Buffer.from(lines.pop() ?? "");
      for (const line of lines) {
        if (!consumeReply(line, session.pending)) { stopWorker(session, "protocol_invalid"); return; }
      }
    });
    worker.stderr?.on?.("data", (chunk) => {
      if (session.stopped) return;
      stderrBytes += Buffer.byteLength(chunk);
      if (stderrBytes > MAX_FRAME_BYTES) stopWorker(session, "frame_limit");
    });
    return await waitForHealth(session);
  };
  const ensureWorker = async () => {
    if (closed) return false;
    if (starting) return await starting;
    if (current?.ready) return true;
    const attempt = { session: current, expired: false };
    let timer;
    const deadline = new Promise((resolve) => {
      timer = setTimeout(() => {
        attempt.expired = true;
        stopWorker(attempt.session);
        resolve(false);
      }, startupBudgetMs);
    });
    starting = Promise.race([current ? waitForHealth(current) : startWorker(attempt), deadline])
      .finally(() => { clearTimeout(timer); starting = null; });
    return await starting;
  };
  // Seconds until the backlog should clear: waiting plus active scans at the recent median scan time.
  const retryLater = (reason) => {
    const times = recent.map((scan) => scan.elapsedMs).sort((left, right) => left - right);
    const estimateMs = times.length === 0
      ? scanTimeoutMs
      : (queue.length + Number(active !== null)) * times[Math.floor(times.length / 2)];
    return Object.freeze({ ...unavailable(reason), retryAfterSeconds: Math.min(60, Math.max(1, Math.ceil(estimateMs / 1000))) });
  };
  const drain = async () => {
    if (closed || active || queue.length === 0) return;
    const entry = queue.shift();
    active = entry;
    clearTimeout(entry.timer);
    let result = unavailable("worker_unavailable");
    let cache = null;
    let segments = null;
    let detail = null;
    const dispatchedAt = Date.now();
    try {
      if (!await ensureWorker() || entry.settled) return;
      const session = current;
      if (assertCheckpointUnchanged) {
        try {
          await assertCheckpointUnchanged();
          await assertSourceUnchanged();
          await validateFile(privacy.adapter, { label: "adapter" });
          await validateFile(privacy.tokenizer, { label: "tokenizer" });
        } catch { close("assets_invalid"); return; }
      }
      if (entry.settled || closed || current !== session) return;
      const reply = await request(session, { type: "scan", body: entry.body.toString("base64") }, scanTimeoutMs);
      result = normalizeScanReply(reply);
      cache = windowCounts(reply);
      segments = segmentCounts(reply);
      detail = graphDetail(reply, result);
      // Only a worker that advertises cooperative timeouts keeps its model and window cache alive across model_timeout.
      if (result.status === "unknown" && (["model_killed", "model_error"].includes(result.reason) || (result.reason === "model_timeout" && !session.cooperativeTimeout))) session.ready = false;
    } catch {} finally {
      entry.settle(result);
      // Record what the caller actually received; close() or a stopped worker may have settled it first.
      const own = entry.outcome === result;
      recordScan(recent, {
        status: entry.outcome.status, reason: entry.outcome.reason ?? null, cache: own ? cache : null, segments: own ? segments : null,
        detail: own ? detail : null, attached: entry.attached, elapsedMs: Date.now() - dispatchedAt, queuedMs: dispatchedAt - entry.admittedAt,
      });
      if (active === entry) active = null;
      void drain();
    }
  };
  if (!await ensureWorker()) { close(); throw new Error("shield privacy worker unavailable"); }
  return Object.freeze({
    version: privacy.version,
    async isReady() {
      if (closed) return false;
      if (!current?.ready) {
        void ensureWorker().catch(() => {});
        return false;
      }
      if (!readiness) {
        const session = current;
        readiness = request(session, { type: "health" }, 750)
          .then((reply) => {
            const ready = !closed && !session.stopped && current === session && validHealth(reply, privacy.version);
            if (!ready) {
              session.ready = false;
              if (reply?.[REQUEST_FAILURE] !== true && !recoveringHealth(reply)) stopWorker(session, "protocol_invalid");
            }
            return ready;
          })
          .finally(() => { readiness = null; });
      }
      return await readiness;
    },
    scan: async (body, options) => tally(await scan(body, options)),
    // Numbers and allowlisted reasons only, so diagnostics can show cache behaviour without any content.
    recentScans: () => recent.map((scan) => ({ ...scan })),
    // Cumulative since start over a fixed key set, unlike the rolling recentScans window.
    scanTotals: () => ({ ...totals, failuresByReason: { ...totals.failuresByReason } }),
    close: () => close(),
  });

  async function scan(body, { signal } = {}) {
    if (closed) return unavailable("worker_closed");
    if (!validBody(body)) return unavailable("body_invalid");
    if (signal?.aborted) return unavailable("aborted");
    const digest = createHash("sha256").update(body).digest("hex");
    const shared = inflight.get(digest);
    // The digest only finds a candidate; the bytes decide, so a collision becomes a separate scan.
    if (shared && !shared.settled && shared.attached < MAX_ATTACHED_WAITERS && shared.body.equals(body)) {
      shared.attached += 1;
      count(totals, "coalesced");
      return await new Promise((resolve) => addWaiter(shared, resolve, signal));
    }
    if (queue.length + Number(active !== null) >= MAX_ADMITTED_SCANS) return retryLater("admission_limit");
    return await new Promise((resolve) => {
      const entry = {
        body: Buffer.from(body), settled: false, attached: 0, waiters: new Set(), admittedAt: Date.now(),
        settle(result) {
          if (entry.settled) return;
          entry.settled = true;
          entry.outcome = result;
          clearTimeout(entry.timer);
          entry.body = null;
          if (inflight.get(digest) === entry) inflight.delete(digest);
          for (const waiter of entry.waiters) waiter.release(ownCopy(result));
          entry.waiters.clear();
        },
      };
      if (!inflight.has(digest)) inflight.set(digest, entry);
      addWaiter(entry, resolve, signal);
      // Waiting has its own bounded deadline; scan time begins only at dispatch.
      entry.timer = setTimeout(() => {
        const index = queue.indexOf(entry);
        if (index !== -1) queue.splice(index, 1);
        entry.settle(retryLater("queue_timeout"));
      }, scanTimeoutMs);
      queue.push(entry);
      void drain();
    });
  }
}

export async function runPrivacyWorkerSelfTest(provision, { spawnWorker = defaultSpawnWorker, validateWorker = validatePrivacyWorkerAsset, validateCheckpoint = attestShieldCheckpoint, validateFile = validatePrivacyPinnedFile, timeoutMs, startupTimeoutMs } = {}) {
  const filter = await createPrivacyFilter({ provision, spawnWorker, validateWorker, validateCheckpoint, validateFile, timeoutMs, startupTimeoutMs });
  try {
    await probePrivacyFilter(filter, { opf: Boolean(provision?.privacy?.checkpoint) });
    return Object.freeze({ version: filter.version });
  } finally {
    filter.close();
  }
}

// Proves a running filter redacts a known email before anything relies on it.
export async function probePrivacyFilter(filter, { opf }) {
  const email = opf ? "alice@example.com" : "CCSHIELD_PRIVACY_PROTOCOL_PROBE_EMAIL";
  const original = Buffer.from(JSON.stringify({ content: email }));
  let result;
  try { result = await filter.scan(original); } catch { result = null; }
  if (!result || !isVerifiedRedaction({ original, result }) || !result.findings.some((finding) => finding.label === (opf ? "private_email" : "email")) || result.redactedBody.includes(email)) {
    throw new Error("shield privacy worker self-test failed");
  }
}

function consumeReply(line, pending) {
  let reply;
  try { reply = JSON.parse(line); } catch { return false; }
  if (!isPlainObject(reply) || typeof reply.id !== "string" || typeof reply.type !== "string") return false;
  const entry = pending.get(reply.id);
  if (!entry) return true;
  if (entry.expectedType !== reply.type) return false;
  pending.delete(reply.id);
  entry.resolve(reply);
  return true;
}

function failPending(pending, reason) {
  for (const entry of pending.values()) entry.resolve(requestFailure(reason));
  pending.clear();
}

function validHealth(reply, version) {
  return isPlainObject(reply) && reply.type === "health" && reply.protocol === PROTOCOL && reply.version === version;
}

// A worker backing off a failed model restart stays alive and answers health with exactly this shape.
function recoveringHealth(reply) {
  return isPlainObject(reply) && reply.type === "health" && reply.status === "unknown" && Object.keys(reply).length === 3;
}

function windowCounts(reply) {
  const cache = reply?.cache;
  const count = (value) => Number.isSafeInteger(value) && value >= 0 && value <= MAX_WINDOW_COUNT;
  return isPlainObject(cache) && count(cache.hits) && count(cache.misses) ? { hits: cache.hits, misses: cache.misses } : null;
}

function segmentCounts(reply) {
  const count = (value) => Number.isSafeInteger(value) && value >= 0 && value <= MAX_WINDOW_COUNT;
  return isPlainObject(reply) && count(reply.segmentHits) && count(reply.segmentMisses) ? { hits: reply.segmentHits, misses: reply.segmentMisses } : null;
}

// The adapter names which protocol-graph rule failed; only these values reach diagnostics.
function graphDetail(reply, result) {
  const graphFailure = result.status === "unknown" && GRAPH_REASONS.has(result.reason);
  return graphFailure && GRAPH_DETAILS.has(reply?.detail) ? reply.detail : null;
}

function ownCopy(result) {
  return Object.freeze({ ...result, ...(Buffer.isBuffer(result.redactedBody) ? { redactedBody: Buffer.from(result.redactedBody) } : {}) });
}

function recordScan(recent, { status, reason, cache, segments, detail, attached, elapsedMs, queuedMs }) {
  const boundedMs = (value) => Math.min(3_600_000, Math.max(0, Math.floor(value)));
  // elapsedMs is worker time from dispatch; queuedMs is the wait from admission to dispatch.
  recent.push({
    status, reason, ...(detail ? { detail } : {}), hits: cache?.hits ?? null, misses: cache?.misses ?? null,
    segmentHits: segments?.hits ?? null, segmentMisses: segments?.misses ?? null,
    attached: Math.min(MAX_ATTACHED_WAITERS, attached), elapsedMs: boundedMs(elapsedMs), queuedMs: boundedMs(queuedMs),
  });
  if (recent.length > RECENT_SCANS) recent.shift();
}

function normalizeScanReply(reply) {
  if (reply?.[REQUEST_FAILURE] === true) return unavailable(reply.reason);
  if (!isPlainObject(reply) || reply.type !== "scan" || typeof reply.status !== "string") return unavailable("reply_invalid");
  if (reply.status === "unknown") return Object.freeze({ status: "unknown", findings: Object.freeze([]), reason: ADAPTER_UNKNOWN_REASONS.has(reply.reason) ? reply.reason : "privacy_unavailable" });
  if (reply.status !== "ok" || !Array.isArray(reply.findings) || reply.findings.length > 128) return unavailable("reply_invalid");
  const findings = [];
  for (const finding of reply.findings) {
    if (!isPlainObject(finding) || !KNOWN_LABELS.has(finding.label) || !Number.isInteger(finding.count) || finding.count < 1 || finding.count > 1024) {
      return Object.freeze({ status: "unknown", findings: Object.freeze([]), reason: "findings_invalid" });
    }
    findings.push(Object.freeze({ label: finding.label, count: finding.count }));
  }
  const result = { status: "ok", findings: Object.freeze(findings) };
  if (reply.redactions !== undefined) {
    const redactions = normalizeRedactions(reply.redactions);
    if (redactions === null) return unavailable("redaction_invalid");
    result.redactions = redactions;
  }
  if (reply.redactedBody !== undefined) {
    const redactedBody = decodeRedactedBody(reply.redactedBody);
    if (redactedBody === null) return unavailable("redaction_invalid");
    result.redactedBody = redactedBody;
  }
  return Object.freeze(result);
}

function normalizeRedactions(value) {
  if (!Array.isArray(value) || value.length > 128) return null;
  const result = [];
  for (const entry of value) {
    if (!isPlainObject(entry) || !KNOWN_LABELS.has(entry.label) || !Number.isInteger(entry.count) || entry.count < 1 || entry.count > 1024) return null;
    const spans = entry.spans === undefined ? undefined : normalizeSpans(entry.spans, entry.count);
    if (spans === null) return null;
    result.push(Object.freeze({ label: entry.label, count: entry.count, ...(spans === undefined ? {} : { spans }) }));
  }
  return Object.freeze(result);
}

function normalizeSpans(value, count) {
  if (!Array.isArray(value) || value.length !== count) return null;
  const spans = [];
  for (const span of value) {
    if (!isPlainObject(span) || !Number.isInteger(span.start) || !Number.isInteger(span.end) || span.start < 0 || span.end <= span.start || span.end > MAX_BODY_BYTES) return null;
    spans.push(Object.freeze({ start: span.start, end: span.end }));
  }
  return Object.freeze(spans);
}

export function isVerifiedRedaction({ original, result } = {}) {
  if (!validBody(original) || result?.status !== "ok" || !Buffer.isBuffer(result.redactedBody) || result.redactedBody.equals(Buffer.from(original))) return false;
  if (!Array.isArray(result.findings) || !Array.isArray(result.redactions)) return false;
  const requiredCounts = new Map();
  for (const finding of result.findings) requiredCounts.set(finding.label, (requiredCounts.get(finding.label) ?? 0) + finding.count);
  const before = opaqueValues(Buffer.from(original));
  const after = opaqueValues(result.redactedBody);
  if (!before || !after || before.length !== after.length
    || before.some(([path, value], index) => after[index][0] !== path || after[index][1] !== value)) return false;
  // Provider-signed values travel unscanned, so an original value may survive only inside one of them.
  const visible = withoutTokens(result.redactedBody, new Set(after.map(([, value]) => JSON.stringify(value))));
  const counts = new Map();
  for (const redaction of result.redactions) {
    if (!Array.isArray(redaction.spans) || redaction.spans.length !== redaction.count) return false;
    for (const span of redaction.spans) {
      if (!Number.isInteger(span.start) || !Number.isInteger(span.end) || span.start < 0 || span.end <= span.start || span.end > original.byteLength) return false;
      const originalValue = Buffer.from(original).subarray(span.start, span.end);
      if (visible.includes(originalValue)) return false;
    }
    counts.set(redaction.label, (counts.get(redaction.label) ?? 0) + redaction.count);
  }
  return [...requiredCounts].every(([label, count]) => counts.get(label) >= count);
}

// Exact-path table shared in meaning with the OPF adapter's collectOpaqueValues; kept independent on purpose.
export function opaqueValues(body) {
  let root;
  try { root = JSON.parse(body.toString("utf8")); } catch { return null; }
  const entries = [];
  const add = (path, value, pattern = OPAQUE_VALUE) => { if (typeof value === "string" && pattern.test(value)) entries.push([path, value]); };
  const base64Source = (block, path) => {
    if (["image", "document"].includes(block?.type) && block?.source?.type === "base64") add(`${path}.source.data`, block.source.data);
  };
  const each = (value, visit) => { if (Array.isArray(value)) value.forEach(visit); };
  each(root?.messages, (message, messageIndex) => each(message?.content, (block, blockIndex) => {
    const path = `${messageIndex}.${blockIndex}`;
    const type = typeof block?.type === "string" ? block.type : undefined;
    base64Source(block, path);
    if (message.role === "user" && type === "tool_result") each(block.content, (nested, index) => base64Source(nested, `${path}.content.${index}`));
    if (message.role !== "assistant") return;
    if (type === "thinking") add(`${path}.signature`, block.signature);
    else if (type === "redacted_thinking") add(`${path}.data`, block.data);
    else if (type === "server_tool_use" || type === "mcp_tool_use") add(`${path}.id`, block.id, PROTOCOL_ID);
    else if (type?.endsWith("_tool_result") && type !== "tool_result") {
      add(`${path}.tool_use_id`, block.tool_use_id, PROTOCOL_ID);
      if (type === "web_search_tool_result") each(block.content, (item, index) => {
        if (item?.type === "web_search_result") add(`${path}.content.${index}.encrypted_content`, item.encrypted_content);
      });
    } else if (type === "text") each(block.citations, (citation, index) => {
      if (citation?.type === "web_search_result_location") add(`${path}.citations.${index}.encrypted_index`, citation.encrypted_index);
    });
  }));
  return entries;
}

// One pass over the body's string literals: a body with thousands of opaque entries must not stall the event loop.
// Tokens are ASCII JSON literals, so a latin1 view compares them exactly; a match nested in an escaped quote never counts.
function withoutTokens(body, tokens) {
  const pieces = [];
  let from = 0;
  for (let at = body.indexOf(0x22); at >= 0;) {
    let end = at + 1;
    while (end < body.length && body[end] !== 0x22) end += body[end] === 0x5c ? 2 : 1;
    if (end >= body.length) break;
    if (tokens.has(body.toString("latin1", at, end + 1))) {
      pieces.push(body.subarray(from, at));
      from = end + 1;
    }
    at = body.indexOf(0x22, end + 1);
  }
  pieces.push(body.subarray(from));
  return Buffer.concat(pieces.flatMap((piece, index) => index ? [Buffer.from([0]), piece] : [piece]));
}

function decodeRedactedBody(value) {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return null;
  const body = Buffer.from(value, "base64");
  if (body.byteLength === 0 || body.byteLength > MAX_BODY_BYTES) return null;
  try { JSON.parse(body.toString("utf8")); } catch { return null; }
  return Buffer.from(body);
}

function assertPrivacyProvision(provision) {
  const privacy = provision?.privacy;
  if (!isPlainObject(privacy) || !safeIdentifier(privacy.version) || !isPlainObject(privacy.worker)
    || !isAbsoluteCanonical(privacy.worker.command) || !Array.isArray(privacy.worker.args)
    || !privacy.worker.args.every((argument) => typeof argument === "string" && argument.length > 0 && argument.length <= 256)
    || !/^[a-f0-9]{64}$/.test(privacy.worker.sha256 ?? "")) {
    throw new TypeError("shield privacy provision is invalid");
  }
  if (privacy.checkpoint !== undefined && (!validTree(privacy.checkpoint) || !validTree(privacy.source)
    || !validPinnedFile(privacy.adapter) || privacy.adapter.path !== resolve(dirname(privacy.worker.command), "opf-adapter.mjs")
    || !validPinnedFile(privacy.tokenizer, true) || !isValidOpfWorkerArgs(privacy.worker.args, privacy))) {
    throw new TypeError("shield privacy provision is invalid");
  }
  return Object.freeze({
    version: privacy.version,
    worker: Object.freeze({ command: privacy.worker.command, args: Object.freeze([...privacy.worker.args]), sha256: privacy.worker.sha256 }),
    ...(privacy.checkpoint ? {
      checkpoint: Object.freeze({ ...privacy.checkpoint }),
      source: Object.freeze({ ...privacy.source }),
      adapter: Object.freeze({ ...privacy.adapter }),
      tokenizer: Object.freeze({ ...privacy.tokenizer }),
    } : {}),
  });
}

function validTree(value) {
  return isPlainObject(value) && Object.keys(value).sort().join(",") === "path,sha256,version"
    && isAbsoluteCanonical(value.path) && resolve(value.path) === value.path
    && /^[a-f0-9]{64}$/.test(value.sha256 ?? "") && safeIdentifier(value.version);
}

function validPinnedFile(value, tokenizer = false) {
  return isPlainObject(value) && Object.keys(value).sort().join(",") === (tokenizer ? "path,sha256,version" : "path,sha256")
    && isAbsoluteCanonical(value.path) && resolve(value.path) === value.path
    && /^[a-f0-9]{64}$/.test(value.sha256 ?? "")
    && (!tokenizer || (value.version === "o200k_base" && value.path.endsWith("/fb374d419588a4632f3f557e76b4b70aebbca790")));
}

async function validatePrivacyPinnedFile(asset, { label } = {}) {
  try {
    const [entry, canonical, bytes] = await Promise.all([lstat(asset.path), realpath(asset.path), readFile(asset.path)]);
    if (canonical !== asset.path || !entry.isFile() || entry.isSymbolicLink() || (entry.mode & 0o022) !== 0
      || (typeof process.getuid === "function" && entry.uid !== process.getuid())
      || createHash("sha256").update(bytes).digest("hex") !== asset.sha256) throw new Error("pinned file drift");
  } catch { throw new Error(`shield privacy ${label ?? "file"} validation failed`); }
}

export async function validatePrivacyWorkerAsset(worker, { io = { lstat, readFile, realpath } } = {}) {
  if (!isPlainObject(worker) || !isAbsolute(worker.command) || resolve(worker.command) !== worker.command || !/^[a-f0-9]{64}$/.test(worker.sha256 ?? "")) {
    throw new Error("shield privacy worker provision is invalid");
  }
  let entry;
  let canonicalPath;
  let bytes;
  try { [entry, canonicalPath, bytes] = await Promise.all([io.lstat(worker.command), io.realpath(worker.command), io.readFile(worker.command)]); }
  catch { throw new Error("shield privacy worker validation failed"); }
  if (canonicalPath !== worker.command || entry.isSymbolicLink?.() || !entry.isFile?.() || (entry.mode & 0o022) !== 0 || (entry.mode & 0o100) === 0
    || (typeof process.getuid === "function" && entry.uid !== process.getuid())
    || createHash("sha256").update(bytes).digest("hex") !== worker.sha256) {
    throw new Error("shield privacy worker validation failed");
  }
  return Object.freeze({ command: worker.command, sha256: worker.sha256 });
}

function validBody(body) { return (Buffer.isBuffer(body) || body instanceof Uint8Array) && body.byteLength <= MAX_BODY_BYTES; }
function unavailable(reason = "privacy_unavailable") { return Object.freeze({ status: "unavailable", findings: Object.freeze([]), reason }); }
function requestFailure(reason) { return { [REQUEST_FAILURE]: true, reason }; }
function safeIdentifier(value) { return typeof value === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(value); }
function isAbsoluteCanonical(value) { return typeof value === "string" && value.startsWith("/") && !value.includes("//") && !value.includes("/../") && !value.endsWith("/.."); }
function isPlainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
// The OPF worker's embedded Python reads only CCSHIELD_OPF_WARM_SECONDS, so the old name is mapped here.
export function privacyWorkerEnv(env = process.env) {
  const child = { ...env };
  const warm = readEnv(env, "CCSHIELD_OPF_WARM_SECONDS");
  delete child[envNamesFor("CCSHIELD_OPF_WARM_SECONDS")[1]];
  if (warm !== undefined) child.CCSHIELD_OPF_WARM_SECONDS = warm;
  return child;
}

function defaultSpawnWorker({ command, args, shell, stdio }) { return spawn(command, args, { shell, stdio, env: privacyWorkerEnv() }); }
