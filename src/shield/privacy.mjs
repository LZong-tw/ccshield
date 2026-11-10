import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";

import { envNamesFor, readEnv } from "../compat-env.mjs";
import { attestShieldCheckpoint } from "./checkpoint.mjs";
import { OPF_MAX_SCAN_TIMEOUT_MS, OPF_OPEN_BUDGET_MS, isValidOpfWorkerArgs } from "./opf-args.mjs";
import { laneWindowCachePath } from "./paths.mjs";
import { BLOCK_LOCATION, isGraphFailureDetail, PRIVACY_PROTOCOL as PROTOCOL } from "./protocol.mjs";
const MAX_BODY_BYTES = 1_048_576;
const MAX_FRAME_BYTES = 4 * 1_048_576; // base64 redacted body (≤1 MiB → ~1.4 MiB) plus findings must fit
const DEFAULT_TIMEOUT_MS = 2_000;
const DEFAULT_STARTUP_TIMEOUT_MS = 60_000;
const MAX_ADMITTED_SCANS = 4;
const DISK_COUNTS = ["diskHits", "diskMisses", "diskWrites", "diskErrors"];
const MAX_ATTACHED_WAITERS = 8;
const RECENT_SCANS = 32;
const MAX_WINDOW_COUNT = 65_536;
const COOPERATIVE_TIMEOUTS = new Set(["model_timeout", "projected_timeout"]);
// A projected refusal that computed a window is resumed in place; each pass caches at least one more window.
const MAX_RESUMED_SCANS = 64;
const MAX_TOTAL = 4_294_967_295;
// A fixed key set keeps the diagnostics payload bounded; everything else lands in "other".
const TOTAL_FAILURE_REASONS = ["admission_limit", "queue_timeout", "scan_timeout", "model_timeout", "projected_timeout", "model_error", "model_killed", "worker_unavailable"];
const REQUEST_FAILURE = Symbol("privacy request failure");
const GRAPH_REASONS = new Set(["invalid-protocol-graph", "protocol-id-limit", "protocol-control-mutation", "signed-block-mutation"]);
// The adapter lists at most 16 label:block pairs left in signed thinking; diagnostics keep the first few.
const MAX_PASSTHROUGH_ENTRIES = 16;
const RECENT_PASSTHROUGH_ENTRIES = 4;
const ADAPTER_UNKNOWN_REASONS = new Set([
  "invalid-prediction", "prediction-span-limit", "inconsistent-counts", "invalid-span", "unmapped-span", "cross-field-span",
  "inconsistent-quoting", "unmapped-finding", "redaction-too-large", "value-survived",
  "invalid-protocol-graph", "protocol-id-collision", "conflicting-protocol-context", "protocol-id-limit", "adapter-error",
  "protocol-graph-mutation", "protocol-control-mutation", "signed-block-mutation",
  "invalid-source-provenance", "json-key-collision", "invalid-json-topology",
  "model_timeout", "projected_timeout", "model_error", "model_killed",
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
  const startupCapMs = privacy.checkpoint ? OPF_OPEN_BUDGET_MS : DEFAULT_STARTUP_TIMEOUT_MS;
  const startupBudgetMs = startupTimeoutMs ?? startupCapMs;
  // One budget per request, from admission to reply: queueing, startup and the scan all spend it.
  const scanTimeoutMs = timeoutMs ?? (privacy.checkpoint ? Number(privacy.worker.args[21]) : DEFAULT_TIMEOUT_MS);
  if (typeof spawnWorker !== "function") throw new TypeError("shield privacy worker launcher is required");
  if (typeof validateWorker !== "function") throw new TypeError("shield privacy worker validator is required");
  if (typeof validateCheckpoint !== "function") throw new TypeError("shield privacy checkpoint validator is required");
  if (typeof validateFile !== "function") throw new TypeError("shield privacy file validator is required");
  if (!Number.isInteger(scanTimeoutMs) || scanTimeoutMs < 1 || scanTimeoutMs > (privacy.checkpoint ? OPF_MAX_SCAN_TIMEOUT_MS : 30_000)) throw new TypeError("shield privacy worker timeout is invalid");
  if (!Number.isInteger(startupBudgetMs) || startupBudgetMs < 1 || startupBudgetMs > startupCapMs) throw new TypeError("shield privacy startup timeout is invalid");

  let assertCheckpointUnchanged;
  let assertSourceUnchanged;
  let current = null;
  let starting = null;
  // Why the latest start attempt gave up ("timeout", "spawn", "health" or
  // "assets"), so a refused construction can say which without carrying any
  // worker output.
  let startFailure = null;
  let readiness = null;
  let active = null;
  const queue = [];
  const inflight = new Map();
  const recent = [];
  const totals = {
    scans: 0, ok: 0, unknown: 0, unavailable: 0, coalesced: 0, aborted: 0,
    diskHits: 0, diskMisses: 0, diskWrites: 0, diskErrors: 0,
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
    } catch (error) {
      if (!attempt.expired) {
        startFailure = "assets";
        close("assets_invalid");
      }
      throw error;
    }
    if (closed || attempt.expired) return false;
    let worker;
    try {
      worker = spawnWorker({
        command: privacy.checkpoint ? process.execPath : privacy.worker.command,
        args: privacy.checkpoint ? [privacy.worker.command, ...privacy.worker.args, ...windowCacheArgs] : privacy.worker.args,
        shell: false,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch {
      startFailure = "spawn";
      return false;
    }
    if (!worker?.stdin || !worker?.stdout || typeof worker.stdin.write !== "function" || typeof worker.stdout.on !== "function") {
      try { worker?.kill?.(); } catch {}
      startFailure = "spawn";
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
    const healthy = await waitForHealth(session);
    // A worker that exits or answers health wrongly before the deadline.
    if (!healthy && !attempt.expired) startFailure = "health";
    return healthy;
  };
  const ensureWorker = async () => {
    if (closed) return false;
    if (starting) return await starting;
    if (current?.ready) return true;
    const attempt = { session: current, expired: false };
    startFailure = null;
    let timer;
    const deadline = new Promise((resolve) => {
      timer = setTimeout(() => {
        attempt.expired = true;
        startFailure = "timeout";
        stopWorker(attempt.session);
        resolve(false);
      }, startupBudgetMs);
    });
    starting = Promise.race([current ? waitForHealth(current) : startWorker(attempt), deadline])
      .finally(() => { clearTimeout(timer); starting = null; });
    return await starting;
  };
  // Median time of recent cold scans: mostly misses, or no window counts at all (the regex worker). Hot scans
  // finish from cache in a fraction of the time and would understate what a backlog costs.
  const coldMs = () => {
    const times = recent.filter((scan) => scan.hits === null || (scan.misses > 0 && scan.misses >= scan.hits))
      .map((scan) => scan.elapsedMs).sort((left, right) => left - right);
    return times.length === 0 ? null : times[Math.floor(times.length / 2)];
  };
  const retryAfter = (estimateMs) => Math.min(60, Math.max(1, Math.ceil(estimateMs / 1000)));
  // Seconds until the backlog should clear: waiting plus active scans at the cold median.
  const retryLater = (reason) => {
    const cold = coldMs();
    const estimateMs = cold === null ? scanTimeoutMs : (queue.length + Number(active !== null)) * cold;
    return Object.freeze({ ...unavailable(reason), retryAfterSeconds: retryAfter(estimateMs) });
  };
  // OPF scans can take minutes; refuse now, rather than at queue timeout, a scan that could not start within its
  // budget behind the cold work ahead of it. Without a cold sample nothing is projected.
  const projectedRefusal = () => {
    const cold = privacy.checkpoint && active !== null ? coldMs() : null;
    if (cold === null) return null;
    const now = Date.now();
    const activeEnd = Math.min(Math.max(now, (active.dispatchedAt ?? now) + cold), active.admittedAt + scanTimeoutMs);
    const startMs = activeEnd + queue.length * cold - now;
    return startMs > scanTimeoutMs ? Object.freeze({ ...unavailable("admission_limit"), retryAfterSeconds: retryAfter(startMs) }) : null;
  };
  const resumable = (entry, session, reply) => !closed && !entry.settled && entry.waiters.size > 0 && queue.length === 0
    && current === session && session.ready && session.cooperativeTimeout && !session.stopped
    && reply?.type === "scan" && reply.status === "unknown" && reply.reason === "projected_timeout" && windowCounts(reply)?.misses > 0;
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
    entry.dispatchedAt = dispatchedAt;
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
      let reply;
      if (privacy.checkpoint) {
        // OPF spends one budget from admission: queueing and model startup count. The worker enforces it and
        // kills Python at budget + 5 s; this deadline only backs that up.
        const budgetMs = entry.admittedAt + scanTimeoutMs - Date.now();
        if (budgetMs <= 0) { result = retryLater("queue_timeout"); return; }
        reply = await request(session, { type: "scan", body: entry.body.toString("base64"), budgetMs }, budgetMs + 6_000);
        cache = windowCounts(reply);
        // A projected refusal hands back budget the caller already granted. While the caller still waits, nobody
        // is queued behind it and the pass cached a window, scan the same body again on what is left instead of
        // answering 503: an idle worker would spend that time warming this body anyway. Only a complete scan
        // comes back ok, so a resumed body is never forwarded unscanned.
        for (let resumed = 0; resumed < MAX_RESUMED_SCANS && resumable(entry, session, reply); resumed += 1) {
          const remainingMs = entry.admittedAt + scanTimeoutMs - Date.now();
          if (remainingMs <= 0) break;
          reply = await request(session, { type: "scan", body: entry.body.toString("base64"), budgetMs: remainingMs }, remainingMs + 6_000);
          cache = addWindowCounts(cache, windowCounts(reply));
        }
      } else {
        reply = await request(session, { type: "scan", body: entry.body.toString("base64") }, scanTimeoutMs);
        cache = windowCounts(reply);
      }
      result = normalizeScanReply(reply);
      segments = segmentCounts(reply);
      detail = graphDetail(reply, result);
      // The caller's failure log needs the rule too, or a fail-closed refusal is indistinguishable from the next.
      if (detail) result = Object.freeze({ ...result, detail });
      // Only a worker that advertises cooperative timeouts keeps its model and window cache alive across model_timeout.
      if (result.status === "unknown" && (["model_killed", "model_error"].includes(result.reason) || (COOPERATIVE_TIMEOUTS.has(result.reason) && !session.cooperativeTimeout))) session.ready = false;
    } catch {} finally {
      entry.settle(result);
      // Record what the caller actually received; close() or a stopped worker may have settled it first.
      const own = entry.outcome === result;
      if (own && cache) for (const name of DISK_COUNTS) if (cache[name] !== undefined) totals[name] = Math.min(MAX_TOTAL, totals[name] + cache[name]);
      recordScan(recent, {
        status: entry.outcome.status, reason: entry.outcome.reason ?? null, cache: own ? cache : null, segments: own ? segments : null,
        detail: own ? detail : null, passthrough: own ? result.passthrough ?? null : null, attached: entry.attached, elapsedMs: Date.now() - dispatchedAt, queuedMs: dispatchedAt - entry.admittedAt,
      });
      if (active === entry) active = null;
      void drain();
    }
  };
  const refused = (error) => Object.assign(error, { opf: Boolean(privacy.checkpoint), ...(startFailure ? { startFailure } : {}) });
  let started;
  try {
    started = await ensureWorker();
  } catch (error) {
    // startWorker only throws its own fixed-message errors (attestation, pinned files).
    close();
    throw refused(error);
  }
  if (!started) {
    close();
    throw refused(new Error("shield privacy worker unavailable"));
  }
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
    const refusal = projectedRefusal();
    if (refusal) return refusal;
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
          // Every failure carries its queue wait so the daemon's failure log can tell queueing from model time.
          // An entry that never left the queue (queue timeout, worker loss) waited until now. Coalesced waiters
          // receive the first requester's wait.
          const delivered = result.status === "ok" ? result : Object.freeze({ ...result, queuedMs: (entry.dispatchedAt ?? Date.now()) - entry.admittedAt });
          for (const waiter of entry.waiters) waiter.release(ownCopy(delivered));
          entry.waiters.clear();
        },
      };
      if (!inflight.has(digest)) inflight.set(digest, entry);
      addWaiter(entry, resolve, signal);
      // Waiting has its own bounded deadline; for OPF it is the same budget the scan later runs on.
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
  if (!isPlainObject(cache) || !count(cache.hits) || !count(cache.misses)) return null;
  const disk = Object.fromEntries(DISK_COUNTS.filter((name) => count(cache[name])).map((name) => [name, cache[name]]));
  return { hits: cache.hits, misses: cache.misses, ...disk };
}

// A resumed pass re-hits every window the earlier passes cached, so hits stay those the request found on arrival;
// misses and the disk writes and errors add up to the windows this request computed.
function addWindowCounts(total, next) {
  if (total === null || next === null) return next ?? total;
  const merge = (name) => ["hits", "diskHits"].includes(name) || next[name] === undefined
    ? total[name]
    : Math.min(MAX_WINDOW_COUNT, (total[name] ?? 0) + next[name]);
  return Object.fromEntries(["hits", "misses", ...DISK_COUNTS].map((name) => [name, merge(name)]).filter(([, value]) => value !== undefined));
}

function segmentCounts(reply) {
  const count = (value) => Number.isSafeInteger(value) && value >= 0 && value <= MAX_WINDOW_COUNT;
  return isPlainObject(reply) && count(reply.segmentHits) && count(reply.segmentMisses) ? { hits: reply.segmentHits, misses: reply.segmentMisses } : null;
}

// The adapter names which protocol-graph rule failed; only these values reach diagnostics.
function graphDetail(reply, result) {
  const graphFailure = result.status === "unknown" && GRAPH_REASONS.has(result.reason);
  return graphFailure && isGraphFailureDetail(reply?.detail) ? reply.detail : null;
}

function ownCopy(result) {
  return Object.freeze({ ...result, ...(Buffer.isBuffer(result.redactedBody) ? { redactedBody: Buffer.from(result.redactedBody) } : {}) });
}

function recordScan(recent, { status, reason, cache, segments, detail, passthrough, attached, elapsedMs, queuedMs }) {
  const boundedMs = (value) => Math.min(3_600_000, Math.max(0, Math.floor(value)));
  // elapsedMs is worker time from dispatch; queuedMs is the wait from admission to dispatch.
  recent.push({
    status, reason, ...(detail ? { detail } : {}),
    ...(passthrough ? { passthrough: passthrough.slice(0, RECENT_PASSTHROUGH_ENTRIES).map((entry) => ({ ...entry })) } : {}), hits: cache?.hits ?? null, misses: cache?.misses ?? null, diskHits: cache?.diskHits ?? null,
    segmentHits: segments?.hits ?? null, segmentMisses: segments?.misses ?? null,
    attached: Math.min(MAX_ATTACHED_WAITERS, attached), elapsedMs: boundedMs(elapsedMs), queuedMs: boundedMs(queuedMs),
  });
  if (recent.length > RECENT_SCANS) recent.shift();
}

function normalizeScanReply(reply) {
  if (reply?.[REQUEST_FAILURE] === true) return unavailable(reply.reason);
  if (!isPlainObject(reply) || reply.type !== "scan" || typeof reply.status !== "string") return unavailable("reply_invalid");
  if (reply.status === "unknown") {
    const reason = ADAPTER_UNKNOWN_REASONS.has(reply.reason) ? reply.reason : "privacy_unavailable";
    const retry = COOPERATIVE_TIMEOUTS.has(reason) && Number.isInteger(reply.retryAfterSeconds) && reply.retryAfterSeconds >= 1 && reply.retryAfterSeconds <= 60;
    return Object.freeze({ status: "unknown", findings: Object.freeze([]), reason, ...(retry ? { retryAfterSeconds: reply.retryAfterSeconds } : {}) });
  }
  if (reply.status !== "ok" || !Array.isArray(reply.findings) || reply.findings.length > 128) return unavailable("reply_invalid");
  const findings = [];
  for (const finding of reply.findings) {
    if (!isPlainObject(finding) || !KNOWN_LABELS.has(finding.label) || !Number.isInteger(finding.count) || finding.count < 1 || finding.count > 1024) {
      return Object.freeze({ status: "unknown", findings: Object.freeze([]), reason: "findings_invalid" });
    }
    findings.push(Object.freeze({ label: finding.label, count: finding.count }));
  }
  const result = { status: "ok", findings: Object.freeze(findings) };
  // Diagnostics only: a malformed list is dropped rather than failing a scan that is otherwise ok.
  const passthrough = normalizePassthrough(reply.passthrough);
  if (passthrough) result.passthrough = passthrough;
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

function normalizePassthrough(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_PASSTHROUGH_ENTRIES) return null;
  const entries = [];
  for (const entry of value) {
    if (!isPlainObject(entry) || Object.keys(entry).length !== 3 || !KNOWN_LABELS.has(entry.label) || typeof entry.at !== "string" || !BLOCK_LOCATION.test(entry.at)
      || !Number.isInteger(entry.count) || entry.count < 1 || entry.count > MAX_BODY_BYTES) return null;
    entries.push(Object.freeze({ label: entry.label, at: entry.at, count: entry.count }));
  }
  return Object.freeze(entries);
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
  const before = protectedValues(Buffer.from(original));
  const after = protectedValues(result.redactedBody);
  if (!before || !after || before.length !== after.length
    || before.some(([path, value], index) => after[index][0] !== path || after[index][1] !== value)) return false;
  // Provider-signed values travel unscanned, signed thinking and control names must reach the API unchanged,
  // so an original value may survive only inside one of them. Each protected entry hides one literal, never
  // every literal equal to it: a prose block that merely repeats a tool name is still checked.
  const tokens = new Map();
  for (const [, value] of after) {
    const token = Buffer.from(JSON.stringify(value)).toString("latin1");
    tokens.set(token, (tokens.get(token) ?? 0) + 1);
  }
  const visible = withoutTokens(result.redactedBody, tokens);
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

function protectedValues(body) {
  const opaque = opaqueValues(body);
  const names = opaque && controlNames(body);
  const thinking = names && signedThinking(body, new Set(opaque.map(([path]) => path)));
  return thinking && [...opaque, ...names, ...thinking];
}

// Assistant thinking whose signature is shaped like a provider token (the same OPAQUE_VALUE test as
// opaqueValues), which the API checks against that signature and so must arrive byte-identical; the OPF
// adapter leaves it untouched. A signature already listed as opaque is not repeated.
export function signedThinking(body, opaquePaths = new Set()) {
  let root;
  try { root = JSON.parse(body.toString("utf8")); } catch { return null; }
  const entries = [];
  const each = (value, visit) => { if (Array.isArray(value)) value.forEach(visit); };
  each(root?.messages, (message, messageIndex) => each(message?.content, (block, blockIndex) => {
    if (message?.role !== "assistant" || block?.type !== "thinking" || typeof block.signature !== "string" || !OPAQUE_VALUE.test(block.signature)) return;
    const path = `${messageIndex}.${blockIndex}`;
    if (typeof block.thinking === "string") entries.push([`${path}.thinking`, block.thinking]);
    if (!opaquePaths.has(`${path}.signature`)) entries.push([`${path}.signature`, block.signature]);
  }));
  return entries;
}

// Names the API resolves against each other (a tool definition, the tool_choice and tool_use blocks naming it)
// plus the model. The OPF adapter pins these; a finding they happen to repeat stays, the name never changes.
export function controlNames(body) {
  let root;
  try { root = JSON.parse(body.toString("utf8")); } catch { return null; }
  const entries = [];
  const add = (path, value) => { if (typeof value === "string") entries.push([path, value]); };
  const each = (value, visit) => { if (Array.isArray(value)) value.forEach(visit); };
  add("model", root?.model);
  each(root?.tools, (tool, index) => add(`tools.${index}.name`, tool?.name));
  add("tool_choice.name", root?.tool_choice?.name);
  each(root?.messages, (message, messageIndex) => each(message?.content, (block, blockIndex) => {
    if (["tool_use", "server_tool_use"].includes(block?.type)) add(`${messageIndex}.${blockIndex}.name`, block.name);
  }));
  return entries;
}

// One pass over the body's string literals: a body with thousands of opaque entries must not stall the event loop.
// tokens maps each literal to how many occurrences to drop; occurrences past that count stay visible.
// Tokens are the UTF-8 bytes of JSON.stringify(value) read as latin1, so a latin1 view of the body compares them
// exactly; a literal escaped differently stays visible (fail closed), and a match nested in an escaped quote never counts.
function withoutTokens(body, tokens) {
  const pieces = [];
  let from = 0;
  for (let at = body.indexOf(0x22); at >= 0;) {
    let end = at + 1;
    while (end < body.length && body[end] !== 0x22) end += body[end] === 0x5c ? 2 : 1;
    if (end >= body.length) break;
    const token = body.toString("latin1", at, end + 1);
    const left = tokens.get(token);
    if (left) {
      tokens.set(token, left - 1);
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
