import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { readApprovalChannelRegistration, requestApprovalChannel } from "./approval-channel.mjs";
import { classifyShieldRequest } from "./classify.mjs";

const INSPECTION_MAX_BYTES = 1_048_576;
const DIAGNOSTICS_PATH = "/_airkit/shield/diagnostics";
const FAILURE_REASONS = new Map([
  ["body_read", new Set(["body_read_failed", "body_too_large"])],
  ["evaluation", new Set(["evaluation_unavailable"])],
  ["secret_scan", new Set(["scanner_unavailable"])],
  ["privacy_scan", new Set([
    "privacy_unavailable", "worker_closed", "body_invalid", "admission_limit", "frame_limit", "queue_timeout",
    "scan_timeout", "worker_unavailable", "protocol_invalid", "assets_invalid", "reply_invalid", "findings_invalid", "redaction_invalid",
    "invalid-prediction", "inconsistent-counts", "invalid-span", "unmapped-span", "cross-field-span",
    "inconsistent-quoting", "unmapped-finding", "redaction-too-large", "value-survived",
    "invalid-protocol-graph", "protocol-id-collision", "conflicting-protocol-context", "protocol-id-limit", "adapter-error",
    "protocol-graph-mutation", "protocol-control-mutation", "signed-block-mutation",
    "invalid-source-provenance", "json-key-collision", "invalid-json-topology",
    "model_timeout", "model_error", "model_killed",
    "redaction-projection-limit", "redaction-match-limit", "redaction-body-limit", "redaction-frame-limit",
  ])],
  ["policy", new Set(["policy_unavailable", "secret_block_invalid"])],
  ["redaction", new Set(["redaction_invalid"])],
  ["audit", new Set(["audit_unavailable"])],
  ["upstream", new Set(["target_unavailable", "transport_unavailable", "redirect_blocked"])],
]);
const INTERNAL_HEADERS = new Set([
  "connection",
  "content-length",
  "host",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "forwarded",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-original-url",
  "x-airkit-shield",
  "x-airkit-shield-control",
  "x-airkit-shield-approval",
  "x-airkit-shield-approval-socket",
]);

export async function startShieldProxy({ capability, controlCapability, targetOrigin, allowDestinationLeases = false, decide, decisionCache = null, decisionContext = null, approvalBroker = null, recordShieldDecision = null, onDecision = null, isReady = null, scanStats = null, now = Date.now, port = 0 } = {}) {
  assertCapability(capability);
  assertCapability(controlCapability);
  const target = targetOrigin === undefined && allowDestinationLeases ? null : assertFixedTarget(targetOrigin);
  if (typeof decide !== "function") throw new TypeError("shield proxy decision function is required");
  const record = resolveDecisionRecorder(recordShieldDecision, onDecision);
  if (approvalBroker !== null && (typeof approvalBroker?.request !== "function" || typeof approvalBroker?.consume !== "function")) {
    throw new TypeError("shield proxy approval broker is invalid");
  }
  if (isReady !== null && typeof isReady !== "function") throw new TypeError("shield proxy readiness function is invalid");
  if (typeof now !== "function") throw new TypeError("shield proxy clock is invalid");
  assertPort(port);
  if (scanStats !== null && typeof scanStats !== "function") throw new TypeError("shield scan stats source is invalid");

  if ((decisionCache === null) !== (decisionContext === null)) throw new TypeError("shield decision cache and identity must be configured together");
  if (decisionCache !== null && (typeof decisionCache.getOrCompute !== "function" || !validDecisionContext(decisionContext))) {
    throw new TypeError("shield decision cache configuration is invalid");
  }
  const approvalRegistration = { channel: null };
  const destinationLeases = new Map();
  const failures = [];
  const server = createServer((request, response) => {
    void handleShieldRequest({ request, response, capability, controlCapability, target, allowDestinationLeases, destinationLeases, decide, decisionCache, decisionContext, approvalBroker, recordShieldDecision: record, isReady, approvalRegistration, now, failures, scanStats });
  });
  await listenLoopback(server, port);
  const address = server.address();
  if (address === null || typeof address === "string" || address.address !== "127.0.0.1") {
    await closeServer(server);
    throw new Error("shield proxy did not expose a loopback listener");
  }
  return {
    origin: `http://127.0.0.1:${address.port}`,
    close: () => closeServer(server),
  };
}

async function handleShieldRequest({ request, response, capability, controlCapability, target, allowDestinationLeases, destinationLeases, decide, decisionCache, decisionContext, approvalBroker, recordShieldDecision, isReady, approvalRegistration, now, failures, scanStats }) {
  const startedAt = Date.now();
  const fail = (stage, reason, bytes = 0) => recordFailure(failures, { stage, reason, bytes, elapsedMs: Date.now() - startedAt });
  if (isDiagnosticsPath(request.url)) {
    request.resume();
    response.setHeader("cache-control", "no-store");
    if (!capabilityMatches(request.headers["x-airkit-shield-control"], controlCapability)) {
      await finish(response, { status: 401, code: "shield_unauthorized" }); return;
    }
    if (request.method !== "GET" || request.url !== DIAGNOSTICS_PATH) {
      await finish(response, { status: 403, code: "shield_blocked" }); return;
    }
    const body = Buffer.from(JSON.stringify({ failures, ...(scanStats ? { scans: scanStats() } : {}) }));
    response.writeHead(200, { "content-type": "application/json", "content-length": String(body.byteLength), "cache-control": "no-store" });
    response.end(body); return;
  }
  const isApprovalRegistration = request.url === "/_airkit/shield/approval-channel" && (request.method === "POST" || request.method === "DELETE");
  const isLeaseRequest = request.url === "/_airkit/shield/destination-lease" && (request.method === "POST" || request.method === "DELETE");
  if (isLeaseRequest) {
    if (!allowDestinationLeases || !capabilityMatches(request.headers["x-airkit-shield-control"], controlCapability)) { request.resume(); await finish(response, { status: 401, code: "shield_unauthorized" }); return; }
    const lease = await readDestinationLease(request, request.method === "POST", now);
    const current = request.method === "POST" ? destinationLeases.get(lease?.capability) ?? null : null;
    if (current !== null && current.expiresAt <= now()) destinationLeases.delete(lease.capability);
    if (
      lease === null
      || (request.method === "POST" && lease.renew && (current === null || current.expiresAt <= now()))
      || (request.method === "POST" && !lease.renew && current !== null && current.expiresAt > now())
    ) { await finish(response, { status: 403, code: "shield_blocked" }); return; }
    if (request.method === "POST") destinationLeases.set(lease.capability, {
      target: lease.target,
      expiresAt: lease.expiresAt,
      launcherContext: lease.launcherContext ?? current?.launcherContext ?? null,
    });
    else destinationLeases.delete(lease.capability);
    response.writeHead(204, { "cache-control": "no-store" }); response.end(); return;
  }
  const requestCapability = request.headers["x-airkit-shield"];
  const lease = allowDestinationLeases ? destinationLeases.get(String(requestCapability ?? "")) ?? null : null;
  if (lease !== null && lease.expiresAt <= now()) destinationLeases.delete(String(requestCapability ?? ""));
  const leaseTarget = lease !== null && lease.expiresAt > now() ? lease.target : null;
  if (!isApprovalRegistration && !capabilityMatches(requestCapability, capability) && leaseTarget === null) {
    request.resume();
    await finish(response, { status: 401, code: "shield_unauthorized" });
    return;
  }
  const requestTarget = leaseTarget ?? target;
  const launcherContext = leaseTarget === null ? null : lease?.launcherContext ?? null;

  if (request.method === "GET" && request.url === "/_airkit/shield/ready") {
    request.resume();
    try {
      if (isReady !== null && await isReady() !== true) {
        await finish(response, { status: 503, code: "shield_unavailable" });
        return;
      }
    } catch {
      await finish(response, { status: 503, code: "shield_unavailable" });
      return;
    }
    response.writeHead(204, { "cache-control": "no-store" });
    response.end();
    return;
  }

  if (isLivenessProbe(request.method, request.headers["content-length"])) {
    const probePath = safeProbePath(request.url);
    if (probePath !== null) {
      request.resume();
      const lifecycle = requestLifecycleSignal(request, response);
      if (lifecycle.signal.aborted) return;
      if (requestTarget === null) {
        fail("upstream", "target_unavailable");
        await finish(response, { status: 503, code: "shield_unavailable" });
        return;
      }
      try {
        const upstream = await fetch(new URL(probePath, requestTarget), {
          method: request.method,
          headers: forwardHeaders(request.headers),
          redirect: "manual",
          signal: lifecycle.signal,
        });
        if (upstream.status >= 300 && upstream.status < 400) {
          fail("upstream", "redirect_blocked");
          await discardResponse(upstream);
          await finish(response, { status: 503, code: "shield_unavailable" });
          return;
        }
        writeUpstreamHeaders(response, upstream);
        await streamResponse(upstream, response, lifecycle.signal);
      } catch {
        fail("upstream", "transport_unavailable");
        if (!response.headersSent) {
          await finish(response, { status: 503, code: "shield_unavailable" });
        } else if (!response.destroyed) {
          response.destroy();
        }
      }
      return;
    }
  }

  if (isApprovalRegistration) {
    if (!capabilityMatches(request.headers["x-airkit-shield-control"], controlCapability)) {
      request.resume();
      await finish(response, { status: 401, code: "shield_unauthorized" });
      return;
    }
    if (request.method === "DELETE") {
      request.resume();
      approvalRegistration.channel = null;
      response.writeHead(204, { "cache-control": "no-store" });
      response.end();
      return;
    }
    const channel = await readApprovalRegistration(request);
    if (channel === null || approvalRegistration.channel !== null) {
      await finish(response, { status: 403, code: "shield_blocked" });
      return;
    }
    approvalRegistration.channel = channel;
    response.writeHead(204, { "cache-control": "no-store" });
    response.end();
    return;
  }

  const path = safeMessagesPath(request.url);
  if (path === null) {
    request.resume();
    await finish(response, { status: 403, code: "shield_blocked" });
    return;
  }
  if (!hasIdentityContentEncoding(request.headers["content-encoding"])) {
    request.resume();
    await finish(response, { status: 403, code: "shield_blocked" });
    return;
  }

  const lifecycle = requestLifecycleSignal(request, response);
  if (lifecycle.signal.aborted) return;

  let inspection;
  try {
    inspection = await readInspection(request);
  } catch {
    fail("body_read", "body_read_failed");
    await finish(response, { status: 503, code: "shield_unavailable" });
    return;
  }
  if (inspection.tooLarge) {
    fail("body_read", "body_too_large", inspection.bytes);
    await finish(response, { status: 403, code: "shield_blocked" });
    return;
  }

  if (lifecycle.signal.aborted) return;
  let decision;
  try {
    const evaluate = async () => await decide({ method: request.method ?? "GET", path, bytes: inspection.bytes, body: inspection.body, signal: lifecycle.signal, launcherContext });
    decision = decisionCache === null || launcherContext !== null
      ? await evaluate()
      : await cachedDecision({ decisionCache, decisionContext, body: inspection.body, evaluate });
  } catch (error) {
    const failure = error?.shieldFailure;
    if (FAILURE_REASONS.get(failure?.stage)?.has(failure?.reason)) fail(failure.stage, failure.reason, inspection.bytes);
    else fail("evaluation", "evaluation_unavailable", inspection.bytes);
    await finish(response, { status: 503, code: "shield_unavailable" });
    return;
  }
  const auditDecision = buildDecisionMetadata(decision, startedAt);
  let forwardBody = inspection.body;
  let permitted = decision?.action === "allow";
  if (decision?.action === "redact") {
    const redactedBody = validateRedactedBody(decision.redactedBody);
    if (redactedBody === null) {
      fail("redaction", "redaction_invalid", inspection.bytes);
      await finish(response, { status: 503, code: "shield_unavailable" });
      return;
    }
    forwardBody = redactedBody;
    permitted = true;
  }
  if (decision?.action === "require_approval") {
    permitted = await approveRequest({ approvalBroker, approvalChannel: approvalRegistration.channel, decision, inspection, auditDecision, signal: lifecycle.signal });
    auditDecision.override = permitted;
  }
  try {
    await recordShieldDecision(auditDecision);
  } catch {
    fail("audit", "audit_unavailable", inspection.bytes);
    await finish(response, { status: 503, code: "shield_unavailable" });
    return;
  }
  if (!permitted) {
    await finish(response, { status: 403, code: "shield_blocked" });
    return;
  }
  if (lifecycle.signal.aborted) return;

  try {
    if (requestTarget === null) {
      fail("upstream", "target_unavailable", inspection.bytes);
      await finish(response, { status: 503, code: "shield_unavailable" }); return;
    }
    const upstream = await fetch(new URL(path, requestTarget), {
      method: request.method,
      headers: forwardHeaders(request.headers),
      body: request.method === "GET" || request.method === "HEAD" ? undefined : forwardBody,
      redirect: "manual",
      signal: lifecycle.signal,
    });
    if (upstream.status >= 300 && upstream.status < 400) {
      fail("upstream", "redirect_blocked", inspection.bytes);
      await discardResponse(upstream);
      await finish(response, { status: 503, code: "shield_unavailable" });
      return;
    }
    writeUpstreamHeaders(response, upstream);
    await streamResponse(upstream, response, lifecycle.signal);
  } catch {
    fail("upstream", "transport_unavailable", inspection.bytes);
    if (!response.headersSent) {
      await finish(response, { status: 503, code: "shield_unavailable" });
    } else if (!response.destroyed) {
      response.destroy();
    }
  }
}

function isDiagnosticsPath(value) {
  if (typeof value !== "string") return false;
  const paths = [value.split(/[?#]/, 1)[0]];
  try {
    paths.push(new URL(value, "http://shield.local").pathname);
  } catch {}
  return paths.some((path) => {
    if (path.startsWith(DIAGNOSTICS_PATH)) return true;
    try { return decodeURIComponent(path).startsWith(DIAGNOSTICS_PATH); }
    catch { return false; }
  });
}

function recordFailure(failures, { stage, reason, bytes, elapsedMs }) {
  if (!FAILURE_REASONS.get(stage)?.has(reason)) return;
  const bounded = (value, max) => Number.isFinite(value) ? Math.min(max, Math.max(0, Math.floor(value))) : 0;
  failures.push({ stage, reason, bytes: bounded(bytes, INSPECTION_MAX_BYTES), elapsedMs: bounded(elapsedMs, 3_600_000) });
  if (failures.length > 16) failures.shift();
}

export function createShieldFailure(stage, reason, message) {
  const defaults = {
    body_read: "body_read_failed", evaluation: "evaluation_unavailable", secret_scan: "scanner_unavailable",
    privacy_scan: "privacy_unavailable", policy: "policy_unavailable", redaction: "redaction_invalid",
    audit: "audit_unavailable", upstream: "transport_unavailable",
  };
  const safeStage = FAILURE_REASONS.has(stage) ? stage : "evaluation";
  const safeReason = FAILURE_REASONS.get(safeStage).has(reason) ? reason : defaults[safeStage];
  return Object.assign(new Error(message), { shieldFailure: { stage: safeStage, reason: safeReason } });
}

async function cachedDecision({ decisionCache, decisionContext, body, evaluate }) {
  const requestDigest = createHash("sha256").update(body).digest("hex");
  const key = { ...decisionContext, requestDigest };
  const result = await decisionCache.getOrCompute(key, async () => {
    const decision = await evaluate();
    const redactedBody = decision?.action === "redact" ? validateRedactedBody(decision.redactedBody) : Buffer.alloc(0);
    if (redactedBody === null) throw new Error("shield decision redaction is invalid");
    const action = decision?.action;
    const reasonCodes = validReasonCodes(decision?.reasonCodes)
      ? decision.reasonCodes
      : [action === "allow" ? "policy_allow" : "policy_blocked"];
    return { ...key, action, reasonCodes, transformCount: decision?.transformCount ?? 0, body: redactedBody };
  });
  if (!result || typeof result !== "object" || !["evaluated", "cache_hit", "coalesced"].includes(result.source)) {
    throw new Error("shield decision cache result provenance is invalid");
  }
  const cached = result.decision;
  return {
    action: cached.action,
    reasonCodes: cached.reasonCodes,
    transformCount: cached.transformCount,
    ...(cached.action === "redact" ? { redactedBody: cached.body } : {}),
    lane: decisionContext.lane,
    destinationClass: decisionContext.destinationClass,
    bundleVersion: decisionContext.policyVersion,
    detectorVersions: decisionContext.detectorVersions,
    decisionSource: result.source,
  };
}

async function readApprovalRegistration(request) {
  const chunks = [];
  let bytes = 0;
  try {
    for await (const chunk of request) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytes += buffer.byteLength;
      if (bytes > 16 * 1024) return null;
      chunks.push(buffer);
    }
    return readApprovalChannelRegistration(JSON.parse(Buffer.concat(chunks).toString("utf8")));
  } catch {
    return null;
  }
}

async function readDestinationLease(request, needsTarget, now = Date.now) {
  const chunks = [];
  let bytes = 0;
  try {
    for await (const chunk of request) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytes += buffer.byteLength;
      if (bytes > 4 * 1024) return null;
      chunks.push(buffer);
    }
    const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.capability !== "string" || !/^[A-Za-z0-9._-]{32,512}$/.test(value.capability)) return null;
    if (!needsTarget) return { capability: value.capability };
    const target = assertFixedTarget(value.targetOrigin);
    if (target.protocol !== "http:" || target.hostname !== "127.0.0.1") return null;
    if (!Number.isInteger(value.expiresAt) || value.expiresAt <= now() || value.expiresAt > now() + 120_000 || (value.renew !== undefined && value.renew !== true)) return null;
    let launcherContext = null;
    if (Object.hasOwn(value, "launcherContext")) {
      try { classifyShieldRequest({ body: Buffer.alloc(0), launcherContext: value.launcherContext }); } catch { return null; }
      launcherContext = value.launcherContext;
    }
    return { capability: value.capability, target, expiresAt: value.expiresAt, renew: value.renew === true, launcherContext };
  } catch { return null; }
}

async function discardResponse(upstream) {
  try { await upstream.body?.cancel(); } catch {}
}

function assertCapability(capability) {
  if (typeof capability !== "string" || capability.length < 32) throw new Error("shield proxy capability is missing or invalid");
}

function assertFixedTarget(targetOrigin) {
  let target;
  try { target = new URL(targetOrigin); } catch { target = null; }
  if (
    target === null ||
    (target.protocol !== "http:" && target.protocol !== "https:") ||
    target.username !== "" ||
    target.password !== "" ||
    target.pathname !== "/" ||
    target.search !== "" ||
    target.hash !== ""
  ) throw new Error("shield proxy target origin is invalid");
  return target;
}

function assertPort(port) {
  if (!Number.isInteger(port) || port < 0 || port > 65_535) throw new Error("shield proxy port must be an integer from 0 through 65535");
}

function capabilityMatches(value, expected) {
  const received = typeof value === "string" ? Buffer.from(value) : Buffer.alloc(0);
  const target = Buffer.from(expected);
  return received.byteLength === target.byteLength && timingSafeEqual(received, target);
}

function safeMessagesPath(value) {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || value.includes("\\")) return null;
  let target;
  try { target = new URL(value, "http://shield.local"); } catch { return null; }
  return target.pathname === "/v1/messages" ? `${target.pathname}${target.search}` : null;
}

function safeProbePath(value) {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || value.includes("\\")) return null;
  let target;
  try { target = new URL(value, "http://shield.local"); } catch { return null; }
  return `${target.pathname}${target.search}`;
}

function isLivenessProbe(method, contentLength) {
  if (method !== "HEAD" && method !== "GET" && method !== "OPTIONS") return false;
  if (contentLength === undefined) return true;
  const parsed = Number(contentLength);
  return Number.isInteger(parsed) && parsed === 0;
}

async function readInspection(request) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += buffer.byteLength;
    if (bytes > INSPECTION_MAX_BYTES) {
      request.resume();
      return { body: null, bytes, tooLarge: true };
    }
    chunks.push(buffer);
  }
  return { body: Buffer.concat(chunks), bytes, tooLarge: false };
}

function hasIdentityContentEncoding(value) {
  return value === undefined || (typeof value === "string" && value.trim().toLowerCase() === "identity");
}

function forwardHeaders(headers) {
  const forwarded = new Headers();
  for (const [name, value] of Object.entries(headers ?? {})) {
    if (INTERNAL_HEADERS.has(name.toLowerCase()) || value === undefined) continue;
    forwarded.set(name, Array.isArray(value) ? value.join(", ") : value);
  }
  return forwarded;
}

function writeUpstreamHeaders(response, upstream) {
  const headers = {};
  for (const [name, value] of upstream.headers) {
    const normalized = name.toLowerCase();
    if (normalized !== "content-encoding" && normalized !== "content-length" && !INTERNAL_HEADERS.has(normalized)) headers[name] = value;
  }
  response.writeHead(upstream.status, headers);
}

async function streamResponse(upstream, response, signal) {
  if (upstream.body === null) {
    response.end();
    return;
  }
  for await (const chunk of upstream.body) {
    if (!response.write(chunk)) await waitForDrain(response, signal);
  }
  response.end();
}

function requestLifecycleSignal(request, response) {
  const controller = new AbortController();
  const abort = () => {
    if (!controller.signal.aborted) controller.abort();
  };
  request.once("aborted", abort);
  request.once("error", abort);
  response.once("close", () => {
    if (response.writableFinished !== true) abort();
  });
  if (request.aborted === true || request.destroyed === true || response.destroyed === true) abort();
  return controller;
}

function waitForDrain(response, signal) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      response.off("drain", onDrain);
      response.off("close", onClose);
      response.off("error", onError);
      signal?.removeEventListener("abort", onAbort);
    };
    const onDrain = () => { cleanup(); resolve(); };
    const onClose = () => { cleanup(); reject(new Error("shield downstream closed")); };
    const onError = () => { cleanup(); reject(new Error("shield downstream failed")); };
    const onAbort = () => { cleanup(); reject(signal.reason ?? new Error("shield downstream aborted")); };
    response.once("drain", onDrain);
    response.once("close", onClose);
    response.once("error", onError);
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) onAbort();
    else if (response.destroyed) onClose();
  });
}

async function finish(response, { status, code }) {
  if (!response.headersSent) {
    const body = Buffer.from(JSON.stringify({ error: { code } }));
    response.writeHead(status, { "content-type": "application/json", "content-length": String(body.byteLength) });
    response.end(body);
  }
}

async function approveRequest({ approvalBroker, approvalChannel, decision, inspection, auditDecision, signal }) {
  if (signal.aborted) return false;
  const scope = {
    requestId: auditDecision.requestId,
    digest: createHash("sha256").update(inspection.body).digest("hex"),
    bundleVersion: auditDecision.bundleVersion,
    destinationClass: auditDecision.destinationClass,
    reasonCodes: auditDecision.reasonCodes,
    signal,
  };
  try {
    if (approvalChannel) return await requestApprovalChannel({ ...approvalChannel, scope });
    if (!approvalBroker) return false;
    const grant = await approvalBroker.request(scope);
    return grant !== null && approvalBroker.consume(grant, scope) === true;
  } catch {
    return false;
  }
}

function buildDecisionMetadata(decision, startedAt) {
  const action = decision?.action;
  const reasonCodes = validReasonCodes(decision?.reasonCodes)
    ? [...decision.reasonCodes]
    : [action === "allow" ? "policy_allow" : "policy_blocked"];
  return {
    requestId: safeIdentifier(decision?.requestId) ?? randomUUID(),
    lane: decision?.lane === "managed" || decision?.lane === "subscription" ? decision.lane : "unknown",
    destinationClass: decision?.destinationClass === "managed" || decision?.destinationClass === "subscription" ? decision.destinationClass : "unknown",
    bundleVersion: safeIdentifier(decision?.bundleVersion) ?? "unknown",
    detectorVersions: safeVersionMap(decision?.detectorVersions),
    action: action === "allow" || action === "block" || action === "redact" || action === "require_approval" ? action : "block",
    reasonCodes,
    transformCount: Number.isInteger(decision?.transformCount) && decision.transformCount >= 0 ? decision.transformCount : 0,
    decisionSource: ["evaluated", "cache_hit", "coalesced"].includes(decision?.decisionSource)
      ? decision.decisionSource
      : "evaluated",
    override: false,
    elapsedMs: Math.max(0, Date.now() - startedAt),
  };
}

function resolveDecisionRecorder(recordShieldDecision, onDecision) {
  const record = recordShieldDecision ?? onDecision;
  if (typeof record !== "function") return async () => { throw new Error("shield audit is unavailable"); };
  return record;
}

function validReasonCodes(value) {
  return Array.isArray(value) && value.length > 0 && value.length <= 32
    && value.every((code) => typeof code === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(code));
}

function validDecisionContext(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    && (value.lane === "managed" || value.lane === "subscription")
    && value.destinationClass === value.lane
    && safeIdentifier(value.policyVersion) !== null
    && safeVersionMap(value.detectorVersions) !== null
    && Object.keys(safeVersionMap(value.detectorVersions)).length > 0;
}

function safeIdentifier(value) {
  return typeof value === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(value) ? value : null;
}

function safeVersionMap(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return {};
  const entries = Object.entries(value);
  if (entries.length > 32 || entries.some(([name, version]) => safeIdentifier(name) === null || safeIdentifier(version) === null)) return {};
  return Object.fromEntries(entries);
}

function validateRedactedBody(value) {
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array) || value.byteLength === 0 || value.byteLength > INSPECTION_MAX_BYTES) return null;
  const body = Buffer.from(value);
  try { JSON.parse(body.toString("utf8")); } catch { return null; }
  return body;
}

function listenLoopback(server, port) {
  return new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, "127.0.0.1");
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
}
