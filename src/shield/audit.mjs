import { createAuditEvent, validateAuditEvent } from "../audit/event.mjs";
import { encryptAuditValue } from "../audit/crypto.mjs";

const ACTIONS = new Set(["allow", "block", "redact", "require_approval", "unavailable", "unauthorized", "transition"]);
const LANES = new Set(["managed", "subscription", "unknown"]);
const DESTINATION_CLASSES = new Set(["managed", "subscription", "unknown"]);
const DECISION_KEYS = ["action", "bundleVersion", "decisionSource", "destinationClass", "detectorVersions", "elapsedMs", "lane", "override", "reasonCodes", "requestId", "transformCount"];
const DECISION_SOURCES = new Set(["evaluated", "cache_hit", "coalesced"]);
// Optional on decisions only; omitted keys stay absent so pre-media auditd keeps accepting the event.
const MEDIA_KEYS = Object.freeze({
  imageVersion: "image_version",
  imageCount: "image_count",
  imageTransformCount: "image_transform_count",
  documentCount: "document_count",
  mediaOutcome: "media_outcome",
});

export function buildShieldDecisionEvent(decision, { now = () => new Date() } = {}) {
  return buildShieldEvent("shield_decision", decision, { now });
}

export function buildShieldPolicyTransitionEvent(transition, { now = () => new Date() } = {}) {
  return buildShieldEvent("shield_policy_transition", transition, { now });
}

function buildShieldEvent(eventKind, decision, { now }) {
  const metadata = assertShieldDecisionMetadata(decision, { media: eventKind === "shield_decision" });
  const observedAt = now();
  if (!(observedAt instanceof Date) || Number.isNaN(observedAt.getTime())) throw new TypeError("shield audit clock is invalid");
  const event = createAuditEvent({
    source: "airkit-shield",
    source_version: "1",
    logical_request_id: metadata.requestId,
    client: "airkit-shield",
    event_kind: eventKind,
    observed_at: observedAt.toISOString(),
    payload: {
      lane: metadata.lane,
      destination_class: metadata.destinationClass,
      policy_version: metadata.bundleVersion,
      gitleaks_version: metadata.detectorVersions.gitleaks ?? "unknown",
      privacy_version: metadata.detectorVersions.privacy ?? "unknown",
      action: metadata.action,
      reasons: metadata.reasonCodes,
      transform_count: metadata.transformCount,
      decision_source: metadata.decisionSource,
      override: metadata.override,
      elapsed_ms: metadata.elapsedMs,
      ...Object.fromEntries(Object.entries(MEDIA_KEYS)
        .filter(([key]) => Object.hasOwn(metadata, key))
        .map(([key, column]) => [column, metadata[key]])),
    },
  });
  // The ack path has no spool to validate for us; refuse here rather than let auditd reject it later.
  validateAuditEvent(event);
  return event;
}

export function createShieldDecisionRecorder({ client = null, spool = null, masterKey = null, now } = {}) {
  if (client !== null && typeof client?.send !== "function") throw new TypeError("shield audit client is invalid");
  if (client !== null && (masterKey === null || masterKey === undefined)) throw new TypeError("shield audit transport requires a master key");
  if (spool !== null && (typeof spool?.stats !== "function" || typeof spool?.enqueue !== "function")) {
    throw new TypeError("shield audit spool is invalid");
  }

  return Object.freeze({
    async isReady() {
      if (!spool) return client !== null;
      try {
        return (await spool.stats())?.atCapacity !== true;
      } catch {
        return false;
      }
    },
    async recordShieldDecision(decision) {
      return persistShieldEvent(buildShieldDecisionEvent(decision, { now }), { client, spool, masterKey });
    },
    async recordShieldPolicyTransition(transition) {
      return persistShieldEvent(buildShieldPolicyTransitionEvent(transition, { now }), { client, spool, masterKey });
    },
  });
}

async function persistShieldEvent(event, { client, spool, masterKey }) {
  if (client) {
    try {
      const ack = await client.send(encryptShieldDecisionEvent(event, masterKey));
      if (ack?.status === "committed" || ack?.status === "duplicate") return Object.freeze({ durable: "ack" });
    } catch {
      // A trusted encrypted spool may provide the only durable fallback.
    }
  }
  if (!spool) throw unavailable();
  try {
    const state = await spool.stats();
    if (state?.atCapacity === true) throw unavailable();
    const entry = await spool.enqueue(event);
    if (entry?.event?.event_id !== event.event_id) throw unavailable();
    return Object.freeze({ durable: "spool" });
  } catch (error) {
    if (error?.code === "AIRKIT_SHIELD_AUDIT_UNAVAILABLE") throw error;
    throw unavailable();
  }
}

function encryptShieldDecisionEvent(event, masterKey) {
  return Object.freeze({
    event_id: event.event_id,
    encrypted: encryptAuditValue({
      masterKey,
      purpose: "request-evidence/v1",
      identity: event.event_id,
      plaintext: Buffer.from(JSON.stringify(event), "utf8"),
    }),
  });
}

export async function recordShieldDecision(decision, dependencies) {
  return createShieldDecisionRecorder(dependencies).recordShieldDecision(decision);
}

export function assertShieldDecisionMetadata(value, { media = false } = {}) {
  const normalized = isPlainObject(value) && !Object.hasOwn(value, "decisionSource")
    ? { ...value, decisionSource: "evaluated" }
    : value;
  if (!isPlainObject(normalized) || !hasAllowedKeys(normalized, DECISION_KEYS, media ? Object.keys(MEDIA_KEYS) : [])
    || typeof normalized.requestId !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(normalized.requestId)
    || !LANES.has(normalized.lane) || !DESTINATION_CLASSES.has(normalized.destinationClass)
    || typeof normalized.bundleVersion !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(normalized.bundleVersion)
    || !isVersionMap(normalized.detectorVersions) || !ACTIONS.has(normalized.action)
    || !validReasonCodes(normalized.reasonCodes) || !Number.isInteger(normalized.transformCount) || normalized.transformCount < 0 || normalized.transformCount > 1_000_000
    || !DECISION_SOURCES.has(normalized.decisionSource)
    || typeof normalized.override !== "boolean" || !Number.isFinite(normalized.elapsedMs) || normalized.elapsedMs < 0 || normalized.elapsedMs > 3_600_000) {
    throw new TypeError("shield decision metadata is invalid");
  }
  return Object.freeze({
    requestId: normalized.requestId,
    lane: normalized.lane,
    destinationClass: normalized.destinationClass,
    bundleVersion: normalized.bundleVersion,
    detectorVersions: Object.freeze({ ...normalized.detectorVersions }),
    action: normalized.action,
    reasonCodes: Object.freeze([...normalized.reasonCodes]),
    transformCount: normalized.transformCount,
    decisionSource: normalized.decisionSource,
    override: normalized.override,
    elapsedMs: normalized.elapsedMs,
    ...Object.fromEntries(Object.keys(MEDIA_KEYS)
      .filter((key) => Object.hasOwn(normalized, key))
      .map((key) => [key, normalized[key]])),
  });
}

function unavailable() {
  const error = new Error("shield audit is unavailable");
  error.code = "AIRKIT_SHIELD_AUDIT_UNAVAILABLE";
  return error;
}

function hasAllowedKeys(value, required, optional) {
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => allowed.has(key));
}

function validReasonCodes(value) {
  return Array.isArray(value) && value.length > 0 && value.length <= 32
    && value.every((code) => typeof code === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(code));
}

function isVersionMap(value) {
  return isPlainObject(value) && Object.keys(value).length <= 32
    && Object.entries(value).every(([name, version]) => /^[A-Za-z0-9._-]{1,128}$/.test(name)
      && typeof version === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(version));
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}
