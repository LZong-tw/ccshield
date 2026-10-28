import { randomUUID } from "node:crypto";

export const SHIELD_EVENT_SCHEMA = "ccshield.audit/v1";
const EVENT_KINDS = new Set(["shield_decision", "shield_policy_transition"]);
const EVENT_KEYS = ["event_id", "event_kind", "logical_request_id", "observed_at", "payload", "schema", "session_id"];
const MAX_EVIDENCE_CHARS = 16 * 1024 * 1024;
const ACTIONS = new Set(["allow", "block", "redact", "require_approval", "unavailable", "unauthorized", "transition"]);
const LANES = new Set(["managed", "subscription", "unknown"]);
const DESTINATION_CLASSES = new Set(["managed", "subscription", "unknown"]);
const DECISION_KEYS = ["action", "bundleVersion", "decisionSource", "destinationClass", "detectorVersions", "elapsedMs", "lane", "override", "reasonCodes", "requestId", "transformCount"];
const DECISION_SOURCES = new Set(["evaluated", "cache_hit", "coalesced"]);
// Optional on decisions only; omitted keys stay absent and store as NULL.
const MEDIA_KEYS = Object.freeze({
  imageVersion: "image_version",
  imageCount: "image_count",
  imageTransformCount: "image_transform_count",
  documentCount: "document_count",
  mediaOutcome: "media_outcome",
});
const MEDIA_COUNT_KEYS = ["imageCount", "imageTransformCount", "documentCount"];
// The store's media_outcome CHECK must accept every value here (test/store-media-outcome.test.mjs).
export const MEDIA_OUTCOMES = Object.freeze(new Set(["none", "blocked_document", "blocked_source", "blocked_scan", "blocked_secret", "scanned", "unscanned_override"]));
// Set by provisioning from the worker source digest; anything else could smuggle an id or secret into the row.
const IMAGE_VERSION = /^image-[0-9a-f]{12}$/;

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
  const event = {
    schema: SHIELD_EVENT_SCHEMA,
    event_id: randomUUID(),
    event_kind: eventKind,
    logical_request_id: metadata.requestId,
    session_id: metadata.sessionId ?? null,
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
  };
  validateShieldEvent(event);
  return Object.freeze(event);
}

// The store is the only sink. A failed write throws so the proxy fails closed
// instead of forwarding a request it could not account for.
export function createShieldDecisionRecorder({ store, now } = {}) {
  if (typeof store?.recordEvent !== "function") throw new TypeError("shield audit store is invalid");
  let healthy = true;

  const persist = (event, evidence) => {
    try {
      store.recordEvent(event, evidence);
      healthy = true;
      return Object.freeze({ durable: "store", eventId: event.event_id });
    } catch {
      healthy = false;
      throw unavailable();
    }
  };

  return Object.freeze({
    async isReady() {
      return healthy;
    },
    // `evidence` holds the original and forwarded text of a redacted request.
    // It is encrypted at rest and is never part of the metadata event.
    async recordShieldDecision(decision, evidence = null) {
      const event = buildShieldDecisionEvent(decision, { now });
      return persist(event, normalizeEvidence(evidence));
    },
    async recordShieldPolicyTransition(transition) {
      return persist(buildShieldPolicyTransitionEvent(transition, { now }), null);
    },
  });
}

export async function recordShieldDecision(decision, dependencies, evidence = null) {
  return createShieldDecisionRecorder(dependencies).recordShieldDecision(decision, evidence);
}

export function validateShieldEvent(event) {
  if (!isPlainObject(event) || !hasAllowedKeys(event, EVENT_KEYS, [])
    || event.schema !== SHIELD_EVENT_SCHEMA || !EVENT_KINDS.has(event.event_kind)
    || typeof event.event_id !== "string" || !/^[0-9a-f-]{36}$/.test(event.event_id)
    || typeof event.logical_request_id !== "string" || event.logical_request_id.length === 0
    || !(event.session_id === null || (typeof event.session_id === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(event.session_id)))
    || typeof event.observed_at !== "string" || Number.isNaN(Date.parse(event.observed_at))
    || !isPlainObject(event.payload)) {
    throw new TypeError("shield audit event is invalid");
  }
  return event;
}

function normalizeEvidence(evidence) {
  if (evidence === null || evidence === undefined) return null;
  if (!isPlainObject(evidence) || !hasAllowedKeys(evidence, [], ["originalText", "redactedText"])) {
    throw new TypeError("shield audit evidence is invalid");
  }
  for (const value of Object.values(evidence)) {
    if (typeof value !== "string" || value.length > MAX_EVIDENCE_CHARS) throw new TypeError("shield audit evidence is invalid");
  }
  return Object.keys(evidence).length === 0 ? null : evidence;
}

export function assertShieldDecisionMetadata(value, { media = false } = {}) {
  const normalized = isPlainObject(value) && !Object.hasOwn(value, "decisionSource")
    ? { ...value, decisionSource: "evaluated" }
    : value;
  if (!isPlainObject(normalized) || !hasAllowedKeys(normalized, DECISION_KEYS, ["sessionId", ...(media ? Object.keys(MEDIA_KEYS) : [])])
    || (Object.hasOwn(normalized, "sessionId") && (typeof normalized.sessionId !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(normalized.sessionId)))
    || typeof normalized.requestId !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(normalized.requestId)
    || !LANES.has(normalized.lane) || !DESTINATION_CLASSES.has(normalized.destinationClass)
    || typeof normalized.bundleVersion !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(normalized.bundleVersion)
    || !isVersionMap(normalized.detectorVersions) || !ACTIONS.has(normalized.action)
    || !validReasonCodes(normalized.reasonCodes) || !Number.isInteger(normalized.transformCount) || normalized.transformCount < 0 || normalized.transformCount > 1_000_000
    || !DECISION_SOURCES.has(normalized.decisionSource)
    || typeof normalized.override !== "boolean" || !Number.isFinite(normalized.elapsedMs) || normalized.elapsedMs < 0 || normalized.elapsedMs > 3_600_000
    || !validMedia(normalized)) {
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
    ...(Object.hasOwn(normalized, "sessionId") ? { sessionId: normalized.sessionId } : {}),
    ...Object.fromEntries(Object.keys(MEDIA_KEYS)
      .filter((key) => Object.hasOwn(normalized, key))
      .map((key) => [key, normalized[key]])),
  });
}

function unavailable() {
  const error = new Error("shield audit is unavailable");
  error.code = "CCSHIELD_AUDIT_UNAVAILABLE";
  return error;
}

function hasAllowedKeys(value, required, optional) {
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => allowed.has(key));
}

// Media fields describe counts only, never content: no URLs, file ids, bytes or OCR text.
function validMedia(value) {
  const has = (key) => Object.hasOwn(value, key);
  return (!has("imageVersion") || (typeof value.imageVersion === "string" && IMAGE_VERSION.test(value.imageVersion)))
    && MEDIA_COUNT_KEYS.every((key) => !has(key) || isCount(value[key]))
    && (!has("mediaOutcome") || MEDIA_OUTCOMES.has(value.mediaOutcome))
    && !(value.mediaOutcome?.startsWith?.("blocked_") && value.action !== "block")
    && !(has("imageTransformCount") && value.imageTransformCount > value.transformCount);
}

function isCount(value) {
  return Number.isInteger(value) && value >= 0 && value <= 1_000_000;
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
