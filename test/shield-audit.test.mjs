import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { buildShieldDecisionEvent, buildShieldPolicyTransitionEvent, createShieldDecisionRecorder } from "../src/shield/audit.mjs";
import { openShieldStore } from "../src/store.mjs";

const MASTER_KEY = Buffer.alloc(32, 9);

const decision = Object.freeze({
  requestId: "request-1",
  lane: "subscription",
  destinationClass: "subscription",
  bundleVersion: "2026.09.02",
  detectorVersions: { gitleaks: "8.24.3" },
  action: "allow",
  reasonCodes: ["policy_allow"],
  transformCount: 0,
  override: false,
  elapsedMs: 4,
});

test("shield decision builder admits only metadata allowlist", () => {
  const event = buildShieldDecisionEvent(decision, { now: () => new Date("2026-09-02T00:00:00.000Z") });
  assert.equal(event.event_kind, "shield_decision");
  assert.deepEqual(event.payload, {
    lane: "subscription",
    destination_class: "subscription",
    policy_version: "2026.09.02",
    gitleaks_version: "8.24.3",
    privacy_version: "unknown",
    action: "allow",
    reasons: ["policy_allow"],
    transform_count: 0,
    decision_source: "evaluated",
    override: false,
    elapsed_ms: 4,
  });
  for (const forbidden of ["body", "path", "url", "headers", "digest", "span", "prompt", "grant", "cacheKey"]) {
    assert.throws(() => buildShieldDecisionEvent({ ...decision, [forbidden]: "sentinel-secret" }), /shield decision/i);
  }
  assert.doesNotMatch(JSON.stringify(event), /sentinel-secret/);
});

const MEDIA = Object.freeze({
  imageVersion: "image-0123456789ab",
  imageCount: 2,
  imageTransformCount: 1,
  documentCount: 0,
  mediaOutcome: "scanned",
});

test("shield decisions carry media counters only when the decision sets them", () => {
  const plain = buildShieldDecisionEvent(decision);
  for (const column of ["image_version", "image_count", "image_transform_count", "document_count", "media_outcome"]) {
    assert.equal(Object.hasOwn(plain.payload, column), false, column);
  }

  const media = buildShieldDecisionEvent({ ...decision, action: "redact", transformCount: 3, ...MEDIA });
  assert.deepEqual({
    image_version: media.payload.image_version,
    image_count: media.payload.image_count,
    image_transform_count: media.payload.image_transform_count,
    document_count: media.payload.document_count,
    media_outcome: media.payload.media_outcome,
  }, { image_version: "image-0123456789ab", image_count: 2, image_transform_count: 1, document_count: 0, media_outcome: "scanned" });

  const blocked = buildShieldDecisionEvent({ ...decision, action: "block", reasonCodes: ["media_document_blocked"], documentCount: 1, mediaOutcome: "blocked_document" });
  assert.deepEqual([blocked.payload.document_count, blocked.payload.media_outcome, Object.hasOwn(blocked.payload, "image_count")], [1, "blocked_document", false]);

  const overridden = buildShieldDecisionEvent({ ...decision, imageCount: 2, documentCount: 0, mediaOutcome: "unscanned_override" });
  assert.deepEqual([overridden.payload.image_count, overridden.payload.media_outcome], [2, "unscanned_override"]);
});

test("shield media values are refused before they reach the audit transport", () => {
  for (const bad of [
    { imageVersion: "https://images.example/a.png" },
    { imageVersion: "file_abc" },
    { imageCount: -1 },
    { documentCount: 1.5 },
    { mediaOutcome: "allowed" },
    { mediaOutcome: null },
    { mediaOutcome: "blocked_secret" },
    { imageTransformCount: 1 },
    { image_count: 1 },
    { ocrText: "hunter2" },
  ]) {
    assert.throws(() => buildShieldDecisionEvent({ ...decision, ...bad }), /shield (decision|metadata)/i, JSON.stringify(bad));
  }
  assert.throws(
    () => buildShieldPolicyTransitionEvent({ ...decision, action: "transition", reasonCodes: ["policy_replaced"], mediaOutcome: "none" }),
    /shield decision/i,
  );
});


test("shield policy transitions use the same metadata-only event contract", () => {
  const event = buildShieldPolicyTransitionEvent({
    ...decision,
    action: "transition",
    reasonCodes: ["policy_replaced"],
  });
  assert.equal(event.event_kind, "shield_policy_transition");
  assert.equal(event.payload.action, "transition");
  assert.equal(event.payload.reasons[0], "policy_replaced");
  assert.doesNotMatch(JSON.stringify(event), /capability|body|secret/i);
});

test("shield audit admits only declared cache provenance", () => {
  const coalesced = buildShieldDecisionEvent({ ...decision, decisionSource: "coalesced" });
  assert.equal(coalesced.payload.decision_source, "coalesced");
  assert.throws(() => buildShieldDecisionEvent({ ...decision, decisionSource: "request_digest" }), /shield decision/i);
});

async function withStore(t) {
  const root = await mkdtemp(join(tmpdir(), "ccshield-audit-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const databasePath = join(root, "audit.sqlite");
  const store = openShieldStore({ databasePath, masterKey: MASTER_KEY, now: () => new Date("2026-10-06T00:00:00.000Z") });
  t.after(() => store.close());
  return { databasePath, store };
}

test("shield media counters round-trip through the store and decision queries", async (t) => {
  const { store } = await withStore(t);
  const at = (iso) => ({ now: () => new Date(iso) });
  store.recordEvent(buildShieldDecisionEvent({ ...decision, requestId: "media-1", action: "redact", transformCount: 3, ...MEDIA }, at("2026-10-06T00:00:01.000Z")));
  store.recordEvent(buildShieldDecisionEvent({ ...decision, requestId: "plain-1" }, at("2026-10-06T00:00:02.000Z")));
  store.recordEvent(buildShieldPolicyTransitionEvent({ ...decision, requestId: "transition-1", action: "transition", reasonCodes: ["policy_replaced"] }));

  const project = (row) => [row.logical_request_id, row.image_version, row.image_count, row.image_transform_count, row.document_count, row.media_outcome];
  assert.deepEqual(store.queryDecisions().map(project), [
    ["media-1", "image-0123456789ab", 2, 1, 0, "scanned"],
    ["plain-1", null, null, null, null, null],
  ]);
  assert.deepEqual(store.queryDecisions({ requestId: "media-1" }).map(project), [["media-1", "image-0123456789ab", 2, 1, 0, "scanned"]]);
  const [transition] = store.queryTransitions();
  assert.equal(transition.logical_request_id, "transition-1");
  assert.equal(Object.hasOwn(transition, "media_outcome"), false);
});

test("durable recorder commits the decision to the store before it resolves", async (t) => {
  const { databasePath, store } = await withStore(t);
  const now = () => new Date("2026-09-02T00:00:00.000Z");
  const recorder = createShieldDecisionRecorder({ store, now });
  const evidence = { originalText: "token sentinel-original-9f3", redactedText: "token [REDACTED-sentinel-forwarded]" };
  const result = await recorder.recordShieldDecision({ ...decision, action: "redact", transformCount: 1 }, evidence);
  assert.equal(result.durable, "store");
  assert.match(result.eventId, /^[0-9a-f-]{36}$/);

  const [row] = store.queryDecisions();
  const expected = buildShieldDecisionEvent({ ...decision, action: "redact", transformCount: 1 }, { now }).payload;
  assert.equal(row.event_id, result.eventId);
  assert.equal(row.logical_request_id, "request-1");
  assert.equal(row.observed_at, "2026-09-02T00:00:00.000Z");
  for (const [key, value] of Object.entries(expected)) assert.deepEqual(row[key], value, key);
  assert.equal(row.has_evidence, true);
  assert.doesNotMatch(JSON.stringify(row), /sentinel-original|REDACTED-sentinel/);

  const onDisk = await readFile(databasePath);
  assert.equal(onDisk.includes("sentinel-original-9f3"), false);
  assert.equal(onDisk.includes("REDACTED-sentinel-forwarded"), false);
  assert.deepEqual({ ...store.revealEvidence(result.eventId) }, evidence);
});

test("durable recorder persists policy transition events through the same store", async (t) => {
  const { store } = await withStore(t);
  const recorder = createShieldDecisionRecorder({ store });
  await recorder.recordShieldPolicyTransition({ ...decision, action: "transition", reasonCodes: ["policy_replaced"] });
  assert.deepEqual(store.queryDecisions(), []);
  const [transition] = store.queryTransitions();
  assert.equal(transition.action, "transition");
  assert.deepEqual(transition.reasons, ["policy_replaced"]);
});

test("store failure fails closed without leaking the underlying error", async () => {
  const unavailable = createShieldDecisionRecorder({
    store: { recordEvent: () => { throw new Error("raw-secret must not escape"); } },
  });
  await assert.rejects(unavailable.recordShieldDecision(decision), (error) => {
    assert.equal(error.code, "CCSHIELD_AUDIT_UNAVAILABLE");
    assert.match(error.message, /shield audit is unavailable/);
    assert.doesNotMatch(`${error.message} ${error.stack}`, /raw-secret/);
    return true;
  });
  assert.equal(await unavailable.isReady(), false);
});

test("recorder readiness recovers once the store accepts writes again", async () => {
  let failing = true;
  const written = [];
  const recorder = createShieldDecisionRecorder({
    store: { recordEvent: (event) => { if (failing) throw new Error("disk full"); written.push(event); } },
  });
  await assert.rejects(recorder.recordShieldDecision(decision), /shield audit is unavailable/);
  assert.equal(await recorder.isReady(), false);
  assert.equal(written.length, 0);
  failing = false;
  const result = await recorder.recordShieldDecision(decision);
  assert.equal(result.durable, "store");
  assert.equal(await recorder.isReady(), true);
  assert.equal(written.length, 1);
});
