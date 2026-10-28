import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";

import { checksumMigration, openShieldStore, SHIELD_MIGRATIONS } from "../src/store.mjs";
import { buildShieldDecisionEvent, buildShieldPolicyTransitionEvent, createShieldDecisionRecorder } from "../src/shield/audit.mjs";

const MASTER_KEY = Buffer.alloc(32, 7);
const SECRET_ORIGINAL = "my email is alice.sentinel@example.test";
const SECRET_REDACTED = "my email is [REDACTED-sentinel-forwarded]";

const decision = Object.freeze({
  requestId: "request-1",
  lane: "subscription",
  destinationClass: "subscription",
  bundleVersion: "2026.10.14",
  detectorVersions: { gitleaks: "8.24.3", privacy: "opf-1" },
  action: "allow",
  reasonCodes: ["policy_allow"],
  transformCount: 0,
  override: false,
  elapsedMs: 3,
});

async function withStore(t, options = {}) {
  const root = await mkdtemp(join(tmpdir(), "ccshield-store-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const databasePath = join(root, "lane", "audit.sqlite");
  const open = (extra = {}) => openShieldStore({ databasePath, masterKey: MASTER_KEY, ...options, ...extra });
  return { root, databasePath, open };
}

const at = (iso) => ({ now: () => new Date(iso) });

test("an empty database applies every migration with a recorded checksum", async (t) => {
  const { databasePath, open } = await withStore(t);
  const store = open();
  assert.deepEqual(store.health(), { ok: true, migrations: ["001_initial", "002_media_unscanned_override"], decisions: 0 });
  store.close();

  const db = new DatabaseSync(databasePath);
  try {
    const rows = db.prepare("SELECT id, checksum, applied_at FROM shield_migrations").all();
    assert.deepEqual(rows.map((row) => row.id), SHIELD_MIGRATIONS.map((migration) => migration.id));
    rows.forEach((row, index) => {
      assert.equal(row.checksum, checksumMigration(SHIELD_MIGRATIONS[index]));
      assert.notEqual(row.applied_at, null);
    });
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all().map((row) => row.name);
    assert.deepEqual(tables, ["shield_decisions", "shield_migrations", "shield_policy_transitions"]);
  } finally {
    db.close();
  }

  // Reopening an up-to-date database is a no-op.
  open().close();
  assert.equal((await stat(databasePath)).mode & 0o777, 0o600);
});

test("a ledger checksum mismatch refuses to open the store", async (t) => {
  const { databasePath, open } = await withStore(t);
  open().close();
  const db = new DatabaseSync(databasePath);
  db.prepare("UPDATE shield_migrations SET checksum = ? WHERE id = '001_initial'").run("0".repeat(64));
  db.close();
  assert.throws(() => open(), (error) => error.code === "CCSHIELD_STORE_MIGRATION_CHECKSUM_MISMATCH");
});

test("an interrupted or newer ledger refuses to open the store", async (t) => {
  const { databasePath, open } = await withStore(t);
  open().close();
  const db = new DatabaseSync(databasePath);
  db.prepare("INSERT INTO shield_migrations (id, checksum, started_at, applied_at) VALUES ('002_future', 'x', '2026-10-14T00:00:00.000Z', NULL)").run();
  assert.throws(() => open(), (error) => error.code === "CCSHIELD_STORE_MIGRATION_INTERRUPTED");
  db.prepare("UPDATE shield_migrations SET applied_at = started_at WHERE id = '002_future'").run();
  db.close();
  assert.throws(() => open(), (error) => error.code === "CCSHIELD_STORE_TOO_NEW");
});

test("decisions are queryable by session and by action", async (t) => {
  const { open } = await withStore(t);
  const store = open();
  t.after(() => store.close());
  store.recordEvent(buildShieldDecisionEvent({ ...decision, requestId: "a-1", sessionId: "session-a" }, at("2026-10-14T00:00:01.000Z")));
  store.recordEvent(buildShieldDecisionEvent({ ...decision, requestId: "a-2", sessionId: "session-a", action: "redact", reasonCodes: ["pii_email"], transformCount: 1 }, at("2026-10-14T00:00:02.000Z")));
  store.recordEvent(buildShieldDecisionEvent({ ...decision, requestId: "b-1", sessionId: "session-b", action: "redact", reasonCodes: ["pii_email"], transformCount: 2, imageVersion: "image-0123456789ab", imageCount: 1, imageTransformCount: 0, documentCount: 0, mediaOutcome: "scanned" }, at("2026-10-14T00:00:03.000Z")));
  store.recordEvent(buildShieldPolicyTransitionEvent({ ...decision, requestId: "t-1", action: "transition", reasonCodes: ["policy_replaced"] }));

  assert.deepEqual(store.queryDecisions({ sessionId: "session-a" }).map((row) => row.logical_request_id), ["a-1", "a-2"]);
  assert.deepEqual(store.queryDecisions({ action: "redact" }).map((row) => row.logical_request_id), ["a-2", "b-1"]);
  assert.deepEqual(store.queryDecisions({ sessionId: "session-a", action: "redact" }).map((row) => row.logical_request_id), ["a-2"]);
  assert.deepEqual(store.queryDecisions({ since: new Date("2026-10-14T00:00:02.500Z") }).map((row) => row.logical_request_id), ["b-1"]);

  const [media] = store.queryDecisions({ requestId: "b-1" });
  assert.deepEqual(media.reasons, ["pii_email"]);
  assert.equal(media.override, false);
  assert.deepEqual([media.image_version, media.image_count, media.media_outcome], ["image-0123456789ab", 1, "scanned"]);
  assert.equal(media.has_evidence, false);
  assert.deepEqual(store.queryTransitions().map((row) => [row.logical_request_id, row.action]), [["t-1", "transition"]]);
});

test("evidence round-trips only through revealEvidence and never into query rows", async (t) => {
  const { open } = await withStore(t);
  const store = open();
  t.after(() => store.close());
  const recorder = createShieldDecisionRecorder({ store });
  const result = await recorder.recordShieldDecision(
    { ...decision, action: "redact", reasonCodes: ["pii_email"], transformCount: 1 },
    { originalText: SECRET_ORIGINAL, redactedText: SECRET_REDACTED },
  );
  assert.equal(result.durable, "store");
  const [row] = store.queryDecisions();
  assert.equal(row.has_evidence, true);
  assert.doesNotMatch(JSON.stringify(row), /sentinel/);
  assert.deepEqual(store.revealEvidence(result.eventId), { originalText: SECRET_ORIGINAL, redactedText: SECRET_REDACTED });
  assert.equal(store.revealEvidence("00000000-0000-0000-0000-000000000000"), null);
});

test("retention purges evidence past the window and keeps the metadata", async (t) => {
  let clock = new Date("2026-10-01T00:00:00.000Z");
  const { open } = await withStore(t, { retentionDays: 30, now: () => clock });
  const store = open();
  t.after(() => store.close());
  const recorder = createShieldDecisionRecorder({ store, now: () => clock });
  const old = await recorder.recordShieldDecision({ ...decision, requestId: "old", action: "redact", reasonCodes: ["pii_email"], transformCount: 1 }, { originalText: SECRET_ORIGINAL });
  clock = new Date("2026-10-20T00:00:00.000Z");
  const fresh = await recorder.recordShieldDecision({ ...decision, requestId: "fresh", action: "redact", reasonCodes: ["pii_email"], transformCount: 1 }, { originalText: SECRET_ORIGINAL });

  clock = new Date("2026-11-05T00:00:00.000Z");
  assert.equal(store.purgeExpiredEvidence(), 1);
  assert.equal(store.purgeExpiredEvidence(), 0);

  const rows = Object.fromEntries(store.queryDecisions().map((row) => [row.logical_request_id, row]));
  assert.deepEqual(Object.keys(rows).sort(), ["fresh", "old"]);
  assert.equal(rows.old.has_evidence, false);
  assert.equal(rows.old.evidence_purged_at, "2026-11-05T00:00:00.000Z");
  assert.deepEqual([rows.old.action, rows.old.reasons, rows.old.transform_count], ["redact", ["pii_email"], 1]);
  assert.equal(rows.fresh.has_evidence, true);
  assert.deepEqual(store.revealEvidence(old.eventId), { originalText: null, redactedText: null });
  assert.equal(store.revealEvidence(fresh.eventId).originalText, SECRET_ORIGINAL);
});

test("retention is enforced at open and rejects an invalid window", async (t) => {
  let clock = new Date("2026-01-01T00:00:00.000Z");
  const { open } = await withStore(t, { now: () => clock });
  const store = open();
  await createShieldDecisionRecorder({ store, now: () => clock }).recordShieldDecision(
    { ...decision, action: "redact", reasonCodes: ["pii_email"], transformCount: 1 },
    { originalText: SECRET_ORIGINAL },
  );
  store.close();
  clock = new Date("2026-03-01T00:00:00.000Z");
  const reopened = open();
  assert.equal(reopened.queryDecisions()[0].has_evidence, false);
  reopened.close();
  for (const retentionDays of [0, 1.5, 3651, "30"]) {
    assert.throws(() => open({ retentionDays }), /retention/);
  }
});

test("original text is ciphertext at rest", async (t) => {
  const { databasePath, open } = await withStore(t);
  const store = open();
  await createShieldDecisionRecorder({ store }).recordShieldDecision(
    { ...decision, action: "redact", reasonCodes: ["pii_email"], transformCount: 1 },
    { originalText: SECRET_ORIGINAL, redactedText: SECRET_REDACTED },
  );
  // Read the live files before close too, so a WAL-only copy cannot hide plaintext.
  const files = [databasePath, `${databasePath}-wal`].filter((path) => existsSync(path));
  const live = Buffer.concat(await Promise.all(files.map((path) => readFile(path))));
  store.close();
  const closed = await readFile(databasePath);
  for (const bytes of [live, closed]) {
    assert.equal(bytes.includes("alice.sentinel"), false);
    assert.equal(bytes.includes("sentinel-forwarded"), false);
    // Metadata stays plaintext and queryable.
    assert.equal(bytes.includes("policy_allow") || bytes.includes("pii_email"), true);
  }
});

test("policy transitions refuse evidence and the recorder fails closed on a broken store", async (t) => {
  const { open } = await withStore(t);
  const store = open();
  assert.throws(() => store.recordEvent(buildShieldPolicyTransitionEvent({ ...decision, action: "transition", reasonCodes: ["policy_replaced"] }), { originalText: "x" }), /no evidence/);
  store.close();

  const recorder = createShieldDecisionRecorder({ store });
  await assert.rejects(recorder.recordShieldDecision(decision), (error) => error.code === "CCSHIELD_AUDIT_UNAVAILABLE");
  assert.equal(await recorder.isReady(), false);
  await assert.rejects(recorder.recordShieldDecision(decision, { originalText: 42 }), /evidence is invalid/);
});
