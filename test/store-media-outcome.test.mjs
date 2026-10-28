import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";

import { openShieldStore, SHIELD_MIGRATIONS } from "../src/store.mjs";
import { buildShieldDecisionEvent, createShieldDecisionRecorder, MEDIA_OUTCOMES } from "../src/shield/audit.mjs";

const MASTER_KEY = Buffer.alloc(32, 7);
// src/store.mjs at ad346b2 (the installed release) shipped exactly the first
// migration, so opening with this list behaves as that release does.
const RELEASED_MIGRATIONS = SHIELD_MIGRATIONS.slice(0, 1);

const decision = Object.freeze({
  requestId: "request-1",
  lane: "subscription",
  destinationClass: "subscription",
  bundleVersion: "2026.10.14",
  detectorVersions: { gitleaks: "8.24.3", privacy: "opf-1", image: "image-0123456789ab" },
  action: "allow",
  reasonCodes: ["policy_allow"],
  transformCount: 0,
  override: false,
  elapsedMs: 3,
  imageVersion: "image-0123456789ab",
  imageCount: 1,
  imageTransformCount: 0,
  documentCount: 0,
});

async function databaseIn(t) {
  const root = await mkdtemp(join(tmpdir(), "ccshield-store-media-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  return join(root, "audit.sqlite");
}

function snapshot(databasePath, table) {
  const db = new DatabaseSync(databasePath);
  try {
    return {
      rows: db.prepare(`SELECT * FROM ${table} ORDER BY event_id`).all().map((row) => ({ ...row })),
      columns: db.prepare(`PRAGMA table_info(${table})`).all().map((row) => ({ ...row })),
      indexes: db.prepare("SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = ? ORDER BY name").all(table).map((row) => ({ ...row })),
    };
  } finally {
    db.close();
  }
}

function blockedFor(mediaOutcome) {
  return mediaOutcome.startsWith("blocked_") ? { action: "block", reasonCodes: ["media_blocked"] } : {};
}

test("the real store accepts every media outcome the audit builder can emit", async (t) => {
  const store = openShieldStore({ databasePath: await databaseIn(t), masterKey: MASTER_KEY });
  t.after(() => store.close());
  assert.ok(MEDIA_OUTCOMES.size > 0);
  for (const mediaOutcome of MEDIA_OUTCOMES) {
    const event = buildShieldDecisionEvent({ ...decision, ...blockedFor(mediaOutcome), requestId: mediaOutcome, mediaOutcome }, new Date());
    assert.doesNotThrow(() => store.recordEvent(event), mediaOutcome);
  }
  const stored = store.queryDecisions().map((row) => row.media_outcome).sort();
  assert.deepEqual(stored, [...MEDIA_OUTCOMES].sort());
});

test("an image forwarded under the launch override is durably recorded", async (t) => {
  const store = openShieldStore({ databasePath: await databaseIn(t), masterKey: MASTER_KEY });
  t.after(() => store.close());
  const recorder = createShieldDecisionRecorder({ store });
  const result = await recorder.recordShieldDecision({ ...decision, mediaOutcome: "unscanned_override" });
  assert.equal(result.durable, "store");
  assert.equal(store.queryDecisions()[0].media_outcome, "unscanned_override");
});

test("migrating a released database keeps every row, column and index", async (t) => {
  const databasePath = await databaseIn(t);
  const released = openShieldStore({ databasePath, masterKey: MASTER_KEY, migrations: RELEASED_MIGRATIONS });
  const recorder = createShieldDecisionRecorder({ store: released });
  await recorder.recordShieldDecision({ ...decision, requestId: "plain" });
  await recorder.recordShieldDecision({ ...decision, requestId: "scanned", action: "redact", reasonCodes: ["pii_email"], transformCount: 1, imageTransformCount: 1, mediaOutcome: "scanned" }, { originalText: "alice@example.invalid", redactedText: "[EMAIL]" });
  await recorder.recordShieldDecision({ ...decision, requestId: "blocked", action: "block", reasonCodes: ["media_document_blocked"], documentCount: 1, mediaOutcome: "blocked_document" });
  const { imageVersion, imageCount, imageTransformCount, documentCount, ...withoutMedia } = decision;
  await recorder.recordShieldDecision({ ...withoutMedia, requestId: "legacy" });
  released.close();
  const before = snapshot(databasePath, "shield_decisions");
  const transitionsBefore = snapshot(databasePath, "shield_policy_transitions");
  assert.equal(before.rows.length, 4);

  const migrated = openShieldStore({ databasePath, masterKey: MASTER_KEY });
  assert.deepEqual(migrated.health().migrations, SHIELD_MIGRATIONS.map((migration) => migration.id));
  const evidenceId = before.rows.find((row) => row.logical_request_id === "scanned").event_id;
  assert.deepEqual(migrated.revealEvidence(evidenceId), { originalText: "alice@example.invalid", redactedText: "[EMAIL]" });
  migrated.close();

  const after = snapshot(databasePath, "shield_decisions");
  assert.deepEqual(after.rows, before.rows);
  assert.deepEqual(after.columns, before.columns);
  assert.deepEqual(after.indexes.map((index) => index.name), before.indexes.map((index) => index.name));
  assert.deepEqual(after.indexes, before.indexes);
  assert.deepEqual(snapshot(databasePath, "shield_policy_transitions"), transitionsBefore);

  const db = new DatabaseSync(databasePath);
  try {
    assert.deepEqual(db.prepare("PRAGMA integrity_check").all().map((row) => row.integrity_check), ["ok"]);
    assert.deepEqual(db.prepare("PRAGMA foreign_key_check").all(), []);
  } finally {
    db.close();
  }
});

test("the released code refuses a migrated database instead of writing to it", async (t) => {
  const databasePath = await databaseIn(t);
  openShieldStore({ databasePath, masterKey: MASTER_KEY }).close();
  assert.throws(
    () => openShieldStore({ databasePath, masterKey: MASTER_KEY, migrations: RELEASED_MIGRATIONS }),
    (error) => error.code === "CCSHIELD_STORE_TOO_NEW",
  );
});
