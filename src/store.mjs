import { createHash } from "node:crypto";
import { chmodSync, closeSync, constants, existsSync, mkdirSync, openSync } from "node:fs";
import { dirname } from "node:path";

import { decryptValue, encryptValue } from "./crypto.mjs";

// Loaded on first use rather than at import, so an entry point that imports
// quiet-sqlite.mjs first can keep the experimental warning out of its output.
function LazyDatabaseSync(...args) {
  const { DatabaseSync } = process.getBuiltinModule("node:sqlite");
  return new DatabaseSync(...args);
}

export const DEFAULT_RETENTION_DAYS = 30;
const EVIDENCE_PURPOSE = "evidence/v1";
const EVIDENCE_COLUMNS = Object.freeze(["original_text", "redacted_text"]);
const MEDIA_COLUMNS = Object.freeze(["image_version", "image_count", "image_transform_count", "document_count", "media_outcome"]);
const ACTIONS = "'allow', 'block', 'redact', 'require_approval', 'unavailable', 'unauthorized', 'transition'";
const LANES = "'managed', 'subscription', 'unknown'";

// Shared column set of AirKit's shield tables after its migrations 004-006.
const METADATA_COLUMNS = `
    event_id TEXT PRIMARY KEY,
    logical_request_id TEXT NOT NULL CHECK (length(logical_request_id) > 0),
    session_id TEXT CHECK (session_id IS NULL OR length(session_id) > 0),
    lane TEXT NOT NULL CHECK (lane IN (${LANES})),
    destination_class TEXT NOT NULL CHECK (destination_class IN (${LANES})),
    policy_version TEXT NOT NULL CHECK (length(policy_version) > 0),
    gitleaks_version TEXT NOT NULL CHECK (length(gitleaks_version) > 0),
    privacy_version TEXT NOT NULL CHECK (length(privacy_version) > 0),
    action TEXT NOT NULL CHECK (action IN (${ACTIONS})),
    reasons TEXT NOT NULL CHECK (length(reasons) > 0),
    transform_count INTEGER NOT NULL CHECK (transform_count >= 0),
    decision_source TEXT NOT NULL DEFAULT 'evaluated' CHECK (decision_source IN ('evaluated', 'cache_hit', 'coalesced')),
    override INTEGER NOT NULL CHECK (override IN (0, 1)),
    elapsed_ms REAL NOT NULL CHECK (elapsed_ms >= 0),
    observed_at TEXT NOT NULL`;

const INITIAL_STATEMENTS = Object.freeze([
  `CREATE TABLE shield_decisions (${METADATA_COLUMNS},
    image_version TEXT CHECK (image_version IS NULL OR length(image_version) > 0),
    image_count INTEGER CHECK (image_count IS NULL OR image_count >= 0),
    image_transform_count INTEGER CHECK (image_transform_count IS NULL OR image_transform_count >= 0),
    document_count INTEGER CHECK (document_count IS NULL OR document_count >= 0),
    media_outcome TEXT CHECK (media_outcome IS NULL OR media_outcome IN ('none', 'blocked_document', 'blocked_source', 'blocked_scan', 'blocked_secret', 'scanned')),
    original_text TEXT,
    redacted_text TEXT,
    evidence_purged_at TEXT
  )`,
  `CREATE TABLE shield_policy_transitions (${METADATA_COLUMNS}
  )`,
  "CREATE INDEX idx_shield_decisions_request ON shield_decisions(logical_request_id, observed_at)",
  "CREATE INDEX idx_shield_decisions_session ON shield_decisions(session_id, observed_at)",
  "CREATE INDEX idx_shield_decisions_action ON shield_decisions(action, observed_at)",
  "CREATE INDEX idx_shield_decisions_observed ON shield_decisions(observed_at)",
  "CREATE INDEX idx_shield_policy_transitions_request ON shield_policy_transitions(logical_request_id, observed_at)",
]);

export const SHIELD_MIGRATIONS = Object.freeze([
  Object.freeze({ id: "001_initial", statements: INITIAL_STATEMENTS }),
]);

const LEDGER_SQL = `CREATE TABLE IF NOT EXISTS shield_migrations (
  id TEXT PRIMARY KEY,
  checksum TEXT NOT NULL,
  started_at TEXT NOT NULL,
  applied_at TEXT
)`;

export class ShieldStoreError extends Error {
  constructor(message, { code = "CCSHIELD_STORE_ERROR", cause } = {}) {
    super(message, { cause });
    this.name = "ShieldStoreError";
    this.code = code;
  }
}

export function checksumMigration(migration) {
  return createHash("sha256").update(migration.statements.join(";\n"), "utf8").digest("hex");
}

export function openShieldStore({
  databasePath,
  masterKey,
  retentionDays = DEFAULT_RETENTION_DAYS,
  now = () => new Date(),
  migrations = SHIELD_MIGRATIONS,
  Database = LazyDatabaseSync,
} = {}) {
  if (typeof databasePath !== "string" || databasePath.length === 0) throw new TypeError("shield store database path is required");
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) throw new TypeError("shield store master key must be 32 bytes");
  if (!Number.isInteger(retentionDays) || retentionDays < 1 || retentionDays > 3650) {
    throw new TypeError("shield store retention must be a whole number of days between 1 and 3650");
  }

  createPrivateFile(databasePath);
  const db = new Database(databasePath);
  try {
    db.exec("PRAGMA busy_timeout = 5000");
    db.exec("PRAGMA journal_mode = WAL");
    // Purged evidence must not survive in free pages.
    db.exec("PRAGMA secure_delete = ON");
    assertReadable(db);
    migrate(db, migrations, now);
  } catch (error) {
    db.close();
    throw error;
  }

  const insertDecision = db.prepare(`INSERT INTO shield_decisions (
    event_id, logical_request_id, session_id, lane, destination_class, policy_version, gitleaks_version,
    privacy_version, action, reasons, transform_count, decision_source, override, elapsed_ms, observed_at,
    ${MEDIA_COLUMNS.join(", ")}, original_text, redacted_text
  ) VALUES (${new Array(22).fill("?").join(", ")})`);
  const insertTransition = db.prepare(`INSERT INTO shield_policy_transitions (
    event_id, logical_request_id, session_id, lane, destination_class, policy_version, gitleaks_version,
    privacy_version, action, reasons, transform_count, decision_source, override, elapsed_ms, observed_at
  ) VALUES (${new Array(15).fill("?").join(", ")})`);
  let closed = false;

  const assertOpen = () => {
    if (closed) throw new ShieldStoreError("shield store is closed", { code: "CCSHIELD_STORE_CLOSED" });
  };

  const seal = (column, eventId, text) => (typeof text === "string"
    ? encryptValue({ masterKey, purpose: EVIDENCE_PURPOSE, identity: eventId, aad: `${column}:${eventId}`, plaintext: text })
    : null);

  const store = {
    databasePath,
    retentionDays,

    recordEvent(event, evidence = null) {
      assertOpen();
      const p = event.payload;
      const metadata = [
        event.event_id, event.logical_request_id, event.session_id ?? null, p.lane, p.destination_class,
        p.policy_version, p.gitleaks_version, p.privacy_version, p.action, JSON.stringify(p.reasons),
        p.transform_count, p.decision_source, p.override ? 1 : 0, p.elapsed_ms, event.observed_at,
      ];
      if (event.event_kind === "shield_policy_transition") {
        if (evidence !== null) throw new TypeError("policy transitions carry no evidence");
        insertTransition.run(...metadata);
        return;
      }
      if (event.event_kind !== "shield_decision") throw new TypeError("shield store event kind is unsupported");
      insertDecision.run(
        ...metadata,
        ...MEDIA_COLUMNS.map((column) => p[column] ?? null),
        seal("original_text", event.event_id, evidence?.originalText),
        seal("redacted_text", event.event_id, evidence?.redactedText),
      );
    },

    queryDecisions({ sessionId, action, requestId, since, limit = 100 } = {}) {
      assertOpen();
      return queryTable(db, "shield_decisions", { sessionId, action, requestId, since, limit }).map(decisionRow);
    },

    queryTransitions({ requestId, since, limit = 100 } = {}) {
      assertOpen();
      return queryTable(db, "shield_policy_transitions", { requestId, since, limit }).map(metadataRow);
    },

    // The only path that returns plaintext; callers gate it behind an explicit --reveal.
    revealEvidence(eventId) {
      assertOpen();
      const row = db.prepare("SELECT event_id, original_text, redacted_text FROM shield_decisions WHERE event_id = ?").get(eventId);
      if (!row) return null;
      const open = (column) => (row[column] === null
        ? null
        : decryptValue({ masterKey, purpose: EVIDENCE_PURPOSE, identity: row.event_id, aad: `${column}:${row.event_id}`, packed: row[column] }));
      return Object.freeze({ originalText: open("original_text"), redactedText: open("redacted_text") });
    },

    purgeExpiredEvidence() {
      assertOpen();
      const current = now();
      const cutoff = new Date(current.getTime() - retentionDays * 86_400_000).toISOString();
      const result = db.prepare(`UPDATE shield_decisions
        SET original_text = NULL, redacted_text = NULL, evidence_purged_at = ?
        WHERE observed_at < ? AND (original_text IS NOT NULL OR redacted_text IS NOT NULL)`).run(current.toISOString(), cutoff);
      return Number(result.changes);
    },

    health() {
      assertOpen();
      assertReadable(db);
      verifyLedger(db, migrations);
      const { count } = db.prepare("SELECT count(*) AS count FROM shield_decisions").get();
      return Object.freeze({ ok: true, migrations: migrations.map((migration) => migration.id), decisions: Number(count) });
    },

    close() {
      if (closed) return;
      closed = true;
      db.close();
    },
  };
  // Run retention at open so a daemon restart alone is enough to enforce it.
  store.purgeExpiredEvidence();
  return Object.freeze(store);
}

// Health for `doctor`: read-only, needs no key, never creates or migrates.
export function inspectShieldStore({ databasePath, migrations = SHIELD_MIGRATIONS, Database = LazyDatabaseSync } = {}) {
  if (typeof databasePath !== "string" || !existsSync(databasePath)) return Object.freeze({ state: "missing" });
  let db;
  try {
    db = new Database(databasePath, { readOnly: true });
    db.exec("PRAGMA busy_timeout = 2000");
    assertReadable(db);
    verifyLedger(db, migrations);
    return Object.freeze({ state: "healthy" });
  } catch (error) {
    return Object.freeze({ state: "unavailable", code: error?.code ?? "CCSHIELD_STORE_ERROR" });
  } finally {
    db?.close();
  }
}

function queryTable(db, table, { sessionId, action, requestId, since, limit }) {
  const where = [];
  const values = [];
  if (sessionId !== undefined) { where.push("session_id = ?"); values.push(sessionId); }
  if (action !== undefined) { where.push("action = ?"); values.push(action); }
  if (requestId !== undefined) { where.push("logical_request_id = ?"); values.push(requestId); }
  if (since !== undefined) {
    if (!(since instanceof Date) || Number.isNaN(since.getTime())) throw new TypeError("since must be a valid Date");
    where.push("observed_at >= ?");
    values.push(since.toISOString());
  }
  if (!Number.isInteger(limit) || limit < 1 || limit > 10_000) throw new TypeError("limit must be between 1 and 10000");
  const clause = where.length === 0 ? "" : `WHERE ${where.join(" AND ")}`;
  return db.prepare(`SELECT * FROM ${table} ${clause} ORDER BY observed_at, event_id LIMIT ?`).all(...values, limit);
}

function metadataRow(row) {
  return {
    event_id: row.event_id,
    logical_request_id: row.logical_request_id,
    session_id: row.session_id,
    lane: row.lane,
    destination_class: row.destination_class,
    policy_version: row.policy_version,
    gitleaks_version: row.gitleaks_version,
    privacy_version: row.privacy_version,
    action: row.action,
    reasons: JSON.parse(row.reasons),
    transform_count: row.transform_count,
    decision_source: row.decision_source,
    override: row.override === 1,
    elapsed_ms: row.elapsed_ms,
    observed_at: row.observed_at,
  };
}

function decisionRow(row) {
  return {
    ...metadataRow(row),
    ...Object.fromEntries(MEDIA_COLUMNS.map((column) => [column, row[column]])),
    has_evidence: EVIDENCE_COLUMNS.some((column) => row[column] !== null),
    evidence_purged_at: row.evidence_purged_at,
  };
}

function migrate(db, migrations, now) {
  db.exec(LEDGER_SQL);
  const rows = ledgerRows(db);
  assertNotInterrupted(rows);
  for (const migration of migrations) {
    const checksum = checksumMigration(migration);
    const existing = rows.find((row) => row.id === migration.id);
    if (existing) {
      if (existing.checksum !== checksum) throw checksumMismatch(migration);
      continue;
    }
    db.exec("BEGIN IMMEDIATE");
    try {
      db.prepare("INSERT INTO shield_migrations (id, checksum, started_at, applied_at) VALUES (?, ?, ?, NULL)")
        .run(migration.id, checksum, now().toISOString());
      db.exec(migration.statements.join(";\n"));
      db.prepare("UPDATE shield_migrations SET applied_at = ? WHERE id = ?").run(now().toISOString(), migration.id);
      db.exec("COMMIT");
    } catch (error) {
      db.exec("ROLLBACK");
      throw new ShieldStoreError(`shield store migration ${migration.id} failed`, { code: "CCSHIELD_STORE_MIGRATION_FAILED", cause: error });
    }
  }
  verifyLedger(db, migrations);
}

function verifyLedger(db, migrations) {
  const rows = ledgerRows(db);
  assertNotInterrupted(rows);
  for (const migration of migrations) {
    const row = rows.find((entry) => entry.id === migration.id);
    if (!row) throw new ShieldStoreError(`shield store migration ${migration.id} has not been applied`, { code: "CCSHIELD_STORE_NEEDS_MIGRATION" });
    if (row.checksum !== checksumMigration(migration)) throw checksumMismatch(migration);
  }
  const known = new Set(migrations.map((migration) => migration.id));
  const unknown = rows.find((row) => !known.has(row.id));
  if (unknown) throw new ShieldStoreError(`shield store has unknown migration ${unknown.id}; it was written by a newer ccshield`, { code: "CCSHIELD_STORE_TOO_NEW" });
}

function ledgerRows(db) {
  return db.prepare("SELECT id, checksum, started_at, applied_at FROM shield_migrations ORDER BY id").all();
}

function assertNotInterrupted(rows) {
  const interrupted = rows.find((row) => row.applied_at === null);
  if (interrupted) throw new ShieldStoreError(`shield store migration ${interrupted.id} was interrupted`, { code: "CCSHIELD_STORE_MIGRATION_INTERRUPTED" });
}

function checksumMismatch(migration) {
  return new ShieldStoreError(`shield store migration ${migration.id} checksum mismatch`, { code: "CCSHIELD_STORE_MIGRATION_CHECKSUM_MISMATCH" });
}

function assertReadable(db) {
  const rows = db.prepare("PRAGMA quick_check").all();
  if (rows.length !== 1 || rows[0].quick_check !== "ok") {
    throw new ShieldStoreError("shield store database failed quick_check", { code: "CCSHIELD_STORE_CORRUPT" });
  }
}

// SQLite creates the file with the process umask; create it 0600 first so it never exists world-readable.
function createPrivateFile(path) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const fd = openSync(path, constants.O_RDWR | constants.O_CREAT | constants.O_NOFOLLOW, 0o600);
  closeSync(fd);
  chmodSync(path, 0o600);
}
