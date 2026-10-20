import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { acquireLock, withFileLock } from "../src/shield/file-lock.mjs";

async function withDir(fn) {
  const dir = await mkdtemp(join(tmpdir(), "ccshield-lock-"));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("two read-merge-writes under the lock both land", () => withDir(async (dir) => {
  const lockPath = join(dir, "record.lock");
  const recordPath = join(dir, "record.json");
  await writeFile(recordPath, "{}");
  const merge = (key) => withFileLock(lockPath, async () => {
    const record = JSON.parse(await readFile(recordPath, "utf8"));
    await new Promise((settle) => setTimeout(settle, 30));
    await writeFile(recordPath, JSON.stringify({ ...record, [key]: true }));
  }, { retryMs: 5 });

  await Promise.all([merge("privacy"), merge("gitleaks")]);

  assert.deepEqual(JSON.parse(await readFile(recordPath, "utf8")), { privacy: true, gitleaks: true });
  assert.equal(await acquireLock(lockPath), true, "the lock is released afterwards");
}));

test("a lock left by a dead process is taken over, a live holder times the waiter out", () => withDir(async (dir) => {
  const lockPath = join(dir, "record.lock");
  await writeFile(lockPath, "999999\n");
  assert.equal(await withFileLock(lockPath, async () => "ran", { isProcessAlive: async () => false }), "ran");

  await writeFile(lockPath, "4242\n");
  await assert.rejects(
    withFileLock(lockPath, async () => assert.fail("must not run"), { timeoutMs: 20, retryMs: 5, isProcessAlive: async () => true }),
    /held by pid 4242/,
  );
}));
