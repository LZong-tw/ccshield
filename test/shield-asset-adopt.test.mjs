import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { adoptAsset, storedGitleaksPath, storedRulesPath } from "../src/shield/asset-adopt.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");

async function withDir(fn) {
  const dir = await mkdtemp(join(tmpdir(), "ccshield-adopt-"));
  try { return await fn(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}

test("store paths are content-addressed and reject a non-digest", () => {
  const digest = "c".repeat(64);
  assert.equal(storedRulesPath("/s", digest), `/s/gitleaks-rules/${digest}/gitleaks-rules.toml`);
  assert.equal(storedGitleaksPath("/s", digest), `/s/gitleaks-override/${digest}/gitleaks`);
  assert.throws(() => storedRulesPath("/s", "../x"), /64 lowercase hex/);
});

test("adopt copies a source into the store and the copy survives the source being removed", () => withDir(async (dir) => {
  const source = join(dir, "pkg-v1", "rules.toml");
  const bytes = Buffer.from("rules v1");
  await mkdir(join(dir, "pkg-v1"));
  await writeFile(source, bytes);
  const target = storedRulesPath(join(dir, "store"), sha256(bytes));
  assert.equal(await adoptAsset({ source, sha256: sha256(bytes), target }), target);
  await rm(join(dir, "pkg-v1"), { recursive: true });
  assert.deepEqual(await readFile(target), bytes);
  assert.equal((await stat(target)).mode & 0o777, 0o644);
}));

test("adopt marks an executable 0755, is idempotent, and repairs a tampered copy", () => withDir(async (dir) => {
  const bytes = Buffer.from("binary");
  const target = storedGitleaksPath(join(dir, "store"), sha256(bytes));
  await adoptAsset({ bytes, sha256: sha256(bytes), target, executable: true });
  assert.equal((await stat(target)).mode & 0o777, 0o755);
  await adoptAsset({ bytes, sha256: sha256(bytes), target, executable: true });
  await writeFile(target, "tampered");
  await adoptAsset({ bytes, sha256: sha256(bytes), target, executable: true });
  assert.deepEqual(await readFile(target), bytes);
}));

test("adopt refuses bytes that do not match the digest", () => withDir(async (dir) => {
  const target = storedRulesPath(join(dir, "store"), "d".repeat(64));
  await assert.rejects(adoptAsset({ bytes: Buffer.from("x"), sha256: "d".repeat(64), target }), /digest mismatch before adopt/);
}));
