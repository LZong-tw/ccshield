import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFile, chmod, lstat, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { IMAGE_WORKER_SOURCE, compileImageWorker } from "../shield-image/compile.mjs";
import { attestImageWorker, createImageWorker } from "../shield-image/worker.mjs";
import { provisionImageWorker } from "../src/shield/image-provision.mjs";
import { readShieldAssetsProvision, readShieldImageProvision, shieldAssetStore, shieldPaths } from "../src/shield/paths.mjs";
import { rgbaPng } from "./fixtures/image-corpus.mjs";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function home(t) {
  const homeDir = await realpath(await mkdtemp(join(tmpdir(), "ccshield-image-provision-")));
  t.after(() => rm(homeDir, { recursive: true, force: true }));
  const sourcePath = join(homeDir, "image-worker.swift");
  await writeFile(sourcePath, "// fake swift source\n");
  return { homeDir, sourcePath, paths: shieldPaths({ homeDir, uid: process.getuid?.() }) };
}

// Stands in for swiftc: emits a Node-shebang worker that answers probe with
// the version it was built for. `salt` changes the binary, not the source.
function fakeCompiler({ salt = "", languages = ["en-US", "zh-Hant"], fail = false } = {}) {
  const calls = [];
  const compile = async ({ outDir, version }) => {
    calls.push(version);
    if (fail) throw new Error("swiftc failed");
    const binary = join(outDir, "image-worker");
    await writeFile(binary, `#!${process.execPath}
// ${salt}
let buffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  let index;
  while ((index = buffer.indexOf("\\n")) !== -1) {
    const req = JSON.parse(buffer.slice(0, index));
    buffer = buffer.slice(index + 1);
    process.stdout.write(JSON.stringify({ v: 1, id: req.id, ok: true, worker: ${JSON.stringify(version)}, languages: ${JSON.stringify(languages)} }) + "\\n");
  }
});
`, { mode: 0o700 });
    return binary;
  };
  return { compile, calls };
}

async function listTree(dir) {
  const entries = await readdir(dir, { recursive: true });
  return entries.sort();
}

test("preview compiles and writes nothing", async (t) => {
  const { homeDir, sourcePath, paths } = await home(t);
  const before = await listTree(homeDir);
  const { compile, calls } = fakeCompiler();
  const result = await provisionImageWorker({ paths, sourcePath, compile });
  const srcSha = sha256(await readFile(sourcePath));
  assert.equal(result.action, "preview");
  assert.equal(result.version, `image-${srcSha.slice(0, 12)}`);
  assert.equal(result.path, shieldAssetStore(paths).imageWorker(srcSha).binary);
  assert.deepEqual(calls, []);
  assert.deepEqual(await listTree(homeDir), before);
});

test("write installs a 0500 binary in a 0700 directory and pins it in its own file", async (t) => {
  const { sourcePath, paths } = await home(t);
  const { compile } = fakeCompiler();
  const result = await provisionImageWorker({ paths, sourcePath, compile, write: true });
  assert.equal(result.action, "installed");
  const srcSha = sha256(await readFile(sourcePath));
  const pin = await readShieldImageProvision({ paths });
  assert.deepEqual(pin, {
    path: shieldAssetStore(paths).imageWorker(srcSha).binary,
    sha256: sha256(await readFile(pin.path)),
    source: { path: sourcePath, sha256: srcSha },
    version: `image-${srcSha.slice(0, 12)}`,
  });
  assert.equal((await stat(pin.path)).mode & 0o777, 0o500);
  assert.equal((await stat(dirname(pin.path))).mode & 0o777, 0o700);
  assert.equal((await stat(paths.imageProvisionPath)).mode & 0o777, 0o600);
  const worker = createImageWorker({ path: pin.path, sha256: pin.sha256 });
  t.after(() => worker.close());
  assert.equal((await worker.probe()).worker, pin.version);
});

test("a second write is idempotent and does not recompile", async (t) => {
  const { sourcePath, paths } = await home(t);
  const { compile, calls } = fakeCompiler();
  await provisionImageWorker({ paths, sourcePath, compile, write: true });
  const pin = await readFile(paths.imageProvisionPath, "utf8");
  const again = await provisionImageWorker({ paths, sourcePath, compile, write: true });
  assert.equal(again.action, "unchanged");
  assert.equal(calls.length, 1);
  assert.equal(await readFile(paths.imageProvisionPath, "utf8"), pin);
});

test("a rebuilt binary from the same source says so", async (t) => {
  const { sourcePath, paths } = await home(t);
  await provisionImageWorker({ paths, sourcePath, compile: fakeCompiler().compile, write: true });
  const first = await readShieldImageProvision({ paths });
  await chmod(first.path, 0o700);
  await appendFile(first.path, "// damaged\n");
  await chmod(first.path, 0o500);
  const result = await provisionImageWorker({ paths, sourcePath, compile: fakeCompiler({ salt: "new CLT" }).compile, write: true });
  assert.equal(result.action, "installed");
  assert.equal(result.note, "binary digest changed, source unchanged");
  const second = await readShieldImageProvision({ paths });
  assert.notEqual(second.sha256, first.sha256);
  assert.equal(second.source.sha256, first.source.sha256);
});

test("a failed build or probe keeps the old pin", async (t) => {
  const { sourcePath, paths } = await home(t);
  await provisionImageWorker({ paths, sourcePath, compile: fakeCompiler().compile, write: true });
  const pin = await readFile(paths.imageProvisionPath, "utf8");
  await writeFile(sourcePath, "// changed source\n");
  await assert.rejects(provisionImageWorker({ paths, sourcePath, compile: fakeCompiler({ fail: true }).compile, write: true }));
  await assert.rejects(provisionImageWorker({ paths, sourcePath, compile: fakeCompiler({ languages: ["en-US"] }).compile, write: true }), /languages/);
  assert.equal(await readFile(paths.imageProvisionPath, "utf8"), pin);
  const old = JSON.parse(pin);
  assert.equal(sha256(await readFile(old.path)), old.sha256);
  assert.deepEqual(await readdir(shieldAssetStore(paths).stagingDir), []);
});

test("an old-code reader ignores the image pin", async (t) => {
  const { sourcePath, paths } = await home(t);
  await provisionImageWorker({ paths, sourcePath, compile: fakeCompiler().compile, write: true });
  assert.equal(await readShieldAssetsProvision({ paths }), null);
  await assert.rejects(lstat(paths.assetsProvisionPath), { code: "ENOENT" });
});

test("a pin naming a path outside the store is rejected", async (t) => {
  const { sourcePath, paths } = await home(t);
  await provisionImageWorker({ paths, sourcePath, compile: fakeCompiler().compile, write: true });
  const pin = JSON.parse(await readFile(paths.imageProvisionPath, "utf8"));
  await writeFile(paths.imageProvisionPath, JSON.stringify({ ...pin, path: "/usr/bin/true" }), { mode: 0o600 });
  await assert.rejects(readShieldImageProvision({ paths }), /image provision is invalid/);
});

test("attestation rejects a tampered binary, a wrong owner and a group-writable file", async (t) => {
  const { sourcePath, paths } = await home(t);
  await provisionImageWorker({ paths, sourcePath, compile: fakeCompiler().compile, write: true });
  const pin = await readShieldImageProvision({ paths });
  await attestImageWorker(pin.path, pin.sha256);
  const io = { lstat, readFile, realpath };
  const wrongOwner = { ...io, lstat: async (path) => Object.assign(await lstat(path), { uid: (process.getuid?.() ?? 0) + 1 }) };
  await assert.rejects(attestImageWorker(pin.path, pin.sha256, wrongOwner), { code: "worker_attestation" });
  await chmod(pin.path, 0o520);
  await assert.rejects(attestImageWorker(pin.path, pin.sha256), { code: "worker_attestation" });
  await chmod(pin.path, 0o700);
  await appendFile(pin.path, "// tampered\n");
  await assert.rejects(attestImageWorker(pin.path, pin.sha256), { code: "worker_attestation" });
});

const native = process.platform === "darwin" && process.env.CCSHIELD_NATIVE_IMAGE === "1";
test("native: compile, codesign, probe and mask through the real Swift worker", { skip: !native && "set CCSHIELD_NATIVE_IMAGE=1 on macOS", timeout: 300_000 }, async (t) => {
  const { paths } = await home(t);
  const stagedDigests = [];
  const compile = async (options) => {
    const binary = await compileImageWorker(options);
    stagedDigests.push(sha256(await readFile(binary)));
    return binary;
  };
  await provisionImageWorker({ paths, sourcePath: IMAGE_WORKER_SOURCE, compile, write: true });
  const pin = await readShieldImageProvision({ paths });
  // R6: the digest taken after linking survives the copy, and the copy is still signed.
  assert.deepEqual(stagedDigests, [pin.sha256]);
  assert.equal(spawnSync("codesign", ["-v", pin.path]).status, 0);
  assert.match(spawnSync("codesign", ["-dv", pin.path], { encoding: "utf8" }).stderr, /Signature=adhoc|Authority=/);

  const worker = createImageWorker({ path: pin.path, sha256: pin.sha256, timeoutMs: 30_000 });
  t.after(() => worker.close());
  const probe = await worker.probe();
  assert.equal(probe.worker, pin.version);
  assert.ok(probe.languages.includes("en-US") && probe.languages.includes("zh-Hant"));

  const white = rgbaPng(8, 6, () => [255, 255, 255, 255]);
  assert.deepEqual(await worker.ocr(white), { width: 8, height: 6, regions: [] });
  const masked = await worker.mask(white, [{ x: 2, y: 1, w: 3, h: 2 }]);
  assert.equal(masked.width, 8);
  const chunks = pngChunks(masked.image);
  assert.deepEqual([...new Set(chunks)], ["IHDR", "IDAT", "IEND"]);
  await assert.rejects(worker.ocr(Buffer.from("GIF89a not really")), { code: "decode_failed" });
  await assert.rejects(worker.ocr(Buffer.from("%PDF-1.4\n")), (error) => ["unsupported_type", "decode_failed"].includes(error.code));
});

function pngChunks(bytes) {
  const names = [];
  for (let offset = 8; offset + 8 <= bytes.length;) {
    const length = bytes.readUInt32BE(offset);
    names.push(bytes.toString("latin1", offset + 4, offset + 8));
    offset += length + 12;
  }
  return names;
}

test("the Swift source ships next to the compiler", async () => {
  assert.equal(IMAGE_WORKER_SOURCE, join(dirname(fileURLToPath(import.meta.url)), "..", "shield-image", "image-worker.swift"));
  assert.match(await readFile(IMAGE_WORKER_SOURCE, "utf8"), /^\/\/ SPDX-License-Identifier: MPL-2\.0\n/);
});
