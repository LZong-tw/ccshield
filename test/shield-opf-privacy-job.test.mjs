import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { prepareOpf, recordOpfOutcome } from "../src/shield/detectors.mjs";
import { readOpfJob, runOpfJob } from "../src/shield/opf-job.mjs";
import { provisionOpfPrivacy } from "../src/shield/opf-privacy.mjs";
import { openPrivacyDetector } from "../src/shield/privacy-detector.mjs";
import { provisionPrivacyRecord } from "../src/shield/provision.mjs";
import { shieldAssetStore, shieldPaths } from "../src/shield/paths.mjs";

const WORKER_VERSION = /^const VERSION = "([^"]+)";$/m.exec(
  await readFile(new URL("../detectors/opf/privacy-opf-worker.mjs", import.meta.url), "utf8"),
)[1];
const O200K_CACHE_KEY = "fb374d419588a4632f3f557e76b4b70aebbca790";
const regexAssets = { version: "regex-v1", worker: { command: "/store/regex/regex-v1/privacy-worker.mjs", args: [], sha256: "a".repeat(64) } };
const policy = { detectorVersions: { gitleaks: "8.30.1", privacy: WORKER_VERSION }, detectorFallbacks: { privacy: "regex-v1" } };

function treeSha256(files) {
  const hash = createHash("sha256");
  for (const [name, body] of Object.entries(files).sort(([a], [b]) => Buffer.compare(Buffer.from(a), Buffer.from(b)))) {
    hash.update(name, "utf8").update("\0").update(String(Buffer.byteLength(body))).update("\0").update(body).update("\0");
  }
  return hash.digest("hex");
}

async function writeTree(dir, files) {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  for (const [name, body] of Object.entries(files)) await writeFile(join(dir, name), body, { mode: 0o644 });
}

// A downloaded bundle on disk with pins that match it, so the job's privacy
// provisioning runs the real manifest, digest and record code. Only the
// self-test, which would spawn Python, is faked.
async function withBundle(fn) {
  const home = await realpath(await mkdtemp(join(tmpdir(), "ccshield-opf-privacy-")));
  try {
    const paths = shieldPaths({ env: { HOME: home } });
    const commit = "c".repeat(40);
    const revision = "d".repeat(40);
    const bundle = shieldAssetStore(paths).opfBundle(commit, revision);
    const source = { "source.py": "print('opf')\n" };
    const checkpoint = { "config.json": "{}", "model.safetensors": "weights" };
    const tokenizer = "tokenizer ranks";
    await writeTree(join(bundle.src, "opf"), source);
    await writeTree(join(bundle.checkpoint, "original"), checkpoint);
    await writeTree(bundle.tokenizer, { [O200K_CACHE_KEY]: tokenizer });
    const pins = {
      code: { commit, treeSha256: treeSha256(source) },
      checkpoint: { revision, treeSha256: treeSha256(checkpoint) },
      tokenizer: { cacheName: O200K_CACHE_KEY, encoding: "o200k_base", sha256: createHash("sha256").update(tokenizer).digest("hex") },
      gitleaks: { version: "8.30.1" },
    };
    return await fn({ paths, bundle, pins });
  } finally {
    await rm(home, { recursive: true, force: true });
  }
}

function jobIo({ pins, selfTest }) {
  const box = { record: { version: 3, privacy: { state: "absent" }, regex: regexAssets } };
  const readState = async () => box.record;
  const writeState = async ({ state }) => { box.record = state; };
  return {
    box,
    io: {
      loadPins: async () => pins,
      detectPlatform: async () => ({ supported: true, key: "darwin-arm64" }),
      exists: async () => true,
      fetchOpfBundle: async () => assert.fail("the bundle is already present"),
      buildOpfVenv: async () => ({ state: "verified", python: "3.11.9", torch: "2.4.1" }),
      readAssets: readState,
      writeAssets: writeState,
      provisionOpfPrivacy: (options) => provisionOpfPrivacy({
        ...options,
        provision: (args) => provisionPrivacyRecord({ ...args, runPrivacySelfTest: selfTest, readState, writeState }),
      }),
    },
  };
}

// The lane job's own wiring, minus the retry backoff.
function runJob(paths, io) {
  return runOpfJob({
    paths,
    prepare: ({ onProgress }) => prepareOpf({ paths, io, onProgress }),
    record: (opf) => recordOpfOutcome({ paths, opf, io }),
    sleep: async () => {},
  });
}

function daemon(box) {
  let now = 0;
  const created = [];
  const detector = openPrivacyDetector({
    assets: box.record,
    policy,
    readAssets: async () => box.record,
    createPrivacy: async ({ provision }) => {
      created.push(provision.privacy.version);
      return { version: provision.privacy.version, scan: async () => ({ status: "ok", findings: [] }), isReady: async () => true, close() {} };
    },
    probe: async () => {},
    clock: () => now,
    recheckMs: 1000,
    onUpgradeFailure: (error) => assert.fail(error.message),
  });
  return { detector, created, advance: (ms) => { now += ms; } };
}

test("a successful first run provisions privacy and the running daemon swaps to OPF without a restart", () => withBundle(async ({ paths, bundle, pins }) => {
  const { box, io } = jobIo({ pins, selfTest: async () => ({ version: WORKER_VERSION }) });
  const { detector, created, advance } = daemon(box);
  const privacy = await detector;
  assert.equal(privacy.detectorVersions().privacy, "regex-v1");

  await runJob(paths, io);

  assert.equal((await readOpfJob({ paths })).state, "verified");
  assert.equal(box.record.opf.state, "verified");
  assert.equal(box.record.privacy.state, "verified");
  assert.equal(box.record.privacy.origin, "downloaded");
  assert.equal(box.record.privacy.version, WORKER_VERSION);
  assert.deepEqual(box.record.regex, regexAssets);
  const worker = box.record.privacy.worker.command;
  assert.equal(worker, join(bundle.dir, "worker", "privacy-opf-worker.mjs"));
  assert.equal((await stat(worker)).mode & 0o777, 0o755);
  assert.equal(box.record.privacy.checkpoint.path, join(bundle.checkpoint, "original"));

  advance(1000);
  await privacy.refresh();
  assert.equal(privacy.detectorVersions().privacy, WORKER_VERSION);
  assert.deepEqual(created, ["regex-v1", WORKER_VERSION]);
}));

test("a failed self-test ends the job failed, leaves privacy alone and keeps the daemon on regex", () => withBundle(async ({ paths, pins }) => {
  const { box, io } = jobIo({ pins, selfTest: async () => { throw new Error("worker never answered"); } });
  const { detector, created, advance } = daemon(box);
  const privacy = await detector;

  await runJob(paths, io);

  const job = await readOpfJob({ paths });
  assert.equal(job.state, "failed");
  assert.match(job.reason, /privacy provision failed: worker never answered/);
  assert.deepEqual(box.record.privacy, { state: "absent" });
  advance(1000);
  await privacy.refresh();
  assert.equal(privacy.detectorVersions().privacy, "regex-v1");
  assert.deepEqual(created, ["regex-v1"]);
}));

test("a checkpoint that drifted from its pin ends the job failed before any self-test", () => withBundle(async ({ paths, bundle, pins }) => {
  const { box, io } = jobIo({ pins, selfTest: async () => assert.fail("the self-test must not run") });
  await writeFile(join(bundle.checkpoint, "original", "model.safetensors"), "tampered");

  await runJob(paths, io);

  const job = await readOpfJob({ paths });
  assert.equal(job.state, "failed");
  assert.match(job.reason, /privacy provision failed/);
  assert.deepEqual(box.record.privacy, { state: "absent" });
}));
