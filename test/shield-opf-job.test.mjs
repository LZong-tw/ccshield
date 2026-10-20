import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { runShieldCli } from "../src/shield/cli.mjs";
import { doctorDetectorAssets, ensureOpfJob, fetchDetectorAssets } from "../src/shield/detectors.mjs";
import { liveOpfJob, OPF_JOB_MAX_ATTEMPTS, opfJobFiles, readOpfJob, runOpfJob, startOpfJob } from "../src/shield/opf-job.mjs";
import { shieldPaths } from "../src/shield/paths.mjs";
import { readShieldStatuslineState, shieldStatuslineSuffix } from "../src/shield/statusline-state.mjs";

const LIVE_PID = 4242;
const DEAD_PID = 4343;
const clock = () => new Date("2026-10-20T00:00:00.000Z");

async function withHome(fn) {
  const home = await mkdtemp(join(tmpdir(), "ccshield-opf-job-"));
  try { return await fn(shieldPaths({ env: { HOME: home } }), home); } finally { await rm(home, { recursive: true, force: true }); }
}

// Never spawns: the job body is driven directly, the spawn is recorded.
function jobIo(spawned = []) {
  return {
    pid: LIVE_PID,
    isProcessAlive: async (pid) => pid === LIVE_PID,
    spawnJob: async ({ lane }) => { spawned.push(lane); return 9999; },
  };
}

async function writeLock(paths, pid) {
  const files = opfJobFiles(paths);
  await mkdir(files.dir, { recursive: true });
  await writeFile(files.lock, `${pid}\n`);
}

async function writeJobFile(paths, job) {
  const files = opfJobFiles(paths);
  await mkdir(files.dir, { recursive: true });
  await writeFile(files.job, JSON.stringify(job));
}

function run(paths, { outcomes, recorded = [], sleeps = [] }) {
  let call = 0;
  return runOpfJob({
    paths,
    io: jobIo(),
    now: clock,
    sleep: async (ms) => { sleeps.push(ms); },
    prepare: async ({ onProgress }) => {
      onProgress(90);
      const next = outcomes[Math.min(call, outcomes.length - 1)];
      call += 1;
      if (next instanceof Error) throw next;
      return next;
    },
    record: async (opf) => { recorded.push(opf); },
  });
}

test("the job walks running to verified and records the outcome once", () => withHome(async (paths) => {
  const recorded = [];
  const sleeps = [];
  const result = await run(paths, { outcomes: [{ state: "verified", python: "3.12.4", torch: "2.4.1" }], recorded, sleeps });
  assert.deepEqual(result, { state: "verified", attempt: 1 });
  assert.deepEqual(recorded, [{ state: "verified", python: "3.12.4", torch: "2.4.1" }]);
  assert.deepEqual(sleeps, []);
  const job = await readOpfJob({ paths });
  assert.equal(job.state, "verified");
  assert.equal(job.progress, 100);
  assert.equal(job.python, "3.12.4");
  assert.equal(job.torch, "2.4.1");
  assert.equal(job.updatedAt, "2026-10-20T00:00:00.000Z");
  await assert.rejects(readFile(opfJobFiles(paths).lock), { code: "ENOENT" });
}));

test("the job writes monotonic progress while preparing", () => withHome(async (paths) => {
  let saved;
  await runOpfJob({
    paths, io: jobIo(), now: clock, sleep: async () => {},
    prepare: async ({ onProgress }) => {
      onProgress(25);
      onProgress(10);
      onProgress(60);
      for (let tries = 0; tries < 200 && saved?.progress !== 60; tries += 1) {
        await new Promise((settle) => setTimeout(settle, 5));
        saved = await readOpfJob({ paths });
      }
      return { state: "verified" };
    },
    record: async () => {},
  });
  assert.equal(saved.state, "running");
  assert.equal(saved.progress, 60);
}));

test("the job retries with backoff and ends failed at the attempt cap", () => withHome(async (paths) => {
  const recorded = [];
  const sleeps = [];
  const result = await run(paths, { outcomes: [new Error("tarball digest mismatch")], recorded, sleeps });
  assert.equal(OPF_JOB_MAX_ATTEMPTS, 3);
  assert.deepEqual(result, { state: "failed", attempt: 3, reason: "tarball digest mismatch" });
  assert.deepEqual(sleeps, [30_000, 120_000]);
  assert.deepEqual(recorded, [{ state: "failed", platform: "none", reason: "tarball digest mismatch" }]);
  const job = await readOpfJob({ paths });
  assert.equal(job.state, "failed");
  assert.equal(job.attempt, 3);
  assert.equal(job.reason, "tarball digest mismatch");
}));

test("a failed attempt followed by success records only the success", () => withHome(async (paths) => {
  const recorded = [];
  const sleeps = [];
  const result = await run(paths, { outcomes: [{ state: "failed", reason: "venv build failed" }, { state: "verified" }], recorded, sleeps });
  assert.deepEqual(result, { state: "verified", attempt: 2 });
  assert.deepEqual(sleeps, [30_000]);
  assert.deepEqual(recorded, [{ state: "verified" }]);
}));

test("an unsupported outcome is terminal without retry", () => withHome(async (paths) => {
  const recorded = [];
  const sleeps = [];
  const result = await run(paths, { outcomes: [{ state: "unsupported", reason: "glibc too old" }], recorded, sleeps });
  assert.deepEqual(result, { state: "unsupported", attempt: 1 });
  assert.deepEqual(sleeps, []);
  assert.equal(recorded.length, 1);
}));

test("the job resumes the attempt count from an interrupted job.json", () => withHome(async (paths) => {
  await writeJobFile(paths, { state: "running", pid: DEAD_PID, attempt: 2, progress: 55, reason: "connection reset" });
  await writeLock(paths, DEAD_PID);
  const recorded = [];
  const sleeps = [];
  const result = await run(paths, { outcomes: [new Error("connection reset again")], recorded, sleeps });
  assert.deepEqual(result, { state: "failed", attempt: 3, reason: "connection reset again" });
  assert.deepEqual(sleeps, [120_000]);
  assert.equal(recorded.length, 1);
}));

test("a terminal job.json starts a fresh attempt budget", () => withHome(async (paths) => {
  await writeJobFile(paths, { state: "failed", pid: DEAD_PID, attempt: 3, progress: 0, reason: "old failure" });
  const sleeps = [];
  const result = await run(paths, { outcomes: [new Error("still failing")], sleeps });
  assert.equal(result.attempt, 3);
  assert.deepEqual(sleeps, [30_000, 120_000]);
}));

test("a second job refuses to run while a live holder owns the lock", () => withHome(async (paths) => {
  await writeLock(paths, LIVE_PID);
  let prepared = false;
  const result = await runOpfJob({
    paths, io: { ...jobIo(), pid: 5555 }, now: clock, sleep: async () => {},
    prepare: async () => { prepared = true; return { state: "verified" }; },
    record: async () => {},
  });
  assert.deepEqual(result, { state: "busy" });
  assert.equal(prepared, false);
  assert.equal((await readFile(opfJobFiles(paths).lock, "utf8")).trim(), String(LIVE_PID));
}));

test("start does not spawn while a job is live and reports its progress", () => withHome(async (paths) => {
  await writeLock(paths, LIVE_PID);
  await writeJobFile(paths, { state: "running", pid: LIVE_PID, attempt: 1, progress: 37 });
  const spawned = [];
  const live = await liveOpfJob({ paths, io: jobIo(spawned) });
  assert.equal(live.progress, 37);
  const started = await startOpfJob({ paths, io: jobIo(spawned) });
  assert.deepEqual(started, { started: false, state: "running", pid: LIVE_PID });
  assert.deepEqual(spawned, []);
}));

test("a stale lock from a dead pid is recovered by start and by the job", () => withHome(async (paths) => {
  await writeLock(paths, DEAD_PID);
  await writeJobFile(paths, { state: "running", pid: DEAD_PID, attempt: 1, progress: 80 });
  const spawned = [];
  assert.equal(await liveOpfJob({ paths, io: jobIo(spawned) }), null);
  const started = await startOpfJob({ paths, io: jobIo(spawned) });
  assert.equal(started.started, true);
  assert.deepEqual(spawned, ["subscription"]);
  const result = await run(paths, { outcomes: [{ state: "verified" }] });
  assert.equal(result.state, "verified");
}));

test("background install records Gitleaks and hands OPF to the job", () => withHome(async (paths) => {
  const calls = [];
  const writes = [];
  const io = {
    loadPins: async () => ({ code: { commit: "f".repeat(40) }, checkpoint: { revision: "e".repeat(40) }, gitleaks: { version: "8.30.1" } }),
    detectPlatform: async () => ({ supported: true, key: "darwin-arm64" }),
    installGitleaks: async () => ({ origin: "downloaded", version: "8.30.1", path: "/store/gitleaks", sha256: "a".repeat(64) }),
    fetchOpfBundle: async () => { calls.push("opf"); },
    buildOpfVenv: async () => { calls.push("venv"); return { state: "verified" }; },
    readAssets: async () => null,
    writeAssets: async ({ state }) => writes.push(state),
    startOpfJob: async () => { calls.push("job"); return { started: true, state: "running" }; },
  };
  const result = await fetchDetectorAssets({ paths, write: true, background: true, io });
  assert.equal(result.state, "preparing");
  assert.deepEqual(result.opf, { state: "preparing", job: "started" });
  assert.deepEqual(calls, ["job"]);

  const again = await fetchDetectorAssets({ paths, write: true, background: true, io: { ...io, startOpfJob: async () => ({ started: false, state: "running", pid: LIVE_PID }) } });
  assert.deepEqual(again.opf, { state: "preparing", job: "already running" });

  const unsupported = await fetchDetectorAssets({ paths, write: true, background: true, io: { ...io, detectPlatform: async () => ({ supported: false, key: null, reason: "macOS 13 is not supported" }) } });
  assert.equal(unsupported.opf.state, "unsupported");
  assert.deepEqual(calls, ["job"]);
}));

test("launch starts the job only for a regex-provisioned lane with no OPF record", () => withHome(async (paths) => {
  const starts = [];
  const io = (assets, supported = true) => ({
    readAssets: async () => assets,
    detectPlatform: async () => ({ supported, key: supported ? "darwin-arm64" : null }),
    startOpfJob: async ({ paths: lanePaths }) => { starts.push(lanePaths.lane); return { started: true, state: "running" }; },
  });
  assert.deepEqual(await ensureOpfJob({ paths, io: io(null) }), { started: false });
  assert.deepEqual(await ensureOpfJob({ paths, io: io({ regex: { version: "regex-v1" }, opf: { state: "failed", reason: "x" } }) }), { started: false });
  assert.deepEqual(await ensureOpfJob({ paths, io: io({ regex: { version: "regex-v1" } }, false) }), { started: false });
  assert.deepEqual(await ensureOpfJob({ paths, io: io({ regex: { version: "regex-v1" } }) }), { started: true, state: "running" });
  assert.deepEqual(starts, ["subscription"]);
}));

test("ccshield launch asks for the OPF job on the launched lane", async () => {
  const lanes = [];
  await runShieldCli(["launch", "--lane", "subscription", "--target", "http://127.0.0.1:8804", "--", "echo", "ok"], {
    stdout: { write() {} },
    ensureShieldReady: async () => ({ origin: "http://127.0.0.1:8811", capability: "a".repeat(32), lane: "subscription", targetClass: "subscription" }),
    ensureOpfJob: async ({ paths }) => { lanes.push(paths.lane); return { started: true }; },
    createShieldDestinationLease: async ({ ready }) => ready,
    revokeShieldDestinationLease: async () => {},
    shieldLeaseSetInterval: () => ({ unref() {} }),
    shieldLeaseClearInterval: () => {},
    launchShieldChild: async () => ({ code: 0 }),
  });
  assert.deepEqual(lanes, ["subscription"]);
});

function doctorIo(overrides = {}) {
  return {
    loadPins: async () => ({ code: { commit: "f".repeat(40) }, checkpoint: { revision: "e".repeat(40) }, gitleaks: { version: "8.30.1" } }),
    detectPlatform: async () => ({ supported: true, key: "darwin-arm64" }),
    exists: async () => true,
    liveOpfJob: async () => null,
    readOpfJob: async () => null,
    ...overrides,
  };
}

const regexOnly = Object.freeze({ regex: { version: "regex-v1" } });
const fallback = /regex fallback until OPF is verified/;

test("doctor reports an absent OPF engine and the regex fallback", () => withHome(async (paths) => {
  const result = await doctorDetectorAssets({ paths, assets: regexOnly, io: doctorIo() });
  assert.equal(result.opf.state, "absent");
  assert.equal(result.adapter, "none");
  assert.equal(result.platform.supported, true);
  assert.ok(result.warnings.some((line) => fallback.test(line)));
}));

test("doctor reports a live job as preparing with its percentage", () => withHome(async (paths) => {
  const result = await doctorDetectorAssets({ paths, assets: regexOnly, io: doctorIo({ liveOpfJob: async () => ({ state: "running", progress: 42 }) }) });
  assert.equal(result.opf.state, "preparing 42%");
  assert.ok(result.warnings.some((line) => fallback.test(line)));
}));

test("doctor reports a verified engine with Python, torch and adapter hash", () => withHome(async (paths) => {
  const assets = { ...regexOnly, opf: { state: "verified", platform: "darwin-arm64", bundle: "/store/opf" }, privacy: { adapter: { sha256: "c".repeat(64) } } };
  const result = await doctorDetectorAssets({
    paths, assets,
    io: doctorIo({ readOpfJob: async () => ({ state: "verified", python: "3.12.4", torch: "2.4.1" }) }),
  });
  assert.deepEqual(result.opf, { state: "verified", python: "3.12.4", torch: "2.4.1" });
  assert.equal(result.adapter, "c".repeat(64));
  assert.ok(!result.warnings.some((line) => fallback.test(line)));
}));

test("doctor reports a failed engine with its reason and the fallback notice", () => withHome(async (paths) => {
  const result = await doctorDetectorAssets({ paths, assets: { ...regexOnly, opf: { state: "failed", platform: "darwin-arm64", reason: "venv build failed" } }, io: doctorIo() });
  assert.equal(result.opf.state, "failed: venv build failed");
  assert.ok(result.warnings.some((line) => fallback.test(line)));
}));

test("doctor reports an unsupported platform without the fallback notice", () => withHome(async (paths) => {
  const result = await doctorDetectorAssets({
    paths, assets: regexOnly,
    io: doctorIo({ detectPlatform: async () => ({ supported: false, key: null, reason: "macOS 13 is not supported" }) }),
  });
  assert.equal(result.opf.state, "unsupported");
  assert.equal(result.platform.supported, false);
  assert.ok(!result.warnings.some((line) => fallback.test(line)));
}));

test("statusline shows the PII engine preparing while a job is live", async () => {
  const operational = { state: "protected", lanes: [{ lane: "subscription", state: "protected" }] };
  const preparing = await readShieldStatuslineState({ readOperationalStatus: async () => operational, readOpfPreparing: async () => true });
  assert.match(shieldStatuslineSuffix(preparing), / · PII engine preparing$/);
  const idle = await readShieldStatuslineState({ readOperationalStatus: async () => operational, readOpfPreparing: async () => false });
  assert.doesNotMatch(shieldStatuslineSuffix(idle), /preparing/);
  const broken = await readShieldStatuslineState({ readOperationalStatus: async () => operational, readOpfPreparing: async () => { throw new Error("boom"); } });
  assert.equal("preparing" in broken, false);
  assert.equal("preparing" in idle, false);
});

test("statusline reads a live lock from the lane store", async () => {
  const home = await mkdtemp(join(tmpdir(), "ccshield-opf-statusline-"));
  try {
    const paths = shieldPaths({ env: { HOME: home }, lane: "managed" });
    await writeLock(paths, process.pid);
    const state = await readShieldStatuslineState({ env: { HOME: home }, readOperationalStatus: async () => ({ lanes: [] }) });
    assert.equal(state.preparing, true);
  } finally { await rm(home, { recursive: true, force: true }); }
});
