import { spawn } from "node:child_process";
import { mkdir, open, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { shieldAssetStore } from "./paths.mjs";

export const OPF_JOB_MAX_ATTEMPTS = 3;
const BACKOFF_MS = Object.freeze([30_000, 120_000]);
const TERMINAL = new Set(["verified", "failed", "unsupported"]);
const CLI_PATH = fileURLToPath(new URL("./cli.mjs", import.meta.url));

// The first OPF install downloads ~3 GB and builds a torch venv, so install
// and launch hand it to a detached job. The job owns assets/opf/job.lock while
// it runs; job.json carries progress and the attempt count, which is what lets
// a job killed mid-download resume without ever exceeding the retry cap.
export function opfJobFiles(paths) {
  const { opfRoot } = shieldAssetStore(paths);
  return Object.freeze({ dir: opfRoot, job: join(opfRoot, "job.json"), lock: join(opfRoot, "job.lock") });
}

function defaults(io = {}) {
  return {
    isProcessAlive: io.isProcessAlive ?? defaultIsProcessAlive,
    spawnJob: io.spawnJob ?? defaultSpawnJob,
    pid: io.pid ?? process.pid,
  };
}

export async function readOpfJob({ paths }) {
  try {
    const job = JSON.parse(await readFile(opfJobFiles(paths).job, "utf8"));
    return job && typeof job === "object" && typeof job.state === "string" ? job : null;
  } catch {
    return null;
  }
}

// A job counts as live only while its lock names a running process; a lock
// left by a dead pid is stale and does not block a new start.
export async function liveOpfJob({ paths, io } = {}) {
  const deps = defaults(io);
  const holder = await lockHolder(opfJobFiles(paths).lock);
  if (holder === null || !await deps.isProcessAlive(holder)) return null;
  const job = await readOpfJob({ paths });
  return job?.state === "running" ? job : { state: "running", pid: holder, attempt: 0, progress: 0 };
}

export async function startOpfJob({ paths, io } = {}) {
  const deps = defaults(io);
  const live = await liveOpfJob({ paths, io });
  if (live) return Object.freeze({ started: false, state: "running", pid: live.pid });
  const pid = await deps.spawnJob({ lane: paths.lane });
  return Object.freeze({ started: true, state: "running", ...(Number.isInteger(pid) ? { pid } : {}) });
}

// Runs inside the detached process. `prepare` is the OPF fetch + venv build,
// `record` writes the outcome into the asset records; both are injected so
// the loop is testable without the network or real sleeps.
export async function runOpfJob({ paths, prepare, record, io, sleep = defaultSleep, now = () => new Date() } = {}) {
  const deps = defaults(io);
  const files = opfJobFiles(paths);
  await mkdir(files.dir, { recursive: true, mode: 0o700 });
  if (!await acquireLock(files.lock, deps)) return Object.freeze({ state: "busy" });
  try {
    const prior = await readOpfJob({ paths });
    let attempt = prior && !TERMINAL.has(prior.state) && Number.isInteger(prior.attempt) ? prior.attempt : 0;
    let reason = prior?.reason ?? "no attempt left";
    let platform = "none";
    const save = (fields) => writeJob(files.job, { pid: deps.pid, attempt, updatedAt: now().toISOString(), ...fields });

    while (attempt < OPF_JOB_MAX_ATTEMPTS) {
      if (attempt > 0) {
        await save({ state: "running", progress: 0, reason });
        await sleep(BACKOFF_MS[Math.min(attempt, BACKOFF_MS.length) - 1]);
      }
      attempt += 1;
      let lastPercent = 0;
      let pending = save({ state: "running", progress: 0 });
      const onProgress = (percent) => {
        if (percent <= lastPercent) return;
        lastPercent = percent;
        pending = pending.then(() => save({ state: "running", progress: percent }));
      };
      let opf;
      try {
        opf = await prepare({ onProgress });
      } catch (error) {
        opf = { state: "failed", reason: error?.message ?? String(error) };
      }
      await pending;
      if (opf.state === "verified" || opf.state === "unsupported") {
        await record(opf);
        await save({ state: opf.state, progress: 100, ...(opf.python ? { python: opf.python, torch: opf.torch } : {}), ...(opf.reason ? { reason: opf.reason } : {}) });
        return Object.freeze({ state: opf.state, attempt });
      }
      reason = opf.reason ?? "OPF install failed";
      platform = opf.platform ?? platform;
    }
    await record({ state: "failed", platform, reason });
    await save({ state: "failed", progress: 0, reason });
    return Object.freeze({ state: "failed", attempt, reason });
  } finally {
    await rm(files.lock, { force: true });
  }
}

async function acquireLock(lockPath, deps) {
  for (let tries = 0; tries < 2; tries += 1) {
    try {
      const handle = await open(lockPath, "wx", 0o600);
      try { await handle.writeFile(`${deps.pid}\n`); } finally { await handle.close(); }
      return true;
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      const holder = await lockHolder(lockPath);
      if (holder !== null && await deps.isProcessAlive(holder)) return false;
      await rm(lockPath, { force: true });
    }
  }
  return false;
}

async function lockHolder(lockPath) {
  try {
    const pid = Number.parseInt(await readFile(lockPath, "utf8"), 10);
    return Number.isInteger(pid) && pid > 0 ? pid : null;
  } catch {
    return null;
  }
}

async function writeJob(path, job) {
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify({ version: 1, ...job })}\n`, { mode: 0o600 });
  await rename(temporary, path);
}

function defaultSleep(ms) {
  return new Promise((settle) => setTimeout(settle, ms));
}

async function defaultIsProcessAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code === "EPERM";
  }
}

async function defaultSpawnJob({ lane }) {
  const child = spawn(process.execPath, [CLI_PATH, "__opf-job", "--lane", lane], { detached: true, stdio: "ignore" });
  child.unref();
  return child.pid;
}
