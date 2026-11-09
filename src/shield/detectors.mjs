import { access } from "node:fs/promises";
import { join } from "node:path";
import { loadPins, opfDownloadPlan } from "./opf-fetch.mjs";
import { fetchOpfBundle } from "./opf-install.mjs";
import { liveOpfJob, readOpfJob, runOpfJob, startOpfJob } from "./opf-job.mjs";
import { provisionOpfPrivacy } from "./opf-privacy.mjs";
import { buildOpfVenv } from "./opf-venv.mjs";
import { doctorGitleaksWarnings, gitleaksOverride, installGitleaks, pinnedGitleaksSha256 } from "./gitleaks-install.mjs";
import { detectPlatform } from "./platform.mjs";
import { adoptAsset, storedGitleaksPath } from "./asset-adopt.mjs";
import { defaultIsProcessAlive } from "./file-lock.mjs";
import { OPF_MAX_SCAN_TIMEOUT_MS, OPF_OPEN_BUDGET_MS } from "./opf-args.mjs";
import { readShieldAssetsProvision, shieldAssetStore, updateShieldAssetsProvision } from "./paths.mjs";

const UNSUPPORTED_NOTICE = "OPF is unsupported on this platform; Shield stays on regex + Gitleaks";
const FALLBACK_NOTICE = "Shield is degraded: PII detection runs on the regex fallback until OPF is verified";
// Downloads fill the first 90% of the progress bar; the venv build is the rest.
const DOWNLOAD_SHARE = 90;
// A self-test-only job is one checkpoint verification, one OPF open and one
// probe scan; a minute on top covers the verification and the record writes.
export const OPF_SELF_TEST_WAIT_MS = OPF_OPEN_BUDGET_MS + OPF_MAX_SCAN_TIMEOUT_MS + 60_000;
const OPF_JOB_POLL_MS = 1_000;

function defaults(io = {}) {
  return {
    loadPins: io.loadPins ?? loadPins,
    detectPlatform: io.detectPlatform ?? detectPlatform,
    fetchOpfBundle: io.fetchOpfBundle ?? fetchOpfBundle,
    buildOpfVenv: io.buildOpfVenv ?? buildOpfVenv,
    installGitleaks: io.installGitleaks ?? installGitleaks,
    gitleaksOverride: io.gitleaksOverride ?? gitleaksOverride,
    adoptAsset: io.adoptAsset ?? adoptAsset,
    doctorGitleaksWarnings: io.doctorGitleaksWarnings ?? doctorGitleaksWarnings,
    pinnedGitleaksSha256: io.pinnedGitleaksSha256 ?? pinnedGitleaksSha256,
    exists: io.exists ?? (async (path) => access(path).then(() => true, () => false)),
    readAssets: io.readAssets ?? readShieldAssetsProvision,
    updateAssets: io.updateAssets ?? updateShieldAssetsProvision,
    startOpfJob: io.startOpfJob ?? startOpfJob,
    liveOpfJob: io.liveOpfJob ?? liveOpfJob,
    readOpfJob: io.readOpfJob ?? readOpfJob,
    provisionOpfPrivacy: io.provisionOpfPrivacy ?? provisionOpfPrivacy,
    isProcessAlive: io.isProcessAlive ?? defaultIsProcessAlive,
    sleep: io.sleep ?? ((ms) => new Promise((settle) => setTimeout(settle, ms))),
    now: io.now ?? Date.now,
  };
}

// Gitleaks always installs (it is the detector that must work on day one). OPF
// is downloaded and its venv built only on a supported platform; elsewhere the
// result names the regex + Gitleaks fallback and nothing is fetched. With
// `background`, the OPF half is handed to the detached job and install returns
// as soon as Gitleaks is recorded, unless the bundle and venv are already on
// disk: then the job only re-runs the OPF self-test, and install waits for it.
// Install restarts the daemon next, and a daemon booting beside that self-test
// competes with it for the checkpoint and the CPU inside its fixed OPF startup
// budget; with no signed regex fallback, losing that race exits the daemon.
export async function fetchDetectorAssets({ paths, gitleaksPath, write = false, background = false, io } = {}) {
  const deps = defaults(io);
  const pins = await deps.loadPins();
  const platform = await deps.detectPlatform();
  const opfPlanned = platform.supported ? "download" : "unsupported";
  if (!write) {
    return Object.freeze({
      state: "preview",
      platform: platformSummary(platform),
      gitleaks: { action: gitleaksPath ? "override" : "download", version: pins.gitleaks.version },
      opf: { action: opfPlanned },
    });
  }

  const gitleaks = gitleaksPath
    ? await adoptOverride(await deps.gitleaksOverride({ path: gitleaksPath }), paths, deps)
    : await deps.installGitleaks({ pins, store: shieldAssetStore(paths), platform });
  const gitleaksSummary = { origin: gitleaks.origin, version: gitleaks.version, sha256: gitleaks.sha256 };
  if (background && platform.supported) {
    const selfTestOnly = await opfOnDisk({ paths, pins, deps });
    const job = await deps.startOpfJob({ paths });
    if (selfTestOnly) {
      // Gitleaks is recorded only after the wait: until install reaches the
      // plist, a KeepAlive restart of the running daemon must still find the
      // Gitleaks its config names, including when the wait times out.
      await waitForOpfJob({ paths, pid: job.pid, deps });
      const recorded = await recordDetectorInstall({ paths, gitleaks, deps });
      const outcome = await deps.readOpfJob({ paths });
      const state = outcome?.state ?? "failed";
      return Object.freeze({
        state: state === "verified" ? "verified" : "degraded",
        platform: platformSummary(platform),
        gitleaks: gitleaksSummary,
        opf: { state, job: job.started ? "started" : "already running", ...(outcome?.reason ? { reason: outcome.reason } : {}) },
        recorded,
      });
    }
    const recorded = await recordDetectorInstall({ paths, gitleaks, deps });
    return Object.freeze({
      state: "preparing",
      platform: platformSummary(platform),
      gitleaks: gitleaksSummary,
      opf: { state: "preparing", job: job.started ? "started" : "already running" },
      recorded,
    });
  }
  const opf = await installOpf({ paths, pins, platform, deps });
  const recorded = await recordDetectorInstall({ paths, gitleaks, opf, deps });
  return Object.freeze({
    state: opf.state === "verified" ? "verified" : "degraded",
    platform: platformSummary(platform),
    gitleaks: gitleaksSummary,
    opf: opf.state === "unsupported" ? { state: "unsupported", notice: UNSUPPORTED_NOTICE }
      : { state: opf.state, ...(opf.reason ? { reason: opf.reason } : {}) },
    recorded,
  });
}

async function opfOnDisk({ paths, pins, deps }) {
  const bundle = shieldAssetStore(paths).opfBundle(pins.code.commit, pins.checkpoint.revision);
  return await deps.exists(bundle.dir) && await deps.exists(join(bundle.venv, "bin", "python"));
}

// The spawned pid covers the moment before the job takes its lock; the lock
// covers a job some other install had already started.
async function waitForOpfJob({ paths, pid, deps }) {
  const deadline = deps.now() + OPF_SELF_TEST_WAIT_MS;
  while ((Number.isInteger(pid) && await deps.isProcessAlive(pid)) || await deps.liveOpfJob({ paths })) {
    if (deps.now() >= deadline) throw new Error("the OPF self-test is still running; rerun ccshield install --write after it finishes");
    await deps.sleep(OPF_JOB_POLL_MS);
  }
}

// The OPF fetch + venv build the background job runs. `onProgress` receives
// an integer percent.
export async function prepareOpf({ paths, io, onProgress } = {}) {
  const deps = defaults(io);
  return installOpf({ paths, pins: await deps.loadPins(), platform: await deps.detectPlatform(), deps, onProgress });
}

async function installOpf({ paths, pins, platform, deps, onProgress }) {
  const platformKey = platform.key ?? "none";
  if (!platform.supported) return { state: "unsupported", platform: platformKey, reason: platform.reason ?? "unknown platform" };
  const store = shieldAssetStore(paths);
  const bundle = store.opfBundle(pins.code.commit, pins.checkpoint.revision);
  if (!await deps.exists(bundle.dir)) {
    await deps.fetchOpfBundle({ pins, store, platform, ...(onProgress ? { onProgress: downloadProgress(pins, onProgress) } : {}) });
  }
  onProgress?.(DOWNLOAD_SHARE);
  const venvReady = await deps.exists(join(bundle.venv, "bin", "python"));
  const venv = venvReady ? { state: "verified" } : await deps.buildOpfVenv({ venvDir: bundle.venv, platform });
  if (venv.state !== "verified") return { state: "failed", platform: platformKey, reason: venv.reason ?? "venv build failed" };
  // OPF only counts once the daemon can use it: a failed self-test or digest
  // leaves privacy as it was, so the daemon stays on regex.
  try {
    await deps.provisionOpfPrivacy({ paths, pins, bundle });
  } catch (error) {
    return { state: "failed", platform: platformKey, reason: `privacy provision failed: ${error?.message ?? String(error)}`.slice(0, 500) };
  }
  return { state: "verified", platform: platformKey, bundle: bundle.dir, ...(venv.python ? { python: venv.python, torch: venv.torch } : {}) };
}

function downloadProgress(pins, onProgress) {
  const sizes = new Map(opfDownloadPlan(pins).filter((item) => Number.isFinite(item.size) && item.size > 0).map((item) => [item.name, item.size]));
  const total = [...sizes.values()].reduce((sum, size) => sum + size, 0);
  const written = new Map();
  return ({ name, bytes }) => {
    if (!total || !sizes.has(name)) return;
    written.set(name, Math.min(bytes, sizes.get(name)));
    const done = [...written.values()].reduce((sum, value) => sum + value, 0);
    onProgress(Math.floor((DOWNLOAD_SHARE * done) / total));
  };
}

// The record's opf block has a fixed schema; Python and torch versions stay in
// the job file.
function opfRecord(opf) {
  return opf.state === "verified"
    ? { state: "verified", platform: opf.platform, bundle: opf.bundle }
    : { state: opf.state, platform: opf.platform, reason: opf.reason };
}

// Install owns only the Gitleaks binary reference and the opf block; the
// rules, policy bundle, regex and privacy fields stay as provision wrote them.
// A version-1 record has no regex worker, so it cannot be rewritten until
// `ccshield privacy provision` runs again. Without an opf outcome the
// recorded one is kept. The merge runs under the record's lock, so a
// provision that lands while the job runs keeps what it wrote.
async function recordDetectorInstall({ paths, gitleaks, opf, deps }) {
  let outcome = "skipped: no asset record; run ccshield privacy provision";
  await deps.updateAssets({
    paths,
    update: async (current) => {
      if (!current) return undefined;
      if (!current.regex) {
        outcome = "skipped: legacy asset record; rerun ccshield privacy provision";
        return undefined;
      }
      const { opf: recordedOpf, ...rest } = current;
      const nextOpf = opf ? opfRecord(opf) : recordedOpf;
      outcome = "written";
      return {
        ...rest,
        ...(gitleaks ? { gitleaks: { origin: gitleaks.origin, version: gitleaks.version, path: gitleaks.path, ...(gitleaks.source ? { source: gitleaks.source } : {}), sha256: gitleaks.sha256, rules: current.gitleaks.rules } } : {}),
        ...(nextOpf ? { opf: nextOpf } : {}),
      };
    },
  });
  return outcome;
}

// The background job's outcome lands in each lane record that exists.
export async function recordOpfOutcome({ paths, opf, io } = {}) {
  return recordDetectorInstall({ paths, opf, deps: defaults(io) });
}

// Body of the detached `__opf-job` process.
export async function runOpfJobForLane({ paths, io } = {}) {
  return runOpfJob({
    paths,
    prepare: ({ onProgress }) => prepareOpf({ paths, io, onProgress }),
    record: (opf) => recordOpfOutcome({ paths, opf, io }),
    io,
  });
}

// The first launch starts the job when OPF has never been attempted. A
// recorded failure is left alone, since restarting it on every launch would
// loop without bound; `ccshield install --write` retries it.
export async function ensureOpfJob({ paths, io } = {}) {
  const deps = defaults(io);
  const assets = await deps.readAssets({ paths }).catch(() => null);
  if (!assets?.regex || assets.opf) return { started: false };
  if (!(await deps.detectPlatform()).supported) return { started: false };
  return deps.startOpfJob({ paths });
}

// Doctor warnings only; a drifted or missing detector never fails doctor.
export async function doctorDetectorAssets({ paths, assets, io } = {}) {
  const deps = defaults(io);
  const pins = await deps.loadPins();
  const platform = await deps.detectPlatform();
  const live = await deps.liveOpfJob({ paths });
  const warnings = [];
  if (!platform.supported) warnings.push(`${UNSUPPORTED_NOTICE} (${platform.reason ?? "unknown platform"})`);
  if (assets?.gitleaks) {
    const pinnedSha256 = await deps.pinnedGitleaksSha256({ pins, store: shieldAssetStore(paths) }).catch(() => null);
    warnings.push(...await deps.doctorGitleaksWarnings(assets.gitleaks, pins, { pinnedSha256: pinnedSha256 ?? undefined }));
  }
  if (assets && !live) warnings.push(...await opfWarnings({ paths, opf: assets.opf, pins, platform, deps }));
  const opf = await opfDoctorState({ paths, opf: assets?.opf, live, platform, deps });
  if (assets && platform.supported && opf.state !== "verified") warnings.push(FALLBACK_NOTICE);
  return Object.freeze({
    platform: platformSummary(platform),
    opf,
    adapter: assets?.privacy?.adapter?.sha256 ?? "none",
    warnings: Object.freeze(warnings),
  });
}

async function opfDoctorState({ paths, opf, live, platform, deps }) {
  if (live) return { state: `preparing ${live.progress ?? 0}%` };
  if (opf?.state === "verified") {
    const job = await deps.readOpfJob({ paths });
    return { state: "verified", python: job?.python ?? "unknown", torch: job?.torch ?? "unknown" };
  }
  if (opf?.state === "failed") return { state: `failed: ${opf.reason}` };
  if (opf?.state === "unsupported" || !platform.supported) return { state: "unsupported" };
  return { state: "absent" };
}

async function opfWarnings({ paths, opf, pins, platform, deps }) {
  if (!platform.supported) return [];
  if (!opf) return ["shield OPF was not installed; run ccshield install --write"];
  if (opf.state === "failed") return [`shield OPF install failed: ${opf.reason}`];
  if (opf.state === "unsupported") return ["shield OPF was recorded as unsupported; run ccshield install --write on this platform"];
  const pinned = shieldAssetStore(paths).opfBundle(pins.code.commit, pins.checkpoint.revision);
  if (opf.bundle !== pinned.dir) return ["shield OPF bundle differs from the pinned revision; run ccshield install --write"];
  if (!await deps.exists(join(pinned.venv, "bin", "python"))) return [`shield OPF venv at ${pinned.venv} is missing`];
  return [];
}

function platformSummary(platform) {
  return { supported: platform.supported, key: platform.key ?? "none", ...(platform.reason ? { reason: platform.reason } : {}) };
}

// An override is copied into the asset store so a Homebrew upgrade or cleanup
// of the original path cannot take the daemon's binary away.
async function adoptOverride(gitleaks, paths, deps) {
  const target = storedGitleaksPath(shieldAssetStore(paths).root, gitleaks.sha256);
  await deps.adoptAsset({ source: gitleaks.path, sha256: gitleaks.sha256, target, executable: true });
  return Object.freeze({ ...gitleaks, path: target, source: gitleaks.path });
}
