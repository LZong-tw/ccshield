import { access } from "node:fs/promises";
import { join } from "node:path";
import { loadPins } from "./opf-fetch.mjs";
import { fetchOpfBundle } from "./opf-install.mjs";
import { buildOpfVenv } from "./opf-venv.mjs";
import { doctorGitleaksWarnings, gitleaksOverride, installGitleaks, pinnedGitleaksSha256 } from "./gitleaks-install.mjs";
import { detectPlatform } from "./platform.mjs";
import { readShieldAssetsProvision, shieldAssetStore, writeShieldAssetsProvision } from "./paths.mjs";

const UNSUPPORTED_NOTICE = "OPF is unsupported on this platform; Shield stays on regex + Gitleaks";

function defaults(io = {}) {
  return {
    loadPins: io.loadPins ?? loadPins,
    detectPlatform: io.detectPlatform ?? detectPlatform,
    fetchOpfBundle: io.fetchOpfBundle ?? fetchOpfBundle,
    buildOpfVenv: io.buildOpfVenv ?? buildOpfVenv,
    installGitleaks: io.installGitleaks ?? installGitleaks,
    gitleaksOverride: io.gitleaksOverride ?? gitleaksOverride,
    doctorGitleaksWarnings: io.doctorGitleaksWarnings ?? doctorGitleaksWarnings,
    pinnedGitleaksSha256: io.pinnedGitleaksSha256 ?? pinnedGitleaksSha256,
    exists: io.exists ?? (async (path) => access(path).then(() => true, () => false)),
    readAssets: io.readAssets ?? readShieldAssetsProvision,
    writeAssets: io.writeAssets ?? writeShieldAssetsProvision,
  };
}

// Gitleaks always installs (it is the detector that must work on day one). OPF
// is downloaded and its venv built only on a supported platform; elsewhere the
// result names the regex + Gitleaks fallback and nothing is fetched.
export async function fetchDetectorAssets({ paths, gitleaksPath, write = false, io } = {}) {
  const deps = defaults(io);
  const pins = await deps.loadPins();
  const platform = await deps.detectPlatform();
  const store = shieldAssetStore(paths);
  const bundle = store.opfBundle(pins.code.commit, pins.checkpoint.revision);
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
    ? await deps.gitleaksOverride({ path: gitleaksPath })
    : await deps.installGitleaks({ pins, store, platform });
  const gitleaksSummary = { origin: gitleaks.origin, version: gitleaks.version, sha256: gitleaks.sha256 };
  const platformKey = platform.key ?? "none";
  let opf;
  if (!platform.supported) {
    opf = { state: "unsupported", platform: platformKey, reason: platform.reason ?? "unknown platform" };
  } else {
    if (!await deps.exists(bundle.dir)) await deps.fetchOpfBundle({ pins, store, platform });
    const venvReady = await deps.exists(join(bundle.venv, "bin", "python"));
    const venv = venvReady ? { state: "verified" } : await deps.buildOpfVenv({ venvDir: bundle.venv, platform });
    opf = venv.state === "verified"
      ? { state: "verified", platform: platformKey, bundle: bundle.dir }
      : { state: "failed", platform: platformKey, reason: venv.reason ?? "venv build failed" };
  }
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

// Install owns only the Gitleaks binary reference and the opf block; the
// rules, policy bundle, regex and privacy fields stay as provision wrote them.
// A version-1 record has no regex worker, so it cannot be rewritten until
// `ccshield privacy provision` runs again.
async function recordDetectorInstall({ paths, gitleaks, opf, deps }) {
  const current = await deps.readAssets({ paths });
  if (!current) return "skipped: no asset record; run ccshield privacy provision";
  if (!current.regex) return "skipped: legacy asset record; rerun ccshield privacy provision";
  await deps.writeAssets({
    paths,
    state: {
      ...current,
      gitleaks: { origin: gitleaks.origin, version: gitleaks.version, path: gitleaks.path, sha256: gitleaks.sha256, rules: current.gitleaks.rules },
      opf,
    },
  });
  return "written";
}

// Doctor warnings only; a drifted or missing detector never fails doctor.
export async function doctorDetectorAssets({ paths, assets, io } = {}) {
  const deps = defaults(io);
  const pins = await deps.loadPins();
  const platform = await deps.detectPlatform();
  const warnings = [];
  if (!platform.supported) warnings.push(`${UNSUPPORTED_NOTICE} (${platform.reason ?? "unknown platform"})`);
  if (assets?.gitleaks) {
    const pinnedSha256 = await deps.pinnedGitleaksSha256({ pins, store: shieldAssetStore(paths) }).catch(() => null);
    warnings.push(...await deps.doctorGitleaksWarnings(assets.gitleaks, pins, { pinnedSha256: pinnedSha256 ?? undefined }));
  }
  if (assets) warnings.push(...await opfWarnings({ paths, opf: assets.opf, pins, platform, deps }));
  return Object.freeze({ platform: platformSummary(platform), warnings: Object.freeze(warnings) });
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
