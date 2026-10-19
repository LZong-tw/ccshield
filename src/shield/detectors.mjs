import { access } from "node:fs/promises";
import { join } from "node:path";
import { loadPins } from "./opf-fetch.mjs";
import { fetchOpfBundle } from "./opf-install.mjs";
import { buildOpfVenv } from "./opf-venv.mjs";
import { doctorGitleaksWarnings, gitleaksOverride, installGitleaks, pinnedGitleaksSha256 } from "./gitleaks-install.mjs";
import { detectPlatform } from "./platform.mjs";
import { shieldAssetStore } from "./paths.mjs";

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
  if (!platform.supported) {
    return Object.freeze({ state: "degraded", platform: platformSummary(platform), gitleaks: gitleaksSummary, opf: { state: "unsupported", notice: UNSUPPORTED_NOTICE } });
  }

  if (!await deps.exists(bundle.dir)) await deps.fetchOpfBundle({ pins, store, platform });
  const venvReady = await deps.exists(join(bundle.venv, "bin", "python"));
  const venv = venvReady ? { state: "verified" } : await deps.buildOpfVenv({ venvDir: bundle.venv, platform });
  return Object.freeze({
    state: venv.state === "verified" ? "verified" : "degraded",
    platform: platformSummary(platform),
    gitleaks: gitleaksSummary,
    opf: { state: venv.state, ...(venv.reason ? { reason: venv.reason } : {}) },
  });
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
  return Object.freeze({ platform: platformSummary(platform), warnings: Object.freeze(warnings) });
}

function platformSummary(platform) {
  return { supported: platform.supported, key: platform.key ?? "none", ...(platform.reason ? { reason: platform.reason } : {}) };
}
