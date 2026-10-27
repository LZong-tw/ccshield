import { execFile } from "node:child_process";
import { chmod, lstat, mkdtemp, realpath, rm } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { promisify } from "node:util";

import { commitStaged, downloadVerified, gitleaksDownloadPlan, sha256File } from "./opf-fetch.mjs";

const execFileAsync = promisify(execFile);
const VERSION_TIMEOUT_MS = 5_000;

// Downloads the pinned Gitleaks archive for this platform, verifies it against
// pins.json, and moves the extracted binary into assets/gitleaks/<version>/.
// The binary is only ever visible in the store once the archive digest has
// checked out; every failure leaves the store untouched.
//
// The archive follows OS and CPU only: a machine that is unsupported for OPF
// (macOS 13, old glibc) still gets Gitleaks, so this ignores `supported`.
export async function installGitleaks({ pins, store, platform, os = process.platform, arch = process.arch, fetchImpl, extract = extractGitleaksBinary, onProgress } = {}) {
  const key = platform?.key ?? gitleaksArchiveKey(os, arch);
  if (!key || !pins?.gitleaks?.archives?.[key]) throw new Error(`shield has no pinned Gitleaks for ${key ?? `${os}-${arch}`}`);
  const item = gitleaksDownloadPlan(pins, key);
  const target = store.gitleaks(item.version);

  const existing = await installedBinary(target.binary);
  if (existing) return installed({ version: item.version, path: target.binary, sha256: existing, archiveSha256: item.sha256 });

  const archive = await downloadVerified(item, { stagingDir: store.stagingDir, fetchImpl, onProgress });
  const unpacked = await mkdtemp(join(store.stagingDir, `gitleaks-${item.version}-`));
  try {
    await extract({ archive, dir: unpacked });
    const binary = join(unpacked, "gitleaks");
    let entry;
    try { entry = await lstat(binary); } catch { throw new Error("shield Gitleaks archive has no gitleaks binary"); }
    if (!entry.isFile()) throw new Error("shield Gitleaks archive binary must be a regular file");
    await chmod(binary, 0o755);
    const sha256 = await sha256File(binary);
    try {
      await commitStaged(unpacked, target.dir);
    } catch (error) {
      // Another install got there first; keep its verified copy.
      if (error.code !== "ENOTEMPTY" && error.code !== "EEXIST") throw error;
      const raced = await installedBinary(target.binary);
      if (!raced) throw error;
      return installed({ version: item.version, path: target.binary, sha256: raced, archiveSha256: item.sha256 });
    }
    await rm(archive, { force: true });
    return installed({ version: item.version, path: target.binary, sha256, archiveSha256: item.sha256 });
  } finally {
    await rm(unpacked, { recursive: true, force: true });
  }
}

// `--gitleaks-path <bin>`: adopt a user-supplied binary. Records what it is
// and never downloads anything.
export async function gitleaksOverride({ path, run = runVersion } = {}) {
  if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path) throw new Error("shield Gitleaks override path must be canonical and absolute");
  let entry;
  let canonical;
  try { [entry, canonical] = await Promise.all([lstat(path), realpath(path)]); }
  catch { throw new Error("shield Gitleaks override was not found"); }
  if (canonical !== path) throw new Error("shield Gitleaks override path is not canonical");
  if (!entry.isFile()) throw new Error("shield Gitleaks override must be a regular file");
  if ((entry.mode & 0o100) === 0) throw new Error("shield Gitleaks override is not executable");
  if ((entry.mode & 0o022) !== 0) throw new Error("shield Gitleaks override must not be group or world writable");
  let result;
  try { result = await run({ command: path, args: ["version"] }); }
  catch { throw new Error("shield Gitleaks override version probe failed"); }
  const version = parseVersion(result);
  return Object.freeze({ origin: "override", version, path, sha256: await sha256File(path) });
}

export function gitleaksArchiveKey(os, arch) {
  if (os === "darwin" && arch === "arm64") return "darwin-arm64";
  if (os === "linux" && (arch === "x64" || arch === "arm64")) return `linux-${arch}`;
  return null;
}

// Warnings only: a drifted Gitleaks still runs, but doctor says so.
// `pinnedSha256` is the hash of the binary the pinned archive installs, when
// that copy is present in the store; without it the hash check is skipped.
export async function doctorGitleaksWarnings(recorded, pins, { pinnedSha256, hashFile = sha256File } = {}) {
  const warnings = [];
  const pinned = pins?.gitleaks?.version;
  if (typeof recorded.version !== "string") warnings.push("shield Gitleaks version was not recorded");
  else if (recorded.version !== pinned) warnings.push(`shield Gitleaks ${recorded.version} differs from the pinned ${pinned}`);
  if (pinnedSha256 && recorded.sha256 !== pinnedSha256) warnings.push("shield Gitleaks binary differs from the pinned build");
  let current = null;
  try { current = await hashFile(recorded.path); } catch { /* reported below */ }
  if (current === null) warnings.push(`shield Gitleaks binary at ${recorded.path} is missing`);
  else if (current !== recorded.sha256) warnings.push(`shield Gitleaks binary at ${recorded.path} changed since it was recorded`);
  // Store copies never follow an upgrade of what they were copied from; say so.
  for (const [label, entry] of [["Gitleaks binary", recorded], ["Gitleaks rules", recorded.rules]]) {
    if (typeof entry?.source !== "string") continue;
    let source = null;
    try { source = await hashFile(entry.source); } catch { /* reported below */ }
    if (source === null) warnings.push(`shield ${label} was copied from ${entry.source}, which no longer exists; shield keeps using its stored copy. Run \`ccshield install --write\` to pick up the current one`);
    else if (source !== entry.sha256) warnings.push(`shield ${label} at ${entry.source} was updated, but shield still uses its older stored copy. Run \`ccshield install --write\` to switch`);
  }
  return Object.freeze(warnings);
}

// Reads the pinned copy's hash for doctor, or null when it is not installed.
export async function pinnedGitleaksSha256({ pins, store }) {
  return installedBinary(store.gitleaks(pins.gitleaks.version).binary);
}

// Only the `gitleaks` member is extracted; LICENSE and README stay in the archive.
export async function extractGitleaksBinary({ archive, dir }) {
  try {
    await execFileAsync("tar", ["-xzf", archive, "-C", dir, "gitleaks"], { timeout: 60_000 });
  } catch {
    throw new Error("shield Gitleaks archive could not be extracted");
  }
}

// Same accepted form as the daemon's probe in gitleaks.mjs.
function parseVersion(result) {
  const match = /^v?(\d+\.\d+\.\d+(?:-[A-Za-z0-9._-]+)?)\r?\n$/.exec(result?.stdout ?? "");
  if (result?.code !== 0 || result.stderr !== "" || !match) throw new Error("shield Gitleaks override version probe failed");
  return match[1];
}

async function runVersion({ command, args }) {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, { timeout: VERSION_TIMEOUT_MS, maxBuffer: 64 * 1024 });
    return { code: 0, stdout, stderr };
  } catch (error) {
    return { code: typeof error.code === "number" ? error.code : 1, stdout: error.stdout ?? "", stderr: error.stderr ?? "" };
  }
}

async function installedBinary(path) {
  try {
    const entry = await lstat(path);
    if (!entry.isFile() || (entry.mode & 0o100) === 0) return null;
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
  return sha256File(path);
}

function installed({ version, path, sha256, archiveSha256 }) {
  return Object.freeze({ origin: "downloaded", version, path, sha256, archiveSha256 });
}
