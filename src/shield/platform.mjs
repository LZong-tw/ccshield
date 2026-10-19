import { execFile } from "node:child_process";
import { release } from "node:os";
import { promisify } from "node:util";

const run = promisify(execFile);

// Supported: macOS 14+ arm64, Linux x86_64/aarch64 with glibc >= 2.28.
// Everything else stays on regex + Gitleaks and gets a doctor notice.
export function classifyPlatform({ platform, arch, darwinRelease, glibcVersion }) {
  if (platform === "darwin") {
    if (arch !== "arm64") return unsupported(`macOS on ${arch} is not supported (arm64 only)`);
    // Darwin 23 is macOS 14.
    const major = Number.parseInt(String(darwinRelease ?? "").split(".")[0], 10);
    if (!Number.isFinite(major) || major < 23) return unsupported("macOS 14 or newer is required");
    return supported("darwin-arm64");
  }
  if (platform === "linux") {
    const key = arch === "x64" ? "linux-x64" : arch === "arm64" ? "linux-arm64" : null;
    if (!key) return unsupported(`Linux on ${arch} is not supported`);
    if (!glibcAtLeast(glibcVersion, 2, 28)) return unsupported(glibcVersion ? `glibc ${glibcVersion} is older than 2.28` : "glibc was not found");
    return supported(key);
  }
  return unsupported(`${platform} is not supported`);
}

export async function detectPlatform({ platform = process.platform, arch = process.arch, io = {} } = {}) {
  const darwinRelease = platform === "darwin" ? (io.release ?? release)() : undefined;
  const glibcVersion = platform === "linux" ? await (io.glibcVersion ?? readGlibcVersion)() : undefined;
  return classifyPlatform({ platform, arch, darwinRelease, glibcVersion });
}

async function readGlibcVersion() {
  const reported = process.report?.getReport?.()?.header?.glibcVersionRuntime;
  if (typeof reported === "string") return reported;
  try {
    const { stdout } = await run("ldd", ["--version"], { timeout: 5_000 });
    return /(\d+\.\d+)/.exec(stdout)?.[1] ?? null;
  } catch {
    return null;
  }
}

function glibcAtLeast(version, major, minor) {
  const match = /^(\d+)\.(\d+)/.exec(String(version ?? ""));
  if (!match) return false;
  const [actualMajor, actualMinor] = [Number(match[1]), Number(match[2])];
  return actualMajor > major || (actualMajor === major && actualMinor >= minor);
}

function supported(key) {
  return Object.freeze({ supported: true, key });
}

function unsupported(reason) {
  return Object.freeze({ supported: false, key: null, reason });
}
