import { execFile } from "node:child_process";
import { readFile, rm } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

export const DEFAULT_LOCK_PATH = fileURLToPath(new URL("../../detectors/opf/requirements.lock", import.meta.url));
export const DEFAULT_PYTHON_CANDIDATES = Object.freeze(["python3.13", "python3.12", "python3.11", "python3.10", "python3"]);
const MIN_PYTHON = [3, 10];
const execFileAsync = promisify(execFile);

// run(command, args, options) resolves { stdout, stderr } and rejects on a
// non-zero exit, like a promisified execFile. Tests inject a fake.
function defaultRun(command, args, options = {}) {
  return execFileAsync(command, args, { maxBuffer: 16 * 1024 * 1024, timeout: 30 * 60_000, ...options });
}

export function parsePythonVersion(text) {
  const match = /Python (\d+)\.(\d+)\.(\d+)/.exec(String(text ?? ""));
  return match ? match.slice(1).map(Number) : null;
}

function atLeast([major, minor], [wantMajor, wantMinor]) {
  return major > wantMajor || (major === wantMajor && minor >= wantMinor);
}

// First candidate whose `--version` reports Python >= 3.10, or null.
export async function findPython({ candidates = DEFAULT_PYTHON_CANDIDATES, run = defaultRun } = {}) {
  for (const command of candidates) {
    let output;
    try {
      const { stdout = "", stderr = "" } = await run(command, ["--version"], { timeout: 10_000 });
      // Python 2 prints its version on stderr.
      output = `${stdout}\n${stderr}`;
    } catch {
      continue;
    }
    const version = parsePythonVersion(output);
    if (version && atLeast(version, MIN_PYTHON)) return Object.freeze({ path: command, version: version.join(".") });
  }
  return null;
}

// The torch pin is read from the lock so the version lives in one place.
export function lockedTorchVersion(lockText) {
  const match = /^torch==(\d+\.\d+\.\d+)/m.exec(String(lockText ?? ""));
  if (!match) throw new Error("shield OPF requirements lock does not pin torch");
  return match[1];
}

const PROBE = "import json, platform, torch; print(json.dumps({'python': platform.python_version(), 'torch': torch.__version__}))";

// Builds the OPF venv on this machine. The lock carries its own index lines:
// PyPI plus the PyTorch CPU index as an extra, which resolves the Linux-only
// `torch==X+cpu` wheel. Every requirement is hash-pinned, so pip runs with
// --require-hashes and fetches nothing unlisted. OPF itself is not installed:
// the store keeps only its `opf/` package, which the worker imports from the
// verified source path through sys.path.
// Resolves { state: "verified", python, torch, venvPython } or
// { state: "failed", reason }; it never throws for an expected failure.
export async function buildOpfVenv({
  venvDir, pythonPath, lockPath = DEFAULT_LOCK_PATH, platform, run = defaultRun,
  candidates = DEFAULT_PYTHON_CANDIDATES,
} = {}) {
  if (!venvDir) throw new Error("shield OPF venv needs venvDir");
  // The worker requires an absolute --python, which is derived from venvDir.
  if (!isAbsolute(venvDir)) throw new Error("shield OPF venv dir must be absolute");
  if (!platform?.supported) return failed(`platform is not supported${platform?.reason ? `: ${platform.reason}` : ""}`);

  let expectedTorch;
  try {
    expectedTorch = lockedTorchVersion(await readFile(lockPath, "utf8"));
  } catch (error) {
    return failed(`requirements lock is unreadable: ${error.message}`);
  }

  const python = pythonPath ?? (await findPython({ candidates, run }))?.path;
  if (!python) return failed("Python 3.10 or newer was not found");

  const venvPython = join(venvDir, "bin", "python");
  const pip = ["-I", "-m", "pip", "install", "--disable-pip-version-check", "--no-input"];
  const steps = [
    ["create venv", python, ["-I", "-m", "venv", "--clear", venvDir]],
    ["install locked requirements", venvPython, [...pip, "--require-hashes", "--no-deps", "-r", lockPath]],
  ];
  for (const [label, command, args] of steps) {
    try {
      await run(command, args);
    } catch (error) {
      return discard(venvDir, `${label} failed: ${errorTail(error)}`);
    }
  }

  let probe;
  try {
    const { stdout } = await run(venvPython, ["-I", "-c", PROBE], { timeout: 120_000 });
    probe = JSON.parse(String(stdout).trim().split("\n").at(-1));
  } catch (error) {
    return discard(venvDir, `torch import failed: ${errorTail(error)}`);
  }
  const pythonVersion = parsePythonVersion(`Python ${probe?.python}`);
  if (!pythonVersion || !atLeast(pythonVersion, MIN_PYTHON)) return discard(venvDir, `venv Python ${probe?.python} is older than 3.10`);
  // Linux CPU wheels report a local tag, e.g. 2.14.0+cpu.
  if (String(probe?.torch).split("+")[0] !== expectedTorch) {
    return discard(venvDir, `venv torch ${probe?.torch} does not match the locked ${expectedTorch}`);
  }
  return Object.freeze({ state: "verified", python: probe.python, torch: probe.torch, venvPython });
}

function failed(reason) {
  return Object.freeze({ state: "failed", reason: `shield OPF venv: ${reason}` });
}

// A half-built venv must not look usable to the next run.
async function discard(venvDir, reason) {
  await rm(venvDir, { recursive: true, force: true });
  return failed(reason);
}

function errorTail(error) {
  const text = String(error?.stderr || error?.message || error).trim();
  const lines = text.split("\n").filter(Boolean);
  return lines.slice(-3).join(" | ").slice(0, 500) || "unknown error";
}
