import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { DEFAULT_LOCK_PATH, buildOpfVenv, findPython, lockedTorchVersion, parsePythonVersion } from "../src/shield/opf-venv.mjs";

const supported = Object.freeze({ supported: true, key: "linux-x64" });

function fakeRun(table, calls = []) {
  return async (command, args) => {
    calls.push([command, ...args]);
    const key = args.includes("venv") ? "venv"
      : args.includes("-r") ? "lock"
          : args.includes("-c") ? "probe"
            : args[0] === "--version" ? `version:${command}` : "other";
    const entry = table[key];
    if (entry === undefined) {
      const error = new Error(`spawn ${command} ENOENT`);
      error.code = "ENOENT";
      throw error;
    }
    if (entry instanceof Error) throw entry;
    return { stdout: "", stderr: "", ...entry };
  };
}

function exitError(stderr) {
  return Object.assign(new Error("Command failed"), { code: 1, stderr });
}

async function tempVenv(t) {
  const root = await mkdtemp(join(tmpdir(), "shield-opf-venv-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const venvDir = join(root, "venv");
  await mkdir(venvDir);
  await writeFile(join(venvDir, "marker"), "half-built");
  return { root, venvDir };
}

const exists = (path) => stat(path).then(() => true, () => false);
const probe = (python, torch) => ({ stdout: `${JSON.stringify({ python, torch })}\n` });

test("parsePythonVersion reads the --version banner", () => {
  assert.deepEqual(parsePythonVersion("Python 3.12.4\n"), [3, 12, 4]);
  assert.equal(parsePythonVersion("command not found"), null);
});

test("findPython skips missing and old interpreters and returns the first >= 3.10", async () => {
  const run = fakeRun({
    "version:python3.9": { stdout: "Python 3.9.6\n" },
    "version:python2": { stderr: "Python 2.7.18\n" },
    "version:python3": { stdout: "Python 3.11.9\n" },
  });
  const found = await findPython({ candidates: ["python3.13", "python3.9", "python2", "python3"], run });
  assert.deepEqual(found, { path: "python3", version: "3.11.9" });
  assert.ok(Object.isFrozen(found));
});

test("findPython returns null when nothing qualifies", async () => {
  const run = fakeRun({ "version:python3": { stdout: "Python 3.9.6\n" } });
  assert.equal(await findPython({ candidates: ["python3", "python3.12"], run }), null);
});

test("the torch version comes from the requirements lock", async () => {
  const lock = await readFile(DEFAULT_LOCK_PATH, "utf8");
  assert.match(lockedTorchVersion(lock), /^\d+\.\d+\.\d+$/);
  assert.match(lock, /^--extra-index-url https:\/\/download\.pytorch\.org\/whl\/cpu$/m, "the lock carries the CPU index for Linux torch");
  assert.throws(() => lockedTorchVersion("numpy==2.0.0"), /does not pin torch/);
});

test("a missing Python reaches failed with a reason and spawns no pip", async (t) => {
  const { venvDir } = await tempVenv(t);
  const calls = [];
  const result = await buildOpfVenv({ venvDir,platform: supported, candidates: ["python3.12", "python3"], run: fakeRun({}, calls) });
  assert.equal(result.state, "failed");
  assert.match(result.reason, /^shield OPF venv: Python 3\.10 or newer was not found$/);
  assert.ok(calls.every(([, ...args]) => args[0] === "--version"));
  assert.ok(Object.isFrozen(result));
});

test("an unsupported platform fails before any process runs", async (t) => {
  const { venvDir } = await tempVenv(t);
  const calls = [];
  const result = await buildOpfVenv({
    venvDir,pythonPath: "/usr/bin/python3",
    platform: { supported: false, key: null, reason: "win32 is not supported" }, run: fakeRun({}, calls),
  });
  assert.equal(result.state, "failed");
  assert.match(result.reason, /win32 is not supported/);
  assert.deepEqual(calls, []);
});

test("a verified build runs venv, hash-locked pip, then the probe, and never installs OPF", async (t) => {
  const { venvDir } = await tempVenv(t);
  const torch = lockedTorchVersion(await readFile(DEFAULT_LOCK_PATH, "utf8"));
  const calls = [];
  const result = await buildOpfVenv({
    venvDir,pythonPath: "/opt/python3.12", platform: supported,
    run: fakeRun({ venv: {}, lock: {}, probe: probe("3.12.4", `${torch}+cpu`) }, calls),
  });
  const venvPython = join(venvDir, "bin", "python");
  assert.deepEqual(result, { state: "verified", python: "3.12.4", torch: `${torch}+cpu`, venvPython });

  assert.deepEqual(calls[0], ["/opt/python3.12", "-I", "-m", "venv", "--clear", venvDir]);
  const lockCall = calls[1];
  assert.equal(lockCall[0], venvPython);
  assert.ok(lockCall.includes("--require-hashes"));
  assert.equal(lockCall[lockCall.indexOf("-r") + 1], DEFAULT_LOCK_PATH);
  // The lock's own index lines decide where torch comes from; no CLI override.
  assert.ok(!lockCall.some((arg) => arg.startsWith("--index-url") || arg.startsWith("--extra-index-url")));
  // OPF is imported from the verified store path, never pip-installed.
  assert.deepEqual(calls[2].slice(0, 3), [venvPython, "-I", "-c"]);
  assert.equal(calls.length, 3);
});

test("a pip failure reaches failed, names the step and removes the half-built venv", async (t) => {
  const { venvDir } = await tempVenv(t);
  const result = await buildOpfVenv({
    venvDir,pythonPath: "/opt/python3.12", platform: supported,
    run: fakeRun({ venv: {}, lock: exitError("ERROR: THESE PACKAGES DO NOT MATCH THE HASHES\n    torch from https://example\n") }),
  });
  assert.equal(result.state, "failed");
  assert.match(result.reason, /install locked requirements failed: .*DO NOT MATCH THE HASHES/);
  assert.equal(await exists(venvDir), false);
});

test("a torch version that differs from the lock is not verified", async (t) => {
  const { venvDir } = await tempVenv(t);
  const result = await buildOpfVenv({
    venvDir,pythonPath: "/opt/python3.12", platform: supported,
    run: fakeRun({ venv: {}, lock: {}, probe: probe("3.12.4", "1.0.0") }),
  });
  assert.equal(result.state, "failed");
  assert.match(result.reason, /venv torch 1\.0\.0 does not match the locked/);
  assert.equal(await exists(venvDir), false);
});

test("a probe that cannot import torch is failed", async (t) => {
  const { venvDir } = await tempVenv(t);
  const result = await buildOpfVenv({
    venvDir,pythonPath: "/opt/python3.12", platform: supported,
    run: fakeRun({ venv: {}, lock: {}, probe: exitError("ModuleNotFoundError: No module named 'torch'") }),
  });
  assert.equal(result.state, "failed");
  assert.match(result.reason, /torch import failed: ModuleNotFoundError/);
});

test("a relative venv dir is rejected", async () => {
  await assert.rejects(buildOpfVenv({ venvDir: "venv",platform: supported, run: fakeRun({}) }), /venv dir must be absolute/);
});

test("an unreadable lock is failed before Python is searched", async (t) => {
  const { root, venvDir } = await tempVenv(t);
  const calls = [];
  const result = await buildOpfVenv({ venvDir,lockPath: join(root, "missing.lock"), platform: supported, run: fakeRun({}, calls) });
  assert.equal(result.state, "failed");
  assert.match(result.reason, /requirements lock is unreadable/);
  assert.deepEqual(calls, []);
});
