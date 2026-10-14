import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { once } from "node:events";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { startShieldDaemon } from "../src/shieldd.mjs";
import { canonicalJson } from "../src/shield/policy-bundle.mjs";
import { shieldPaths } from "../src/shield/paths.mjs";

const daemonPath = fileURLToPath(new URL("../src/shieldd.mjs", import.meta.url));

test("audit recorder startup failure releases the already running privacy worker", async (t) => {
  const fixture = await startupFixture(t);
  const failure = new Error("audit startup failure");
  await assert.rejects(startShieldDaemon({
    config: fixture.config,
    paths: fixture.paths,
    createDecisionRecorder: async () => { throw failure; },
  }), (error) => error === failure);

  const workerPid = Number(await readFile(fixture.workerPidPath, "utf8"));
  assert.equal(await waitForProcessExit(workerPid), true, "startup rejection must release its privacy child");
  await assert.rejects(readFile(fixture.paths.identityPath), { code: "ENOENT" });
  await assert.rejects(readFile(fixture.paths.policyStatePath), { code: "ENOENT" });
});

test("identity failure still releases privacy when proxy cleanup rejects", async (t) => {
  const fixture = await startupFixture(t);
  const failure = new Error("identity startup failure");
  await assert.rejects(startShieldDaemon({
    config: fixture.config,
    paths: fixture.paths,
    createDecisionRecorder: async () => ({ recordShieldDecision: async () => ({ durable: "ack" }) }),
    startProxy: async () => ({ origin: "http://127.0.0.1:8811", close: async () => { throw new Error("proxy cleanup failure"); } }),
    writeIdentity: async () => { throw failure; },
  }), (error) => error === failure);

  const workerPid = Number(await readFile(fixture.workerPidPath, "utf8"));
  assert.equal(await waitForProcessExit(workerPid), true, "proxy cleanup failure must not strand the privacy child");
  await assert.rejects(readFile(fixture.paths.identityPath), { code: "ENOENT" });
});

test("startup rejection waits for asynchronous privacy cleanup", async (t) => {
  const fixture = await startupFixture(t);
  let closed = false;
  await assert.rejects(startShieldDaemon({
    config: fixture.config,
    paths: fixture.paths,
    createPrivacy: async () => ({
      version: "privacy-1",
      async close() {
        await new Promise((resolve) => setImmediate(resolve));
        closed = true;
      },
    }),
    createDecisionRecorder: async () => null,
  }), /shield audit recorder is unavailable/);
  assert.equal(closed, true);
});

test("daemon CLI exits on boot failure and prints only its fixed diagnostic even with a lingering handle", async (t) => {
  const fixture = await startupFixture(t);
  // The audit key is unusable: no `security` on PATH (so the real Keychain is
  // never reached) and a key file readable by others, which must be refused.
  const emptyBin = join(fixture.homeDir, "empty-bin");
  await mkdir(emptyBin);
  const keyDir = join(fixture.homeDir, ".config", "ccshield");
  await mkdir(keyDir, { recursive: true, mode: 0o700 });
  await writeFile(join(keyDir, "master.key"), `${"ab".repeat(32)}\n`, { mode: 0o644 });
  await chmod(join(keyDir, "master.key"), 0o644);
  const child = spawn(process.execPath, [
    "--import", "data:text/javascript,setInterval(() => {}, 1000)",
    daemonPath, "--config", fixture.paths.configPath,
  ], {
    env: { HOME: fixture.homeDir, PATH: emptyBin, AIRKIT_SHIELD_ROOT_DIR: fixture.paths.rootDir },
    stdio: ["ignore", "pipe", "pipe"],
  });
  t.after(() => child.kill("SIGKILL"));
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const result = await boundedExit(child, 5_000);

  assert.deepEqual(result, { code: 1, signal: null }, "boot failure must terminate rather than retain background handles");
  assert.equal(stdout, "");
  assert.equal(stderr, "AIRKIT_SHIELDD code=AIRKIT_SHIELDD_BOOT_FAILED\n");
  const workerPid = Number(await readFile(fixture.workerPidPath, "utf8"));
  assert.equal(await waitForProcessExit(workerPid), true);
  await assert.rejects(readFile(fixture.paths.identityPath), { code: "ENOENT" });
});

async function startupFixture(t) {
  const homeDir = await realpath(await mkdtemp(join(tmpdir(), "airkit-shield-boot-")));
  const paths = shieldPaths({ homeDir, env: {} });
  const workerPidPath = join(homeDir, "worker.pid");
  t.after(async () => {
    try {
      const pid = Number(await readFile(workerPidPath, "utf8"));
      if (isProcessAlive(pid)) process.kill(pid, "SIGKILL");
    } catch (error) {
      if (error.code !== "ENOENT" && error.code !== "ESRCH") throw error;
    }
    await rm(homeDir, { recursive: true, force: true });
  });
  const gitleaksPath = join(homeDir, "gitleaks.mjs");
  const workerPath = join(homeDir, "privacy-worker.mjs");
  const rulesPath = join(homeDir, "rules.toml");
  const gitleaks = `#!${process.execPath}\nif (process.argv[2] === "version") console.log("8.24.0");
else { process.stdin.resume(); process.stdin.on("end", () => { console.log('[{"RuleID":"private-key"}]'); process.exitCode = 1; }); }\n`;
  const worker = `#!${process.execPath}\nimport { writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
writeFileSync(${JSON.stringify(workerPidPath)}, String(process.pid));
createInterface({ input: process.stdin }).on("line", (line) => {
  const message = JSON.parse(line);
  if (message.type === "health") console.log(JSON.stringify({ type: "health", id: message.id, protocol: "airkit-privacy-ndjson-v1", version: "privacy-1" }));
});
setInterval(() => {}, 1000);\n`;
  await Promise.all([
    writeFile(gitleaksPath, gitleaks, { mode: 0o700 }),
    writeFile(workerPath, worker, { mode: 0o700 }),
    writeFile(rulesPath, "fixture rules\n", { mode: 0o600 }),
  ]);
  const wasm = await readFile(new URL("./fixtures/shield-policy.wasm", import.meta.url));
  const keys = generateKeyPairSync("ed25519");
  const manifest = {
    formatVersion: 1,
    version: "boot-fixture-1",
    opaAbi: "1",
    opaWasmSdkVersion: "1.8.0",
    wasmSha256: digest(wasm),
    detectorVersions: { gitleaks: "8.24.0", privacy: "privacy-1" },
    selfTest: {
      input: { lane: "subscription", destinationClass: "subscription", interactive: false, repositoryClass: "public", pathClasses: ["source"], secretFindings: [], piiFindings: [] },
      expected: { action: "allow", reasonCodes: [], approvalEligible: false, redactions: [] },
    },
  };
  const bundleText = JSON.stringify({ manifest, wasm: wasm.toString("base64"), signature: sign(null, Buffer.from(canonicalJson(manifest)), keys.privateKey).toString("base64") });
  const rules = { path: rulesPath, sha256: digest("fixture rules\n"), version: "rules-1" };
  const config = {
    capability: "c".repeat(32), controlCapability: "d".repeat(32), lane: "subscription",
    generation: "boot-fixture-1", targetClass: "subscription", targetOrigin: "https://api.anthropic.com",
    gitleaks: { executable: gitleaksPath, sha256: digest(gitleaks), ruleBundle: { ...rules, commandProfile: { versionArgs: ["version"], scanArgs: ["stdin", "--config", "{rules}", "--report-format", "json", "--report-path", "-", "--redact"] } } },
  };
  await mkdir(paths.rootDir, { recursive: true, mode: 0o700 });
  await Promise.all([
    writeFile(paths.configPath, JSON.stringify(config), { mode: 0o600 }),
    writeFile(paths.policyBundlePath, bundleText, { mode: 0o600 }),
    writeFile(paths.policyPublicKeyPath, keys.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 }),
    writeFile(paths.assetsProvisionPath, JSON.stringify({
      version: 1,
      bundle: { path: paths.policyBundlePath, sha256: digest(bundleText), version: manifest.version },
      gitleaks: { path: gitleaksPath, sha256: digest(gitleaks), rules },
      privacy: { path: join(homeDir, "privacy.json"), sha256: "a".repeat(64), version: "privacy-1", worker: { command: workerPath, args: ["--stdio"], sha256: digest(worker) } },
    }), { mode: 0o600 }),
  ]);
  return { homeDir, paths, config, workerPidPath };
}

function digest(bytes) { return createHash("sha256").update(bytes).digest("hex"); }

function isProcessAlive(pid) {
  try { process.kill(pid, 0); return true; }
  catch (error) { if (error.code === "ESRCH") return false; throw error; }
}

async function waitForProcessExit(pid) {
  const deadline = Date.now() + 1_000;
  while (isProcessAlive(pid) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10));
  return !isProcessAlive(pid);
}

async function boundedExit(child, timeoutMs) {
  let timer;
  try {
    return await Promise.race([
      once(child, "close").then(([code, signal]) => ({ code, signal })),
      new Promise((resolve) => { timer = setTimeout(() => resolve(null), timeoutMs); }),
    ]);
  } finally { clearTimeout(timer); }
}
