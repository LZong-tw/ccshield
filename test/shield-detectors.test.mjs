import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { runShieldCli } from "../src/shield/cli.mjs";
import { doctorDetectorAssets, fetchDetectorAssets } from "../src/shield/detectors.mjs";
import { shieldPaths } from "../src/shield/paths.mjs";

const pins = {
  code: { commit: "f".repeat(40) },
  checkpoint: { revision: "e".repeat(40) },
  gitleaks: { version: "8.30.1" },
};
const supported = { supported: true, key: "darwin-arm64" };
const unsupported = { supported: false, key: null, reason: "macOS 13 is not supported" };

function fakes(calls, overrides = {}) {
  return {
    loadPins: async () => pins,
    detectPlatform: async () => supported,
    installGitleaks: async ({ platform }) => { calls.push(["gitleaks", platform.key]); return { origin: "downloaded", version: "8.30.1", path: "/store/gitleaks", sha256: "a".repeat(64) }; },
    gitleaksOverride: async ({ path }) => { calls.push(["override", path]); return { origin: "override", version: "8.29.0", path, sha256: "b".repeat(64) }; },
    fetchOpfBundle: async () => { calls.push(["opf"]); },
    buildOpfVenv: async ({ venvDir }) => { calls.push(["venv", venvDir.endsWith("/venv")]); return { state: "verified" }; },
    exists: async () => false,
    ...overrides,
  };
}

async function withHome(fn) {
  const home = await mkdtemp(join(tmpdir(), "ccshield-detectors-"));
  try { return await fn(shieldPaths({ env: { HOME: home } })); } finally { await rm(home, { recursive: true, force: true }); }
}

test("detector preview plans downloads without touching the network", () => withHome(async (paths) => {
  const calls = [];
  const result = await fetchDetectorAssets({ paths, io: fakes(calls) });
  assert.equal(result.state, "preview");
  assert.deepEqual(result.gitleaks, { action: "download", version: "8.30.1" });
  assert.deepEqual(result.opf, { action: "download" });
  assert.deepEqual(calls, []);
}));

test("detector write installs pinned Gitleaks, the OPF bundle, then the venv", () => withHome(async (paths) => {
  const calls = [];
  const result = await fetchDetectorAssets({ paths, write: true, io: fakes(calls) });
  assert.equal(result.state, "verified");
  assert.deepEqual(result.gitleaks, { origin: "downloaded", version: "8.30.1", sha256: "a".repeat(64) });
  assert.deepEqual(calls, [["gitleaks", "darwin-arm64"], ["opf"], ["venv", true]]);
}));

test("detector write skips an installed bundle and venv", () => withHome(async (paths) => {
  const calls = [];
  const result = await fetchDetectorAssets({ paths, write: true, io: fakes(calls, { exists: async () => true }) });
  assert.equal(result.state, "verified");
  assert.deepEqual(calls, [["gitleaks", "darwin-arm64"]]);
}));

test("--gitleaks-path override records version and sha256 and skips the download", () => withHome(async (paths) => {
  const calls = [];
  const result = await fetchDetectorAssets({ paths, write: true, gitleaksPath: "/usr/local/bin/gitleaks", io: fakes(calls) });
  assert.deepEqual(result.gitleaks, { origin: "override", version: "8.29.0", sha256: "b".repeat(64) });
  assert.deepEqual(calls[0], ["override", "/usr/local/bin/gitleaks"]);
  assert.ok(!calls.some(([name]) => name === "gitleaks"));
}));

test("an unsupported platform never downloads OPF and falls back to regex + Gitleaks", () => withHome(async (paths) => {
  const calls = [];
  const io = fakes(calls, { detectPlatform: async () => unsupported });
  const preview = await fetchDetectorAssets({ paths, io });
  assert.deepEqual(preview.opf, { action: "unsupported" });
  const result = await fetchDetectorAssets({ paths, write: true, io });
  assert.equal(result.state, "degraded");
  assert.equal(result.opf.state, "unsupported");
  assert.match(result.opf.notice, /regex \+ Gitleaks/);
  assert.deepEqual(calls.map(([name]) => name), ["gitleaks"]);
}));

test("a failed venv build leaves detectors degraded with the reason", () => withHome(async (paths) => {
  const io = fakes([], { buildOpfVenv: async () => ({ state: "failed", reason: "Python 3.10 or newer was not found" }) });
  const result = await fetchDetectorAssets({ paths, write: true, io });
  assert.equal(result.state, "degraded");
  assert.deepEqual(result.opf, { state: "failed", reason: "Python 3.10 or newer was not found" });
}));

test("doctor reports Gitleaks drift and the unsupported-platform notice", () => withHome(async (paths) => {
  const seen = [];
  const io = fakes([], {
    detectPlatform: async () => unsupported,
    pinnedGitleaksSha256: async () => "c".repeat(64),
    doctorGitleaksWarnings: async (recorded, pinsArg, options) => { seen.push([recorded.version, pinsArg.gitleaks.version, options.pinnedSha256]); return ["shield Gitleaks 8.29.0 differs from the pinned 8.30.1"]; },
  });
  const result = await doctorDetectorAssets({ paths, assets: { gitleaks: { path: "/g", sha256: "b".repeat(64), version: "8.29.0" } }, io });
  assert.deepEqual(seen, [["8.29.0", "8.30.1", "c".repeat(64)]]);
  assert.equal(result.warnings.length, 2);
  assert.match(result.warnings[0], /unsupported on this platform.*macOS 13/);
  assert.match(result.warnings[1], /differs from the pinned/);
}));

test("doctor is quiet on a supported platform without recorded assets", () => withHome(async (paths) => {
  const result = await doctorDetectorAssets({ paths, assets: null, io: fakes([]) });
  assert.deepEqual(result.warnings, []);
  assert.equal(result.platform.supported, true);
}));

function capture() {
  let text = "";
  return { stdout: { write(chunk) { text += chunk; } }, text: () => text };
}

test("ccshield install passes --gitleaks-path and reports detectors", async () => {
  const home = await mkdtemp(join(tmpdir(), "ccshield-detectors-cli-"));
  const out = capture();
  const seen = [];
  try {
    await runShieldCli(["install", "--gitleaks-path", "/opt/gitleaks", "--lane", "managed"], {
      env: { HOME: home }, stdout: out.stdout,
      fetchDetectorAssets: async ({ paths, gitleaksPath, write }) => { seen.push([paths.lane, gitleaksPath, write]); return { state: "preview", opf: { action: "unsupported" } }; },
      readShieldAssetsProvision: async () => ({ gitleaks: { path: "/opt/gitleaks", sha256: "a".repeat(64), rules: { path: "/opt/r.toml", sha256: "b".repeat(64), version: "rules-1" } } }),
      readShieldPolicyProvision: async () => ({ bundle: {}, publicKey: "key" }), loadShieldPolicy: async () => ({}),
      installShieldService: async ({ paths }) => ({ label: paths.serviceLabel }),
    });
    assert.deepEqual(seen, [["managed", "/opt/gitleaks", false]]);
    assert.match(out.text(), /detectors\.opf\.action: unsupported/);
  } finally { await rm(home, { recursive: true, force: true }); }
});

test("ccshield install rejects a relative --gitleaks-path and uninstall rejects the flag", async () => {
  await assert.rejects(runShieldCli(["install", "--gitleaks-path", "gitleaks"], { shield: {} }), /usage: ccshield install .*--gitleaks-path/);
  await assert.rejects(runShieldCli(["uninstall", "--gitleaks-path", "/opt/gitleaks"], { shield: {} }), /usage: ccshield uninstall \[--lane subscription\|managed\] \[--write\]/);
});

test("ccshield doctor surfaces detector warnings", async () => {
  const out = capture();
  await runShieldCli(["doctor"], {
    stdout: out.stdout,
    shield: { async doctor() { return { state: "stopped", detectors: { warnings: ["shield Gitleaks binary differs from the pinned build"] } }; } },
  });
  assert.match(out.text(), /detectors\.warnings\.0: shield Gitleaks binary differs from the pinned build/);
});
