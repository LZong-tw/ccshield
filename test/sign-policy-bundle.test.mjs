import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { validateShieldPolicyBundle } from "../src/shield/policy-bundle.mjs";

const tool = fileURLToPath(new URL("../tools/sign-policy-bundle.mjs", import.meta.url));

function run(...args) {
  return spawnSync(process.execPath, [tool, ...args], { encoding: "utf8" });
}

async function workspace(t) {
  const dir = await mkdtemp(join(tmpdir(), "ccshield-signer-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  assert.equal(run("keygen", "--out", dir).status, 0);
  const wasm = join(dir, "policy.wasm");
  await writeFile(wasm, Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]));
  const base = ["sign", "--wasm", wasm, "--private-key", join(dir, "policy-signing.key"),
    "--version", "test-1", "--gitleaks-version", "8.24.0", "--privacy-version", "privacy-1"];
  return { dir, base, out: join(dir, "bundle.json") };
}

// Runs the written bundle through the daemon's own validator, so the test
// proves the manifest is accepted, not just that the signature round-trips.
async function readValidated(dir, out) {
  assert.equal((await stat(out)).mode & 0o777, 0o600);
  const bundle = JSON.parse(await readFile(out, "utf8"));
  const publicKey = await readFile(join(dir, "policy-public.pem"));
  const { manifest } = validateShieldPolicyBundle({ ...bundle, wasm: Buffer.from(bundle.wasm, "base64") }, { publicKey });
  return manifest;
}

async function assertRefused(out, args, flag) {
  const result = run(...args);
  assert.notEqual(result.status, 0, JSON.stringify(args));
  assert.match(result.stderr, new RegExp(`${flag} is required`));
  await assert.rejects(stat(out), { code: "ENOENT" });
}

test("without --image-version the signer keeps the 2-key bundle", async (t) => {
  const { dir, base, out } = await workspace(t);
  const result = run(...base, "--out", out);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual({ ...(await readValidated(dir, out)).detectorVersions }, { gitleaks: "8.24.0", privacy: "privacy-1" });
});

test("--image-version signs a 3-key bundle the daemon validator accepts", async (t) => {
  const { dir, base, out } = await workspace(t);
  const result = run(...base, "--image-version", "image-0123456789ab", "--out", out);
  assert.equal(result.status, 0, result.stderr);
  const expected = { gitleaks: "8.24.0", image: "image-0123456789ab", privacy: "privacy-1" };
  assert.deepEqual({ ...(await readValidated(dir, out)).detectorVersions }, expected);
  assert.deepEqual(JSON.parse(result.stdout).detectorVersions, expected);
});

test("--image-version and --privacy-fallback-version sign together", async (t) => {
  const { dir, base, out } = await workspace(t);
  const result = run(...base, "--image-version", "image-0123456789ab", "--privacy-fallback-version", "regex-v1", "--out", out);
  assert.equal(result.status, 0, result.stderr);
  const manifest = await readValidated(dir, out);
  assert.deepEqual({ ...manifest.detectorVersions }, { gitleaks: "8.24.0", image: "image-0123456789ab", privacy: "privacy-1" });
  assert.deepEqual({ ...manifest.detectorFallbacks }, { privacy: "regex-v1" });
});

test("an empty or flag-like --image-version is refused and writes nothing", async (t) => {
  const { base, out } = await workspace(t);
  for (const bad of [["--image-version", ""], ["--image-version", "--out"], ["--image-version"]]) {
    await assertRefused(out, [...base, "--out", out, ...bad], "--image-version");
  }
});

test("a flag-like value counts as missing for every option", async (t) => {
  const { base, out } = await workspace(t);
  await assertRefused(out, [...base, "--out", out, "--privacy-fallback-version", "--version"], "--privacy-fallback-version");
  const withoutPrivacy = base.slice(0, -2);
  await assertRefused(out, [...withoutPrivacy, "--privacy-version", "--out", out], "--privacy-version");
});
