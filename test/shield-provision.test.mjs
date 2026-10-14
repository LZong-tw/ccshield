import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, realpath, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { provisionShieldAssets } from "../src/shield/provision.mjs";
import { assertShieldAssetsProvision, readShieldAssetsProvision, shieldPaths } from "../src/shield/paths.mjs";

const policyPath = "/opt/airkit/policy.json";
const gitleaksPath = "/opt/airkit/gitleaks";
const gitleaksRulesPath = "/opt/airkit/gitleaks-rules.toml";
const privacyPath = "/opt/airkit/privacy-filter.json";
const workerPath = "/opt/airkit/privacy-worker";
const adapterPath = "/opt/airkit/opf-adapter.mjs";
const tokenizerPath = "/opt/airkit/tiktoken-cache/fb374d419588a4632f3f557e76b4b70aebbca790";
const bytes = {
  [policyPath]: Buffer.from(JSON.stringify({ manifest: { version: "policy-1" } })),
  [gitleaksPath]: Buffer.from("gitleaks fixture"),
  [gitleaksRulesPath]: Buffer.from("gitleaks rules fixture"),
  [privacyPath]: Buffer.from(JSON.stringify({
    formatVersion: 1,
    protocol: "airkit-privacy-ndjson-v1",
    version: "privacy-1",
    worker: { command: workerPath, args: ["--stdio"], sha256: sha256(Buffer.from("privacy worker fixture")) },
  })),
  [workerPath]: Buffer.from("privacy worker fixture"),
};
const rulesDigest = sha256(bytes[gitleaksRulesPath]);

test("asset provision previews without writes and only records opaque references after explicit write", async () => {
  const writes = [];
  const preview = await provisionShieldAssets({
    bundlePath: policyPath,
    gitleaksPath,
    gitleaksRulesPath,
    privacyBundlePath: privacyPath,
    io: fixtureIo(),
    runPrivacySelfTest: async () => ({ version: "privacy-1" }),
    writeState: async (value) => writes.push(value),
  });

  assert.equal(writes.length, 0);
  assert.deepEqual(preview, {
    version: 1,
    bundle: { version: "policy-1", sha256: sha256(bytes[policyPath]), path: policyPath },
    gitleaks: {
      sha256: sha256(bytes[gitleaksPath]),
      path: gitleaksPath,
      rules: { path: gitleaksRulesPath, sha256: rulesDigest, version: `rules-${rulesDigest.slice(0, 12)}` },
    },
    privacy: {
      version: "privacy-1",
      sha256: sha256(bytes[privacyPath]),
      path: privacyPath,
      worker: { command: workerPath, args: ["--stdio"], sha256: sha256(bytes[workerPath]) },
    },
  });

  const written = await provisionShieldAssets({
    bundlePath: policyPath,
    gitleaksPath,
    gitleaksRulesPath,
    privacyBundlePath: privacyPath,
    write: true,
    io: fixtureIo(),
    runPrivacySelfTest: async () => ({ version: "privacy-1" }),
    writeState: async (value) => writes.push(value),
  });
  assert.equal(writes.length, 1);
  assert.deepEqual(writes[0], written);
  assert.doesNotMatch(JSON.stringify(writes), /fixture|PRIVATE|secret/i);
});

test("asset provision rejects unsafe, drifted, or protocol-invalid preinstalled artifacts without a download path", async () => {
  const options = {
    bundlePath: policyPath,
    gitleaksPath,
    gitleaksRulesPath,
    privacyBundlePath: privacyPath,
    runPrivacySelfTest: async () => ({ version: "privacy-1" }),
  };
  await assert.rejects(provisionShieldAssets({ ...options, bundlePath: "relative", io: fixtureIo() }), /canonical and absolute/i);
  await assert.rejects(provisionShieldAssets({ ...options, gitleaksRulesPath: undefined, io: fixtureIo() }), /gitleaks rules path must be canonical and absolute/i);
  await assert.rejects(provisionShieldAssets({ ...options, io: fixtureIo({ symlink: privacyPath }) }), /symlink/i);
  await assert.rejects(provisionShieldAssets({ ...options, io: fixtureIo({ owner: 999 }) }), /owner/i);
  await assert.rejects(provisionShieldAssets({ ...options, io: fixtureIo({ executable: false }) }), /executable/i);
  await assert.rejects(provisionShieldAssets({ ...options, io: fixtureIo({ mutate: workerPath }) }), /digest mismatch/i);
  await assert.rejects(provisionShieldAssets({ ...options, io: fixtureIo(), runPrivacySelfTest: async () => ({ version: "wrong-version" }) }), /self-test/i);
});

test("explicit write stores a private canonical asset provision record", async () => {
  const homeDir = await mkdtemp(join(tmpdir(), "airkit-shield-provision-"));
  const paths = shieldPaths({ homeDir, uid: process.getuid?.() });
  try {
    const written = await provisionShieldAssets({
      bundlePath: policyPath,
      gitleaksPath,
      gitleaksRulesPath,
      privacyBundlePath: privacyPath,
      write: true,
      paths,
      io: fixtureIo(),
      runPrivacySelfTest: async () => ({ version: "privacy-1" }),
    });
    assert.equal((await stat(paths.assetsProvisionPath)).mode & 0o777, 0o600);
    assert.deepEqual(await readShieldAssetsProvision({ paths }), written);
    assert.deepEqual(JSON.parse(await readFile(paths.assetsProvisionPath, "utf8")), written);
  } finally {
    await rm(homeDir, { recursive: true, force: true });
  }
});

test("OPF provision pins its model, source, helper, tokenizer and worker arguments", async () => {
  const homeDir = await realpath(await mkdtemp(join(tmpdir(), "airkit-shield-checkpoint-")));
  const checkpointPath = join(homeDir, "model");
  const sourcePath = join(homeDir, "source");
  const checkpointSha256 = createHash("sha256")
    .update("config.json\0", "utf8").update("2\0", "utf8").update("[]").update("\0", "utf8")
    .update("weights.bin\0", "utf8").update("5\0", "utf8").update("model").update("\0", "utf8")
    .digest("hex");
  const checkpoint = { path: checkpointPath, sha256: checkpointSha256, version: "opf-2026-09" };
  const sourceSha256 = createHash("sha256").update("source.py\0", "utf8").update("6\0", "utf8").update("source").update("\0", "utf8").digest("hex");
  const source = { path: sourcePath, sha256: sourceSha256, version: "opf-source-1" };
  const adapterBytes = Buffer.from("adapter helper fixture");
  const adapter = { path: adapterPath, sha256: sha256(adapterBytes) };
  const tokenizerBytes = Buffer.from("tokenizer fixture");
  const tokenizer = { path: tokenizerPath, sha256: sha256(tokenizerBytes), version: "o200k_base" };
  const privacyManifest = {
    ...JSON.parse(bytes[privacyPath]), checkpoint, source, adapter, tokenizer,
    worker: { ...JSON.parse(bytes[privacyPath]).worker, args: [
      "--python", "/opt/airkit/python", "--checkpoint", checkpoint.path,
      "--checkpoint-sha256", checkpoint.sha256, "--checkpoint-version", checkpoint.version,
      "--opf-source", source.path, "--opf-source-sha256", source.sha256,
      "--adapter-sha256", adapter.sha256,
      "--tokenizer", tokenizer.path, "--tokenizer-sha256", tokenizer.sha256,
      "--startup-timeout-ms", "30000", "--scan-timeout-ms", "2000",
    ] },
  };
  const options = {
    bundlePath: policyPath,
    gitleaksPath,
    gitleaksRulesPath,
    privacyBundlePath: privacyPath,
    io: fixtureIo({ privacyManifest, extraBytes: { [adapterPath]: adapterBytes, [tokenizerPath]: tokenizerBytes } }),
    runPrivacySelfTest: async () => ({ version: "privacy-1" }),
  };
  try {
    await mkdir(checkpointPath);
    await mkdir(sourcePath);
    await writeFile(join(checkpointPath, "weights.bin"), "model");
    await writeFile(join(checkpointPath, "config.json"), "[]");
    await writeFile(join(sourcePath, "source.py"), "source");
    const preview = await provisionShieldAssets(options);
    assert.deepEqual(preview.privacy.checkpoint, checkpoint);
    assert.deepEqual(assertShieldAssetsProvision(preview).privacy.checkpoint, checkpoint);
    assert.deepEqual(preview.privacy.source, source);
    assert.deepEqual(preview.privacy.adapter, adapter);
    assert.deepEqual(preview.privacy.tokenizer, tokenizer);
    assert.deepEqual(assertShieldAssetsProvision(preview).privacy.source, source);
    assert.deepEqual(assertShieldAssetsProvision(preview).privacy.adapter, adapter);
    assert.deepEqual(assertShieldAssetsProvision(preview).privacy.tokenizer, tokenizer);

    for (const scanTimeout of ["10000", "25000", "60000"]) {
      const extendedScanManifest = {
        ...privacyManifest,
        worker: { ...privacyManifest.worker, args: [...privacyManifest.worker.args.slice(0, 21), scanTimeout] },
      };
      const extended = await provisionShieldAssets({ ...options, io: fixtureIo({
        privacyManifest: extendedScanManifest,
        extraBytes: { [adapterPath]: adapterBytes, [tokenizerPath]: tokenizerBytes },
      }) });
      assert.equal(extended.privacy.worker.args.at(-1), scanTimeout);
    }

    await assert.rejects(provisionShieldAssets({ ...options, io: fixtureIo({
      privacyManifest: { ...privacyManifest, worker: { ...privacyManifest.worker, args: [...privacyManifest.worker.args.slice(0, 5), "0".repeat(64), ...privacyManifest.worker.args.slice(6)] } },
      extraBytes: { [adapterPath]: adapterBytes, [tokenizerPath]: tokenizerBytes },
    }) }), /privacy bundle manifest|worker arguments/i);
    await assert.rejects(provisionShieldAssets({ ...options, io: fixtureIo({
      privacyManifest: { ...privacyManifest, worker: { ...privacyManifest.worker, args: [...privacyManifest.worker.args.slice(0, 19), "2000", ...privacyManifest.worker.args.slice(20)] } },
      extraBytes: { [adapterPath]: adapterBytes, [tokenizerPath]: tokenizerBytes },
    }) }), /privacy bundle manifest|worker arguments/i);
    await assert.rejects(provisionShieldAssets({ ...options, io: fixtureIo({
      privacyManifest: { ...privacyManifest, adapter: undefined }, extraBytes: { [adapterPath]: adapterBytes, [tokenizerPath]: tokenizerBytes },
    }) }), /privacy bundle manifest/i);

    await writeFile(join(sourcePath, "source.py"), "drift!");
    await assert.rejects(provisionShieldAssets(options), /source|checkpoint/i);
    await writeFile(join(sourcePath, "source.py"), "source");
    await assert.rejects(provisionShieldAssets({ ...options, io: fixtureIo({ privacyManifest, extraBytes: { [adapterPath]: adapterBytes, [tokenizerPath]: tokenizerBytes }, mutate: adapterPath }) }), /adapter|digest/i);
    await assert.rejects(provisionShieldAssets({ ...options, io: fixtureIo({ privacyManifest, extraBytes: { [adapterPath]: adapterBytes, [tokenizerPath]: tokenizerBytes }, mutate: tokenizerPath }) }), /tokenizer|digest/i);

    await writeFile(join(checkpointPath, "weights.bin"), "drift");
    await assert.rejects(provisionShieldAssets(options), /checkpoint/i);
    await writeFile(join(checkpointPath, "weights.bin"), "model");
    await symlink(join(checkpointPath, "weights.bin"), join(checkpointPath, "alias.bin"));
    await assert.rejects(provisionShieldAssets(options), /checkpoint/i);
  } finally {
    await rm(homeDir, { recursive: true, force: true });
  }
});

function fixtureIo({ symlink = null, owner = process.getuid?.(), executable = true, mutate = null, privacyManifest = null, extraBytes = {} } = {}) {
  return {
    async lstat(path) {
      return {
        uid: owner,
        mode: path === gitleaksPath || path === workerPath ? (executable ? 0o100700 : 0o100600) : 0o100600,
        isFile: () => true,
        isSymbolicLink: () => path === symlink,
      };
    },
    async realpath(path) { return path; },
    async readFile(path) { return path === mutate ? Buffer.from("drift") : path === privacyPath && privacyManifest ? Buffer.from(JSON.stringify(privacyManifest)) : bytes[path] ?? extraBytes[path]; },
  };
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
