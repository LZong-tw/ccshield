import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { buildOpfWorkerArgs } from "../src/shield/opf-args.mjs";
import { ASSETS_FORMAT_VERSION, assertShieldAssetsProvision, readShieldAssetsProvision, shieldAssetStore, shieldPaths, writeShieldAssetsProvision } from "../src/shield/paths.mjs";

const digest = (char) => char.repeat(64);
const codeCommit = "a".repeat(40);
const hfRevision = "b".repeat(40);
const tokenizerKey = "fb374d419588a4632f3f557e76b4b70aebbca790";
const workerCommand = "/opt/ccshield/detectors/opf/privacy-worker.mjs";

const base = {
  bundle: { version: "policy-1", sha256: digest("1"), path: "/opt/ccshield/policy.json" },
  gitleaks: { sha256: digest("2"), path: "/opt/ccshield/gitleaks", rules: { path: "/opt/ccshield/rules.toml", sha256: digest("3"), version: "rules-1" } },
  regex: { version: "regex-v1", worker: { command: "/opt/ccshield/regex/regex-v1/privacy-worker.mjs", args: [], sha256: digest("a") } },
};

const { regex: _regex, ...legacyBase } = base;
const storeRegex = (storeRoot) => ({ ...base.regex, worker: { ...base.regex.worker, command: join(storeRoot, "regex", "regex-v1", "privacy-worker.mjs") } });

test("format 2 requires the installed regex detector and keeps it inside the store", () => {
  const { regex, ...withoutRegex } = base;
  assert.throws(() => assertShieldAssetsProvision({ version: 2, ...withoutRegex, privacy: { state: "absent" } }), /invalid/);
  assert.deepEqual(assertShieldAssetsProvision({ version: 2, ...base, privacy: { state: "absent" } }).regex, regex);
  for (const worker of [{ ...regex.worker, args: ["--stdio"] }, { ...regex.worker, sha256: "x" }, { ...regex.worker, command: "relative.mjs" }]) {
    assert.throws(() => assertShieldAssetsProvision({ version: 2, ...base, regex: { ...regex, worker }, privacy: { state: "absent" } }), /regex detector reference is invalid/);
  }
  const storeRoot = "/home/user/.local/share/ccshield/assets";
  assert.throws(() => assertShieldAssetsProvision({ version: 2, ...base, privacy: { state: "absent" } }, { storeRoot }), /inside the asset store/);
  const inside = { ...regex, worker: { ...regex.worker, command: join(storeRoot, "regex", "regex-v1", "privacy-worker.mjs") } };
  assert.equal(assertShieldAssetsProvision({ version: 2, ...base, regex: inside, privacy: { state: "absent" } }, { storeRoot }).regex.worker.command, inside.worker.command);
});

function opfPrivacy(bundle, origin = "downloaded") {
  const checkpoint = { path: bundle.checkpoint, sha256: digest("4"), version: "opf-1" };
  const source = { path: bundle.src, sha256: digest("5"), version: "opf-source-1" };
  const adapter = { path: "/opt/ccshield/detectors/opf/opf-adapter.mjs", sha256: digest("6") };
  const tokenizer = { path: join(bundle.tokenizer, tokenizerKey), sha256: digest("7"), version: "o200k_base" };
  const python = join(bundle.venv, "bin", "python");
  return {
    state: "verified",
    origin,
    version: "opf-1",
    sha256: digest("8"),
    path: "/opt/ccshield/detectors/opf/privacy-filter.json",
    worker: { command: workerCommand, sha256: digest("9"), args: buildOpfWorkerArgs({ python, checkpoint, source, adapter, tokenizer, scanTimeoutMs: 2_000 }) },
    checkpoint, source, adapter, tokenizer,
  };
}

test("asset store lives beside the lane roots and pins bundles by code commit and HF revision", () => {
  const paths = shieldPaths({ homeDir: "/home/user", uid: 501 });
  const store = shieldAssetStore(paths);
  assert.equal(store.root, "/home/user/.local/share/ccshield/assets");
  assert.equal(store.stagingDir, "/home/user/.local/share/ccshield/assets/staging");
  const bundle = store.opfBundle(codeCommit, hfRevision);
  assert.equal(bundle.dir, `/home/user/.local/share/ccshield/assets/opf/${codeCommit}-${hfRevision}`);
  assert.deepEqual([bundle.src, bundle.checkpoint, bundle.venv, bundle.tokenizer], ["src", "checkpoint", "venv", "tokenizer"].map((name) => join(bundle.dir, name)));
  assert.throws(() => store.opfBundle("../x", hfRevision), /40-hex/);
  assert.throws(() => shieldAssetStore({ ...paths }), /canonical/);
});

test("absent and preparing need no OPF fields; failed carries only a reason", () => {
  for (const state of ["absent", "preparing"]) {
    assert.deepEqual(assertShieldAssetsProvision({ version: 2, ...base, privacy: { state } }).privacy, { state });
    assert.throws(() => assertShieldAssetsProvision({ version: 2, ...base, privacy: { state, version: "opf-1" } }), /invalid/);
  }
  assert.deepEqual(assertShieldAssetsProvision({ version: 2, ...base, privacy: { state: "failed", reason: "digest-mismatch" } }).privacy, { state: "failed", reason: "digest-mismatch" });
  assert.throws(() => assertShieldAssetsProvision({ version: 2, ...base, privacy: { state: "failed" } }), /invalid/);
  assert.throws(() => assertShieldAssetsProvision({ version: 2, ...base, privacy: { state: "ready" } }), /invalid/);
});

test("verified requires the OPF references and keeps downloaded files inside the store", () => {
  const paths = shieldPaths({ homeDir: "/home/user", uid: 501 });
  const store = shieldAssetStore(paths);
  const bundle = store.opfBundle(codeCommit, hfRevision);
  const privacy = opfPrivacy(bundle);
  const stored = { ...base, regex: storeRegex(store.root) };
  const accepted = assertShieldAssetsProvision({ version: 2, ...stored, privacy }, { storeRoot: store.root });
  assert.equal(accepted.privacy.state, "verified");
  assert.equal(accepted.privacy.origin, "downloaded");
  assert.deepEqual(accepted.privacy.checkpoint, privacy.checkpoint);

  const { checkpoint: _checkpoint, ...withoutCheckpoint } = privacy;
  assert.throws(() => assertShieldAssetsProvision({ version: 2, ...stored, privacy: withoutCheckpoint }, { storeRoot: store.root }), /invalid/);
  const { worker: _worker, ...withoutWorker } = privacy;
  assert.throws(() => assertShieldAssetsProvision({ version: 2, ...stored, privacy: withoutWorker }, { storeRoot: store.root }), /invalid/);
  assert.throws(() => assertShieldAssetsProvision({ version: 2, ...stored, privacy: { ...privacy, origin: undefined } }, { storeRoot: store.root }), /origin/);
  assert.throws(() => assertShieldAssetsProvision({ version: 2, ...stored, privacy }), /asset store/);

  const outside = opfPrivacy({ src: "/srv/opf/src", checkpoint: "/srv/opf/checkpoint", venv: "/srv/opf/venv", tokenizer: "/srv/opf/tokenizer" });
  assert.throws(() => assertShieldAssetsProvision({ version: 2, ...stored, privacy: outside }, { storeRoot: store.root }), /inside the asset store/);
  const adopted = assertShieldAssetsProvision({ version: 2, ...stored, privacy: { ...outside, origin: "adopted" } }, { storeRoot: store.root });
  assert.equal(adopted.privacy.origin, "adopted");
});

test("legacy version-1 files migrate: the old strict shape is verified, anything else is failed", async () => {
  const legacyPrivacy = { version: "privacy-1", sha256: digest("8"), path: "/opt/ccshield/privacy-filter.json", worker: { command: "/opt/ccshield/privacy-worker", args: ["--stdio"], sha256: digest("9") } };
  const migrated = assertShieldAssetsProvision({ version: 1, ...legacyBase, privacy: legacyPrivacy });
  assert.equal(migrated.version, ASSETS_FORMAT_VERSION);
  assert.equal(migrated.privacy.state, "verified");
  assert.equal(migrated.privacy.origin, undefined);

  const legacyOpf = { ...opfPrivacy({ src: "/srv/opf/src", checkpoint: "/srv/opf/checkpoint", venv: "/srv/opf/venv", tokenizer: "/srv/opf/tokenizer" }) };
  delete legacyOpf.state;
  delete legacyOpf.origin;
  assert.equal(assertShieldAssetsProvision({ version: 1, ...legacyBase, privacy: legacyOpf }).privacy.origin, "adopted");

  for (const privacy of [{ ...legacyPrivacy, state: "verified" }, { version: "privacy-1" }, null]) {
    assert.deepEqual(assertShieldAssetsProvision({ version: 1, ...legacyBase, privacy }).privacy, { state: "failed", reason: "legacy-schema" });
  }

  const homeDir = await mkdtemp(join(tmpdir(), "ccshield-assets-schema-"));
  try {
    const paths = shieldPaths({ homeDir, uid: process.getuid?.() });
    await mkdir(paths.rootDir, { recursive: true, mode: 0o700 });
    await writeFile(paths.assetsProvisionPath, JSON.stringify({ version: 1, ...legacyBase, privacy: legacyPrivacy }), { mode: 0o600 });
    assert.equal((await readShieldAssetsProvision({ paths })).privacy.state, "verified");
  } finally {
    await rm(homeDir, { recursive: true, force: true });
  }
});

const v3Gitleaks = { origin: "downloaded", version: "8.30.1", ...base.gitleaks };

test("format 3 records the installed Gitleaks origin and the OPF install state", () => {
  const storeRoot = "/opt/ccshield/assets";
  const stored = { ...base, regex: storeRegex(storeRoot), privacy: { state: "absent" } };
  const bundle = join(storeRoot, "opf", "opfBundle");
  const record = assertShieldAssetsProvision({ version: 3, ...stored, gitleaks: v3Gitleaks, opf: { state: "verified", platform: "darwin-arm64", bundle } }, { storeRoot });
  assert.deepEqual(record.gitleaks, v3Gitleaks);
  assert.deepEqual(record.opf, { state: "verified", platform: "darwin-arm64", bundle });
  assert.deepEqual(assertShieldAssetsProvision({ version: 3, ...stored, opf: { state: "unsupported", platform: "none", reason: "macOS 13 is not supported" } }).opf.state, "unsupported");

  assert.throws(() => assertShieldAssetsProvision({ version: 3, ...stored, opf: { state: "verified", platform: "darwin-arm64", bundle: "/elsewhere/opf" } }, { storeRoot }), /inside the asset store/);
  assert.throws(() => assertShieldAssetsProvision({ version: 3, ...stored, opf: { state: "failed", platform: "darwin-arm64" } }), /OPF install record is invalid/);
  assert.throws(() => assertShieldAssetsProvision({ version: 3, ...stored, gitleaks: { ...v3Gitleaks, origin: "guessed" } }), /invalid/);
  assert.throws(() => assertShieldAssetsProvision({ version: 3, ...stored, gitleaks: { origin: "override", ...base.gitleaks } }), /invalid/);
  // Only format 3 may carry install fields.
  assert.throws(() => assertShieldAssetsProvision({ version: 2, ...stored, gitleaks: v3Gitleaks }), /invalid/);
  assert.throws(() => assertShieldAssetsProvision({ version: 2, ...stored, opf: { state: "failed", platform: "none", reason: "x" } }), /invalid/);
});

test("format 2 records stay readable and normalize to the current version", async () => {
  const homeDir = await mkdtemp(join(tmpdir(), "ccshield-assets-v2-"));
  try {
    const paths = shieldPaths({ homeDir, uid: process.getuid?.() });
    const store = shieldAssetStore(paths);
    await mkdir(paths.rootDir, { recursive: true, mode: 0o700 });
    await writeFile(paths.assetsProvisionPath, JSON.stringify({ version: 2, ...base, regex: storeRegex(store.root), privacy: { state: "absent" } }), { mode: 0o600 });
    const record = await readShieldAssetsProvision({ paths });
    assert.equal(record.version, ASSETS_FORMAT_VERSION);
    assert.equal(record.opf, undefined);
    assert.equal(record.gitleaks.origin, undefined);
    // A normalized record round-trips through the writer.
    await writeShieldAssetsProvision({ paths, state: { ...record, gitleaks: v3Gitleaks, opf: { state: "failed", platform: "darwin-arm64", reason: "Python 3.10 or newer was not found" } } });
    const updated = await readShieldAssetsProvision({ paths });
    assert.deepEqual(updated.gitleaks, v3Gitleaks);
    assert.equal(updated.opf.state, "failed");
    assert.equal(updated.privacy.state, "absent");
  } finally {
    await rm(homeDir, { recursive: true, force: true });
  }
});
