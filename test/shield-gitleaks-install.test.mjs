import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { access, chmod, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { doctorGitleaksWarnings, gitleaksOverride, installGitleaks, pinnedGitleaksSha256 } from "../src/shield/gitleaks-install.mjs";
import { shieldAssetStore, shieldPaths } from "../src/shield/paths.mjs";

const execFileAsync = promisify(execFile);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const platform = Object.freeze({ supported: true, key: "darwin-arm64" });
const fakeBinary = "#!/bin/sh\necho 8.30.1\n";

async function fixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "ccshield-gitleaks-")));
  const build = join(root, "build");
  await mkdir(build);
  await writeFile(join(build, "gitleaks"), fakeBinary, { mode: 0o755 });
  await writeFile(join(build, "LICENSE"), "MIT\n");
  const archivePath = join(root, "gitleaks.tar.gz");
  await execFileAsync("tar", ["-czf", archivePath, "-C", build, "gitleaks", "LICENSE"]);
  const archive = await readFile(archivePath);
  const store = shieldAssetStore(shieldPaths({ homeDir: join(root, "home"), uid: process.getuid() }));
  return { root, archive, store, cleanup: () => rm(root, { recursive: true, force: true }) };
}

function pinsFor(base, archive, { version = "8.30.1", digest = sha256(archive) } = {}) {
  return { gitleaks: { version, archives: { "darwin-arm64": { name: `gitleaks_${version}_darwin_arm64.tar.gz`, url: `${base}/gitleaks.tar.gz`, sha256: digest, size: archive.length } } } };
}

async function withServer(body, payload) {
  const requests = [];
  const server = createServer((request, response) => {
    requests.push(request.url);
    response.writeHead(200, { "content-length": payload.length });
    response.end(payload);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    return await body(`http://127.0.0.1:${server.address().port}`, requests);
  } finally {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  }
}

const exists = (path) => access(path).then(() => true, () => false);

test("the pinned archive installs an executable binary into gitleaks/<version>/", async () => {
  const { archive, store, cleanup } = await fixture();
  try {
    await withServer(async (base) => {
      const result = await installGitleaks({ pins: pinsFor(base, archive), store, platform });
      const target = store.gitleaks("8.30.1");
      assert.equal(result.origin, "downloaded");
      assert.equal(result.version, "8.30.1");
      assert.equal(result.path, target.binary);
      assert.equal(result.sha256, sha256(Buffer.from(fakeBinary)));
      assert.equal(result.archiveSha256, sha256(archive));
      assert.ok(Object.isFrozen(result));
      assert.equal((await stat(target.binary)).mode & 0o777, 0o755);
      assert.deepEqual(await readdir(target.dir), ["gitleaks"]);
      assert.deepEqual(await readdir(store.stagingDir), []);
      assert.equal(await pinnedGitleaksSha256({ pins: pinsFor(base, archive), store }), result.sha256);
    }, archive);
  } finally {
    await cleanup();
  }
});

test("a second install reuses the verified copy without downloading", async () => {
  const { archive, store, cleanup } = await fixture();
  try {
    await withServer(async (base, requests) => {
      const first = await installGitleaks({ pins: pinsFor(base, archive), store, platform });
      const second = await installGitleaks({ pins: pinsFor(base, archive), store, platform });
      assert.deepEqual(second, first);
      assert.equal(requests.length, 1);
    }, archive);
  } finally {
    await cleanup();
  }
});

test("a bad digest leaves nothing installed", async () => {
  const { archive, store, cleanup } = await fixture();
  try {
    await withServer(async (base) => {
      await assert.rejects(installGitleaks({ pins: pinsFor(base, archive, { digest: "0".repeat(64) }), store, platform }), /digest verification/);
    }, archive);
    assert.equal(await exists(join(store.root, "gitleaks")), false);
    assert.deepEqual(await readdir(store.stagingDir), []);
  } finally {
    await cleanup();
  }
});

test("an archive without the binary leaves nothing installed", async () => {
  const { root, store, cleanup } = await fixture();
  try {
    const empty = join(root, "empty");
    await mkdir(empty);
    await writeFile(join(empty, "README.md"), "no binary\n");
    await execFileAsync("tar", ["-czf", join(root, "bad.tar.gz"), "-C", empty, "README.md"]);
    const bad = await readFile(join(root, "bad.tar.gz"));
    await withServer(async (base) => {
      await assert.rejects(installGitleaks({ pins: pinsFor(base, bad), store, platform }), /shield Gitleaks archive/);
    }, bad);
    assert.equal(await exists(join(store.root, "gitleaks")), false);
  } finally {
    await cleanup();
  }
});

test("an OS/arch with no pin never starts a download", async () => {
  const { archive, store, cleanup } = await fixture();
  try {
    let fetched = false;
    const fetchImpl = async () => { fetched = true; throw new Error("unexpected fetch"); };
    await assert.rejects(
      installGitleaks({ pins: pinsFor("http://127.0.0.1:9", archive), store, platform: { supported: false, key: null, reason: "freebsd is not supported" }, os: "freebsd", arch: "x64", fetchImpl }),
      /no pinned Gitleaks for freebsd-x64/,
    );
    await assert.rejects(installGitleaks({ pins: pinsFor("http://127.0.0.1:9", archive), store, os: "linux", arch: "x64", fetchImpl }), /no pinned Gitleaks for linux-x64/);
    assert.equal(fetched, false);
  } finally {
    await cleanup();
  }
});

test("a machine unsupported for OPF still gets the pinned Gitleaks", async () => {
  const { archive, store, cleanup } = await fixture();
  try {
    await withServer(async (base) => {
      const macos13 = { supported: false, key: null, reason: "macOS 14 or newer is required" };
      const result = await installGitleaks({ pins: pinsFor(base, archive), store, platform: macos13, os: "darwin", arch: "arm64" });
      assert.equal(result.path, store.gitleaks("8.30.1").binary);
    }, archive);
  } finally {
    await cleanup();
  }
});

test("the override records version and hash and never downloads", async () => {
  const { root, cleanup } = await fixture();
  try {
    const binary = join(root, "my-gitleaks");
    await writeFile(binary, fakeBinary, { mode: 0o755 });
    const calls = [];
    const run = async (request) => { calls.push(request); return { code: 0, stdout: "8.29.0\n", stderr: "" }; };
    const recorded = await gitleaksOverride({ path: binary, run });
    assert.deepEqual(recorded, { origin: "override", version: "8.29.0", path: binary, sha256: sha256(Buffer.from(fakeBinary)) });
    assert.deepEqual(calls, [{ command: binary, args: ["version"] }]);
    assert.equal((await gitleaksOverride({ path: binary })).version, "8.30.1");
  } finally {
    await cleanup();
  }
});

test("the override rejects unsafe or unrecognisable binaries", async () => {
  const { root, cleanup } = await fixture();
  try {
    const binary = join(root, "my-gitleaks");
    await writeFile(binary, fakeBinary, { mode: 0o644 });
    await assert.rejects(gitleaksOverride({ path: binary }), /not executable/);
    await chmod(binary, 0o775);
    await assert.rejects(gitleaksOverride({ path: binary }), /group or world writable/);
    await chmod(binary, 0o755);
    await assert.rejects(gitleaksOverride({ path: "relative/gitleaks" }), /canonical and absolute/);
    await assert.rejects(gitleaksOverride({ path: binary, run: async () => ({ code: 0, stdout: "not a version\n", stderr: "" }) }), /version probe failed/);
    await assert.rejects(gitleaksOverride({ path: binary, run: async () => ({ code: 0, stdout: "8.30.1\n", stderr: "warning\n" }) }), /version probe failed/);
    assert.equal((await gitleaksOverride({ path: binary, run: async () => ({ code: 0, stdout: "v8.31.0-rc1\n", stderr: "" }) })).version, "8.31.0-rc1");
  } finally {
    await cleanup();
  }
});

test("doctor warns on a version mismatch, a different build and a changed file", async () => {
  const { root, cleanup } = await fixture();
  try {
    const binary = join(root, "my-gitleaks");
    await writeFile(binary, fakeBinary, { mode: 0o755 });
    const pins = { gitleaks: { version: "8.30.1" } };
    const recorded = { origin: "override", version: "8.30.1", path: binary, sha256: sha256(Buffer.from(fakeBinary)) };

    assert.deepEqual(await doctorGitleaksWarnings(recorded, pins, { pinnedSha256: recorded.sha256 }), []);
    assert.deepEqual(await doctorGitleaksWarnings({ ...recorded, version: "8.29.0" }, pins), ["shield Gitleaks 8.29.0 differs from the pinned 8.30.1"]);
    assert.deepEqual(await doctorGitleaksWarnings(recorded, pins, { pinnedSha256: "f".repeat(64) }), ["shield Gitleaks binary differs from the pinned build"]);
    const { version: _legacy, ...unversioned } = recorded;
    assert.deepEqual(await doctorGitleaksWarnings(unversioned, pins), ["shield Gitleaks version was not recorded"]);

    await writeFile(binary, "#!/bin/sh\necho tampered\n");
    assert.deepEqual(await doctorGitleaksWarnings(recorded, pins), [`shield Gitleaks binary at ${binary} changed since it was recorded`]);
    await rm(binary);
    assert.deepEqual(await doctorGitleaksWarnings(recorded, pins), [`shield Gitleaks binary at ${binary} is missing`]);
  } finally {
    await cleanup();
  }
});

test("the store pins Gitleaks by plain semver under assets/gitleaks/", () => {
  const store = shieldAssetStore(shieldPaths({ homeDir: "/home/user", uid: 501 }));
  assert.deepEqual({ ...store.gitleaks("8.30.1") }, {
    dir: "/home/user/.local/share/ccshield/assets/gitleaks/8.30.1",
    binary: "/home/user/.local/share/ccshield/assets/gitleaks/8.30.1/gitleaks",
  });
  for (const version of ["../8.30.1", "v8.30.1", "8.30", undefined]) assert.throws(() => store.gitleaks(version), /plain semver/);
});

test("doctor warns when the original a store copy was adopted from was upgraded or removed", async () => {
  const { root, cleanup } = await fixture();
  try {
    const stored = join(root, "stored-gitleaks");
    const source = join(root, "brew-gitleaks");
    const rulesStored = join(root, "stored-rules.toml");
    const rulesSource = join(root, "pkg-rules.toml");
    await writeFile(stored, fakeBinary, { mode: 0o755 });
    await writeFile(source, fakeBinary, { mode: 0o755 });
    await writeFile(rulesStored, "rules v1");
    await writeFile(rulesSource, "rules v1");
    const pins = { gitleaks: { version: "8.30.1" } };
    const recorded = {
      origin: "override", version: "8.30.1", path: stored, source, sha256: sha256(Buffer.from(fakeBinary)),
      rules: { path: rulesStored, source: rulesSource, sha256: sha256(Buffer.from("rules v1")), version: "rules-1" },
    };
    assert.deepEqual(await doctorGitleaksWarnings(recorded, pins), []);

    await writeFile(source, "#!/bin/sh\necho 8.31.0\n");
    await writeFile(rulesSource, "rules v2");
    const upgraded = await doctorGitleaksWarnings(recorded, pins);
    assert.equal(upgraded.length, 2);
    assert.match(upgraded[0], /Gitleaks binary at .*brew-gitleaks was updated.*ccshield install --write/);
    assert.match(upgraded[1], /Gitleaks rules at .*pkg-rules\.toml was updated/);

    await rm(source);
    assert.match((await doctorGitleaksWarnings(recorded, pins))[0], /brew-gitleaks, which no longer exists.*stored copy/);
  } finally {
    await cleanup();
  }
});
