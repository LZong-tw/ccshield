import assert from "node:assert/strict";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, mkdtemp, open as fsOpen, readFile, rename, rm, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  assertShieldIdentity,
  invalidateShieldPolicyBinding,
  readShieldIdentity,
  shieldPaths,
  writeShieldConfig,
  writeShieldIdentity,
} from "../src/shield/paths.mjs";

const capability = "c".repeat(32);
const identity = {
  origin: "http://127.0.0.1:8811",
  capability,
  version: 1,
  pid: 42,
  lane: "subscription",
  generation: "generation-1",
  targetClass: "subscription",
  policyVersion: "2026.09.02.1",
  detectorVersions: { gitleaks: "8.24.0" },
};

test("Shield identity is private and loopback-only", () => {
  const paths = shieldPaths({ homeDir: "/tmp/home", uid: 501 });
  assert.equal(paths.rootDir, "/tmp/home/.local/share/ccshield/subscription");
  assert.equal(paths.launchdTarget, "gui/501/com.ccshield.subscription");
  assert.throws(() => assertShieldIdentity({ origin: "https://proxy.example" }), /loopback/);
});

test("Shield paths isolate managed and subscription state and services", () => {
  const subscription = shieldPaths({ homeDir: "/tmp/home", uid: 501, lane: "subscription" });
  const managed = shieldPaths({ homeDir: "/tmp/home", uid: 501, lane: "managed" });

  assert.notEqual(subscription.rootDir, managed.rootDir);
  assert.notEqual(subscription.configPath, managed.configPath);
  assert.notEqual(subscription.identityPath, managed.identityPath);
  assert.notEqual(subscription.policyStatePath, managed.policyStatePath);
  assert.notEqual(subscription.launchAgentPath, managed.launchAgentPath);
  assert.notEqual(subscription.launchdTarget, managed.launchdTarget);
});

test("shield paths reject relative and escaping overrides", () => {
  assert.throws(() => shieldPaths({ homeDir: "/tmp/home", rootDir: "relative" }), /absolute/);
  assert.throws(() => shieldPaths({ homeDir: "/tmp/home", rootDir: "/tmp/other-state" }), /canonical/);
  assert.throws(() => shieldPaths({ homeDir: "/tmp/home", configPath: "/tmp/config.json" }), /under rootDir/);
});

test("identity rejects missing capability", async () => {
  const paths = shieldPaths({ homeDir: "/tmp/home", uid: 501 });
  const io = privateFileIo(async () => '{"origin":"http://127.0.0.1:8811"}');
  await assert.rejects(readShieldIdentity({ paths, io }), /capability/);
});

test("identity binds a launch lane and configuration generation", () => {
  assert.throws(() => assertShieldIdentity({ ...identity, lane: "managed" }), /targetClass.*lane/i);
  assert.throws(() => assertShieldIdentity({ ...identity, generation: "" }), /generation/i);
  assert.throws(() => assertShieldIdentity({ ...identity, policyVersion: "" }), /policy version/i);
});

test("identity carries optional media coverage and rejects unknown values", () => {
  assert.equal(Object.hasOwn(assertShieldIdentity(identity), "media"), false);
  for (const images of ["unscanned", "pending", "ocr-text", "unavailable", "unscanned-override"]) {
    const media = { documents: "blocked", images };
    assert.deepEqual(assertShieldIdentity({ ...identity, media }).media, media);
  }
  for (const bad of [
    null,
    "blocked",
    { documents: "blocked" },
    { documents: "scanned", images: "unscanned" },
    { documents: "blocked", images: "scanned" },
    { documents: "blocked", images: "unscanned", audio: "blocked" },
  ]) {
    assert.throws(() => assertShieldIdentity({ ...identity, media: bad }), /media/i, JSON.stringify(bad));
  }
});

test("missing identity is reported as null", async () => {
  const paths = shieldPaths({ homeDir: "/tmp/home", uid: 501 });
  const io = privateFileIo(async () => { const error = new Error("missing"); error.code = "ENOENT"; throw error; });
  assert.equal(await readShieldIdentity({ paths, io }), null);
});

// Adapts a readFile-style mock to the descriptor-based private-file reader in paths.mjs.
function privateFileIo(readFile, { uid = process.getuid?.(), mode = 0o100600 } = {}) {
  const entry = { dev: 1, ino: 1, uid, mode, isFile: () => true, isSymbolicLink: () => false };
  return {
    constants,
    async lstat() { return entry; },
    async open(path) {
      const contents = await readFile(path, "utf8");
      return { stat: async () => entry, readFile: async () => contents, close: async () => {} };
    },
  };
}

async function identityHome(t) {
  const homeDir = await mkdtemp(join(tmpdir(), "ccshield-read-"));
  t.after(() => rm(homeDir, { recursive: true, force: true }));
  const paths = shieldPaths({ homeDir, uid: process.getuid() });
  await mkdir(join(paths.identityPath, ".."), { recursive: true, mode: 0o700 });
  return paths;
}

test("identity reads check the opened descriptor, not the path", async (t) => {
  const paths = await identityHome(t);
  const body = `${JSON.stringify(identity)}\n`;
  const decoy = `${paths.identityPath}.decoy`;
  await writeFile(decoy, body, { mode: 0o600 });

  await symlink(decoy, paths.identityPath);
  await assert.rejects(readShieldIdentity({ paths }), /shield identity must not be a symlink/);
  await unlink(paths.identityPath);

  await writeFile(paths.identityPath, body, { mode: 0o644 });
  await chmod(paths.identityPath, 0o644);
  await assert.rejects(readShieldIdentity({ paths }), /shield identity must be private/);
  await unlink(paths.identityPath);

  execFileSync("mkfifo", ["-m", "600", paths.identityPath]);
  await assert.rejects(readShieldIdentity({ paths }), /shield identity must be a regular file/, "a FIFO must not block the open");
  await unlink(paths.identityPath);

  await writeFile(paths.identityPath, body, { mode: 0o600 });
  assert.deepEqual(await readShieldIdentity({ paths }), assertShieldIdentity(identity));
});

test("identity reads reject a file swapped in after the descriptor was opened", async (t) => {
  const paths = await identityHome(t);
  await writeFile(paths.identityPath, `${JSON.stringify(identity)}\n`, { mode: 0o600 });
  const io = {
    constants,
    open: fsOpen,
    async lstat(path) { return { ...(await lstat(path)), ino: -1 }; },
  };
  await assert.rejects(readShieldIdentity({ paths, io }), /shield identity was replaced while being read/);
});

test("identity writes use a private directory and atomic 0600 replacement", async () => {
  const homeDir = await mkdtemp("/tmp/ccshield-");
  const paths = shieldPaths({ homeDir, uid: 501 });
  try {
    await writeShieldIdentity({ paths, identity });
    assert.equal((await stat(paths.rootDir)).mode & 0o777, 0o700);
    assert.equal((await stat(paths.identityPath)).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(await readFile(paths.identityPath, "utf8")), identity);
  } finally {
    await rm(homeDir, { recursive: true, force: true });
  }
});

test("Shield configuration writes use managed private state and atomic 0600 replacement", async () => {
  const homeDir = await mkdtemp("/tmp/ccshield-");
  const paths = shieldPaths({ homeDir, uid: 501 });
  const config = {
    capability,
    targetOrigin: "https://api.anthropic.com",
    lane: "subscription",
    generation: "generation-1",
    targetClass: "subscription",
  };
  try {
    await writeShieldConfig({ paths, config });
    assert.equal((await stat(paths.rootDir)).mode & 0o777, 0o700);
    assert.equal((await stat(paths.configPath)).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(await readFile(paths.configPath, "utf8")), config);
  } finally {
    await rm(homeDir, { recursive: true, force: true });
  }
});

test("identity writes reject a pre-existing symlink state root", async () => {
  const homeDir = await mkdtemp("/tmp/ccshield-");
  const targetDir = await mkdtemp("/tmp/ccshield-target-");
  const paths = shieldPaths({ homeDir, uid: 501 });
  try {
    await mkdir(join(paths.rootDir, ".."), { recursive: true });
    await symlink(targetDir, paths.rootDir);
    await assert.rejects(writeShieldIdentity({ paths, identity }), /symlink/);
    assert.equal((await stat(targetDir)).mode & 0o777, 0o700);
  } finally {
    await rm(homeDir, { recursive: true, force: true });
    await rm(targetDir, { recursive: true, force: true });
  }
});

test("identity writes reject a symlink in the canonical ancestor chain", async () => {
  const homeDir = await mkdtemp("/tmp/ccshield-");
  const targetDir = await mkdtemp("/tmp/ccshield-target-");
  const paths = shieldPaths({ homeDir, uid: 501 });
  try {
    await mkdir(join(homeDir, ".local"), { recursive: true });
    await symlink(targetDir, join(homeDir, ".local", "share"));
    await assert.rejects(writeShieldIdentity({ paths, identity }), /symlink/);
  } finally {
    await rm(homeDir, { recursive: true, force: true });
    await rm(targetDir, { recursive: true, force: true });
  }
});

test("identity writes reject a state directory owned by another uid", async () => {
  const homeDir = await mkdtemp("/tmp/ccshield-");
  const paths = shieldPaths({ homeDir, uid: 501 });
  const realLstat = lstat;
  try {
    const io = {
      mkdir,
      chmod,
      lstat: async (path) => {
        const entry = await realLstat(path);
        if (path === paths.rootDir) return { uid: 999, isSymbolicLink: () => entry.isSymbolicLink(), isDirectory: () => entry.isDirectory() };
        return entry;
      },
    };
    await assert.rejects(writeShieldIdentity({ paths, identity, io }), /owner/);
  } finally {
    await rm(homeDir, { recursive: true, force: true });
  }
});

test("identity writes reject caller paths outside the canonical layout", async () => {
  const homeDir = await mkdtemp("/tmp/ccshield-");
  const identityPath = join(homeDir, ".local", "share", "ccshield", "subscription", "other.json");
  const paths = shieldPaths({ homeDir, uid: 501, identityPath });
  try {
    await assert.rejects(writeShieldIdentity({ paths, identity }), /canonical/);
  } finally {
    await rm(homeDir, { recursive: true, force: true });
  }
});

test("identity writes reject a complete forged paths object rooted outside ccshield state", async () => {
  const homeDir = await mkdtemp("/tmp/ccshield-");
  const externalHome = await mkdtemp("/tmp/ccshield-forged-");
  const canonicalPaths = shieldPaths({ homeDir, uid: 501 });
  const forgedRoot = join(externalHome, ".local", "share", "ccshield");
  const forgedPaths = {
    rootDir: forgedRoot,
    configPath: join(forgedRoot, "config.json"),
    identityPath: join(forgedRoot, "identity.json"),
    socketPath: join(forgedRoot, "shield.sock"),
    launchAgentPath: canonicalPaths.launchAgentPath,
    launchdDomain: canonicalPaths.launchdDomain,
    launchdTarget: canonicalPaths.launchdTarget,
  };
  try {
    const writeError = await writeShieldIdentity({ paths: forgedPaths, identity }).then(
      () => null,
      (error) => error,
    );
    const externalIdentityExists = await lstat(forgedPaths.identityPath).then(
      () => true,
      (error) => {
        if (error?.code === "ENOENT") return false;
        throw error;
      },
    );
    assert.equal(externalIdentityExists, false, "writer must not create identity files outside canonical ccshield state");
    assert.match(writeError?.message ?? "", /shieldPaths/);
  } finally {
    await rm(homeDir, { recursive: true, force: true });
    await rm(externalHome, { recursive: true, force: true });
  }
});

test("policy binding invalidation succeeds on a lane that has never bound one", async () => {
  const homeDir = await mkdtemp("/tmp/ccshield-");
  const paths = shieldPaths({ homeDir, uid: 501 });
  try {
    await mkdir(paths.rootDir, { recursive: true, mode: 0o700 });
    await invalidateShieldPolicyBinding({ paths });
    await writeShieldIdentity({ paths, identity });
    await invalidateShieldPolicyBinding({ paths });
    await assert.rejects(stat(paths.identityPath), /ENOENT/);
  } finally {
    await rm(homeDir, { recursive: true, force: true });
  }
});

test("identity temporary file uses exclusive no-follow open flags", async () => {
  const homeDir = await mkdtemp("/tmp/ccshield-");
  const paths = shieldPaths({ homeDir, uid: 501 });
  const calls = [];
  try {
    const io = { chmod, constants, lstat, mkdir, readFile, rename, unlink, open: async (...args) => { calls.push(args); return fsOpen(...args); } };
    await writeShieldIdentity({ paths, identity, io });
    assert.ok((calls.at(-1)[1] & constants.O_NOFOLLOW) !== 0);
    assert.ok((calls.at(-1)[1] & constants.O_EXCL) !== 0);
  } finally {
    await rm(homeDir, { recursive: true, force: true });
  }
});
