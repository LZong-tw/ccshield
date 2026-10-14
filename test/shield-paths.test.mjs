import assert from "node:assert/strict";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, mkdtemp, open as fsOpen, readFile, rename, rm, stat, symlink, unlink } from "node:fs/promises";
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
  assert.equal(paths.rootDir, "/tmp/home/.local/state/airkit-shield/subscription");
  assert.equal(paths.launchdTarget, "gui/501/com.airkit.shield.subscription");
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
  const io = { async readFile() { return '{"origin":"http://127.0.0.1:8811"}'; } };
  await assert.rejects(readShieldIdentity({ paths, io }), /capability/);
});

test("identity binds a launch lane and configuration generation", () => {
  assert.throws(() => assertShieldIdentity({ ...identity, lane: "managed" }), /targetClass.*lane/i);
  assert.throws(() => assertShieldIdentity({ ...identity, generation: "" }), /generation/i);
  assert.throws(() => assertShieldIdentity({ ...identity, policyVersion: "" }), /policy version/i);
});

test("missing identity is reported as null", async () => {
  const paths = shieldPaths({ homeDir: "/tmp/home", uid: 501 });
  const io = { async readFile() { const error = new Error("missing"); error.code = "ENOENT"; throw error; } };
  assert.equal(await readShieldIdentity({ paths, io }), null);
});

test("identity writes use a private directory and atomic 0600 replacement", async () => {
  const homeDir = await mkdtemp("/tmp/airkit-shield-");
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
  const homeDir = await mkdtemp("/tmp/airkit-shield-");
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
  const homeDir = await mkdtemp("/tmp/airkit-shield-");
  const targetDir = await mkdtemp("/tmp/airkit-shield-target-");
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
  const homeDir = await mkdtemp("/tmp/airkit-shield-");
  const targetDir = await mkdtemp("/tmp/airkit-shield-target-");
  const paths = shieldPaths({ homeDir, uid: 501 });
  try {
    await mkdir(join(homeDir, ".local"), { recursive: true });
    await symlink(targetDir, join(homeDir, ".local", "state"));
    await assert.rejects(writeShieldIdentity({ paths, identity }), /symlink/);
  } finally {
    await rm(homeDir, { recursive: true, force: true });
    await rm(targetDir, { recursive: true, force: true });
  }
});

test("identity writes reject a state directory owned by another uid", async () => {
  const homeDir = await mkdtemp("/tmp/airkit-shield-");
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
  const homeDir = await mkdtemp("/tmp/airkit-shield-");
  const identityPath = join(homeDir, ".local", "state", "airkit-shield", "subscription", "other.json");
  const paths = shieldPaths({ homeDir, uid: 501, identityPath });
  try {
    await assert.rejects(writeShieldIdentity({ paths, identity }), /canonical/);
  } finally {
    await rm(homeDir, { recursive: true, force: true });
  }
});

test("identity writes reject a complete forged paths object rooted outside AirKit state", async () => {
  const homeDir = await mkdtemp("/tmp/airkit-shield-");
  const externalHome = await mkdtemp("/tmp/airkit-shield-forged-");
  const canonicalPaths = shieldPaths({ homeDir, uid: 501 });
  const forgedRoot = join(externalHome, ".local", "state", "airkit-shield");
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
    assert.equal(externalIdentityExists, false, "writer must not create identity files outside canonical AirKit state");
    assert.match(writeError?.message ?? "", /shieldPaths/);
  } finally {
    await rm(homeDir, { recursive: true, force: true });
    await rm(externalHome, { recursive: true, force: true });
  }
});

test("policy binding invalidation succeeds on a lane that has never bound one", async () => {
  const homeDir = await mkdtemp("/tmp/airkit-shield-");
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
  const homeDir = await mkdtemp("/tmp/airkit-shield-");
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
