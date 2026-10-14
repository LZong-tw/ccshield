import assert from "node:assert/strict";
import { test } from "node:test";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { getMasterKey, inspectMasterKey, KEYFILE_WARNING, keyfilePath, secretToolProvider } from "../src/keys.mjs";

// A stand-in for macOS `security` backed by a JSON file. It logs argv so the
// test can prove the key never travels on the command line.
const FAKE_SECURITY = `#!${process.execPath}
const fs = require("node:fs");
const db = process.env.FAKE_KEYCHAIN_FILE;
const log = process.env.FAKE_SECURITY_LOG;
const items = fs.existsSync(db) ? JSON.parse(fs.readFileSync(db, "utf8")) : {};
const args = process.argv.slice(2);
fs.appendFileSync(log, JSON.stringify(args) + "\\n");
const opt = (list, flag) => list[list.indexOf(flag) + 1];
function run(list) {
  if (list[0] === "find-generic-password") {
    const value = items[opt(list, "-s") + "/" + opt(list, "-a")];
    if (value === undefined) return 44;
    if (list.includes("-w")) process.stdout.write(value + "\\n");
    return 0;
  }
  if (list[0] === "add-generic-password") {
    items[opt(list, "-s") + "/" + opt(list, "-a")] = opt(list, "-w");
    fs.writeFileSync(db, JSON.stringify(items));
    return 0;
  }
  return 2;
}
if (args[0] === "-i") {
  const input = fs.readFileSync(0, "utf8");
  for (const line of input.split("\\n").filter(Boolean)) run(line.trim().split(/\\s+/));
  process.exit(0);
}
process.exit(run(args));
`;

async function sandbox(t, { withSecurity }) {
  const root = await mkdtemp(join(tmpdir(), "ccshield-keys-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const bin = join(root, "bin");
  await mkdir(bin);
  if (withSecurity) {
    await writeFile(join(bin, "security"), FAKE_SECURITY);
    await chmod(join(bin, "security"), 0o755);
  }
  const env = {
    HOME: join(root, "home"),
    PATH: bin,
    FAKE_KEYCHAIN_FILE: join(root, "keychain.json"),
    FAKE_SECURITY_LOG: join(root, "security.log"),
  };
  await mkdir(env.HOME);
  return { root, env };
}

test("a fake security binary on PATH round-trips the key through the Keychain", async (t) => {
  const { env } = await sandbox(t, { withSecurity: true });
  const first = await getMasterKey({ env, platform: "darwin" });
  assert.equal(first.source, "keychain");
  assert.equal(first.warning, null);
  assert.equal(first.key.length, 32);

  const second = await getMasterKey({ env, platform: "darwin" });
  assert.equal(second.source, "keychain");
  assert.equal(second.key.equals(first.key), true);
  assert.equal(existsSync(keyfilePath({ env })), false);

  const argv = await readFile(env.FAKE_SECURITY_LOG, "utf8");
  assert.equal(argv.includes(first.key.toString("hex")), false, "the key must not appear in argv");
  assert.deepEqual(await inspectMasterKey({ env, platform: "darwin" }), { source: "keychain", present: true, warning: null });
});

test("a missing security binary falls back to a 0600 key file with a doctor warning", async (t) => {
  const { env } = await sandbox(t, { withSecurity: false });
  const first = await getMasterKey({ env, platform: "darwin" });
  assert.equal(first.source, "keyfile");
  assert.equal(first.warning, KEYFILE_WARNING);
  const path = keyfilePath({ env });
  assert.equal(path, join(env.HOME, ".config", "ccshield", "master.key"));
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  assert.equal((await stat(join(env.HOME, ".config", "ccshield"))).mode & 0o777, 0o700);

  const second = await getMasterKey({ env, platform: "darwin" });
  assert.equal(second.key.equals(first.key), true);
  assert.deepEqual(await inspectMasterKey({ env, platform: "darwin" }), { source: "keyfile", present: true, warning: KEYFILE_WARNING });
});

test("security is looked up only on the caller's PATH, never the system default", async (t) => {
  const { root, env } = await sandbox(t, { withSecurity: true });
  const bin = env.PATH;
  // With no PATH a plain spawn would fall back to /usr/bin; a relative entry
  // would resolve against the cwd. Neither may run a `security` binary.
  for (const PATH of [undefined, "", "bin"]) {
    const scoped = { ...env, PATH };
    if (PATH === undefined) delete scoped.PATH;
    const home = join(root, `home-${PATH ?? "none"}`);
    await mkdir(home);
    const result = await getMasterKey({ env: { ...scoped, HOME: home }, platform: "darwin" });
    assert.equal(result.source, "keyfile");
    assert.deepEqual(await inspectMasterKey({ env: { ...scoped, HOME: home }, platform: "darwin" }), { source: "keyfile", present: true, warning: KEYFILE_WARNING });
  }
  assert.equal(existsSync(env.FAKE_SECURITY_LOG), false, "no security binary may run without an absolute PATH entry");
  assert.equal((await getMasterKey({ env: { ...env, PATH: `relative:${bin}` }, platform: "darwin" })).source, "keychain");
});

test("an existing key file with a looser mode is refused", async (t) => {
  const { env } = await sandbox(t, { withSecurity: false });
  const path = keyfilePath({ env });
  await mkdir(join(path, ".."), { recursive: true });
  await writeFile(path, `${"ab".repeat(32)}\n`, { mode: 0o644 });
  await chmod(path, 0o644);
  await assert.rejects(getMasterKey({ env, platform: "darwin" }), /must have mode 0600/);
  await assert.rejects(getMasterKey({ env, platform: "linux" }), /must have mode 0600/);
  assert.match((await inspectMasterKey({ env, platform: "darwin" })).warning, /must have mode 0600/);
});

test("an existing key file wins over creating a new Keychain item", async (t) => {
  const { env } = await sandbox(t, { withSecurity: true });
  const path = keyfilePath({ env });
  await mkdir(join(path, ".."), { recursive: true, mode: 0o700 });
  await writeFile(path, `${"cd".repeat(32)}\n`, { mode: 0o600 });
  const result = await getMasterKey({ env, platform: "darwin" });
  assert.equal(result.source, "keyfile");
  assert.equal(result.key.toString("hex"), "cd".repeat(32));
  assert.equal(existsSync(env.FAKE_KEYCHAIN_FILE), false, "no Keychain item may be created next to an existing key file");
});

test("non-macOS platforms use the key file and secret-tool stays a P3 stub", async (t) => {
  const { env } = await sandbox(t, { withSecurity: true });
  const result = await getMasterKey({ env, platform: "linux" });
  assert.equal(result.source, "keyfile");
  assert.equal(existsSync(env.FAKE_SECURITY_LOG), false, "security must not run off macOS");
  assert.throws(() => secretToolProvider(), /P3/);
});

test("a malformed Keychain value is rejected rather than used", async (t) => {
  const { env } = await sandbox(t, { withSecurity: true });
  await writeFile(env.FAKE_KEYCHAIN_FILE, JSON.stringify({ "ccshield/audit-master-key": "not-hex" }));
  await assert.rejects(getMasterKey({ env, platform: "darwin" }), /keychain master key is malformed/);
});
