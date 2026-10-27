import assert from "node:assert/strict";
import { test } from "node:test";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { getMasterKey, inspectMasterKey, KEYFILE_WARNING, KEYRING_UNAVAILABLE, keyfilePath } from "../src/keys.mjs";

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

// An in-memory `secret-tool` runner. It records argv and stdin separately so
// the tests can prove the key travels only on stdin.
function fakeSecretTool({ lookup } = {}) {
  const calls = [];
  let stored = null;
  const run = async (args, options = {}) => {
    calls.push({ args, input: options.input });
    if (args[0] === "lookup") {
      if (lookup) return lookup(stored);
      return stored ? { status: 0, stdout: stored, stderr: "" } : { status: 1, stdout: "", stderr: "" };
    }
    if (args[0] === "store") {
      stored = options.input;
      return { status: 0, stdout: "", stderr: "" };
    }
    return { status: 2, stdout: "", stderr: "unknown command" };
  };
  return { run, calls, get stored() { return stored; } };
}

const DBUS_ERROR = { status: 1, stdout: "", stderr: "secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY\n" };

test("linux stores a new key in the Secret Service with the key on stdin only", async (t) => {
  const { env } = await sandbox(t, { withSecurity: true });
  const tool = fakeSecretTool();
  const first = await getMasterKey({ env, platform: "linux", runSecretTool: tool.run });
  assert.deepEqual({ source: first.source, warning: first.warning, length: first.key.length }, { source: "secret-tool", warning: null, length: 32 });
  const hex = first.key.toString("hex");
  assert.equal(tool.stored, hex);
  const store = tool.calls.find((call) => call.args[0] === "store");
  assert.deepEqual(store.args, ["store", "--label=ccshield audit master key", "service", "ccshield", "account", "audit-master-key"]);
  assert.equal(tool.calls.some((call) => call.args.join(" ").includes(hex)), false, "the key must not appear in argv");
  assert.equal(existsSync(keyfilePath({ env })), false);
  assert.equal(existsSync(env.FAKE_SECURITY_LOG), false, "security must not run on linux");

  const second = await getMasterKey({ env, platform: "linux", runSecretTool: tool.run });
  assert.equal(second.source, "secret-tool");
  assert.equal(second.key.equals(first.key), true);
  assert.equal(tool.calls.filter((call) => call.args[0] === "store").length, 1);
  assert.deepEqual(await inspectMasterKey({ env, platform: "linux", runSecretTool: tool.run }), { source: "secret-tool", present: true, warning: null });
});

test("linux falls back to the key file when secret-tool is missing", async (t) => {
  const { env } = await sandbox(t, { withSecurity: false });
  const runSecretTool = async () => ({ status: null, missing: true, stdout: "", stderr: "" });
  const result = await getMasterKey({ env, platform: "linux", runSecretTool });
  assert.deepEqual({ source: result.source, warning: result.warning }, { source: "keyfile", warning: KEYFILE_WARNING });
  assert.equal((await stat(keyfilePath({ env }))).mode & 0o777, 0o600);
  assert.deepEqual(await inspectMasterKey({ env, platform: "linux", runSecretTool }), { source: "keyfile", present: true, warning: KEYFILE_WARNING });
  // The default runner only searches the caller's PATH, which has no secret-tool here.
  assert.equal((await getMasterKey({ env, platform: "linux" })).key.equals(result.key), true);
});

test("linux falls back to the key file without storing when the Secret Service is unreachable", async (t) => {
  const { env } = await sandbox(t, { withSecurity: false });
  const tool = fakeSecretTool({ lookup: () => DBUS_ERROR });
  const result = await getMasterKey({ env, platform: "linux", runSecretTool: tool.run });
  assert.equal(result.source, "keyfile");
  assert.equal(result.warning, KEYFILE_WARNING);
  assert.equal(tool.calls.some((call) => call.args[0] === "store"), false, "a DBus failure is not a miss");
});

test("linux falls back to the key file when a store does not read back", async (t) => {
  const { env } = await sandbox(t, { withSecurity: false });
  const tool = fakeSecretTool({ lookup: () => ({ status: 1, stdout: "", stderr: "" }) });
  const result = await getMasterKey({ env, platform: "linux", runSecretTool: tool.run });
  assert.equal(result.source, "keyfile");
  assert.equal(tool.calls.filter((call) => call.args[0] === "store").length, 1);
});

test("linux keeps an existing key file instead of creating a Secret Service item", async (t) => {
  const { env } = await sandbox(t, { withSecurity: false });
  const path = keyfilePath({ env });
  await mkdir(join(path, ".."), { recursive: true, mode: 0o700 });
  await writeFile(path, `${"cd".repeat(32)}\n`, { mode: 0o600 });
  const tool = fakeSecretTool();
  const result = await getMasterKey({ env, platform: "linux", runSecretTool: tool.run });
  assert.equal(result.source, "keyfile");
  assert.equal(result.key.toString("hex"), "cd".repeat(32));
  assert.equal(tool.stored, null, "no Secret Service item may be created next to an existing key file");
});

test("linux inspect is read-only and a malformed Secret Service value is rejected", async (t) => {
  const { env } = await sandbox(t, { withSecurity: false });
  const tool = fakeSecretTool();
  assert.deepEqual(await inspectMasterKey({ env, platform: "linux", runSecretTool: tool.run }), { source: "none", present: false, warning: null });
  assert.equal(tool.calls.some((call) => call.args[0] !== "lookup"), false, "inspect must never store");

  const bad = fakeSecretTool({ lookup: () => ({ status: 0, stdout: "not-hex\n", stderr: "" }) });
  await assert.rejects(getMasterKey({ env, platform: "linux", runSecretTool: bad.run }), /secret-tool master key is malformed/);
  assert.match((await inspectMasterKey({ env, platform: "linux", runSecretTool: bad.run })).warning, /malformed/);
});

test("other platforms use the key file and run neither keyring tool", async (t) => {
  const { env } = await sandbox(t, { withSecurity: true });
  const tool = fakeSecretTool();
  const result = await getMasterKey({ env, platform: "freebsd", runSecretTool: tool.run });
  assert.equal(result.source, "keyfile");
  assert.equal(tool.calls.length, 0);
  assert.equal(existsSync(env.FAKE_SECURITY_LOG), false);
});

test("a malformed Keychain value is rejected rather than used", async (t) => {
  const { env } = await sandbox(t, { withSecurity: true });
  await writeFile(env.FAKE_KEYCHAIN_FILE, JSON.stringify({ "ccshield/audit-master-key": "not-hex" }));
  await assert.rejects(getMasterKey({ env, platform: "darwin" }), /keychain master key is malformed/);
});

test("linux refuses to mint a key file once the Secret Service holds the key and lookup fails", async (t) => {
  const { env } = await sandbox(t, { withSecurity: false });
  let down = false;
  const tool = fakeSecretTool({ lookup: (stored) => (down ? DBUS_ERROR : stored ? { status: 0, stdout: stored, stderr: "" } : { status: 1, stdout: "", stderr: "" }) });
  const first = await getMasterKey({ env, platform: "linux", runSecretTool: tool.run });
  assert.equal(first.source, "secret-tool");

  down = true;
  await assert.rejects(getMasterKey({ env, platform: "linux", runSecretTool: tool.run }), new RegExp(KEYRING_UNAVAILABLE));
  assert.equal(existsSync(keyfilePath({ env })), false, "no key file may appear behind an unreachable keyring");
  assert.deepEqual(await inspectMasterKey({ env, platform: "linux", runSecretTool: tool.run }), { source: "secret-tool", present: true, warning: KEYRING_UNAVAILABLE });

  down = false;
  const again = await getMasterKey({ env, platform: "linux", runSecretTool: tool.run });
  assert.equal(again.key.equals(first.key), true);
});

test("linux never overwrites a keyring key when a later lookup looks like a miss", async (t) => {
  const { env } = await sandbox(t, { withSecurity: false });
  let silent = false;
  const tool = fakeSecretTool({ lookup: (stored) => (silent || !stored ? { status: 1, stdout: "", stderr: "" } : { status: 0, stdout: stored, stderr: "" }) });
  const first = await getMasterKey({ env, platform: "linux", runSecretTool: tool.run });
  silent = true;
  await assert.rejects(getMasterKey({ env, platform: "linux", runSecretTool: tool.run }), new RegExp(KEYRING_UNAVAILABLE));
  assert.equal(tool.stored, first.key.toString("hex"), "the existing item must not be replaced");
  assert.equal(tool.calls.filter((call) => call.args[0] === "store").length, 1);
});

test("linux adopts the key a concurrent first run stored instead of splitting to a key file", async (t) => {
  const { env } = await sandbox(t, { withSecurity: false });
  const winner = "ef".repeat(32);
  let stores = 0;
  const run = async (args) => {
    if (args[0] === "store") return (stores += 1, { status: 0, stdout: "", stderr: "" });
    return stores ? { status: 0, stdout: winner, stderr: "" } : { status: 1, stdout: "", stderr: "" };
  };
  const result = await getMasterKey({ env, platform: "linux", runSecretTool: run });
  assert.equal(result.source, "secret-tool");
  assert.equal(result.key.toString("hex"), winner);
  assert.equal(existsSync(keyfilePath({ env })), false);
});

test("linux inspect warns when lookup fails and no key is known", async (t) => {
  const { env } = await sandbox(t, { withSecurity: false });
  const tool = fakeSecretTool({ lookup: () => DBUS_ERROR });
  const result = await inspectMasterKey({ env, platform: "linux", runSecretTool: tool.run });
  assert.equal(result.present, false);
  assert.match(result.warning, /unreachable Secret Service/);
});
