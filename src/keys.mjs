import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { accessSync, constants } from "node:fs";
import { chmod, lstat, mkdir, open, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { delimiter, isAbsolute, join } from "node:path";

export const KEYCHAIN_SERVICE = "ccshield";
export const KEYCHAIN_ACCOUNT = "audit-master-key";
export const KEYFILE_WARNING = "master key is stored in a 0600 key file, not the OS keyring";
const KEY_HEX = /^[0-9a-f]{64}$/;
const SECURITY_ITEM_NOT_FOUND = 44;

export function keyfilePath({ env = process.env } = {}) {
  const home = typeof env.HOME === "string" && env.HOME.length > 0 ? env.HOME : homedir();
  return join(home, ".config", "ccshield", "master.key");
}

// Resolves the 32-byte audit master key: Keychain on macOS, otherwise a 0600
// key file with a warning that `doctor` reports.
export async function getMasterKey({ env = process.env, platform = process.platform, runSecurity = (args, options) => runCommand("security", args, { ...options, env }) } = {}) {
  const path = keyfilePath({ env });
  if (platform !== "darwin") return keyfileResult(await readOrCreateKeyfile(path));

  const found = await runSecurity(["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w"]);
  if (found.status === 0) return { key: parseKey(found.stdout, "keychain"), source: "keychain", warning: null };

  // A key file means an earlier run fell back. Keep using it: creating a
  // Keychain item now would leave older evidence under a different key.
  const existing = await readKeyfile(path);
  if (existing) return keyfileResult(existing);

  if (found.status === SECURITY_ITEM_NOT_FOUND) {
    const key = randomBytes(32);
    // `security -i` reads the command from stdin, so the key never appears in argv.
    const added = await runSecurity(["-i"], { input: `add-generic-password -U -s ${KEYCHAIN_SERVICE} -a ${KEYCHAIN_ACCOUNT} -w ${key.toString("hex")}\n` });
    if (added.status === 0) {
      const check = await runSecurity(["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w"]);
      if (check.status === 0 && parseKey(check.stdout, "keychain").equals(key)) return { key, source: "keychain", warning: null };
    }
  }
  return keyfileResult(await readOrCreateKeyfile(path));
}

// Read-only view for `doctor`; never creates a key.
export async function inspectMasterKey({ env = process.env, platform = process.platform, runSecurity = (args, options) => runCommand("security", args, { ...options, env }) } = {}) {
  const path = keyfilePath({ env });
  if (platform === "darwin") {
    const found = await runSecurity(["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT]);
    if (found.status === 0) return { source: "keychain", present: true, warning: null };
  }
  try {
    const key = await readKeyfile(path);
    return key ? { source: "keyfile", present: true, warning: KEYFILE_WARNING } : { source: "none", present: false, warning: null };
  } catch (error) {
    return { source: "keyfile", present: true, warning: error.message };
  }
}

// Linux Secret Service support lands in P3; nothing selects this yet.
export function secretToolProvider() {
  throw new Error("secret-tool key storage is not implemented yet (P3)");
}

function keyfileResult(key) {
  return { key, source: "keyfile", warning: KEYFILE_WARNING };
}

async function readOrCreateKeyfile(path) {
  const existing = await readKeyfile(path);
  if (existing) return existing;
  const dir = join(path, "..");
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await chmod(dir, 0o700);
  const key = randomBytes(32);
  let handle;
  try {
    handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  } catch (error) {
    // Another process won the race; use its key.
    if (error?.code === "EEXIST") return await readKeyfile(path);
    throw error;
  }
  try {
    await handle.writeFile(`${key.toString("hex")}\n`);
    await handle.chmod(0o600);
  } finally {
    await handle.close();
  }
  return key;
}

async function readKeyfile(path) {
  let entry;
  try {
    entry = await lstat(path);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  if (entry.isSymbolicLink() || !entry.isFile()) throw new Error(`key file ${path} must be a regular file`);
  if ((entry.mode & 0o077) !== 0) throw new Error(`key file ${path} must have mode 0600; refusing a key readable by others`);
  if (typeof process.getuid === "function" && entry.uid !== process.getuid()) throw new Error(`key file ${path} has an unexpected owner`);
  return parseKey(await readFile(path, "utf8"), "key file");
}

function parseKey(text, label) {
  const hex = String(text).trim();
  if (!KEY_HEX.test(hex)) throw new Error(`${label} master key is malformed`);
  return Buffer.from(hex, "hex");
}

// Only the caller's PATH is searched. With no PATH the spawn would fall back to
// the system default and reach /usr/bin/security behind the caller's back.
function findOnPath(command, env) {
  const path = typeof env?.PATH === "string" ? env.PATH : "";
  for (const dir of path.split(delimiter)) {
    if (!isAbsolute(dir)) continue;
    const candidate = join(dir, command);
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {}
  }
  return null;
}

function runCommand(command, args, { input, env } = {}) {
  const executable = findOnPath(command, env);
  if (!executable) return Promise.resolve({ status: null, missing: true, stdout: "", stderr: "" });
  return new Promise((resolve) => {
    const child = execFile(executable, args, { env, timeout: 10_000, maxBuffer: 16 * 1024 }, (error, stdout, stderr) => {
      if (!error) return resolve({ status: 0, stdout, stderr });
      resolve({ status: typeof error.code === "number" ? error.code : null, missing: error.code === "ENOENT", stdout: stdout ?? "", stderr: stderr ?? "" });
    });
    child.stdin?.on("error", () => {});
    child.stdin?.end(input ?? "");
  });
}
