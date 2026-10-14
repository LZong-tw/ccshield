import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";

const MAX_BODY_BYTES = 1_048_576;
const MAX_OUTPUT_BYTES = 64 * 1024;
const SCAN_TIMEOUT_MS = 2_000;
const MAX_FINDINGS = 512;
const defaultIo = { lstat, readFile, realpath };

// The only argument vector Shield will run Gitleaks with. `shield install`
// writes it into the daemon config and the daemon revalidates it here, so both
// sides read this constant rather than repeating the array.
export const GITLEAKS_COMMAND_PROFILE = Object.freeze({
  versionArgs: Object.freeze(["version"]),
  scanArgs: Object.freeze(["stdin", "--config", "{rules}", "--report-format", "json", "--report-path", "-", "--redact"]),
});

export async function createGitleaksScanner({ executable, sha256, ruleBundle, run = runGitleaks, io = defaultIo } = {}) {
  const provision = await validateProvision({ executable, sha256, ruleBundle, io });
  if (typeof run !== "function") throw new TypeError("shield gitleaks runner is required");

  const versionResult = await invoke(run, { command: provision.executable, args: provision.ruleBundle.commandProfile.versionArgs, input: Buffer.alloc(0) });
  const version = parseVersion(versionResult);
  const selfTestResult = await invoke(run, {
    command: provision.executable,
    args: scanArguments(provision.ruleBundle),
    input: Buffer.from("-----BEGIN PRIVATE KEY-----\nAIRKIT_SHIELD_SEMANTIC_SENTINEL\n-----END PRIVATE KEY-----\n"),
  });
  const selfTestFindings = parseFindings(selfTestResult);
  if (selfTestFindings.length !== 1 || selfTestFindings[0].category !== "private-key" || selfTestFindings[0].count !== 1) {
    throw new Error("shield gitleaks semantic self-test failed");
  }

  return Object.freeze({
    version,
    async scan(body) {
      const input = boundedBody(body);
      const result = await invoke(run, {
        command: provision.executable,
        args: scanArguments(provision.ruleBundle),
        input,
      });
      return Object.freeze({ findings: freezeFindings(parseFindings(result)) });
    },
  });
}

async function validateProvision({ executable, sha256, ruleBundle, io }) {
  const executablePath = await validateAsset({ path: executable, digest: sha256, executable: true, label: "executable", io });
  if (!ruleBundle || typeof ruleBundle !== "object" || Array.isArray(ruleBundle)
    || !hasExactKeys(ruleBundle, ["commandProfile", "path", "sha256", "version"])
    || typeof ruleBundle.version !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(ruleBundle.version)) {
    throw new Error("shield gitleaks rule bundle is invalid");
  }
  const rulePath = await validateAsset({ path: ruleBundle.path, digest: ruleBundle.sha256, executable: false, label: "rule bundle", io });
  const commandProfile = assertCommandProfile(ruleBundle.commandProfile);
  return Object.freeze({ executable: executablePath, ruleBundle: Object.freeze({ path: rulePath, version: ruleBundle.version, commandProfile }) });
}

async function validateAsset({ path, digest, executable, label, io }) {
  if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path) throw new Error(`shield gitleaks ${label} path must be canonical and absolute`);
  if (typeof digest !== "string" || !/^[a-f0-9]{64}$/.test(digest)) throw new Error(`shield gitleaks ${label} digest is invalid`);
  let entry;
  let canonicalPath;
  let bytes;
  try {
    [entry, canonicalPath, bytes] = await Promise.all([io.lstat(path), io.realpath(path), io.readFile(path)]);
  } catch {
    throw new Error(`shield gitleaks ${label} validation failed`);
  }
  if (canonicalPath !== path) throw new Error(`shield gitleaks ${label} path is not canonical`);
  if (entry.isSymbolicLink?.()) throw new Error(`shield gitleaks ${label} must not be a symlink`);
  if (!entry.isFile?.()) throw new Error(`shield gitleaks ${label} must be a regular file`);
  const ownerUid = process.getuid?.();
  if (Number.isInteger(ownerUid) && entry.uid !== ownerUid) throw new Error(`shield gitleaks ${label} has unexpected owner`);
  if ((entry.mode & 0o022) !== 0) throw new Error(`shield gitleaks ${label} must not be group or world writable`);
  if (executable && (entry.mode & 0o100) === 0) throw new Error("shield gitleaks executable is not executable");
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) throw new Error(`shield gitleaks ${label} contents are invalid`);
  if (createHash("sha256").update(bytes).digest("hex") !== digest) throw new Error(`shield gitleaks ${label} digest mismatch`);
  return path;
}

function assertCommandProfile(value) {
  if (!isPlainObject(value) || !hasExactKeys(value, ["scanArgs", "versionArgs"])
    || JSON.stringify(value.versionArgs) !== JSON.stringify(GITLEAKS_COMMAND_PROFILE.versionArgs)
    || JSON.stringify(value.scanArgs) !== JSON.stringify(GITLEAKS_COMMAND_PROFILE.scanArgs)) {
    throw new Error("shield gitleaks command profile is invalid");
  }
  return Object.freeze({ versionArgs: Object.freeze([...value.versionArgs]), scanArgs: Object.freeze([...value.scanArgs]) });
}

function scanArguments(ruleBundle) {
  return ruleBundle.commandProfile.scanArgs.map((argument) => argument === "{rules}" ? ruleBundle.path : argument);
}

async function invoke(run, request) {
  let result;
  try {
    result = await run({ ...request, shell: false, timeout: SCAN_TIMEOUT_MS, maxOutputBytes: MAX_OUTPUT_BYTES });
  } catch {
    throw new Error("shield gitleaks scan failed");
  }
  if (!result || typeof result !== "object" || !Number.isInteger(result.code)
    || typeof result.stdout !== "string" || typeof result.stderr !== "string"
    || Buffer.byteLength(result.stdout) > MAX_OUTPUT_BYTES || Buffer.byteLength(result.stderr) > MAX_OUTPUT_BYTES) {
    throw new Error("shield gitleaks scan failed");
  }
  return result;
}

function parseVersion(result) {
  if (result.code !== 0) throw new Error("shield gitleaks version probe failed");
  const match = /^v?(\d+\.\d+\.\d+(?:-[A-Za-z0-9._-]+)?)\r?\n$/.exec(result.stdout);
  if (!match || result.stderr !== "") throw new Error("shield gitleaks version probe failed");
  return match[1];
}

function parseFindings(result) {
  if (result.code !== 0 && result.code !== 1) throw new Error("shield gitleaks scan failed");
  let parsed;
  try { parsed = JSON.parse(result.stdout); } catch { throw new Error("shield gitleaks scan failed"); }
  if (!Array.isArray(parsed) || parsed.length > MAX_FINDINGS) throw new Error("shield gitleaks scan failed");
  const counts = new Map();
  for (const finding of parsed) {
    const category = finding?.RuleID;
    if (!isPlainObject(finding) || typeof category !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(category)) {
      throw new Error("shield gitleaks scan failed");
    }
    counts.set(category, (counts.get(category) ?? 0) + 1);
  }
  return [...counts].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0).map(([category, count]) => ({ category, count }));
}

function freezeFindings(findings) {
  return Object.freeze(findings.map((finding) => Object.freeze({ ...finding })));
}

function boundedBody(body) {
  if (!(Buffer.isBuffer(body) || body instanceof Uint8Array) || body.byteLength > MAX_BODY_BYTES) {
    throw new Error("shield gitleaks scan input is invalid");
  }
  return Buffer.from(body);
}

function hasExactKeys(value, expected) {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function runGitleaks({ command, args, input, timeout, maxOutputBytes, shell }) {
  return new Promise((resolveResult, rejectResult) => {
    let settled = false;
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      callback(value);
    };
    const child = spawn(command, args, { shell, stdio: ["pipe", "pipe", "pipe"] });
    const fail = () => {
      child.kill();
      finish(rejectResult, new Error("shield gitleaks scan failed"));
    };
    const append = (current, chunk) => {
      const next = Buffer.concat([current, Buffer.from(chunk)]);
      if (next.length > maxOutputBytes) { fail(); return current; }
      return next;
    };
    const timer = setTimeout(fail, timeout);
    child.once("error", fail);
    child.stdout.on("data", (chunk) => { stdout = append(stdout, chunk); });
    child.stderr.on("data", (chunk) => { stderr = append(stderr, chunk); });
    child.once("close", (code) => finish(resolveResult, { code, stdout: stdout.toString("utf8"), stderr: stderr.toString("utf8") }));
    child.stdin.once("error", fail);
    child.stdin.end(input);
  });
}
