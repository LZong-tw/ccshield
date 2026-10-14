import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { createGitleaksScanner } from "../src/shield/gitleaks.mjs";

const executable = "/opt/airkit/gitleaks";
const rulesPath = "/opt/airkit/gitleaks-rules.toml";
const executableBytes = Buffer.from("gitleaks executable fixture");
const rulesBytes = Buffer.from("[rules]\nfixture = true\n");
const privateKey = "-----BEGIN PRIVATE KEY-----\\nfixture-secret-must-not-escape\\n-----END PRIVATE KEY-----";
const terraformState = '{"resources":[{"instances":[{"attributes":{"private_key":"fixture-secret-must-not-escape"}}]}]}';
const commandProfile = {
  versionArgs: ["version"],
  scanArgs: ["stdin", "--config", "{rules}", "--report-format", "json", "--report-path", "-", "--redact"],
};

test("scanner provisions canonical trusted assets and scans with bounded shell-free execution", async () => {
  const calls = [];
  const scanner = await createGitleaksScanner({
    executable,
    sha256: sha256(executableBytes),
    ruleBundle: { path: rulesPath, sha256: sha256(rulesBytes), version: "airkit-rules-1", commandProfile },
    io: fixtureIo(),
    run: async (request) => {
      calls.push(request);
      if (request.args[0] === "version") return { code: 0, stdout: "8.24.0\n", stderr: "" };
      if (request.input.includes("BEGIN PRIVATE KEY")) return report("private-key");
      return report("terraform-state");
    },
  });

  assert.equal(scanner.version, "8.24.0");
  const keyResult = await scanner.scan(Buffer.from(privateKey));
  const stateResult = await scanner.scan(Buffer.from(terraformState));
  assert.deepEqual(keyResult, { findings: [{ category: "private-key", count: 1 }] });
  assert.deepEqual(stateResult, { findings: [{ category: "terraform-state", count: 1 }] });
  assert.equal(Object.isFrozen(keyResult), true);
  assert.equal(Object.isFrozen(keyResult.findings), true);
  assert.equal(Object.isFrozen(keyResult.findings[0]), true);
  assert.ok(calls.every((call) => call.command === executable && call.shell === false));
  assert.ok(calls.every((call) => call.timeout === 2_000 && call.maxOutputBytes === 64 * 1024));
  assert.ok(calls.every((call) => Buffer.isBuffer(call.input) && call.input.length <= 1_048_576));
  assert.deepEqual(calls.at(1).args, ["stdin", "--config", rulesPath, "--report-format", "json", "--report-path", "-", "--redact"]);
  assert.doesNotMatch(JSON.stringify(keyResult), /fixture-secret|BEGIN PRIVATE KEY/);
});

test("scanner rejects noncanonical, symlinked, foreign-owned, and digest-drifted provisioned assets", async () => {
  const options = {
    executable,
    sha256: sha256(executableBytes),
    ruleBundle: { path: rulesPath, sha256: sha256(rulesBytes), version: "airkit-rules-1", commandProfile },
    run: async () => ({ code: 0, stdout: "8.24.0\n", stderr: "" }),
  };

  await assert.rejects(createGitleaksScanner({ ...options, executable: "gitleaks", io: fixtureIo() }), /absolute/i);
  await assert.rejects(createGitleaksScanner({ ...options, io: fixtureIo({ executableLink: true }) }), /symlink/i);
  await assert.rejects(createGitleaksScanner({ ...options, io: fixtureIo({ owner: 999 }) }), /owner/i);
  await assert.rejects(createGitleaksScanner({ ...options, sha256: "0".repeat(64), io: fixtureIo() }), /digest/i);
  await assert.rejects(createGitleaksScanner({ ...options, ruleBundle: { ...options.ruleBundle, commandProfile: { versionArgs: ["version"], scanArgs: ["detect"] } }, io: fixtureIo() }), /command profile/i);
  await assert.rejects(createGitleaksScanner({ ...options, io: fixtureIo({ readError: new Error("/private/untrusted/rules.toml") }) }), (error) => {
    assert.match(error.message, /validation failed/i);
    assert.doesNotMatch(error.message, /private\/untrusted/);
    return true;
  });
});

test("scanner fails closed without returning raw child output", async () => {
  const scanner = await createGitleaksScanner({
    executable,
    sha256: sha256(executableBytes),
    ruleBundle: { path: rulesPath, sha256: sha256(rulesBytes), version: "airkit-rules-1", commandProfile },
    io: fixtureIo(),
    run: async (request) => request.args[0] === "version"
      ? { code: 0, stdout: "8.24.0\n", stderr: "" }
      : request.input.includes("AIRKIT_SHIELD_SEMANTIC_SENTINEL")
        ? report("private-key")
      : { code: 2, stdout: privateKey, stderr: terraformState },
  });

  await assert.rejects(scanner.scan(Buffer.from(privateKey)), (error) => {
    assert.match(error.message, /scan failed/i);
    assert.doesNotMatch(error.message, /fixture-secret|BEGIN PRIVATE KEY|resources/);
    return true;
  });
});

test("semantic probe requires the provisioned private-key category and count", async () => {
  await assert.rejects(createGitleaksScanner({
    executable,
    sha256: sha256(executableBytes),
    ruleBundle: { path: rulesPath, sha256: sha256(rulesBytes), version: "airkit-rules-1", commandProfile },
    io: fixtureIo(),
    run: async (request) => request.args[0] === "version"
      ? { code: 0, stdout: "8.24.0\n", stderr: "" }
      : report("terraform-state"),
  }), /semantic self-test/i);
});

function fixtureIo({ executableLink = false, owner = process.getuid?.(), readError } = {}) {
  return {
    async lstat(path) {
      const isExecutable = path === executable;
      return {
        uid: owner,
        mode: isExecutable ? 0o100700 : 0o100600,
        isFile: () => true,
        isSymbolicLink: () => isExecutable && executableLink,
      };
    },
    async realpath(path) { return path; },
    async readFile(path) {
      if (readError) throw readError;
      return path === executable ? executableBytes : rulesBytes;
    },
  };
}

function report(ruleId) {
  return { code: 1, stdout: JSON.stringify([{ RuleID: ruleId, Secret: privateKey }]), stderr: "" };
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
