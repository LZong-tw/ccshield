import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, copyFile, mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { createGitleaksScanner } from "../src/shield/gitleaks.mjs";

// Real Gitleaks against real request bodies. Text arrives JSON-escaped, so a
// newline is the two characters `\` `n`, and the `n` sits right against
// whatever starts the next line.
const installed = (() => {
  try { return execFileSync("/usr/bin/which", ["gitleaks"], { encoding: "utf8" }).trim() || null; } catch { return null; }
})();

const KEY = "AKIAZ7WQ3MRX2KBTLRPV";
const body = (text) => Buffer.from(JSON.stringify({ messages: [{ role: "user", content: [{ type: "text", text }] }] }));

test("a secret is caught wherever it sits in a text request", { skip: !installed && "gitleaks is not installed" }, async (t) => {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "shield-gitleaks-")));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const executable = join(dir, "gitleaks");
  const rules = join(dir, "rules.toml");
  await copyFile(await realpath(installed), executable);
  await chmod(executable, 0o755);
  await copyFile(fileURLToPath(new URL("../detectors/gitleaks/gitleaks-rules.toml", import.meta.url)), rules);
  const sha256 = async (path) => createHash("sha256").update(await readFile(path)).digest("hex");
  const scanner = await createGitleaksScanner({
    executable,
    sha256: await sha256(executable),
    ruleBundle: {
      path: rules,
      sha256: await sha256(rules),
      version: "test",
      commandProfile: { versionArgs: ["version"], scanArgs: ["stdin", "--config", "{rules}", "--report-format", "json", "--report-path", "-", "--redact"] },
    },
  });

  for (const text of [`key: ${KEY}`, `key:\n${KEY}`, `key:\r\n${KEY}`, `key:\t${KEY}`, `${KEY}\nnext line`]) {
    const { findings } = await scanner.scan(body(text));
    assert.ok(findings.length > 0, `missed ${JSON.stringify(text)}`);
  }
  // An escaped backslash before `n` is a literal backslash and an n, not a newline.
  const { findings } = await scanner.scan(body("path C:\\new"));
  assert.deepEqual(findings, []);
});
