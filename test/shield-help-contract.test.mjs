import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { runShieldCli } from "../src/shield/cli.mjs";

const CLI_PATH = fileURLToPath(new URL("../src/cli.mjs", import.meta.url));

const SHIELD_COMMANDS = [
  "ccshield install [--lane subscription|managed] [--gitleaks-path /absolute/gitleaks] [--write]",
  "ccshield uninstall [--lane subscription|managed] [--write]",
  "ccshield start",
  "ccshield stop",
  "ccshield status",
  "ccshield doctor",
  "ccshield policy <status [--lane subscription|managed]|install --bundle /absolute/policy-bundle --public-key /absolute/policy-public-key [--lane subscription|managed] [--write]>",
  "ccshield privacy provision --gitleaks /absolute/gitleaks --gitleaks-rules /absolute/gitleaks-rules.toml [--bundle /absolute/privacy-manifest] [--policy-bundle /absolute/policy-bundle] [--lane subscription|managed] [--write]",
  "ccshield image provision [--image-source /absolute/image-worker.swift] [--lane subscription|managed] [--write]",
  "ccshield launch --lane subscription|managed [--target http://127.0.0.1:port] -- command [args...]",
];

const pattern = (command) => new RegExp(command.replace(/[|()[\].?+*^$\\]/g, "\\$&"));

function capture() {
  let value = "";
  return { stdout: { write(chunk) { value += String(chunk); } }, value: () => value };
}

test("the ccshield bin and runShieldCli expose the documented command contract", async (t) => {
  const home = mkdtempSync(join(tmpdir(), "ccshield-help-"));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  for (const argv of [[], ["help"], ["-h"], ["--help"]]) {
    const result = spawnSync(process.execPath, [CLI_PATH, ...argv], { encoding: "utf8", env: { PATH: process.env.PATH, HOME: home } });
    assert.equal(result.status, 0, JSON.stringify(argv));
    assert.equal(result.stderr, "", JSON.stringify(argv));
    for (const command of SHIELD_COMMANDS) assert.match(result.stdout, pattern(command));
    assert.doesNotMatch(result.stdout, /airkit/i);
  }

  for (const argv of [[], ["help"], ["-h"], ["--help"]]) {
    const output = capture();
    const code = await runShieldCli(argv, { stdout: output.stdout });

    assert.equal(code, 0);
    for (const command of SHIELD_COMMANDS) assert.match(output.value(), pattern(command));
  }
});
test("shield uninstall previews by default, exits 0, hides paths and rejects an ambiguous lane", async () => {
  const seen = [];
  const shield = { async uninstall(options) {
    seen.push(options);
    return { state: options.write ? "stopped" : "preview", exitCode: 0, write: options.write, lane: options.lane,
      service: { label: `com.ccshield.${options.lane}`, installed: true, removed: options.write, operations: [{ op: "unlink", path: "/private/plist" }] } };
  } };
  const output = capture();
  assert.equal(await runShieldCli(["uninstall", "--lane", "managed"], { stdout: output.stdout, shield }), 0);
  assert.deepEqual(seen, [{ write: false, lane: "managed" }]);
  assert.match(output.value(), /state: preview/);
  assert.doesNotMatch(output.value(), /\/private\/plist/);
  assert.equal(await runShieldCli(["uninstall", "--write"], { stdout: capture().stdout, shield }), 0);
  assert.deepEqual(seen[1], { write: true, lane: "subscription" });
  for (const argv of [["uninstall", "--lane", "subscription", "--lane", "managed"], ["uninstall", "--lane", "managed", "--lane", "subscription"], ["uninstall", "--lane", "other"]]) {
    await assert.rejects(runShieldCli(argv, { stdout: capture().stdout, shield }), /usage: ccshield uninstall/);
  }
  assert.equal(seen.length, 2);
});
