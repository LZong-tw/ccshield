import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { installPlugin, pluginSettings } from "../src/plugin/install.mjs";

test("plugin settings carry only an absolute subagentStatusLine command", () => {
  const settings = pluginSettings({ pluginRoot: "/opt/cc shield", nodePath: "/usr/bin/node" });
  assert.deepEqual(Object.keys(settings), ["subagentStatusLine"]);
  assert.equal(settings.subagentStatusLine.type, "command");
  assert.equal(settings.subagentStatusLine.command, `"/usr/bin/node" "/opt/cc shield/src/plugin/subagent-statusline.mjs"`);
  assert.doesNotMatch(JSON.stringify(settings), /CLAUDE_PLUGIN_ROOT|ANTHROPIC|"env"|"statusLine"/);
});

test("relative roots are rejected", () => {
  assert.throws(() => pluginSettings({ pluginRoot: "rel", nodePath: "/usr/bin/node" }), /absolute/);
});

test("install previews by default and writes only with --write", async (t) => {
  const root = mkdtempSync(join(tmpdir(), "ccshield-plugin-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const preview = await installPlugin({ pluginRoot: root, nodePath: "/usr/bin/node" });
  assert.equal(preview.state, "preview");
  assert.equal(existsSync(join(root, "settings.json")), false);
  const written = await installPlugin({ pluginRoot: root, nodePath: "/usr/bin/node", write: true });
  assert.equal(written.state, "written");
  assert.deepEqual(JSON.parse(readFileSync(join(root, "settings.json"), "utf8")), pluginSettings({ pluginRoot: root, nodePath: "/usr/bin/node" }));
});

test("the shipped manifest and hooks are well formed and use the plugin root", () => {
  const manifest = JSON.parse(readFileSync(new URL("../.claude-plugin/plugin.json", import.meta.url), "utf8"));
  assert.equal(manifest.name, "ccshield");
  const hooks = JSON.parse(readFileSync(new URL("../hooks/hooks.json", import.meta.url), "utf8"));
  const command = hooks.hooks.SessionStart[0].hooks[0].command;
  assert.match(command, /\$\{CLAUDE_PLUGIN_ROOT\}\/src\/plugin\/session-check\.mjs/);
});

test("the CLI wires plugin install and migrate without starting the shield", async (t) => {
  const { runShieldCli } = await import("../src/shield/cli.mjs");
  const root = mkdtempSync(join(tmpdir(), "ccshield-cli-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  let text = "";
  const stdout = { write: (chunk) => { text += chunk; } };
  const shield = new Proxy({}, { get() { throw new Error("shield must not load"); } });
  assert.equal(await runShieldCli(["plugin", "install", "--plugin-root", root], { stdout, shield }), 0);
  assert.match(text, /state: preview/);
  assert.equal(existsSync(join(root, "settings.json")), false);
  text = "";
  assert.equal(await runShieldCli(["migrate"], { stdout, shield, env: { HOME: root } }), 0);
  assert.match(text, /state: clean/);
  await assert.rejects(runShieldCli(["plugin", "bogus"], { stdout, shield }), /ccshield plugin install/);
});
