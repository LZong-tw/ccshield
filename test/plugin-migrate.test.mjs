import assert from "node:assert/strict";
import test from "node:test";

import { detectAirkitInstall } from "../src/plugin/migrate.mjs";

const home = "/h";
function io(files) {
  const writes = [];
  return {
    writes,
    exists: async (path) => Object.hasOwn(files, path) || Object.keys(files).some((f) => f.startsWith(`${path}/`)),
    readFile: async (path) => { if (!Object.hasOwn(files, path)) throw new Error("ENOENT"); return files[path]; },
    readdir: async (path) => Object.keys(files).filter((f) => f.startsWith(`${path}/`)).map((f) => f.slice(path.length + 1).split("/")[0]),
    writeFile: async (...args) => writes.push(args),
  };
}

test("a clean home reports nothing to migrate", async () => {
  const result = await detectAirkitInstall({ home, io: io({}) });
  assert.deepEqual(result, { state: "clean", exitCode: 0, findings: [] });
});

test("AirKit Shield state, agents and the airkit-context statusline are detected with hints and no writes", async () => {
  const fake = io({
    "/h/.local/state/airkit-shield/subscription/config.json": "{}",
    "/h/Library/LaunchAgents/com.airkit.shield.subscription.plist": "",
    "/h/Library/LaunchAgents/com.other.plist": "",
    "/h/.config/ai-runtime-kit/plugins/airkit-context/settings.json": JSON.stringify({ subagentStatusLine: { command: "node x" } }),
  });
  const result = await detectAirkitInstall({ home, io: fake });
  assert.equal(result.state, "found");
  assert.equal(result.exitCode, 0);
  assert.deepEqual(result.findings.map((f) => f.kind), ["state", "launch-agent", "statusline"]);
  for (const finding of result.findings) assert.equal(typeof finding.hint, "string");
  assert.equal(fake.writes.length, 0);
});

test("an airkit-context plugin without a statusline is not reported", async () => {
  const result = await detectAirkitInstall({ home, io: io({ "/h/.config/ai-runtime-kit/plugins/airkit-context/settings.json": "{}" }) });
  assert.equal(result.state, "clean");
});
