import assert from "node:assert/strict";
import test from "node:test";

import { readShieldStatuslineState, runShieldStatusline, shieldStatuslineState, shieldStatuslineSuffix } from "../src/shield/statusline-state.mjs";

test("Shield statusline state projects only neutral protection health", async () => {
  const state = await readShieldStatuslineState({
    readOperationalStatus: async () => ({
      state: "protected",
      lanes: [
        { lane: "managed", state: "protected", capability: "must-not-export", cost: 12 },
        { lane: "subscription", state: "unavailable", origin: "http://127.0.0.1:8811" },
      ],
    }),
  });
  assert.deepEqual(state, {
    shield: "protected",
    lanes: [
      { lane: "managed", state: "protected", approval: "available" },
      { lane: "subscription", state: "unavailable", approval: "blocked" },
    ],
  });
  assert.doesNotMatch(JSON.stringify(state), /capability|cost|127\.0\.0\.1/);
});

test("Shield statusline state fails closed for malformed operational data", () => {
  assert.deepEqual(shieldStatuslineState(null), { shield: "unavailable", lanes: [] });
});

test("Shield statusline consumer hands neutral state to the supported subagent statusline runtime", async () => {
  const calls = [];
  await runShieldStatusline({
    readOperationalStatus: async () => ({ state: "protected", lanes: [{ lane: "managed", state: "protected", capability: "must-not-export" }] }),
    runSubagentStatusLine: async (options) => calls.push(options),
    env: { HOME: "/private/home" },
  });
  assert.equal(calls.length, 1);
  assert.deepEqual(Object.keys(calls[0]).sort(), ["env", "input", "output", "statuslineSuffix"]);
  assert.equal(calls[0].statuslineSuffix, " · Shield subscription:unavailable managed:protected");
});

test("Shield statusline suffix never reports an unprotected lane as protected", () => {
  assert.equal(
    shieldStatuslineSuffix(shieldStatuslineState({ state: "protected", lanes: [{ lane: "managed", state: "protected" }] })),
    " · Shield subscription:unavailable managed:protected",
  );
  assert.equal(shieldStatuslineSuffix(null), " · Shield subscription:unavailable managed:unavailable");
});

test("Shield statusline suffix reduces a hostile operational payload to lane enums", () => {
  const suffix = shieldStatuslineSuffix({
    shield: "protected; leak",
    lanes: [
      { lane: "managed", state: "protected http://127.0.0.1:8080", approval: "available" },
      { lane: "../../etc/passwd", state: "protected", approval: "available" },
      { lane: "subscription", state: "blocked", capability: "c".repeat(32) },
    ],
  });
  assert.equal(suffix, " · Shield subscription:blocked managed:unavailable");
  assert.doesNotMatch(suffix, /capability|cost|passwd|127\.0\.0\.1|c{8}/);
});

test("Shield statusline renders task rows even when operational status stalls", async () => {
  const calls = [];
  const started = Date.now();
  await runShieldStatusline({
    readOperationalStatus: () => new Promise(() => {}),
    runSubagentStatusLine: async (options) => calls.push(options),
    env: { HOME: "/private/home" },
    deadlineMs: 25,
  });
  assert.ok(Date.now() - started < 2_000);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].statuslineSuffix, " · Shield subscription:unavailable managed:unavailable");
});

test("Shield statusline degrades to unavailable when operational status throws", async () => {
  const calls = [];
  await runShieldStatusline({
    readOperationalStatus: async () => { throw new Error("launchctl unavailable"); },
    runSubagentStatusLine: async (options) => calls.push(options),
    env: { HOME: "/private/home" },
  });
  assert.equal(calls[0].statuslineSuffix, " · Shield subscription:unavailable managed:unavailable");
});
