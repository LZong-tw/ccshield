import assert from "node:assert/strict";
import { test } from "node:test";

import { envNamesFor, LEGACY_ENV_NAMES, readEnv, resetCompatWarningsForTest } from "../src/compat-env.mjs";

test("every CCSHIELD_* name maps to exactly one AIRKIT_* name", () => {
  for (const [name, legacy] of Object.entries(LEGACY_ENV_NAMES)) {
    assert.match(name, /^CCSHIELD_[A-Z_]+$/);
    assert.match(legacy, /^AIRKIT_[A-Z_]+$/);
  }
  assert.equal(new Set(Object.values(LEGACY_ENV_NAMES)).size, Object.keys(LEGACY_ENV_NAMES).length);
});

test("the new name wins and the old name is read with a single warning", () => {
  resetCompatWarningsForTest();
  const warnings = [];
  const warn = (message) => warnings.push(message);
  assert.equal(readEnv({ CCSHIELD_ROOT_DIR: "/new", AIRKIT_SHIELD_ROOT_DIR: "/old" }, "CCSHIELD_ROOT_DIR", { warn }), "/new");
  assert.deepEqual(warnings, []);
  assert.equal(readEnv({ AIRKIT_SHIELD_ROOT_DIR: "/old" }, "CCSHIELD_ROOT_DIR", { warn }), "/old");
  assert.equal(readEnv({ AIRKIT_SHIELD_ROOT_DIR: "/old" }, "CCSHIELD_ROOT_DIR", { warn }), "/old");
  assert.deepEqual(warnings, ["AIRKIT_SHIELD_ROOT_DIR is deprecated; set CCSHIELD_ROOT_DIR instead"]);
  assert.equal(readEnv({}, "CCSHIELD_ROOT_DIR", { warn }), undefined);
});

test("unknown names are a programming error", () => {
  assert.throws(() => readEnv({}, "CCSHIELD_NOPE"), /unknown ccshield environment variable/);
  assert.throws(() => envNamesFor("AIRKIT_SHIELD_CAPABILITY"), /unknown ccshield environment variable/);
  assert.deepEqual(envNamesFor("CCSHIELD_CAPABILITY"), ["CCSHIELD_CAPABILITY", "AIRKIT_SHIELD_CAPABILITY"]);
});
