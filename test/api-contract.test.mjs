import assert from "node:assert/strict";
import { test } from "node:test";

// Only the package entry point; a deep import here would hide a missing export.
import * as api from "@untionglim/shield";

const CONTRACT = Object.freeze({
  buildShieldChildEnv: "function",
  ensureShieldReady: "function",
  readShieldStatus: "function",
  resolveShieldLauncher: "function",
  resolveShieldLauncherMarker: "function",
  shieldLauncherDescriptors: "function",
  startPxpipeHop: "function",
});

test("the package entry point exports exactly the documented surface", () => {
  assert.deepEqual(Object.keys(api).sort(), Object.keys(CONTRACT).sort());
  for (const [name, type] of Object.entries(CONTRACT)) assert.equal(typeof api[name], type, name);
});

test("internal modules are not reachable through the package exports map", async () => {
  await assert.rejects(import("@untionglim/shield/src/store.mjs"), { code: "ERR_PACKAGE_PATH_NOT_EXPORTED" });
});

test("readShieldStatus never throws and projects the statusline from the same read", async () => {
  const failed = await api.readShieldStatus({ readOperationalStatus: async () => { throw new Error("launchctl unavailable"); } });
  assert.equal(failed.state, "unavailable");
  assert.equal(failed.statuslineSuffix, " · Shield subscription:unavailable managed:unavailable");

  const seen = [];
  const status = await api.readShieldStatus({
    env: { HOME: "/nonexistent" },
    readOperationalStatus: async (options) => {
      seen.push(options);
      return { state: "protected", lanes: [{ lane: "subscription", state: "protected", audit: "healthy" }, { lane: "managed", state: "unavailable", audit: "unavailable" }] };
    },
  });
  assert.equal(typeof seen[0].audit, "function", "audit health defaults to a per-lane store check");
  assert.equal(status.state, "protected");
  assert.deepEqual(status.statusline.lanes.map((lane) => [lane.lane, lane.state]), [["subscription", "protected"], ["managed", "unavailable"]]);
  assert.equal(status.statuslineSuffix, " · Shield subscription:protected managed:unavailable");
});

test("per-lane audit health comes from that lane's store", async () => {
  const { mkdtemp, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const home = await mkdtemp(join(tmpdir(), "ccshield-api-"));
  try {
    const seen = [];
    await api.readShieldStatus({
      env: { HOME: home, UID: "501" },
      readOperationalStatus: async ({ audit }) => {
        for (const lane of ["subscription", "managed"]) seen.push(await audit({ lane, paths: { auditDatabasePath: join(home, lane, "audit.sqlite") } }));
        return { state: "unavailable", lanes: [] };
      },
    });
    assert.deepEqual(seen, ["unavailable", "unavailable"], "a lane without a store is not healthy");
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
