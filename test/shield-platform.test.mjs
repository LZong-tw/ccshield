import assert from "node:assert/strict";
import test from "node:test";

import { classifyPlatform, detectPlatform } from "../src/shield/platform.mjs";

test("supported platforms map to a pins.json archive key", () => {
  assert.deepEqual(classifyPlatform({ platform: "darwin", arch: "arm64", darwinRelease: "23.0.0" }), { supported: true, key: "darwin-arm64" });
  assert.deepEqual(classifyPlatform({ platform: "linux", arch: "x64", glibcVersion: "2.28" }), { supported: true, key: "linux-x64" });
  assert.deepEqual(classifyPlatform({ platform: "linux", arch: "arm64", glibcVersion: "2.35" }), { supported: true, key: "linux-arm64" });
});

test("everything else is unsupported with a reason", () => {
  for (const input of [
    { platform: "darwin", arch: "x64", darwinRelease: "23.0.0" },
    { platform: "darwin", arch: "arm64", darwinRelease: "22.6.0" },
    { platform: "linux", arch: "x64", glibcVersion: "2.27" },
    { platform: "linux", arch: "x64", glibcVersion: null },
    { platform: "linux", arch: "ia32", glibcVersion: "2.35" },
    { platform: "win32", arch: "x64" },
  ]) {
    const result = classifyPlatform(input);
    assert.equal(result.supported, false, JSON.stringify(input));
    assert.equal(result.key, null);
    assert.match(result.reason, /\S/);
  }
});

test("detectPlatform uses injected probes", async () => {
  assert.equal((await detectPlatform({ platform: "darwin", arch: "arm64", io: { release: () => "24.1.0" } })).key, "darwin-arm64");
  assert.equal((await detectPlatform({ platform: "linux", arch: "x64", io: { glibcVersion: async () => "2.17" } })).supported, false);
});
