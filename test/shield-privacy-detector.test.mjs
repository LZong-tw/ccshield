import assert from "node:assert/strict";
import test from "node:test";

import { openPrivacyDetector } from "../src/shield/privacy-detector.mjs";

const policy = { detectorVersions: { gitleaks: "8.24.0", privacy: "privacy-1" }, detectorFallbacks: { privacy: "regex-v1" } };
const regexAssets = { version: "regex-v1", worker: { command: "/store/regex/regex-v1/privacy-worker.mjs", args: [], sha256: "a".repeat(64) } };
const opfAssets = { state: "verified", version: "privacy-1", worker: { command: "/store/opf/worker", args: ["--stdio"], sha256: "b".repeat(64) } };

function fakeFilter(version, log) {
  return {
    version,
    async scan(body) { log.push(`${version}:${body}`); return { status: "ok", findings: [] }; },
    isReady: async () => true,
    close() { log.push(`close:${version}`); },
  };
}

const lanePaths = Object.freeze({ lane: "subscription" });

function harness({ assets, stored = assets, probe = async () => {}, failures = [] } = {}) {
  const log = [];
  let now = 0;
  const state = { stored };
  const created = [];
  const lanes = [];
  const detector = openPrivacyDetector({
    paths: lanePaths,
    assets,
    policy,
    readAssets: async () => state.stored,
    createPrivacy: async ({ provision, paths }) => {
      created.push(provision.privacy.version);
      lanes.push(paths);
      return fakeFilter(provision.privacy.version, log);
    },
    probe,
    clock: () => now,
    recheckMs: 1000,
    onOpfFailure: (error) => failures.push(error.message),
  });
  return { detector, log, state, created, lanes, advance: (ms) => { now += ms; } };
}

test("the daemon starts on the regex fallback while OPF is absent", async () => {
  const { detector, created } = harness({ assets: { privacy: { state: "absent" }, regex: regexAssets } });
  const privacy = await detector;
  assert.deepEqual(created, ["regex-v1"]);
  assert.equal(privacy.detectorVersions().privacy, "regex-v1");
  assert.equal(privacy.detectorVersions().gitleaks, "8.24.0");
});

test("a verified OPF provision is used directly and regex is never started", async () => {
  const { detector, created } = harness({ assets: { privacy: opfAssets, regex: regexAssets } });
  const privacy = await detector;
  assert.deepEqual(created, ["privacy-1"]);
  assert.equal(privacy.detectorVersions().privacy, "privacy-1");
});

test("only the OPF filter is given the lane paths for its window cache", async () => {
  const opfFirst = harness({ assets: { privacy: opfAssets, regex: regexAssets } });
  await opfFirst.detector;
  assert.deepEqual(opfFirst.lanes, [lanePaths]);
  const regexOnly = harness({ assets: { privacy: { state: "absent" }, regex: regexAssets } });
  await regexOnly.detector;
  assert.deepEqual(regexOnly.lanes, [undefined]);
});

test("without a signed fallback naming the installed regex worker the daemon refuses to start", async () => {
  const absent = { state: "absent" };
  for (const [assets, fallbacks] of [
    [{ privacy: absent, regex: regexAssets }, undefined],
    [{ privacy: absent, regex: regexAssets }, { privacy: "regex-v2" }],
    [{ privacy: absent }, { privacy: "regex-v1" }],
  ]) {
    await assert.rejects(openPrivacyDetector({
      assets,
      policy: { ...policy, detectorFallbacks: fallbacks },
      readAssets: async () => assets,
      createPrivacy: async () => assert.fail("no detector may start"),
    }), /does not match policy metadata/);
  }
});

test("OPF swaps in mid-run after it is verified and passes the probe", async () => {
  const { detector, state, log, advance } = harness({ assets: { privacy: { state: "absent" }, regex: regexAssets } });
  const privacy = await detector;
  state.stored = { privacy: opfAssets, regex: regexAssets };

  assert.equal(privacy.refresh(), undefined, "rechecks are rate limited");
  advance(1000);
  await privacy.refresh();
  assert.equal(privacy.detectorVersions().privacy, "privacy-1");

  await privacy.scan("new");
  await privacy.scan("old", { version: "regex-v1" });
  assert.deepEqual(log, ["privacy-1:new", "regex-v1:old"], "requests keyed to regex finish on regex");
  await assert.rejects(privacy.scan("x", { version: "regex-v9" }), /unavailable/);

  await privacy.close();
  assert.deepEqual(log.slice(-2).sort(), ["close:privacy-1", "close:regex-v1"]);
});

test("a failed OPF probe keeps regex active and is not retried until the store changes", async () => {
  const failures = [];
  let probes = 0;
  const { detector, state, log, advance } = harness({
    assets: { privacy: { state: "absent" }, regex: regexAssets },
    probe: async () => { probes += 1; throw new Error("probe failed"); },
    failures,
  });
  const privacy = await detector;
  state.stored = { privacy: opfAssets, regex: regexAssets };

  advance(1000);
  await privacy.refresh();
  assert.equal(privacy.detectorVersions().privacy, "regex-v1");
  assert.deepEqual(failures, ["probe failed"]);
  assert.ok(log.includes("close:privacy-1"), "the rejected OPF worker is shut down");

  advance(1000);
  await privacy.refresh();
  assert.equal(probes, 1, "the same failed store state is not probed again");

  state.stored = { privacy: { ...opfAssets, worker: { ...opfAssets.worker, sha256: "c".repeat(64) } }, regex: regexAssets };
  advance(1000);
  await privacy.refresh();
  assert.equal(probes, 2);
});

test("OPF recorded for a different privacy version is never swapped in", async () => {
  const { detector, state, created, advance } = harness({ assets: { privacy: { state: "absent" }, regex: regexAssets } });
  const privacy = await detector;
  state.stored = { privacy: { ...opfAssets, version: "privacy-2" }, regex: regexAssets };
  advance(1000);
  await privacy.refresh();
  assert.deepEqual(created, ["regex-v1"]);
  assert.equal(privacy.detectorVersions().privacy, "regex-v1");
});

test("a recorded OPF that no longer opens starts the daemon on the signed regex fallback", async () => {
  const failures = [];
  const created = [];
  let stored = { privacy: opfAssets, regex: regexAssets };
  let now = 0;
  const privacy = await openPrivacyDetector({
    assets: stored,
    policy,
    readAssets: async () => stored,
    createPrivacy: async ({ provision }) => {
      created.push(provision.privacy.version);
      if (provision.privacy.version === "privacy-1") throw new Error("shield privacy worker validation failed");
      return fakeFilter(provision.privacy.version, []);
    },
    probe: async () => {},
    clock: () => now,
    recheckMs: 1000,
    onOpfFailure: (error) => failures.push(error.message),
  });
  assert.equal(privacy.detectorVersions().privacy, "regex-v1");
  assert.deepEqual(failures, ["shield privacy worker validation failed"]);

  now += 1000;
  await privacy.refresh();
  assert.deepEqual(created, ["privacy-1", "regex-v1"], "the same broken record is not reopened");

  stored = { privacy: { ...opfAssets, worker: { ...opfAssets.worker, sha256: "c".repeat(64) } }, regex: regexAssets };
  now += 1000;
  await privacy.refresh();
  assert.deepEqual(created, ["privacy-1", "regex-v1", "privacy-1"], "a changed record is tried again");
});

test("a recorded OPF that no longer opens still refuses to start without a signed fallback", async () => {
  await assert.rejects(openPrivacyDetector({
    assets: { privacy: opfAssets, regex: regexAssets },
    policy: { ...policy, detectorFallbacks: undefined },
    readAssets: async () => null,
    createPrivacy: async () => { throw new Error("shield privacy worker validation failed"); },
  }), /worker validation failed/);
});
