import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { OPF_MAX_SCAN_TIMEOUT_MS, OPF_SCAN_TIMEOUT_MS } from "../src/shield/opf-args.mjs";

test("pinned OPF worker scan-timeout cap matches OPF_MAX_SCAN_TIMEOUT_MS", () => {
  const source = readFileSync(new URL("../detectors/opf/privacy-opf-worker.mjs", import.meta.url), "utf8");
  const match = source.match(/"--scan-timeout-ms" \? ([\d_]+) :/);
  assert.ok(match, "worker scan-timeout cap not found");
  assert.equal(Number(match[1].replaceAll("_", "")), OPF_MAX_SCAN_TIMEOUT_MS);
  assert.equal(Math.max(...OPF_SCAN_TIMEOUT_MS), OPF_MAX_SCAN_TIMEOUT_MS);
});
