import assert from "node:assert/strict";
import { test } from "node:test";
import { buildOpfWorkerArgs, isValidOpfWorkerArgs } from "../src/shield/opf-args.mjs";

const references = {
  checkpoint: { path: "/opt/ccshield/checkpoint", sha256: "a".repeat(64), version: "test-1" },
  source: { path: "/opt/ccshield/opf", sha256: "b".repeat(64) },
  adapter: { sha256: "c".repeat(64) },
  tokenizer: { path: "/opt/ccshield/tiktoken-cache/fb374d419588a4632f3f557e76b4b70aebbca790", sha256: "d".repeat(64) },
};
const args = buildOpfWorkerArgs({ ...references, python: "/opt/ccshield/python", scanTimeoutMs: 2_000 });

test("the OPF worker argv keeps its 22-argument wire order", () => {
  assert.deepEqual(args, [
    "--python", "/opt/ccshield/python", "--checkpoint", "/opt/ccshield/checkpoint",
    "--checkpoint-sha256", "a".repeat(64), "--checkpoint-version", "test-1",
    "--opf-source", "/opt/ccshield/opf", "--opf-source-sha256", "b".repeat(64),
    "--adapter-sha256", "c".repeat(64),
    "--tokenizer", references.tokenizer.path, "--tokenizer-sha256", "d".repeat(64),
    "--startup-timeout-ms", "30000", "--scan-timeout-ms", "2000",
  ]);
  assert.equal(isValidOpfWorkerArgs(args, references), true);
});

test("the OPF worker argv rejects anything the builder would not produce", () => {
  const replace = (index, value) => args.map((entry, at) => at === index ? value : entry);
  for (const bad of [
    replace(21, "3000"), replace(21, "02000"), replace(1, "python"), replace(1, "/opt//python"), replace(5, "f".repeat(64)),
    replace(19, "60000"), args.slice(0, 20), [...args, "--extra"], null,
  ]) assert.equal(isValidOpfWorkerArgs(bad, references), false, JSON.stringify(bad));
  assert.equal(isValidOpfWorkerArgs(args, { ...references, checkpoint: undefined }), false);
});
