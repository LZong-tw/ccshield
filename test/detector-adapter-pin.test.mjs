import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";

// Byte-identical with the upstream adapter; any edit must be a deliberate re-pin.
const ADAPTER_SHA256 = "8714c7024df5a44c0676ae5562a5ce1111d6b535e79b1a0b4e6d41f2da7ff4be";

test("OPF adapter bytes match the pinned hash", async () => {
  const bytes = await readFile(resolve(import.meta.dirname, "../detectors/opf/opf-adapter.mjs"));
  assert.equal(createHash("sha256").update(bytes).digest("hex"), ADAPTER_SHA256);
});

// The worker refuses helpers whose bytes differ from its HELPERS table.
test("OPF helper bytes match the digests pinned in the worker", async () => {
  const opf = resolve(import.meta.dirname, "../detectors/opf");
  const worker = await readFile(resolve(opf, "privacy-opf-worker.mjs"), "utf8");
  const table = worker.match(/const HELPERS = \{([^}]*)\}/)?.[1];
  assert.ok(table, "HELPERS table not found in the worker");
  const pinned = Object.fromEntries([...table.matchAll(/"([\w.-]+\.py)": "([a-f0-9]{64})"/g)].map((m) => [m[1], m[2]]));
  assert.deepEqual(Object.keys(pinned).sort(), ["opf-cpu-grouped.py", "opf-mmap-weights.py", "opf-viterbi-deadline.py", "opf-window-cache.py"]);
  for (const [name, digest] of Object.entries(pinned)) {
    const bytes = await readFile(resolve(opf, "python", name));
    assert.equal(createHash("sha256").update(bytes).digest("hex"), digest, name);
  }
});
