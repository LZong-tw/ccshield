import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";

// Byte-identical with the upstream adapter; any edit must be a deliberate re-pin.
const ADAPTER_SHA256 = "92e1f5e883f142fa7acca25fa8afeaca5bbe27dcf95b695a86bdb26695c2b980";

test("OPF adapter bytes match the pinned hash", async () => {
  const bytes = await readFile(resolve(import.meta.dirname, "../detectors/opf/opf-adapter.mjs"));
  assert.equal(createHash("sha256").update(bytes).digest("hex"), ADAPTER_SHA256);
});
