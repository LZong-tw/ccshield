import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { PRIVACY_PROTOCOL } from "../src/shield/protocol.mjs";

// The workers are pinned and run standalone, so they cannot import the constant.
test("standalone privacy workers speak the daemon's protocol", async () => {
  for (const path of ["../detectors/opf/privacy-opf-worker.mjs", "../detectors/regex/privacy-worker.mjs"]) {
    const source = await readFile(new URL(path, import.meta.url), "utf8");
    assert.match(source, new RegExp(`^const PROTOCOL = "${PRIVACY_PROTOCOL}";$`, "m"), path);
  }
});
