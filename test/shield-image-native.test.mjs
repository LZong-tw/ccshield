import assert from "node:assert/strict";
import { mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";

import { createImageInspector } from "../shield-image/inspector.mjs";
import { decodePng } from "../shield-image/png.mjs";
import { checkImageReadiness, READINESS_FIXTURE } from "../shield-image/readiness.mjs";
import { extractMedia, patchImages } from "../src/shield/media.mjs";
import { CORPUS, openNativeHarness, pngChunkTypes, reads, renderCorpus } from "./fixtures/image-corpus/native-corpus.mjs";

// Real Vision, real Gitleaks, the regex privacy worker, on a synthetic corpus.
// Opt-in: it compiles Swift and can spend ~30 s on the first recognition.
const native = process.platform === "darwin" && process.env.CCSHIELD_NATIVE_IMAGE === "1";

describe("native image pipeline", { skip: !native && "set CCSHIELD_NATIVE_IMAGE=1 on macOS", timeout: 600_000 }, () => {
  let dir;
  let harness;
  const inspector = () => createImageInspector({ ...harness, timeoutMs: 60_000 });

  before(async () => {
    dir = await realpath(await mkdtemp(join(tmpdir(), "shield-image-native-")));
    await renderCorpus(join(dir, "corpus"));
    harness = await openNativeHarness(dir);
  });
  after(async () => {
    harness?.close();
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  test("the pinned readiness fixture passes", async () => {
    assert.deepEqual(await checkImageReadiness({ worker: harness.worker }), { ready: true });
  });

  for (const entry of CORPUS) {
    test(`corpus: ${entry.file}`, { todo: entry.knownMiss }, async () => {
      const bytes = await readFile(join(dir, "corpus", entry.file));
      if (entry.rejected) {
        await assert.rejects(inspector().inspect([{ bytes, lastTurn: true }]), { code: "image_rejected" });
        return;
      }
      const [result] = await inspector().inspect([{ bytes, lastTurn: true }]);
      if (entry.secret) {
        assert.deepEqual(result, { status: "secret", confirmedSecret: true });
        return;
      }
      assert.equal(result.status, "ok");
      assert.deepEqual(result.piiFindings.map((finding) => finding.label).sort(), [...entry.pii].sort());
      const page = await harness.worker.ocr(result.bytes);
      for (const text of entry.gone) assert.equal(reads(page.regions, text), false, `still reads ${text}`);
      for (const text of entry.kept) assert.ok(reads(page.regions, text), `lost ${text}`);
    });
  }

  test("an allowed clean image is normalized to a PNG with no metadata chunks", async () => {
    const [result] = await inspector().inspect([{ bytes: await readFile(join(dir, "corpus", "exif.jpg")), lastTurn: true }]);
    assert.deepEqual([...new Set(pngChunkTypes(result.bytes))], ["IHDR", "IDAT", "IEND"]);
    const { width, height } = decodePng(result.bytes);
    assert.deepEqual([width, height], [640, 200], "EXIF orientation is applied, then dropped");
  });

  test("an image inside a tool_result is masked and spliced back byte for byte", async () => {
    const png = await readFile(join(dir, "corpus", "english.png"));
    const image = { type: "image", source: { type: "base64", media_type: "image/png", data: png.toString("base64") } };
    const body = Buffer.from(JSON.stringify({ model: "m", messages: [{ role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: [image] }] }] }));
    const media = extractMedia(body);
    assert.equal(media.images.length, 1);
    const [result] = await inspector().inspect(media.images.map(({ bytes, lastTurn }) => ({ bytes, lastTurn })));
    const spliced = patchImages(body, [{ image: media.images[0], bytes: result.bytes }]);
    const again = extractMedia(spliced);
    assert.ok(again.images[0].bytes.equals(result.bytes), "the bytes that leave are the bytes that were scanned");
    assert.equal(reads((await harness.worker.ocr(again.images[0].bytes)).regions, "bob.lee@example.com"), false);
  });

  test("the readiness fixture's email is masked end to end", async () => {
    const [result] = await inspector().inspect([{ bytes: await readFile(READINESS_FIXTURE), lastTurn: true }]);
    assert.deepEqual(result.piiFindings, [{ label: "email", count: 1 }]);
    const page = await harness.worker.ocr(result.bytes);
    assert.equal(reads(page.regions, "@example.invalid"), false);
    assert.ok(reads(page.regions, "Customer"));
  });
});
