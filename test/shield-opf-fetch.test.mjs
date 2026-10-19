import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { downloadVerified, gitleaksDownloadPlan, loadPins, opfDownloadPlan } from "../src/shield/opf-fetch.mjs";

const payload = Buffer.from("x".repeat(64 * 1024) + "pinned asset");
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function withServer(handler, body) {
  const server = createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    return await body(`http://127.0.0.1:${server.address().port}`);
  } finally {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  }
}

function rangeHandler({ truncateFirst = false, requests = [] } = {}) {
  return (request, response) => {
    requests.push(request.headers.range ?? null);
    const match = /^bytes=(\d+)-$/.exec(request.headers.range ?? "");
    const start = match ? Number(match[1]) : 0;
    const body = payload.subarray(start);
    response.writeHead(match ? 206 : 200, { "content-length": body.length });
    if (truncateFirst && requests.length === 1) {
      response.write(body.subarray(0, 1000), () => setTimeout(() => response.destroy(), 50));
      return;
    }
    response.end(body);
  };
}

async function tempDir() {
  return mkdtemp(join(tmpdir(), "ccshield-fetch-"));
}

test("a verified download lands in staging under its name", async () => {
  const root = await tempDir();
  try {
    await withServer(rangeHandler(), async (base) => {
      const path = await downloadVerified({ name: "a.bin", url: `${base}/a`, sha256: sha256(payload), size: payload.length }, { stagingDir: join(root, "staging") });
      assert.deepEqual(await readFile(path), payload);
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a bad digest leaves nothing outside staging and no partial file", async () => {
  const root = await tempDir();
  try {
    await withServer(rangeHandler(), async (base) => {
      await assert.rejects(
        downloadVerified({ name: "a.bin", url: `${base}/a`, sha256: "0".repeat(64), size: payload.length }, { stagingDir: join(root, "staging") }),
        /digest verification/,
      );
    });
    assert.deepEqual(await readdir(root), ["staging"]);
    assert.deepEqual(await readdir(join(root, "staging")), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a truncated download resumes with a range request", async () => {
  const root = await tempDir();
  const requests = [];
  try {
    await withServer(rangeHandler({ truncateFirst: true, requests }), async (base) => {
      const item = { name: "a.bin", url: `${base}/a`, sha256: sha256(payload), size: payload.length };
      const options = { stagingDir: join(root, "staging") };
      await assert.rejects(downloadVerified(item, options));
      const path = await downloadVerified(item, options);
      assert.deepEqual(await readFile(path), payload);
    });
    assert.equal(requests[0], null);
    assert.match(requests[1], /^bytes=[1-9]\d*-$/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("an oversize partial file is discarded instead of resumed", async () => {
  const root = await tempDir();
  try {
    const stagingDir = join(root, "staging");
    await withServer(rangeHandler(), async (base) => {
      const item = { name: "a.bin", url: `${base}/a`, sha256: sha256(payload), size: payload.length };
      await downloadVerified(item, { stagingDir }).then((path) => rm(path));
      await writeFile(join(stagingDir, "a.bin.part"), Buffer.alloc(payload.length + 10));
      assert.deepEqual(await readFile(await downloadVerified(item, { stagingDir })), payload);
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("plans come from pins.json without duplicated digests", async () => {
  const pins = await loadPins();
  const plan = opfDownloadPlan(pins);
  assert.equal(plan[0].sha256, pins.code.tarball.sha256);
  assert.equal(plan[0].advisory, true);
  const weights = plan.find((item) => item.name === "original/model.safetensors");
  assert.equal(weights.sha256, pins.checkpoint.files["original/model.safetensors"].sha256);
  assert.ok(weights.url.includes(`/resolve/${pins.checkpoint.revision}/`));
  assert.equal(plan.at(-1).sha256, pins.tokenizer.sha256);
  for (const key of ["darwin-arm64", "linux-x64", "linux-arm64"]) {
    const item = gitleaksDownloadPlan(pins, key);
    assert.equal(item.sha256, pins.gitleaks.archives[key].sha256);
    assert.ok(item.url.endsWith(`/v${pins.gitleaks.version}/${pins.gitleaks.archives[key].name}`));
  }
  assert.throws(() => gitleaksDownloadPlan(pins, "win32-x64"), /no Gitleaks pin/);
});
