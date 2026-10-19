import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readdir, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { fetchOpfBundle } from "../src/shield/opf-install.mjs";
import { classifyPlatform } from "../src/shield/platform.mjs";
import { shieldAssetStore, shieldPaths } from "../src/shield/paths.mjs";

const run = promisify(execFile);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const COMMIT = "a".repeat(40);
const REVISION = "b".repeat(40);
const supported = Object.freeze({ supported: true, key: "darwin-arm64" });

const sourceFiles = { "opf/__init__.py": "", "opf/model.py": "print('opf')\n", "opf/data/labels.json": "[]\n", "README.md": "not part of the tree\n" };
const checkpointFiles = { "config.json": "{\"n\":1}\n", "model.safetensors": "weights".repeat(1000) };
const tokenizerBytes = Buffer.from("tiktoken ranks\n");

// Same layout as checkpoint.mjs: sorted relative paths, then path\0size\0bytes\0.
function treeDigest(files) {
  const hash = createHash("sha256");
  for (const name of Object.keys(files).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))) {
    const bytes = Buffer.from(files[name]);
    hash.update(name).update("\0").update(String(bytes.length)).update("\0").update(bytes).update("\0");
  }
  return hash.digest("hex");
}

async function fixture() {
  const work = await realpath(await mkdtemp(join(tmpdir(), "ccshield-opf-install-")));
  const repo = join(work, `privacy-filter-${COMMIT}`);
  for (const [name, body] of Object.entries(sourceFiles)) {
    await mkdir(join(repo, name, ".."), { recursive: true });
    await writeFile(join(repo, name), body);
  }
  const tarball = join(work, "source.tar.gz");
  await run("tar", ["-czf", tarball, "-C", work, `privacy-filter-${COMMIT}`], { env: { ...process.env, COPYFILE_DISABLE: "1" } });
  const home = join(work, "home");
  await mkdir(home);
  const store = shieldAssetStore(shieldPaths({ homeDir: home, uid: 501 }));
  return { work, store, tarballBytes: await readFile(tarball) };
}

function routesFor(tarballBytes) {
  const routes = new Map([[`/code/${COMMIT}.tar.gz`, tarballBytes], ["/o200k_base.tiktoken", tokenizerBytes]]);
  for (const [name, body] of Object.entries(checkpointFiles)) routes.set(`/hf/resolve/${REVISION}/original/${name}`, Buffer.from(body));
  return routes;
}

function pinsFor(base, tarballBytes, overrides = {}) {
  const opfTree = Object.fromEntries(Object.entries(sourceFiles)
    .filter(([name]) => name.startsWith("opf/")).map(([name, body]) => [name.slice("opf/".length), body]));
  return {
    formatVersion: 1,
    code: {
      repository: `${base}/code`,
      commit: COMMIT,
      tarball: { url: `${base}/code/${COMMIT}.tar.gz`, sha256: overrides.tarballSha256 ?? sha256(tarballBytes), advisory: true },
      treeSha256: overrides.codeTreeSha256 ?? treeDigest(opfTree),
    },
    checkpoint: {
      repository: `${base}/hf`,
      revision: REVISION,
      treeSha256: overrides.checkpointTreeSha256 ?? treeDigest(checkpointFiles),
      files: Object.fromEntries(Object.entries(checkpointFiles)
        .map(([name, body]) => [`original/${name}`, { sha256: sha256(Buffer.from(body)), size: Buffer.byteLength(body) }])),
    },
    tokenizer: {
      encoding: "o200k_base",
      url: `${base}/o200k_base.tiktoken`,
      cacheName: "c".repeat(40),
      sha256: sha256(tokenizerBytes),
      size: tokenizerBytes.length,
    },
  };
}

async function withServer(routes, body) {
  const requests = [];
  const server = createServer((request, response) => {
    requests.push(request.url);
    const bytes = routes.get(request.url);
    if (!bytes) {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { "content-length": bytes.length }).end(bytes);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    return await body(`http://127.0.0.1:${server.address().port}`, requests);
  } finally {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  }
}

test("a verified bundle lands in the store with the worker's layout", async () => {
  const { work, store, tarballBytes } = await fixture();
  try {
    await withServer(routesFor(tarballBytes), async (base) => {
      const pins = pinsFor(base, tarballBytes);
      const result = await fetchOpfBundle({ pins, store, platform: supported });
      const bundle = store.opfBundle(COMMIT, REVISION);

      assert.ok(Object.isFrozen(result));
      assert.deepEqual(result.warnings, []);
      assert.deepEqual(result.source, { path: join(bundle.src, "opf"), sha256: pins.code.treeSha256, version: COMMIT });
      assert.deepEqual(result.checkpoint, { path: join(bundle.checkpoint, "original"), sha256: pins.checkpoint.treeSha256, version: REVISION });
      assert.equal(result.tokenizer.path, join(bundle.tokenizer, "c".repeat(40)));
      assert.equal(result.tokenizer.sha256, pins.tokenizer.sha256);
      assert.equal(result.venv, bundle.venv);

      assert.equal(await readFile(join(result.source.path, "model.py"), "utf8"), "print('opf')\n");
      assert.deepEqual((await readdir(result.checkpoint.path)).sort(), ["config.json", "model.safetensors"]);
      assert.deepEqual(await readFile(result.tokenizer.path), tokenizerBytes);
      assert.deepEqual((await readdir(bundle.dir)).sort(), ["checkpoint", "src", "tokenizer"]);
      await assert.rejects(stat(join(bundle.src, "README.md")), { code: "ENOENT" });
      assert.deepEqual(await readdir(store.stagingDir), ["source.tar.gz"]);

      await assert.rejects(fetchOpfBundle({ pins, store, platform: supported }), /already installed/);
    });
  } finally {
    await rm(work, { recursive: true, force: true });
  }
});

for (const [label, override] of [
  ["checkpoint", { checkpointTreeSha256: "0".repeat(64) }],
  ["source", { codeTreeSha256: "0".repeat(64) }],
]) {
  test(`a bad ${label} tree digest leaves nothing outside staging`, async () => {
    const { work, store, tarballBytes } = await fixture();
    try {
      await withServer(routesFor(tarballBytes), async (base) => {
        const pins = pinsFor(base, tarballBytes, override);
        await assert.rejects(fetchOpfBundle({ pins, store, platform: supported }), /^Error: shield privacy OPF .* validation failed$/);
        assert.deepEqual(await readdir(store.root), ["staging"]);
      });
    } finally {
      await rm(work, { recursive: true, force: true });
    }
  });
}

test("an unsupported platform fails before any download starts", async () => {
  const { work, store, tarballBytes } = await fixture();
  try {
    let calls = 0;
    const fetchImpl = async () => { calls += 1; throw new Error("unexpected fetch"); };
    const platform = classifyPlatform({ platform: "linux", arch: "ia32" });
    assert.equal(platform.supported, false);
    await assert.rejects(fetchOpfBundle({ pins: pinsFor("http://127.0.0.1:9", tarballBytes), store, platform, fetchImpl }), /unsupported/);
    assert.equal(calls, 0);
    await assert.rejects(stat(store.root), { code: "ENOENT" });
  } finally {
    await rm(work, { recursive: true, force: true });
  }
});

test("an advisory tarball digest mismatch only warns", async () => {
  const { work, store, tarballBytes } = await fixture();
  try {
    await withServer(routesFor(tarballBytes), async (base) => {
      const pins = pinsFor(base, tarballBytes, { tarballSha256: "0".repeat(64) });
      const result = await fetchOpfBundle({ pins, store, platform: supported });
      assert.equal(result.warnings.length, 1);
      assert.equal(result.warnings[0].code, "advisory-tarball-digest");
      assert.equal(result.tarball.sha256, sha256(tarballBytes));
      assert.equal(result.tarball.matched, false);
      assert.equal(await readFile(join(result.source.path, "model.py"), "utf8"), "print('opf')\n");
    });
  } finally {
    await rm(work, { recursive: true, force: true });
  }
});
