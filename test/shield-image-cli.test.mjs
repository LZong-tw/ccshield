import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { runShieldCli } from "../src/shield/cli.mjs";
import { IMAGE_WORKER_SOURCE } from "../shield-image/compile.mjs";

const CLI_PATH = fileURLToPath(new URL("../src/cli.mjs", import.meta.url));

function capture() {
  let value = "";
  return { stdout: { write(chunk) { value += String(chunk); } }, value: () => value };
}

function fakeShield() {
  const seen = [];
  return { seen, shield: { async imageProvision(options) {
    seen.push(options);
    return { state: options.write ? "degraded" : "preview", write: options.write, action: options.write ? "installed" : "preview",
      version: "image-0123456789ab", path: "/private/secret/image-worker", note: "binary digest changed, source unchanged" };
  } } };
}

test("image provision previews by default, hides paths and reports the version", async () => {
  const { seen, shield } = fakeShield();
  const output = capture();
  assert.equal(await runShieldCli(["image", "provision"], { stdout: output.stdout, shield }), 0);
  assert.deepEqual(seen, [{ lane: "subscription", write: false }]);
  assert.match(output.value(), /state: preview/);
  assert.match(output.value(), /version: image-0123456789ab/);
  assert.match(output.value(), /note: binary digest changed, source unchanged/);
  assert.doesNotMatch(output.value(), /\/private\/secret/);
});

test("image provision passes --image-source, --lane and --write through", async () => {
  const { seen, shield } = fakeShield();
  assert.equal(await runShieldCli(["image", "provision", "--image-source", "/abs/w.swift", "--lane", "managed", "--write"], { stdout: capture().stdout, shield }), 1);
  assert.deepEqual(seen, [{ sourcePath: "/abs/w.swift", lane: "managed", write: true }]);
});

test("image provision rejects bad arguments before doing anything", async () => {
  const { seen, shield } = fakeShield();
  for (const argv of [["image"], ["image", "status"], ["image", "provision", "--image-source"], ["image", "provision", "--image-source", "relative.swift"],
    ["image", "provision", "--image-source", "/a", "--image-source", "/b"], ["image", "provision", "--lane", "other"], ["image", "provision", "--bogus"],
    ["image", "provision", "--write", "--write"]]) {
    await assert.rejects(runShieldCli(argv, { stdout: capture().stdout, shield }), /usage: ccshield image provision/, JSON.stringify(argv));
  }
  assert.equal(seen.length, 0);
});

test("manual preview in a temporary HOME writes nothing", async (t) => {
  const home = await realpath(await mkdtemp(join(tmpdir(), "ccshield-image-cli-")));
  t.after(() => rm(home, { recursive: true, force: true }));
  const source = join(home, "w.swift");
  await writeFile(source, "// source\n");
  for (const argv of [["image", "provision"], ["image", "provision", "--image-source", source]]) {
    const result = spawnSync(process.execPath, [CLI_PATH, ...argv], { encoding: "utf8", env: { PATH: process.env.PATH, HOME: home } });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /state: preview/);
    assert.match(result.stdout, /version: image-[0-9a-f]{12}/);
    assert.match(result.stdout, /upToDate: false/);
    assert.doesNotMatch(result.stdout, new RegExp(home));
  }
  assert.deepEqual((await readdir(home)).sort(), ["w.swift"]);
  assert.ok(IMAGE_WORKER_SOURCE.endsWith("image-worker.swift"));
});
