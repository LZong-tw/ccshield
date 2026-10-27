import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { compileImageWorker, IMAGE_WORKER_SOURCE } from "../shield-image/compile.mjs";
import { createImageInspector } from "../shield-image/inspector.mjs";
import { checkImageReadiness, READINESS_FIXTURE } from "../shield-image/readiness.mjs";
import { decodePng } from "../shield-image/png.mjs";
import { createImageWorker } from "../shield-image/worker.mjs";
import { createGitleaksScanner, GITLEAKS_COMMAND_PROFILE } from "../src/shield/gitleaks.mjs";
import { createPrivacyFilter } from "../src/shield/privacy.mjs";

// Real Vision, real Gitleaks, the regex privacy worker. Opt-in: it compiles
// Swift and spends ~30 s on the first recognition.
const native = process.platform === "darwin" && process.env.CCSHIELD_NATIVE_IMAGE === "1";
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

test("native: the readiness fixture passes, and its email is masked end to end", { skip: !native && "set CCSHIELD_NATIVE_IMAGE=1 on macOS", timeout: 300_000 }, async (t) => {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "shield-image-native-")));
  t.after(() => rm(dir, { recursive: true, force: true }));

  await mkdir(join(dir, "bin"), { mode: 0o700 });
  const binary = await compileImageWorker({ sourcePath: IMAGE_WORKER_SOURCE, outDir: join(dir, "bin"), version: "image-0123456789ab" });
  const worker = createImageWorker({ path: binary, sha256: sha256(await readFile(binary)) });
  t.after(() => worker.close());

  const gitleaksPath = await realpath(execFileSync("/usr/bin/which", ["gitleaks"], { encoding: "utf8" }).trim());
  const rules = new URL("../detectors/gitleaks/gitleaks-rules.toml", import.meta.url).pathname;
  const gitleaks = await createGitleaksScanner({
    executable: gitleaksPath,
    sha256: sha256(await readFile(gitleaksPath)),
    ruleBundle: { path: rules, sha256: sha256(await readFile(rules)), version: "rules-1", commandProfile: GITLEAKS_COMMAND_PROFILE },
  });

  const workerDir = join(dir, "privacy");
  await mkdir(workerDir, { mode: 0o700 });
  const source = await readFile(new URL("../detectors/regex/privacy-worker.mjs", import.meta.url), "utf8");
  const regexWorker = join(workerDir, "privacy-worker.mjs");
  await writeFile(regexWorker, source.replace(/^#!.*/, `#!${await realpath(process.execPath)}`), { mode: 0o755 });
  await chmod(regexWorker, 0o755);
  const privacy = await createPrivacyFilter({ provision: { privacy: { version: "regex-v1", worker: { command: regexWorker, args: [], sha256: sha256(await readFile(regexWorker)) } } } });
  t.after(() => privacy.close());

  const started = Date.now();
  const readiness = await checkImageReadiness({ worker });
  assert.deepEqual(readiness, { ready: true }, `readiness after ${Date.now() - started} ms`);

  const inspector = createImageInspector({
    worker,
    scanSecrets: (body) => gitleaks.scan(body),
    scanPrivacy: (body) => privacy.scan(body, { version: "regex-v1" }),
    context: () => ({ policyVersion: "native", detectorVersions: { gitleaks: gitleaks.version, image: "image-0123456789ab", privacy: "regex-v1" } }),
    timeoutMs: 60_000,
  });
  const fixture = await readFile(READINESS_FIXTURE);
  const [result] = await inspector.inspect([{ bytes: fixture, lastTurn: true }]);
  assert.equal(result.status, "ok");
  assert.deepEqual(result.piiFindings, [{ label: "email", count: 1 }]);
  assert.ok(result.maskCount >= 1);
  const masked = decodePng(result.bytes);
  const original = decodePng(fixture);
  assert.deepEqual([masked.width, masked.height], [original.width, original.height]);
  const after = await worker.ocr(result.bytes);
  assert.equal(after.regions.some((region) => region.text.includes("@example.invalid")), false, "the masked image no longer reads as the email");
  assert.ok(after.regions.some((region) => region.text.includes("Customer")), "unmasked text survives");
});
