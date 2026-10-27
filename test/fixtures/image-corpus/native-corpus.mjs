// SPDX-License-Identifier: MPL-2.0
// The synthetic corpus for the native image tests and the eval script. Images
// are rendered at test time by render.swift; byte-level edge cases are built here.
import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const RENDERER = fileURLToPath(new URL("./render.swift", import.meta.url));

// expect: pii = labels the scan must report; gone = text the masked image must
// no longer read; kept = text that must survive; secret / rejected = outcome.
// knownMiss marks a case the pipeline currently gets wrong (see the report).
export const CORPUS = Object.freeze([
  { file: "english.png", pii: ["email"], gone: ["bob.lee@example.com"], kept: ["Contact the owner"] },
  { file: "chinese.png", pii: ["email"], gone: ["mei.chen@example.org"], kept: ["請於週五前回覆"] },
  { file: "rotated.png", pii: ["email"], gone: ["bob.lee@example.com"], kept: ["before Friday"] },
  { file: "exif.jpg", pii: ["email"], gone: ["bob.lee@example.com"], kept: ["Contact the owner"] },
  { file: "alpha.png", pii: ["email"], gone: ["bob.lee@example.com"], kept: ["Contact the owner"] },
  { file: "dark.png", pii: ["email"], gone: ["bob.lee@example.com"], kept: ["Contact the owner"] },
  { file: "ui-12.png", pii: ["email"], gone: ["ann.wu@example.net"], kept: ["Settings"] },
  { file: "ui-11.png", pii: ["email"], gone: ["ann.wu@example.net"], kept: ["Settings"], knownMiss: "Vision reads `ann.wu@ example.net` with a space at 11 px, so no email detector matches" },
  { file: "card.png", pii: ["credit-card"], gone: ["4242 4242 4242 4242"], kept: ["Payment method on file"] },
  { file: "secret.png", secret: true },
  { file: "clean.png", pii: [], gone: [], kept: ["Quarterly roadmap"] },
  { file: "empty.png", pii: [], gone: [], kept: [] },
  { file: "animated.gif", rejected: true },
  { file: "animated.png", rejected: true },
  { file: "animated.webp", rejected: true },
  { file: "corrupt.png", rejected: true },
  { file: "oversized.png", rejected: true },
]);

export async function renderCorpus(dir, { xcrun = "xcrun" } = {}) {
  await mkdir(join(dir, "module-cache"), { recursive: true, mode: 0o700 });
  const renderer = join(dir, "render");
  await run(xcrun, ["swiftc", "-O", "-module-cache-path", join(dir, "module-cache"), RENDERER, "-o", renderer]);
  await run(renderer, [dir]);
  const english = await readFile(join(dir, "english.png"));
  await writeFile(join(dir, "corrupt.png"), english.subarray(0, Math.floor(english.length / 2)));
  await writeFile(join(dir, "oversized.png"), declaredPng(20_000, 20_000));
  await writeFile(join(dir, "animated.webp"), animatedWebp());
  return dir;
}

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code) => (code === 0 ? resolve() : reject(new Error(`${command} exited ${code}: ${stderr.slice(-400)}`))));
  });
}

// A PNG signature and IHDR declaring a size far past maxPixels; no pixel data.
function declaredPng(width, height) {
  const ihdr = Buffer.alloc(25);
  ihdr.writeUInt32BE(13, 0);
  ihdr.write("IHDR", 4, "latin1");
  ihdr.writeUInt32BE(width, 8);
  ihdr.writeUInt32BE(height, 12);
  ihdr.set([8, 6, 0, 0, 0], 16);
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), ihdr]);
}

// RIFF/WEBP with VP8X's animation flag and two ANMF frames.
function animatedWebp() {
  const chunk = (tag, body) => {
    const head = Buffer.alloc(8);
    head.write(tag, 0, "latin1");
    head.writeUInt32LE(body.length, 4);
    return Buffer.concat([head, body, body.length % 2 ? Buffer.alloc(1) : Buffer.alloc(0)]);
  };
  const u24 = (value) => Buffer.from([value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff]);
  const vp8x = Buffer.concat([Buffer.from([0x02, 0, 0, 0]), u24(15), u24(15)]);
  const anim = Buffer.from([0, 0, 0, 0, 0, 0]);
  const frame = Buffer.concat([u24(0), u24(0), u24(15), u24(15), u24(100), Buffer.from([0])]);
  const body = Buffer.concat([Buffer.from("WEBP"), chunk("VP8X", vp8x), chunk("ANIM", anim), chunk("ANMF", frame), chunk("ANMF", frame)]);
  const riff = Buffer.alloc(8);
  riff.write("RIFF", 0, "latin1");
  riff.writeUInt32LE(body.length, 4);
  return Buffer.concat([riff, body]);
}

export function pngChunkTypes(bytes) {
  const types = [];
  for (let offset = 8; offset + 8 <= bytes.length;) {
    const length = bytes.readUInt32BE(offset);
    types.push(bytes.toString("latin1", offset + 4, offset + 8));
    offset += 12 + length;
  }
  return types;
}

// A real worker, real Gitleaks and a privacy filter, all under `dir`. The regex
// worker is used unless a privacy provision (e.g. OPF) is passed in.
export async function openNativeHarness(dir, { privacyProvision } = {}) {
  const { createHash } = await import("node:crypto");
  const { execFileSync } = await import("node:child_process");
  const { chmod, realpath } = await import("node:fs/promises");
  const { compileImageWorker, IMAGE_WORKER_SOURCE } = await import("../../../shield-image/compile.mjs");
  const { createImageWorker } = await import("../../../shield-image/worker.mjs");
  const { createGitleaksScanner, GITLEAKS_COMMAND_PROFILE } = await import("../../../src/shield/gitleaks.mjs");
  const { createPrivacyFilter } = await import("../../../src/shield/privacy.mjs");
  const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

  await mkdir(join(dir, "bin"), { recursive: true, mode: 0o700 });
  const binary = await compileImageWorker({ sourcePath: IMAGE_WORKER_SOURCE, outDir: join(dir, "bin"), version: "image-0123456789ab" });
  const worker = createImageWorker({ path: binary, sha256: sha256(await readFile(binary)), probeTimeoutMs: 120_000, timeoutMs: 60_000 });

  const gitleaksPath = await realpath(execFileSync("/usr/bin/which", ["gitleaks"], { encoding: "utf8" }).trim());
  const rules = fileURLToPath(new URL("../../../detectors/gitleaks/gitleaks-rules.toml", import.meta.url));
  const gitleaks = await createGitleaksScanner({
    executable: gitleaksPath,
    sha256: sha256(await readFile(gitleaksPath)),
    ruleBundle: { path: rules, sha256: sha256(await readFile(rules)), version: "rules-1", commandProfile: GITLEAKS_COMMAND_PROFILE },
  });

  let provision = privacyProvision;
  if (!provision) {
    await mkdir(join(dir, "privacy"), { recursive: true, mode: 0o700 });
    const command = join(dir, "privacy", "privacy-worker.mjs");
    const source = await readFile(new URL("../../../detectors/regex/privacy-worker.mjs", import.meta.url), "utf8");
    await writeFile(command, source.replace(/^#!.*/, `#!${await realpath(process.execPath)}`), { mode: 0o755 });
    await chmod(command, 0o755);
    provision = { version: "regex-v1", worker: { command, args: [], sha256: sha256(await readFile(command)) } };
  }
  const privacy = await createPrivacyFilter({ provision: { privacy: provision } });
  const versions = { gitleaks: gitleaks.version, image: "image-0123456789ab", privacy: provision.version };
  return {
    worker,
    versions,
    scanSecrets: (body) => gitleaks.scan(body),
    scanPrivacy: (body) => privacy.scan(body, { version: provision.version }),
    context: () => ({ policyVersion: "native", detectorVersions: { ...versions } }),
    close() { worker.close(); privacy.close(); },
  };
}

// True when no OCR region reads the text, with or without spaces.
export function reads(regions, text) {
  const squash = (value) => value.replace(/\s+/g, "");
  return regions.some((region) => region.text.includes(text) || squash(region.text).includes(squash(text)));
}
