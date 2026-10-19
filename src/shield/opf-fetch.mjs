import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, open, readFile, rename, rm, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Every digest comes from detectors/opf/pins.json; none is repeated here.
export const DEFAULT_PINS_PATH = fileURLToPath(new URL("../../detectors/opf/pins.json", import.meta.url));
const SHA256 = /^[a-f0-9]{64}$/;

export async function loadPins(path = DEFAULT_PINS_PATH) {
  const pins = JSON.parse(await readFile(path, "utf8"));
  if (pins?.formatVersion !== 1) throw new Error("shield OPF pins have an unsupported format");
  return pins;
}

// Plain, ordered list of what the OPF bundle needs. Gitleaks is planned
// separately because it has its own store directory.
export function opfDownloadPlan(pins) {
  const { code, checkpoint, tokenizer } = pins;
  const items = [{
    kind: "code", name: "source.tar.gz", url: code.tarball.url,
    sha256: code.tarball.sha256, size: code.tarball.size ?? null, advisory: code.tarball.advisory === true,
  }];
  for (const [file, pin] of Object.entries(checkpoint.files)) {
    items.push({
      kind: "checkpoint", name: file,
      url: `${checkpoint.repository}/resolve/${checkpoint.revision}/${file}`,
      sha256: pin.sha256, size: pin.size, advisory: false,
    });
  }
  items.push({ kind: "tokenizer", name: tokenizer.cacheName, url: tokenizer.url, sha256: tokenizer.sha256, size: tokenizer.size, advisory: false });
  for (const item of items) {
    if (!SHA256.test(item.sha256 ?? "")) throw new Error(`shield OPF pin for ${item.name} has no valid sha256`);
    if (item.name.split("/").some((part) => part === ".." || part === "")) throw new Error(`shield OPF pin name ${item.name} is unsafe`);
  }
  return items;
}

export function gitleaksDownloadPlan(pins, platformKey) {
  const { version, archives } = pins.gitleaks;
  const archive = archives?.[platformKey];
  if (!archive) throw new Error(`shield has no Gitleaks pin for ${platformKey}`);
  if (!SHA256.test(archive.sha256 ?? "")) throw new Error("shield Gitleaks pin has no valid sha256");
  // The name becomes a path under staging, so it must be one plain file name.
  if (typeof archive.name !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(archive.name)) {
    throw new Error(`shield Gitleaks pin name for ${platformKey} is unsafe`);
  }
  return {
    kind: "gitleaks", name: archive.name, version,
    url: archive.url ?? `https://github.com/gitleaks/gitleaks/releases/download/v${version}/${archive.name}`,
    sha256: archive.sha256, size: archive.size, advisory: false,
  };
}

// Downloads `item` into `stagingDir/<name>.part`, resuming with a Range
// request when a partial file exists, and returns the verified path
// `stagingDir/<name>`. A digest or size mismatch deletes the partial file and
// throws; nothing is ever written outside stagingDir.
export async function downloadVerified(item, { stagingDir, fetchImpl = fetch, onProgress } = {}) {
  const finalPath = join(stagingDir, item.name);
  const partPath = `${finalPath}.part`;
  await mkdir(dirname(finalPath), { recursive: true, mode: 0o700 });

  if (await fileMatches(finalPath, item)) return finalPath;

  let offset = await sizeOf(partPath);
  if (item.size != null && offset > item.size) {
    await rm(partPath, { force: true });
    offset = 0;
  }
  if (item.size == null || offset < item.size) {
    const headers = offset > 0 ? { range: `bytes=${offset}-` } : {};
    const response = await fetchImpl(item.url, { headers, redirect: "follow" });
    if (offset > 0 && response.status === 200) {
      // The server ignored the range; start over rather than append.
      offset = 0;
    } else if (offset > 0 && response.status !== 206) {
      throw new Error(`shield download of ${item.name} failed: HTTP ${response.status}`);
    } else if (offset === 0 && response.status !== 200) {
      throw new Error(`shield download of ${item.name} failed: HTTP ${response.status}`);
    }
    const handle = await open(partPath, offset === 0 ? "w" : "a", 0o600);
    let written = offset;
    try {
      for await (const chunk of response.body) {
        await handle.write(chunk);
        written += chunk.length;
        if (item.size != null && written > item.size) throw new Error(`shield download of ${item.name} exceeds the pinned size`);
        onProgress?.({ name: item.name, bytes: written, size: item.size });
      }
    } finally {
      await handle.close();
    }
  }

  const size = await sizeOf(partPath);
  if (item.size != null && size !== item.size) {
    // A short read stays as .part so the next attempt resumes it.
    throw new Error(`shield download of ${item.name} is incomplete (${size} of ${item.size} bytes)`);
  }
  // An advisory digest (the codeload tarball) is checked by the caller against
  // something authoritative, so a mismatch keeps the file instead of failing.
  const digest = await sha256File(partPath);
  if (digest !== item.sha256 && !item.advisory) {
    await rm(partPath, { force: true });
    throw new Error(`shield download of ${item.name} failed digest verification`);
  }
  await rename(partPath, finalPath);
  return finalPath;
}

// Atomic hand-over from staging into the store. The target must not already
// exist: a verified directory is never overwritten in place.
export async function commitStaged(stagedPath, targetPath) {
  await mkdir(dirname(targetPath), { recursive: true, mode: 0o700 });
  await rename(stagedPath, targetPath);
}

export async function sha256File(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

async function fileMatches(path, item) {
  const size = await sizeOf(path);
  if (size === 0 || (item.size != null && size !== item.size)) return false;
  return (await sha256File(path)) === item.sha256;
}

async function sizeOf(path) {
  try {
    return (await stat(path)).size;
  } catch (error) {
    if (error.code === "ENOENT") return 0;
    throw error;
  }
}
