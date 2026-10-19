import { execFile } from "node:child_process";
import { chmod, lstat, mkdir, readdir, rename, rm } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { verifyShieldCheckpoint } from "./checkpoint.mjs";
import { commitStaged, downloadVerified, opfDownloadPlan, sha256File } from "./opf-fetch.mjs";

const run = promisify(execFile);

// Codeload tarballs wrap the repository in a `<repo>-<commit>/` directory;
// stripping it keeps the layout independent of that name.
export async function extractTarball(archive, destination) {
  await run("tar", ["-xzf", archive, "-C", destination, "--strip-components=1"], {
    env: { ...process.env, COPYFILE_DISABLE: "1" },
  });
}

// Downloads the pinned OPF code, checkpoint and tokenizer into staging,
// verifies every authoritative digest there, then hands the assembled bundle
// to the store with one rename. Nothing lands outside staging unless all of
// it verified.
export async function fetchOpfBundle({ pins, store, platform, fetchImpl = fetch, extract = extractTarball, onProgress } = {}) {
  if (!platform?.supported) {
    throw new Error(`shield OPF is unsupported on this platform: ${platform?.reason ?? "unknown platform"}`);
  }
  const commit = pins.code.commit;
  const revision = pins.checkpoint.revision;
  const bundle = store.opfBundle(commit, revision);
  if (await exists(bundle.dir)) throw new Error(`shield OPF bundle is already installed at ${bundle.dir}`);

  const downloads = new Map();
  for (const item of opfDownloadPlan(pins)) {
    downloads.set(item.name, await downloadVerified(item, { stagingDir: store.stagingDir, fetchImpl, onProgress }));
  }

  const warnings = [];
  const tarball = downloads.get("source.tar.gz");
  const tarballSha256 = await sha256File(tarball);
  if (tarballSha256 !== pins.code.tarball.sha256) {
    warnings.push(Object.freeze({
      code: "advisory-tarball-digest",
      message: `shield OPF source tarball digest differs from the advisory pin (${tarballSha256}); the extracted tree digest is authoritative`,
    }));
  }

  const staged = join(store.stagingDir, `bundle-${commit}-${revision}`);
  await rm(staged, { recursive: true, force: true });
  const extracted = join(staged, "extract");
  await mkdir(extracted, { recursive: true, mode: 0o700 });
  await extract(tarball, extracted);
  const stagedSource = join(staged, "src");
  await mkdir(stagedSource, { mode: 0o700 });
  await rename(join(extracted, "opf"), join(stagedSource, "opf"));
  await rm(extracted, { recursive: true, force: true });
  // Archive modes survive extraction; the tree digest ignores modes but the
  // verifier rejects group/other-writable entries.
  await dropGroupOtherWrite(join(stagedSource, "opf"));
  await verifyShieldCheckpoint({ path: join(stagedSource, "opf"), sha256: pins.code.treeSha256, version: commit }, { label: "OPF source" });

  // The checkpoint is verified where it was downloaded so a failure leaves the
  // files in place as the resume cache for the next attempt.
  const downloadedCheckpoint = join(store.stagingDir, "original");
  await verifyShieldCheckpoint({ path: downloadedCheckpoint, sha256: pins.checkpoint.treeSha256, version: revision }, { label: "OPF checkpoint" });

  await mkdir(join(staged, "checkpoint"), { mode: 0o700 });
  await mkdir(join(staged, "tokenizer"), { mode: 0o700 });
  await rename(downloadedCheckpoint, join(staged, "checkpoint", "original"));
  await rename(downloads.get(pins.tokenizer.cacheName), join(staged, "tokenizer", pins.tokenizer.cacheName));
  await commitStaged(staged, bundle.dir);

  return Object.freeze({
    dir: bundle.dir,
    venv: bundle.venv,
    source: Object.freeze({ path: join(bundle.src, "opf"), sha256: pins.code.treeSha256, version: commit }),
    checkpoint: Object.freeze({ path: join(bundle.checkpoint, "original"), sha256: pins.checkpoint.treeSha256, version: revision }),
    tokenizer: Object.freeze({ path: join(bundle.tokenizer, pins.tokenizer.cacheName), sha256: pins.tokenizer.sha256, encoding: pins.tokenizer.encoding }),
    tarball: Object.freeze({ sha256: tarballSha256, advisory: true, matched: tarballSha256 === pins.code.tarball.sha256 }),
    warnings: Object.freeze(warnings),
  });
}

async function exists(path) {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

async function dropGroupOtherWrite(path) {
  const entry = await lstat(path);
  if (entry.isSymbolicLink()) throw new Error("shield OPF source archive contains a symbolic link");
  if ((entry.mode & 0o022) !== 0) await chmod(path, entry.mode & 0o755);
  if (entry.isDirectory()) {
    for (const name of await readdir(path)) await dropGroupOtherWrite(join(path, name));
  }
}
