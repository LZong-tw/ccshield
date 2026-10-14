import { constants } from "node:fs";
import { createHash } from "node:crypto";
import { lstat, open, readdir, realpath } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";

const MAX_FILES = 10_000;

export async function attestShieldCheckpoint(checkpoint, options = {}) {
  const before = await snapshotTree(checkpoint.path);
  await verifyShieldCheckpoint(checkpoint, options);
  const after = await snapshotTree(checkpoint.path);
  if (before !== after) throw new Error("shield privacy checkpoint changed during validation");
  return async () => {
    if (await snapshotTree(checkpoint.path) !== after) throw new Error("shield privacy checkpoint metadata changed");
  };
}

export async function verifyShieldCheckpoint(checkpoint, { label = "checkpoint" } = {}) {
  if (!checkpoint || typeof checkpoint !== "object" || Array.isArray(checkpoint)
    || Object.keys(checkpoint).sort().join(",") !== "path,sha256,version"
    || typeof checkpoint.path !== "string" || !isAbsolute(checkpoint.path) || resolve(checkpoint.path) !== checkpoint.path
    || !/^[a-f0-9]{64}$/.test(checkpoint.sha256 ?? "")
    || typeof checkpoint.version !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(checkpoint.version)) {
    throw new Error(`shield privacy ${label} reference is invalid`);
  }

  try {
    const files = [];
    await collect(checkpoint.path, "", files);
    if (files.length === 0) throw new Error("empty checkpoint");
    files.sort((left, right) => Buffer.compare(Buffer.from(left.relative), Buffer.from(right.relative)));
    const hash = createHash("sha256");
    for (const file of files) {
      const handle = await open(file.absolute, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const entry = await handle.stat();
        assertOwned(entry, "file");
        hash.update(file.relative, "utf8").update("\0").update(String(entry.size)).update("\0");
        let bytesRead = 0;
        for await (const chunk of handle.createReadStream({ autoClose: false })) {
          bytesRead += chunk.byteLength;
          hash.update(chunk);
        }
        if (bytesRead !== entry.size) throw new Error("checkpoint changed during read");
        hash.update("\0");
      } finally {
        await handle.close();
      }
    }
    if (hash.digest("hex") !== checkpoint.sha256) throw new Error("checkpoint digest mismatch");
  } catch {
    throw new Error(`shield privacy ${label} validation failed`);
  }
  return Object.freeze({ path: checkpoint.path, sha256: checkpoint.sha256, version: checkpoint.version });
}

async function collect(directory, relativeDir, files) {
  const entry = await lstat(directory);
  assertOwned(entry, "directory");
  if (await realpath(directory) !== directory) throw new Error("checkpoint path is not canonical");
  for (const name of await readdir(directory)) {
    const absolute = join(directory, name);
    const relative = relativeDir ? `${relativeDir}/${name}` : name;
    const child = await lstat(absolute);
    if (child.isDirectory()) {
      await collect(absolute, relative, files);
    } else {
      assertOwned(child, "file");
      if (await realpath(absolute) !== absolute) throw new Error("checkpoint path is not canonical");
      files.push({ absolute, relative });
      if (files.length > MAX_FILES) throw new Error("checkpoint has too many files");
    }
  }
}

function assertOwned(entry, kind) {
  const mode = Number(entry.mode);
  const uid = Number(entry.uid);
  if ((kind === "directory" ? !entry.isDirectory() : !entry.isFile()) || entry.isSymbolicLink()
    || (mode & 0o022) !== 0
    || (typeof process.getuid === "function" && uid !== process.getuid())) {
    throw new Error("checkpoint asset is unsafe");
  }
}

async function snapshotTree(root) {
  const entries = [];
  async function visit(path, relative) {
    const entry = await lstat(path, { bigint: true });
    assertOwned(entry, entry.isDirectory() ? "directory" : "file");
    if (await realpath(path) !== path) throw new Error("checkpoint path is not canonical");
    entries.push([relative, entry.isDirectory() ? "d" : "f", entry.dev, entry.ino,
      entry.uid, entry.mode, entry.size, entry.mtimeNs, entry.ctimeNs].join("\0"));
    if (entries.length > MAX_FILES + 1) throw new Error("checkpoint has too many entries");
    if (entry.isDirectory()) {
      const names = await readdir(path);
      names.sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
      for (const name of names) await visit(join(path, name), relative ? `${relative}/${name}` : name);
    }
  }
  await visit(root, "");
  return entries.join("\n");
}
