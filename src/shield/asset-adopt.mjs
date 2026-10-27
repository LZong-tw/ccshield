import { createHash } from "node:crypto";
import { lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";

const defaultIo = { lstat, mkdir, open, readFile, rename, unlink };

// Files the daemon reads at boot (rule bundle, a user-supplied Gitleaks) used
// to be recorded at the path the user passed in. That path often lives inside
// a versioned package or a Homebrew Cellar directory, and an upgrade that
// removes it leaves the daemon failing its boot check. Copying the bytes into
// the asset store under their digest gives a path nothing else owns.
export function storedRulesPath(storeRoot, sha256) {
  return join(storeRoot, "gitleaks-rules", assertDigest(sha256), "gitleaks-rules.toml");
}

export function storedGitleaksPath(storeRoot, sha256) {
  return join(storeRoot, "gitleaks-override", assertDigest(sha256), "gitleaks");
}

// Writes `bytes` to `target` unless an identical copy is already there. The
// target is content-addressed (pass `bytes`, or a `source` path to read), so an existing file with the right digest is
// the same asset; anything else at that path is replaced atomically.
export async function adoptAsset({ bytes, source, sha256, target, executable = false, io = defaultIo } = {}) {
  if (bytes === undefined) bytes = await io.readFile(source);
  if (digest(bytes) !== sha256) throw new Error("shield asset digest mismatch before adopt");
  const mode = executable ? 0o755 : 0o644;
  try {
    const existing = await io.lstat(target);
    if (existing.isFile() && !existing.isSymbolicLink() && (existing.mode & 0o022) === 0
      && digest(await io.readFile(target)) === sha256) return target;
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const dir = dirname(target);
  await io.mkdir(dir, { recursive: true, mode: 0o755 });
  const entry = await io.lstat(dir);
  if (entry.isSymbolicLink() || !entry.isDirectory()) throw new Error("shield asset directory must be a real directory");
  if (typeof process.getuid === "function" && entry.uid !== process.getuid()) throw new Error("shield asset directory has unexpected owner");
  const temporaryPath = `${target}.tmp-${process.pid}-${Date.now()}`;
  try {
    const handle = await io.open(temporaryPath, "wx", 0o600);
    try { await handle.writeFile(bytes); await handle.chmod(mode); }
    finally { await handle.close(); }
    await io.rename(temporaryPath, target);
  } catch (error) {
    await io.unlink(temporaryPath).catch(() => {});
    throw error;
  }
  if (digest(await io.readFile(target)) !== sha256) throw new Error("shield asset digest mismatch after adopt");
  return target;
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function assertDigest(sha256) {
  if (!/^[a-f0-9]{64}$/.test(sha256 ?? "")) throw new Error("shield asset digest must be 64 lowercase hex");
  return sha256;
}
