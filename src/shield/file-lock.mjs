import { open, readFile, rm } from "node:fs/promises";

// A pid lock file created with O_EXCL. A holder that is no longer running left
// it behind, so it is taken over once; a live holder means the lock is busy.
export async function acquireLock(lockPath, { pid = process.pid, isProcessAlive = defaultIsProcessAlive } = {}) {
  for (let tries = 0; tries < 2; tries += 1) {
    try {
      const handle = await open(lockPath, "wx", 0o600);
      try { await handle.writeFile(`${pid}\n`); } finally { await handle.close(); }
      return true;
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      const holder = await lockHolder(lockPath);
      if (holder !== null && await isProcessAlive(holder)) return false;
      await rm(lockPath, { force: true });
    }
  }
  return false;
}

export async function lockHolder(lockPath) {
  try {
    const pid = Number.parseInt(await readFile(lockPath, "utf8"), 10);
    return Number.isInteger(pid) && pid > 0 ? pid : null;
  } catch {
    return null;
  }
}

// Runs `fn` while holding the lock, waiting for a live holder to let go. Only
// meant for short critical sections such as a record's read-merge-write.
export async function withFileLock(lockPath, fn, { timeoutMs = 30_000, retryMs = 50, sleep = defaultSleep, ...deps } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (!await acquireLock(lockPath, deps)) {
    if (Date.now() >= deadline) throw new Error(`shield lock ${lockPath} is held by pid ${await lockHolder(lockPath) ?? "unknown"}`);
    await sleep(retryMs);
  }
  try {
    return await fn();
  } finally {
    await rm(lockPath, { force: true });
  }
}

export async function defaultIsProcessAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code === "EPERM";
  }
}

function defaultSleep(ms) {
  return new Promise((settle) => setTimeout(settle, ms));
}
