// SPDX-License-Identifier: MPL-2.0
import { spawn } from "node:child_process";
import { copyFile, mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const IMAGE_WORKER_SOURCE = join(dirname(fileURLToPath(import.meta.url)), "image-worker.swift");

// Builds the worker into `outDir`, which the caller owns and keeps private.
// swiftc only allows top-level code in main.swift once there is a second file,
// so the source is copied in under that name next to the generated version.
export async function compileImageWorker({ sourcePath, outDir, version, xcrun = "xcrun", timeoutMs = 240_000 }) {
  if (!/^image-[0-9a-f]{12}$/.test(version ?? "")) throw new Error("image worker version is invalid");
  const cache = join(outDir, "module-cache");
  await mkdir(cache, { mode: 0o700 });
  await copyFile(sourcePath, join(outDir, "main.swift"));
  await writeFile(join(outDir, "version.swift"), `let workerVersion = "${version}"\n`);
  const binary = join(outDir, "image-worker");
  const args = ["swiftc", "-O", "-warnings-as-errors", "-module-cache-path", cache,
    "-o", binary, join(outDir, "main.swift"), join(outDir, "version.swift")];
  await run(xcrun, args, timeoutMs);
  return binary;
}

function run(command, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (chunk) => { if (stderr.length < 16_384) stderr += chunk; });
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.on("error", (error) => { clearTimeout(timer); reject(error); });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error(`image worker compile failed (${signal ?? `exit ${code}`}): ${stderr.trim().slice(-2000)}`));
    });
  });
}
