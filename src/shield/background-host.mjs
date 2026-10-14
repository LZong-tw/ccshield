import { spawnSync } from "node:child_process";

export const DEFAULT_BACKGROUND_HOST_GRACE_MS = 30 * 60 * 1_000;

export async function hasBackgroundClaudeHost(origin, detector = detectBackgroundClaudeHost) {
  try {
    return await detector(origin) === true;
  } catch {
    return false;
  }
}

export function scheduleBackgroundHostRelease(origin, { detector = detectBackgroundClaudeHost, graceMs = DEFAULT_BACKGROUND_HOST_GRACE_MS, setTimeoutFn = setTimeout, onReleased } = {}) {
  if (!Number.isInteger(graceMs) || graceMs < 1_000 || typeof onReleased !== "function") return false;
  let released = false;
  const check = async () => {
    if (!await hasBackgroundClaudeHost(origin, detector)) {
      if (!released) {
        released = true;
        await onReleased();
      }
      return;
    }
    const timer = setTimeoutFn(() => { void check(); }, graceMs);
    timer.unref?.();
  };
  const timer = setTimeoutFn(() => { void check(); }, graceMs);
  timer.unref?.();
  return true;
}

export function detectBackgroundClaudeHost(adapterOrigin) {
  const result = spawnSync("ps", ["eww", "-axo", "pid=,command="], { encoding: "utf8" });
  if (result.status !== 0 || typeof result.stdout !== "string") return false;
  let endpoint;
  try {
    endpoint = new URL(adapterOrigin).origin;
  } catch {
    return false;
  }
  return result.stdout
    .split(/\r?\n/)
    .some((line) => backgroundHostUsesAdapter(line, endpoint));
}

export function backgroundHostUsesAdapter(commandLine, adapterOrigin) {
  if (typeof commandLine !== "string" || typeof adapterOrigin !== "string") return false;
  return commandLine.includes("--bg-pty-host")
    && /(?:^|\/|\s)claude(?:\s|$)/.test(commandLine)
    && commandLine.includes(adapterOrigin);
}
