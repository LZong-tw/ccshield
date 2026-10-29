import { isAbsolute, resolve } from "node:path";

export const OPF_STARTUP_TIMEOUT_MS = 60_000;
export const OPF_SCAN_TIMEOUT_MS = Object.freeze([2_000, 10_000, 25_000, 60_000, 240_000]);
export const OPF_WINDOW_CACHE_MAX_MIB = 256;

// The only argv the OPF worker accepts. Provisioning writes it and the daemon
// re-checks it before every spawn, so both sides build it here. The disk cache
// directory is per lane and is appended at spawn time, never stored here.
export function buildOpfWorkerArgs({ python, checkpoint, source, adapter, tokenizer, scanTimeoutMs, windowCacheMaxMib = OPF_WINDOW_CACHE_MAX_MIB }) {
  return [
    "--python", python,
    "--checkpoint", checkpoint?.path,
    "--checkpoint-sha256", checkpoint?.sha256,
    "--checkpoint-version", checkpoint?.version,
    "--opf-source", source?.path,
    "--opf-source-sha256", source?.sha256,
    "--adapter-sha256", adapter?.sha256,
    "--tokenizer", tokenizer?.path,
    "--tokenizer-sha256", tokenizer?.sha256,
    "--startup-timeout-ms", String(OPF_STARTUP_TIMEOUT_MS),
    "--scan-timeout-ms", String(scanTimeoutMs),
    "--window-cache-max-mib", String(windowCacheMaxMib),
  ];
}

export function isValidWindowCacheMaxMib(value) {
  return Number.isInteger(value) && (value === 0 || (value >= 16 && value <= 4096));
}

export function isValidOpfWorkerArgs(args, references) {
  if (!Array.isArray(args)) return false;
  const python = args[1];
  const scanTimeoutMs = Number(args[21]);
  const windowCacheMaxMib = Number(args[23]);
  if (typeof python !== "string" || !isAbsolute(python) || resolve(python) !== python
    || !OPF_SCAN_TIMEOUT_MS.includes(scanTimeoutMs) || args[21] !== String(scanTimeoutMs)
    || !isValidWindowCacheMaxMib(windowCacheMaxMib) || args[23] !== String(windowCacheMaxMib)) return false;
  const expected = buildOpfWorkerArgs({ ...references, python, scanTimeoutMs, windowCacheMaxMib });
  return args.length === expected.length && expected.every((value, index) => typeof value === "string" && args[index] === value);
}
