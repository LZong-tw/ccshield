import { appendFileSync, chmodSync, renameSync, statSync } from "node:fs";
import { readFile } from "node:fs/promises";

// Failure reasons outlive the in-memory diagnostics ring only if they reach disk. Each line carries
// counts, timings and allowlisted codes; body text, redactions and headers never get here.
const FIELDS = ["ts", "stage", "reason", "bytes", "elapsedMs", "queuedMs", "launch"];
const DEFAULT_MAX_BYTES = 256 * 1024;

export function createFailureLog({ path, maxBytes = DEFAULT_MAX_BYTES }) {
  return Object.freeze({
    append(entry) {
      const line = `${JSON.stringify(pick(entry))}\n`;
      try {
        if (sizeOf(path) + Buffer.byteLength(line) > maxBytes) renameSync(path, `${path}.1`);
        appendFileSync(path, line, { mode: 0o600 });
        chmodSync(path, 0o600);
      } catch {
        // Logging must never turn a 503 into a crash; the in-memory diagnostics still hold the failure.
      }
    },
  });
}

export async function readFailureLog(path, { limit = 10 } = {}) {
  const entries = [];
  for (const file of [`${path}.1`, path]) {
    let text;
    try { text = await readFile(file, "utf8"); } catch { continue; }
    for (const line of text.split("\n")) {
      try {
        const entry = JSON.parse(line);
        if (entry && typeof entry === "object" && typeof entry.stage === "string") entries.push(pick(entry));
      } catch {}
    }
  }
  return entries.slice(-limit);
}

function pick(entry) {
  return Object.fromEntries(FIELDS.filter((key) => entry[key] !== undefined).map((key) => [key, entry[key]]));
}

function sizeOf(path) {
  try { return statSync(path).size; } catch { return 0; }
}
