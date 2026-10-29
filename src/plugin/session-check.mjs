#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);
// x-airkit-shield is the pre-Phase-5 spelling, still emitted for an old daemon.
const CAPABILITY_HEADER = /^x-(?:ccshield-capability|airkit-shield):\s*\S/i;
const WARNING = "ccshield: this session is not behind ccshield; requests go out unscanned. Start it with `ccshield launch --lane subscription -- claude`.";

// Claude Code hands its own environment to hooks, so a session started by
// `ccshield launch` carries the loopback base URL and the capability header
// that buildShieldChildEnv set. Both must be present; the header value is
// never echoed.
export function shieldSessionCheck(env = process.env) {
  const headers = String(env?.ANTHROPIC_CUSTOM_HEADERS ?? "").split(/\r?\n/).map((line) => line.trim());
  if (isLoopback(env?.ANTHROPIC_BASE_URL) && headers.some((line) => CAPABILITY_HEADER.test(line))) return { behind: true };
  return { behind: false, message: WARNING };
}

function isLoopback(value) {
  try {
    const url = new URL(String(value));
    return url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname);
  } catch {
    return false;
  }
}

export async function runSessionCheck({ env = process.env, output = process.stdout } = {}) {
  const result = shieldSessionCheck(env);
  if (!result.behind) output.write(JSON.stringify({ systemMessage: result.message }));
  return 0;
}

function isDirectEntrypoint() {
  try {
    return Boolean(process.argv[1]) && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

if (isDirectEntrypoint()) {
  runSessionCheck().then((code) => { process.exitCode = code; }, () => { process.exitCode = 0; });
}
