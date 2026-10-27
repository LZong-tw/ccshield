import { access, readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

const defaultIo = {
  exists: (path) => access(path).then(() => true, () => false),
  readFile: (path) => readFile(path, "utf8"),
  readdir: (path) => readdir(path).catch(() => []),
};

// Detection only: reports what an AirKit install left behind and how to move
// off it. It never writes, stops or removes anything.
export async function detectAirkitInstall({ home, io = defaultIo }) {
  const findings = [];
  const stateDir = join(home, ".local", "state", "airkit-shield");
  if (await io.exists(stateDir)) {
    findings.push({ kind: "state", path: stateDir, hint: "AirKit Shield state is separate from ccshield; run `ccshield install --write` and re-provision, then remove AirKit Shield through AirKit." });
  }
  const agentsDir = join(home, "Library", "LaunchAgents");
  for (const name of (await io.readdir(agentsDir)).filter((entry) => /^com\.airkit\.shield\..+\.plist$/.test(entry)).sort()) {
    findings.push({ kind: "launch-agent", path: join(agentsDir, name), hint: "AirKit Shield service is installed; stop it through AirKit before starting the ccshield service on the same lane." });
  }
  const contextSettings = join(home, ".config", "ai-runtime-kit", "plugins", "airkit-context", "settings.json");
  let settings = null;
  try { settings = JSON.parse(await io.readFile(contextSettings)); } catch { settings = null; }
  if (settings?.subagentStatusLine) {
    findings.push({ kind: "statusline", path: contextSettings, hint: "airkit-context also sets subagentStatusLine; only one plugin's line is shown. Disable one of them in /plugin." });
  }
  return { state: findings.length ? "found" : "clean", exitCode: 0, findings };
}
