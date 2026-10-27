import { writeFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";

// Plugin settings.json only honours `agent` and `subagentStatusLine`, and
// ${CLAUDE_PLUGIN_ROOT} expansion there is unverified, so the command is
// written with absolute paths at install time instead of shipped.
export function pluginSettings({ pluginRoot, nodePath = process.execPath }) {
  for (const [name, value] of Object.entries({ pluginRoot, nodePath })) {
    if (typeof value !== "string" || !isAbsolute(value)) throw new Error(`${name} must be an absolute path`);
  }
  const script = join(pluginRoot, "src", "plugin", "subagent-statusline.mjs");
  return { subagentStatusLine: { type: "command", command: `${quote(nodePath)} ${quote(script)}`, refreshInterval: 1 } };
}

function quote(path) {
  if (/["$`\\]/.test(path)) throw new Error(`path cannot be quoted for a shell command: ${path}`);
  return `"${path}"`;
}

export async function installPlugin({ pluginRoot, nodePath, write = false, io = { writeFile } }) {
  const settings = pluginSettings({ pluginRoot, nodePath });
  const settingsPath = join(pluginRoot, "settings.json");
  if (!write) return { state: "preview", exitCode: 0, settingsPath, settings };
  await io.writeFile(settingsPath, `${JSON.stringify(settings, null, 2)}\n`, { mode: 0o644 });
  return { state: "written", exitCode: 0, settingsPath, settings };
}
