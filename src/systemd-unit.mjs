// Renders the systemd user unit that runs shieldd on Linux, the counterpart of the launchd plist.
// The unit carries no Environment= lines: shieldd reads everything it needs from its config file,
// and anything placed here would be readable through `systemctl --user show`.
export function renderUnit({ nodePath, daemonPath, configPath, label }) {
  for (const [name, value] of Object.entries({ nodePath, daemonPath, configPath, label })) {
    if (typeof value !== "string" || value.length === 0) throw new TypeError(`${name} is required`);
  }
  if (/[\0-\x1f\x7f]/.test(label)) throw new Error("label must not contain control characters");
  const execStart = [nodePath, daemonPath, "--config", configPath].map(quoteArg).join(" ");
  return [
    "[Unit]",
    `Description=${label}`,
    "",
    "[Service]",
    "Type=simple",
    `ExecStart=${execStart}`,
    "Restart=on-failure",
    "",
    "[Install]",
    "WantedBy=default.target",
    "",
  ].join("\n");
}

// The unit's Description carries the label, so uninstall can refuse a unit it did not write.
export function unitLabel(text) {
  if (typeof text !== "string") return undefined;
  return /^Description=(.*)$/m.exec(text)?.[1];
}

export function unitExecArgs(text) {
  if (typeof text !== "string") return [];
  const line = /^ExecStart=(.*)$/m.exec(text)?.[1];
  if (line === undefined) return [];
  return [...line.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((match) => unquote(match[1]));
}

// Same message shape as describePlistDrift: name the program path that differs.
export function describeUnitDrift(existing, expected) {
  const found = unitExecArgs(existing);
  const wanted = unitExecArgs(expected);
  for (let index = 0; index < Math.max(found.length, wanted.length); index += 1) {
    if (found[index] !== wanted[index]) {
      return `installed unit runs ${quote(found[index])}, this runtime expects ${quote(wanted[index])}`;
    }
  }
  return "installed unit differs from this runtime's unit outside ExecStart";
}

// systemd expands % specifiers and $ variables even inside quotes, so both are doubled.
function quoteArg(value) {
  if (/[\0-\x1f\x7f]/.test(value)) throw new Error("unit arguments must not contain control characters");
  const escaped = value.replaceAll("\\", "\\\\").replaceAll("\"", "\\\"").replaceAll("%", "%%").replaceAll("$", "$$$$");
  return `"${escaped}"`;
}

function unquote(value) {
  return value.replace(/\\(.)/g, "$1").replaceAll("%%", "%").replaceAll("$$", "$");
}

function quote(value) {
  return value === undefined ? "(nothing)" : JSON.stringify(value);
}
