// Old AirKit Shield variable names, honoured for one release so AirKit can
// switch to this package (P5) without a flag day. New names always win.
// TODO(P5): drop the mapping once AirKit sets the CCSHIELD_* names itself.
export const LEGACY_ENV_NAMES = Object.freeze({
  CCSHIELD_ROOT_DIR: "AIRKIT_SHIELD_ROOT_DIR",
  CCSHIELD_GUI_UID: "AIRKIT_GUI_UID",
  CCSHIELD_LAUNCHER: "AIRKIT_SHIELD_LAUNCHER",
  CCSHIELD_SUBSCRIPTION: "AIRKIT_SHIELD_SUBSCRIPTION",
  CCSHIELD_CAPABILITY: "AIRKIT_SHIELD_CAPABILITY",
  CCSHIELD_CONTROL_CAPABILITY: "AIRKIT_SHIELD_CONTROL_CAPABILITY",
  CCSHIELD_APPROVAL_CAPABILITY: "AIRKIT_SHIELD_APPROVAL_CAPABILITY",
  CCSHIELD_APPROVAL_SOCKET: "AIRKIT_SHIELD_APPROVAL_SOCKET",
});

// Endpoints that AirKit's own launchers export. Shield only reads them to
// check a Headroom launcher marker; it never sets them.
// TODO(P5): move into AirKit and pass the endpoint through the public API.
export const AIRKIT_LAUNCHER_ENDPOINT_ENV = Object.freeze({
  provider: "AIRCLAUDE_PROVIDER_BASE_URL",
  anthropicProvider: "AIRCLAUDE_ANTHROPIC_PROVIDER_BASE_URL",
});

const warned = new Set();

function defaultWarn(message) {
  process.stderr.write(`ccshield: ${message}\n`);
}

// Reads a CCSHIELD_* variable, falling back to its AirKit name with a
// once-per-process deprecation warning.
export function readEnv(env, name, { warn = defaultWarn } = {}) {
  const legacy = LEGACY_ENV_NAMES[name];
  if (legacy === undefined) throw new TypeError(`unknown ccshield environment variable: ${name}`);
  if (env?.[name] !== undefined) return env[name];
  const value = env?.[legacy];
  if (value !== undefined && !warned.has(legacy)) {
    warned.add(legacy);
    warn(`${legacy} is deprecated; set ${name} instead`);
  }
  return value;
}

// Both spellings of a variable, for scrubbing it from a child environment.
export function envNamesFor(name) {
  const legacy = LEGACY_ENV_NAMES[name];
  if (legacy === undefined) throw new TypeError(`unknown ccshield environment variable: ${name}`);
  return [name, legacy];
}

export function resetCompatWarningsForTest() {
  warned.clear();
}
