const PROTECTED_LAUNCHERS = Object.freeze([
  Object.freeze({
    matches: (value) => value === "airclaude",
    name: "airclaude",
    lanes: ["managed"],
    hopChain: ["airclaude", "shield", "managed"],
  }),
  Object.freeze({
    matches: (value) => /^cclaude-[a-z0-9][a-z0-9._-]*$/i.test(value),
    name: "cclaude-*",
    lanes: ["managed"],
    hopChain: ["cclaude-*", "airclaude", "shield", "managed"],
  }),
  Object.freeze({
    matches: (value) => value === "hr-airclaude",
    name: "hr-airclaude",
    lanes: ["managed"],
    hopChain: ["headroom", "airclaude", "shield", "managed"],
  }),
  Object.freeze({
    matches: (value) => value === "hr-claude-web",
    name: "hr-claude-web",
    lanes: ["managed"],
    hopChain: ["headroom", "web", "shield", "managed"],
  }),
]);

const HEADROOM_SUBSCRIPTION_LAUNCHER = Object.freeze({
  matches: (value) => value === "hr-claude-sub",
  name: "hr-claude-sub",
  lanes: ["subscription"],
  hopChain: ["headroom", "subscription", "shield", "subscription"],
});

const DECLARED_BYPASSES = Object.freeze({
  claude: "direct_client",
  "command-claude": "direct_client",
  // This external zsh helper invokes `command claude` directly. It remains a
  // bypass until that launcher itself routes through Shield.
  "hr-claude-sub": "zsh_direct_subscription",
});

const HEADROOM_LAUNCHER_MARKERS = Object.freeze({
  "headroom/hr-airclaude/v1": Object.freeze({
    launcher: "hr-airclaude",
    endpointEnv: "AIRCLAUDE_PROVIDER_BASE_URL",
    path: "/v1/chat/completions",
  }),
  "headroom/hr-claude-web/v1": Object.freeze({
    launcher: "hr-claude-web",
    endpointEnv: "AIRCLAUDE_ANTHROPIC_PROVIDER_BASE_URL",
    path: "/v1/messages",
  }),
});

// A marker is telemetry only: it may select a declared hop-chain label but
// never supplies a destination, credential, or Shield capability. Pairing it
// with the exact local compatibility endpoint makes accidental/inherited
// markers fail closed instead of silently misreporting the launcher identity.
export function resolveShieldLauncherMarker(env = {}) {
  if (!env || typeof env !== "object" || Array.isArray(env)) throw new TypeError("shield launcher environment is invalid");
  const marker = env.AIRKIT_SHIELD_LAUNCHER;
  if (marker === undefined) return "airclaude";
  const contract = HEADROOM_LAUNCHER_MARKERS[marker];
  if (!contract) throw new Error("shield launcher marker is invalid");
  if (!isExactHeadroomEndpoint(env[contract.endpointEnv], contract.path)
    || hasUnexpectedHeadroomOverride(env, contract.endpointEnv)) {
    throw new Error("shield launcher marker does not match its Headroom endpoint");
  }
  return contract.launcher;
}

function hasUnexpectedHeadroomOverride(env, expectedEnv) {
  return ["AIRCLAUDE_PROVIDER_BASE_URL", "AIRCLAUDE_ANTHROPIC_PROVIDER_BASE_URL"]
    .some((key) => key !== expectedEnv && env[key] !== undefined && env[key] !== "");
}

function isExactHeadroomEndpoint(value, path) {
  if (typeof value !== "string" || value.length === 0 || /[\r\n]/.test(value)) return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:"
      && parsed.hostname === "127.0.0.1"
      && parsed.port !== ""
      && parsed.pathname === path
      && parsed.search === ""
      && parsed.hash === ""
      && parsed.username === ""
      && parsed.password === "";
  } catch {
    return false;
  }
}

export function resolveShieldLauncher({ launcher, mode, headroom = false, providerOverride, subscriptionShield = false } = {}) {
  if (typeof launcher !== "string" || launcher.length === 0 || launcher.length > 128) {
    throw new TypeError("shield launcher is required");
  }
  if (mode !== undefined && (typeof mode !== "string" || mode.length === 0 || mode.length > 64)) {
    throw new TypeError("shield launcher mode is invalid");
  }
  if (typeof headroom !== "boolean") throw new TypeError("shield launcher Headroom state is invalid");
  if (typeof subscriptionShield !== "boolean") throw new TypeError("shield launcher subscription Shield state is invalid");
  if (Object.hasOwn(DECLARED_BYPASSES, launcher) && !(launcher === "hr-claude-sub" && subscriptionShield)) {
    return Object.freeze({ coverage: "bypass", bypassReason: DECLARED_BYPASSES[launcher] });
  }
  const descriptor = [...PROTECTED_LAUNCHERS, ...(subscriptionShield ? [HEADROOM_SUBSCRIPTION_LAUNCHER] : [])]
    .find((candidate) => candidate.matches(launcher));
  if (!descriptor) throw new Error(`undeclared Shield launcher: ${launcher}`);
  const isHeadroom = descriptor.name.startsWith("hr-");
  if (headroom !== isHeadroom) throw new Error(`shield launcher Headroom disposition mismatch: ${launcher}`);
  const lane = providerOverride ?? descriptor.lanes[0];
  if (!descriptor.lanes.includes(lane)) throw new Error(`shield launcher lane is not allowed: ${launcher}`);
  const hopChain = [...descriptor.hopChain];
  if (hopChain.at(-1) !== lane) throw new Error(`shield launcher descriptor is invalid: ${launcher}`);
  return Object.freeze({ coverage: "protected", clientLane: lane, destinationClass: lane, hopChain });
}

export function shieldLauncherDescriptors({ subscriptionShield = false } = {}) {
  if (typeof subscriptionShield !== "boolean") throw new TypeError("shield launcher subscription Shield state is invalid");
  const protectedDescriptors = [...PROTECTED_LAUNCHERS, ...(subscriptionShield ? [HEADROOM_SUBSCRIPTION_LAUNCHER] : [])].map(({ name, lanes, hopChain }) => Object.freeze({
    coverage: "protected", launcher: name, lanes: [...lanes], hopChain: [...hopChain],
  }));
  const bypassDescriptors = Object.entries(DECLARED_BYPASSES)
    .filter(([launcher]) => !(launcher === "hr-claude-sub" && subscriptionShield))
    .map(([launcher, bypassReason]) => Object.freeze({
    coverage: "bypass", launcher, bypassReason,
  }));
  return Object.freeze([...protectedDescriptors, ...bypassDescriptors]);
}
