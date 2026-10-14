const DESTINATION_CLASSES = new Set(["managed", "subscription"]);
const MAX_REASON_CODES = 32;
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_TTL_MS = 60_000;

/**
 * The launcher creates this object while it owns an interactive terminal and
 * passes only the broker capability to its protected child.  Shield itself
 * never opens process.stdin/stdout, so a launchd daemon cannot manufacture an
 * approval path.
 */
export function createApprovalBroker({ tty = null, clock = systemClock(), timeoutMs = DEFAULT_TIMEOUT_MS, ttlMs = DEFAULT_TTL_MS } = {}) {
  assertClock(clock);
  assertDuration(timeoutMs, "approval timeout");
  assertDuration(ttlMs, "approval grant TTL");
  const grants = new WeakMap();

  return Object.freeze({
    async request(input) {
      const scope = assertApprovalScope(input);
      if (!isInteractiveTty(tty) || scope.signal?.aborted) return null;

      const approved = await promptForApproval({ tty, scope, clock, timeoutMs });
      if (!approved || scope.signal?.aborted) return null;

      const grant = {};
      const expiry = clock.now() + ttlMs;
      grants.set(grant, {
        requestId: scope.requestId,
        digest: scope.digest,
        bundleVersion: scope.bundleVersion,
        destinationClass: scope.destinationClass,
        expiresAt: expiry,
        consumed: false,
      });
      Object.defineProperties(grant, {
        requestId: { enumerable: true, value: scope.requestId },
        digest: { enumerable: true, value: scope.digest },
        bundleVersion: { enumerable: true, value: scope.bundleVersion },
        destinationClass: { enumerable: true, value: scope.destinationClass },
        expiresAt: { enumerable: true, value: expiry },
        consumed: { enumerable: true, get: () => grants.get(grant)?.consumed === true },
      });
      return Object.freeze(grant);
    },

    consume(grant, input) {
      const scope = assertApprovalScope(input);
      const stored = grants.get(grant);
      if (!stored || stored.consumed || clock.now() > stored.expiresAt || !sameScope(stored, scope)) return false;
      stored.consumed = true;
      return true;
    },
  });
}

async function promptForApproval({ tty, scope, clock, timeoutMs }) {
  const prompt = formatPrompt(scope);
  try {
    tty.write(prompt);
  } catch {
    return false;
  }

  const result = await racePrompt({
    prompt: () => tty.prompt({
      destinationClass: scope.destinationClass,
      reasonCodes: scope.reasonCodes,
      timeoutMs,
      signal: scope.signal,
    }),
    signal: scope.signal,
    clock,
    timeoutMs,
  });
  return result === true || result === "y" || result === "Y" || result?.approved === true;
}

function racePrompt({ prompt, signal, clock, timeoutMs }) {
  return new Promise((resolve) => {
    let settled = false;
    let timer = null;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      if (timer !== null) clock.clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      resolve(value);
    };
    const onAbort = () => finish(false);
    if (signal?.aborted) return finish(false);
    signal?.addEventListener("abort", onAbort, { once: true });
    timer = clock.setTimeout(() => finish(false), timeoutMs);
    Promise.resolve().then(prompt).then(finish, () => finish(false));
  });
}

function formatPrompt({ destinationClass, reasonCodes }) {
  return [
    "AirKit Shield: approval required",
    `Reason: ${reasonCodes.join(", ")} → ${destinationClass}`,
    "Scope: this request only; no source content was stored",
    "Approve? [y/N] ",
  ].join("\n");
}

function assertApprovalScope(value) {
  if (!isPlainObject(value)) throw new TypeError("shield approval request is invalid");
  const keys = Object.keys(value);
  if (keys.some((key) => !["requestId", "digest", "bundleVersion", "destinationClass", "reasonCodes", "signal"].includes(key))) {
    throw new TypeError("shield approval request is invalid");
  }
  if (typeof value.requestId !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(value.requestId)
    || typeof value.digest !== "string" || !/^[a-f0-9]{64}$/.test(value.digest)
    || typeof value.bundleVersion !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(value.bundleVersion)
    || !DESTINATION_CLASSES.has(value.destinationClass)
    || !validReasonCodes(value.reasonCodes)
    || (value.signal !== undefined && !isAbortSignal(value.signal))) {
    throw new TypeError("shield approval request is invalid");
  }
  return Object.freeze({
    requestId: value.requestId,
    digest: value.digest,
    bundleVersion: value.bundleVersion,
    destinationClass: value.destinationClass,
    reasonCodes: Object.freeze([...value.reasonCodes]),
    signal: value.signal,
  });
}

function validReasonCodes(value) {
  return Array.isArray(value) && value.length > 0 && value.length <= MAX_REASON_CODES
    && value.every((code) => typeof code === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(code));
}

function sameScope(grant, scope) {
  return grant.requestId === scope.requestId
    && grant.digest === scope.digest
    && grant.bundleVersion === scope.bundleVersion
    && grant.destinationClass === scope.destinationClass;
}

function isInteractiveTty(value) {
  return value?.interactive === true && typeof value.write === "function" && typeof value.prompt === "function";
}

function assertClock(value) {
  if (typeof value?.now !== "function" || typeof value?.setTimeout !== "function" || typeof value?.clearTimeout !== "function") {
    throw new TypeError("shield approval clock is invalid");
  }
}

function assertDuration(value, label) {
  if (!Number.isInteger(value) || value < 1 || value > 300_000) throw new TypeError(`${label} is invalid`);
}

function isAbortSignal(value) {
  return value !== null && typeof value === "object" && typeof value.aborted === "boolean"
    && typeof value.addEventListener === "function" && typeof value.removeEventListener === "function";
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function systemClock() {
  return { now: () => Date.now(), setTimeout, clearTimeout };
}
