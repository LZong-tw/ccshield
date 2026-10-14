const ACTIONS = new Set(["allow", "block", "require_approval", "redact"]);
const MAX_BODY_BYTES = 4 * 1024 * 1024;

export function createDecisionCache({ clock = () => Date.now(), ttlMs = 30_000, maxEntries = 128 } = {}) {
  if (typeof clock !== "function") throw new TypeError("shield decision cache clock is invalid");
  if (!Number.isInteger(ttlMs) || ttlMs < 1 || ttlMs > 300_000) throw new RangeError("shield decision cache TTL is invalid");
  if (!Number.isInteger(maxEntries) || maxEntries < 1 || maxEntries > 1024) throw new RangeError("shield decision cache size is invalid");
  const entries = new Map();
  const inflight = new Map();
  let transition = null;
  let generation = 0;

  const keyFor = (value) => {
    const input = validateKey(value);
    return JSON.stringify([input.requestDigest, input.policyVersion, input.detectorVersions, input.lane, input.destinationClass]);
  };
  const read = (value) => {
    const key = keyFor(value);
    const entry = entries.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= clock()) {
      entries.delete(key);
      return null;
    }
    entries.delete(key);
    entries.set(key, entry);
    return cloneDecision(entry.decision);
  };
  const write = (value) => {
    const key = keyFor(value);
    const decision = validateDecision(value);
    const now = clock();
    entries.delete(key);
    entries.set(key, { decision, expiresAt: now + ttlMs });
    while (entries.size > maxEntries) entries.delete(entries.keys().next().value);
    return cloneDecision(decision);
  };

  return Object.freeze({
    set: write,
    async getOrCompute(value, compute) {
      if (typeof compute !== "function") throw new TypeError("shield decision cache compute is required");
      const hit = read(value);
      if (hit) return result(hit, "cache_hit");
      const key = keyFor(value);
      let pending = inflight.get(key);
      if (pending) return result(await pending, "coalesced");
      const computeGeneration = generation;
      pending = Promise.resolve().then(compute).then((decision) => {
          if (keyFor(decision) !== key) throw new Error("shield decision cache computed identity mismatch");
          if (computeGeneration !== generation) throw new Error("shield decision cache computation was invalidated");
          return write(decision);
        }).finally(() => {
          if (inflight.get(key) === pending) inflight.delete(key);
        });
      inflight.set(key, pending);
      return result(await pending, "evaluated");
    },
    invalidateTransition(value) {
      transition = stableVersion(value);
      generation += 1;
      entries.clear();
      inflight.clear();
    },
    inspect() { return Object.freeze({ size: entries.size, inFlight: inflight.size, transition }); },
  });
}

function validateKey(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("shield decision cache key is invalid");
  if (typeof value.requestDigest !== "string" || !/^[a-f0-9]{64}$/.test(value.requestDigest)) throw new TypeError("shield decision cache request digest is invalid");
  if (typeof value.policyVersion !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(value.policyVersion)) throw new TypeError("shield decision cache policy version is invalid");
  if (value.lane !== "managed" && value.lane !== "subscription") throw new TypeError("shield decision cache lane is invalid");
  if (value.destinationClass !== value.lane) throw new TypeError("shield decision cache destination is invalid");
  return { requestDigest: value.requestDigest, policyVersion: value.policyVersion, detectorVersions: stableVersions(value.detectorVersions), lane: value.lane, destinationClass: value.destinationClass };
}

function validateDecision(value) {
  const key = validateKey(value);
  if (!ACTIONS.has(value.action)) throw new TypeError("shield decision cache action is invalid");
  if (!Number.isInteger(value.transformCount) || value.transformCount < 0 || value.transformCount > 1_000_000) throw new TypeError("shield decision cache transform count is invalid");
  if (!Buffer.isBuffer(value.body) || value.body.byteLength > MAX_BODY_BYTES) throw new TypeError("shield decision cache transformed body is invalid");
  if (!Array.isArray(value.reasonCodes) || value.reasonCodes.length === 0 || value.reasonCodes.length > 32
    || value.reasonCodes.some((code) => !/^[A-Za-z0-9._-]{1,128}$/.test(code))) {
    throw new TypeError("shield decision cache reason codes are invalid");
  }
  if (value.action !== "redact" && value.body.byteLength !== 0) throw new TypeError("shield decision cache may retain only a transformed body");
  return Object.freeze({ ...key, action: value.action, reasonCodes: [...value.reasonCodes], transformCount: value.transformCount, body: Buffer.from(value.body) });
}

function stableVersions(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("shield decision cache detector versions are invalid");
  const entries = Object.entries(value).sort(([left], [right]) => left.localeCompare(right));
  if (entries.length === 0 || entries.length > 16 || entries.some(([name, version]) => !/^[A-Za-z0-9._-]{1,128}$/.test(name) || !/^[A-Za-z0-9._-]{1,128}$/.test(version))) {
    throw new TypeError("shield decision cache detector versions are invalid");
  }
  return Object.freeze(Object.fromEntries(entries));
}

function stableVersion(value) {
  if (!value || typeof value !== "object" || typeof value.policyVersion !== "string") throw new TypeError("shield decision cache transition is invalid");
  return Object.freeze({ policyVersion: value.policyVersion, detectorVersions: stableVersions(value.detectorVersions) });
}

function cloneDecision(value) {
  return Object.freeze({ ...value, detectorVersions: { ...value.detectorVersions }, reasonCodes: [...value.reasonCodes], body: Buffer.from(value.body) });
}

function result(decision, source) {
  return Object.freeze({ decision: cloneDecision(decision), source });
}
