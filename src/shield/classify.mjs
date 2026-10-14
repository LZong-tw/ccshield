const MAX_BODY_BYTES = 1_048_576;
const REPOSITORY_CLASSES = new Set(["public", "internal", "restricted", "unknown"]);
const PATH_CLASSES = new Set(["source", "environment", "terraform_state", "credential_store", "production_config", "unknown"]);
const DESTINATION_CLASSES = new Set(["subscription", "managed"]);

export function classifyShieldRequest({ body, launcherContext } = {}) {
  assertBoundedBody(body);
  assertLauncherContext(launcherContext);
  return Object.freeze({
    repositoryClass: launcherContext.repository.trustClass,
    pathClasses: Object.freeze([...new Set(launcherContext.pathClasses)].sort()),
    destinationClass: launcherContext.destinationClass,
    interactive: launcherContext.interactive,
  });
}

function assertBoundedBody(body) {
  if (!(Buffer.isBuffer(body) || body instanceof Uint8Array) || body.byteLength > MAX_BODY_BYTES) {
    throw new Error("shield request body is invalid or exceeds the inspection limit");
  }
}

function assertLauncherContext(value) {
  if (!isPlainObject(value) || !hasExactKeys(value, ["destinationClass", "interactive", "pathClasses", "repository"])) {
    throw new Error("shield launcher context is invalid");
  }
  if (!isPlainObject(value.repository) || !hasExactKeys(value.repository, ["remoteHash", "trustClass"])) {
    throw new Error("shield launcher context is invalid");
  }
  if (typeof value.repository.remoteHash !== "string" || !/^[a-f0-9]{64}$/.test(value.repository.remoteHash)) {
    throw new Error("shield launcher context is invalid");
  }
  if (!REPOSITORY_CLASSES.has(value.repository.trustClass)
    || !DESTINATION_CLASSES.has(value.destinationClass)
    || typeof value.interactive !== "boolean"
    || !Array.isArray(value.pathClasses)
    || value.pathClasses.length > 32
    || value.pathClasses.some((pathClass) => !PATH_CLASSES.has(pathClass))) {
    throw new Error("shield launcher context is invalid");
  }
}

function hasExactKeys(value, expected) {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}
