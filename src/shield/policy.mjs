import { loadPolicy as loadOpaPolicy } from "@open-policy-agent/opa-wasm";

import { validateShieldPolicyBundle } from "./policy-bundle.mjs";

const ALLOWED_ACTIONS = new Set(["allow", "block", "require_approval", "redact"]);
const DECISION_FIELDS = ["action", "approvalEligible", "reasonCodes", "redactions"];
const POLICY_INPUT_FIELDS = ["destinationClass", "interactive", "lane", "pathClasses", "piiFindings", "repositoryClass", "secretFindings"];
const LANES = new Set(["subscription", "managed"]);
const REPOSITORY_CLASSES = new Set(["public", "internal", "restricted", "unknown"]);
const PATH_CLASSES = new Set(["source", "environment", "terraform_state", "credential_store", "production_config", "unknown"]);

export async function loadShieldPolicy({ bundle, publicKey, opa = { loadPolicy: loadOpaPolicy } } = {}) {
  const validated = validateShieldPolicyBundle(bundle, { publicKey });
  if (typeof opa?.loadPolicy !== "function") throw new TypeError("shield policy requires an OPA/Wasm evaluator");
  const evaluator = await opa.loadPolicy(validated.wasm);
  if (!evaluator || typeof evaluator.evaluate !== "function") throw new Error("shield policy OPA/Wasm evaluator is invalid");

  const evaluate = async (input) => evaluateShieldDecision(evaluator, input);
  const expected = assertShieldDecision(validated.manifest.selfTest.expected);
  const actual = await evaluate(validated.manifest.selfTest.input);
  if (!sameDecision(actual, expected)) throw new Error("shield policy self-test failed");

  return Object.freeze({
    version: validated.manifest.version,
    detectorVersions: Object.freeze({ ...validated.manifest.detectorVersions }),
    evaluate,
  });
}

export function createShieldPolicyActivation({ load = loadShieldPolicy } = {}) {
  if (typeof load !== "function") throw new TypeError("shield policy activation requires a policy loader");
  let active = null;
  return Object.freeze({
    async activate(options) {
      active = null;
      active = await load(options);
      return active;
    },
    current() {
      return active;
    },
  });
}

export function assertShieldDecision(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("shield policy decision is invalid");
  const keys = Object.keys(value).sort();
  if (keys.length !== DECISION_FIELDS.length || keys.some((key, index) => key !== DECISION_FIELDS[index])) {
    throw new Error("shield policy decision contains unsupported fields");
  }
  if (!ALLOWED_ACTIONS.has(value.action)) throw new Error("shield policy decision action is unsupported");
  if (!Array.isArray(value.reasonCodes) || value.reasonCodes.some((code) => typeof code !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(code))) {
    throw new Error("shield policy decision reason codes are invalid");
  }
  if (typeof value.approvalEligible !== "boolean") throw new Error("shield policy decision approval eligibility is invalid");
  if (!Array.isArray(value.redactions) || value.redactions.some((redaction) => !isSafeRedaction(redaction))) {
    throw new Error("shield policy decision redactions are invalid");
  }
  if (value.action !== "redact" && value.redactions.length !== 0) throw new Error("shield policy decision redactions require redact action");
  if (value.action === "require_approval" ? !value.approvalEligible : value.approvalEligible) {
    throw new Error("shield policy decision approval eligibility conflicts with action");
  }
  return freezeDecision(value);
}

export function assertShieldPolicyInput(value) {
  if (!isPlainObject(value) || !hasExactKeys(value, POLICY_INPUT_FIELDS)
    || !LANES.has(value.lane) || !LANES.has(value.destinationClass)
    || typeof value.interactive !== "boolean" || !REPOSITORY_CLASSES.has(value.repositoryClass)
    || !Array.isArray(value.pathClasses) || value.pathClasses.length > 32
    || value.pathClasses.some((pathClass) => !PATH_CLASSES.has(pathClass))) {
    throw new Error("shield policy input is invalid");
  }
  return Object.freeze({
    lane: value.lane,
    destinationClass: value.destinationClass,
    interactive: value.interactive,
    repositoryClass: value.repositoryClass,
    pathClasses: freezeClassList(value.pathClasses),
    secretFindings: freezeFindings(value.secretFindings),
    piiFindings: freezeFindings(value.piiFindings),
  });
}

async function evaluateShieldDecision(evaluator, input) {
  let results;
  const policyInput = assertShieldPolicyInput(input);
  try {
    results = await evaluator.evaluate(policyInput);
  } catch {
    throw new Error("shield policy evaluation failed");
  }
  if (!Array.isArray(results) || results.length !== 1 || !results[0] || !Object.hasOwn(results[0], "result")) {
    throw new Error("shield policy evaluation returned an invalid result set");
  }
  return enforceSensitiveBlock(policyInput, assertShieldDecision(results[0].result));
}

function isSafeRedaction(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value).sort();
  if (keys.length !== 3 || keys[0] !== "category" || keys[1] !== "end" || keys[2] !== "start") return false;
  return typeof value.category === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(value.category)
    && Number.isInteger(value.start) && value.start >= 0
    && Number.isInteger(value.end) && value.end >= value.start;
}

function freezeDecision(value) {
  return Object.freeze({
    action: value.action,
    reasonCodes: Object.freeze([...value.reasonCodes]),
    approvalEligible: value.approvalEligible,
    redactions: Object.freeze(value.redactions.map((redaction) => Object.freeze({ ...redaction }))),
  });
}

function sameDecision(actual, expected) {
  return JSON.stringify(actual) === JSON.stringify(expected);
}

function enforceSensitiveBlock(input, decision) {
  const hasConfirmedSecret = input.secretFindings.length > 0;
  const hasPrivacySecret = input.piiFindings.some((finding) => finding.category === "secret");
  const hasRestrictedData = input.repositoryClass === "restricted"
    || input.pathClasses.some((pathClass) => pathClass === "environment" || pathClass === "terraform_state" || pathClass === "credential_store" || pathClass === "production_config");
  if (!hasConfirmedSecret && !hasPrivacySecret && !hasRestrictedData) return decision;
  if (hasPrivacySecret && !hasConfirmedSecret && !hasRestrictedData
    && input.lane === "subscription" && input.destinationClass === "subscription" && decision.action === "redact") return decision;
  const reasonCodes = [];
  if (hasConfirmedSecret) reasonCodes.push("confirmed-secret");
  if (hasPrivacySecret) reasonCodes.push("privacy-secret");
  if (hasRestrictedData) reasonCodes.push("restricted-data");
  return Object.freeze({
    action: "block",
    reasonCodes: Object.freeze(reasonCodes),
    approvalEligible: false,
    redactions: Object.freeze([]),
  });
}

function freezeClassList(value) {
  if (!Array.isArray(value) || value.some((pathClass) => !PATH_CLASSES.has(pathClass))) {
    throw new Error("shield policy input is invalid");
  }
  const normalized = [...new Set(value)].sort();
  if (normalized.length !== value.length || normalized.some((pathClass, index) => pathClass !== value[index])) {
    throw new Error("shield policy input is invalid");
  }
  return Object.freeze(normalized);
}

function freezeFindings(value) {
  if (!Array.isArray(value) || value.length > 512) throw new Error("shield policy input is invalid");
  let previous = "";
  const findings = value.map((finding) => {
    if (!isPlainObject(finding) || !hasExactKeys(finding, ["category", "count"])
      || typeof finding.category !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(finding.category)
      || !Number.isInteger(finding.count) || finding.count < 1 || finding.count > 1_000_000
      || finding.category <= previous) {
      throw new Error("shield policy input is invalid");
    }
    previous = finding.category;
    return Object.freeze({ category: finding.category, count: finding.count });
  });
  return Object.freeze(findings);
}

function hasExactKeys(value, expected) {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}
