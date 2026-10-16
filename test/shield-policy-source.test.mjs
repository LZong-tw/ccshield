import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const policy = path.join(root, "policy", "baseline.rego");
const skip = spawnSync("opa", ["version"]).error ? "opa not found" : false;

function decide(overrides = {}) {
  const input = {
    destinationClass: "subscription",
    interactive: false,
    lane: "subscription",
    repositoryClass: "unknown",
    pathClasses: ["unknown"],
    secretFindings: [],
    piiFindings: [],
    ...overrides,
  };
  const run = spawnSync("opa", ["eval", "--format=json", "--data", policy, "--stdin-input", "data.ccshield.shield.decision"], {
    encoding: "utf8",
    input: JSON.stringify(input),
  });
  assert.equal(run.status, 0, run.stderr);
  return JSON.parse(run.stdout).result[0].expressions[0].value;
}

test("policy blocks Gitleaks secrets before PII", { skip }, () => {
  const piiFindings = [{ category: "private_email", count: 1 }];
  assert.deepEqual(decide({ secretFindings: [{ category: "gitleaks", count: 1 }], piiFindings }), {
    action: "block", reasonCodes: ["confirmed-secret"], approvalEligible: false, redactions: [],
  });
  assert.deepEqual(decide({ secretFindings: [{ category: "gitleaks", count: 1 }], piiFindings: [...piiFindings, { category: "secret", count: 1 }] }), {
    action: "block", reasonCodes: ["confirmed-secret"], approvalEligible: false, redactions: [],
  });
});

test("policy blocks restricted data before ordinary PII", { skip }, () => {
  const decision = decide({
    repositoryClass: "restricted",
    piiFindings: [{ category: "private_person", count: 1 }],
  });
  assert.deepEqual(decision, {
    action: "block", reasonCodes: ["restricted-data"], approvalEligible: false, redactions: [],
  });
});

test("policy allows requests without findings", { skip }, () => {
  assert.deepEqual(decide(), {
    action: "allow", reasonCodes: [], approvalEligible: false, redactions: [],
  });
});

test("policy requests verified redaction for native OPF privacy labels", { skip }, () => {
  assert.deepEqual(decide({ piiFindings: [{ category: "private_email", count: 1 }] }), {
    action: "redact", reasonCodes: ["subscription-pii"], approvalEligible: false, redactions: [],
  });
});

test("policy requests verified redaction for OPF-only secrets and mixed PII", { skip }, () => {
  for (const piiFindings of [
    [{ category: "secret", count: 1 }],
    [{ category: "private_email", count: 1 }, { category: "secret", count: 2 }],
  ]) {
    assert.deepEqual(decide({ piiFindings }), {
      action: "redact", reasonCodes: ["subscription-pii"], approvalEligible: false, redactions: [],
    });
  }
});

test("OPF-only secrets cannot override restricted classifications", { skip }, () => {
  for (const restriction of [
    { repositoryClass: "restricted" },
    ...["environment", "terraform_state", "credential_store", "production_config"].map((pathClass) => ({ pathClasses: [pathClass] })),
  ]) {
    assert.deepEqual(decide({ ...restriction, piiFindings: [{ category: "secret", count: 1 }] }), {
      action: "block", reasonCodes: ["restricted-data"], approvalEligible: false, redactions: [],
    });
  }
});
