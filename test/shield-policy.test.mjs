import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { shieldPaths } from "../src/shield/paths.mjs";
import { createShieldPolicyActivation, loadShieldPolicy } from "../src/shield/policy.mjs";

const wasm = Buffer.from("compiled-opa-policy-fixture");
const compiledWasm = await readFile(new URL("./fixtures/shield-policy.wasm", import.meta.url));
const keyPair = generateKeyPairSync("ed25519");

test("policy activation only accepts a signed, digest-matched OPA/Wasm bundle", async () => {
  const bundle = signedBundle();
  const policy = await loadTestPolicy({ bundle });

  assert.equal(policy.version, "2026.09.02.1");
  assert.deepEqual(policy.detectorVersions, { gitleaks: "8.24.0", privacy: "privacy-1" });
  assert.deepEqual(await policy.evaluate(policyInput), allowDecision);
  assert.equal(Object.isFrozen(policy), true);
  assert.equal(Object.isFrozen(policy.detectorVersions), true);
});

test("policy activation rejects unsigned and digest-drifted bundles", async () => {
  await assert.rejects(
    loadTestPolicy({ bundle: { ...signedBundle(), signature: undefined } }),
    /signature/i,
  );
  await assert.rejects(
    loadTestPolicy({ bundle: { ...signedBundle(), wasm: Buffer.from("drift") } }),
    /digest/i,
  );
  await assert.rejects(
    loadTestPolicy({ bundle: { ...signedBundle(), signature: Buffer.alloc(64).toString("base64") } }),
    /signature/i,
  );
});

test("policy activation requires both Gitleaks and Privacy detector versions", async () => {
  await assert.rejects(
    loadTestPolicy({ bundle: signedBundle({ detectorVersions: { gitleaks: "8.24.0" } }) }),
    /detector versions/i,
  );
  await assert.rejects(
    loadTestPolicy({ bundle: signedBundle({ detectorVersions: { privacy: "privacy-1" } }) }),
    /detector versions/i,
  );
  await assert.rejects(
    loadTestPolicy({ bundle: signedBundle({ detectorVersions: { gitleaks: "8.24.0", privacy: "privacy-1", extra: "1" } }) }),
    /detector versions/i,
  );
});

test("policy activation rejects an unsupported OPA ABI and missing self-test", async () => {
  await assert.rejects(
    loadTestPolicy({ bundle: signedBundle({ opaAbi: "999" }) }),
    /ABI/i,
  );
  await assert.rejects(
    loadTestPolicy({ bundle: signedBundle({ selfTest: undefined }) }),
    /self-test/i,
  );
  await assert.rejects(
    loadTestPolicy({ bundle: signedBundle({ opaWasmSdkVersion: "0.0.0" }) }),
    /runtime version/i,
  );
});

test("policy evaluator rejects unsupported actions and failing self-tests", async () => {
  await assert.rejects(
    loadTestPolicy({ opa: fakeOpa({ ...allowDecision, action: "allow_all" }) }),
    /action/i,
  );
  await assert.rejects(
    loadTestPolicy({ opa: fakeOpa({ ...allowDecision, action: "block", reasonCodes: ["fixture"] }) }),
    /self-test/i,
  );
});

test("a failed replacement activation clears a prior allow evaluator", async () => {
  const activation = createShieldPolicyActivation();
  await activation.activate({ bundle: signedBundle(), publicKey: keyPair.publicKey, opa: allowOpa });
  assert.notEqual(activation.current(), null);
  await assert.rejects(
    activation.activate({ bundle: { ...signedBundle(), wasm: Buffer.from("drift") }, publicKey: keyPair.publicKey, opa: allowOpa }),
    /digest/i,
  );
  assert.equal(activation.current(), null);
});

test("policy trust root is injected independently and must be an Ed25519 public key", async () => {
  await assert.rejects(
    loadShieldPolicy({ bundle: { ...signedBundle(), trustedPublicKeys: { attacker: keyPair.publicKey } }, opa: allowOpa }),
    /public key/i,
  );
  await assert.rejects(
    loadTestPolicy({ publicKey: generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey }),
    /Ed25519/i,
  );
  await assert.rejects(
    loadTestPolicy({ publicKey: keyPair.privateKey }),
    /public key/i,
  );
});

test("default OPA SDK evaluates an OPA-compiled Wasm fixture", async () => {
  const policy = await loadShieldPolicy({
    bundle: signedBundle({}, compiledWasm),
    publicKey: keyPair.publicKey,
  });
  assert.deepEqual(await policy.evaluate(policyInput), allowDecision);
  assert.deepEqual(await policy.evaluate({
    ...policyInput,
    secretFindings: [{ category: "private-key", count: 1 }],
  }), blockDecision);
  assert.deepEqual(await policy.evaluate({
    ...policyInput,
    repositoryClass: "restricted",
  }), {
    action: "block",
    reasonCodes: ["restricted-data"],
    approvalEligible: false,
    redactions: [],
  });
  assert.deepEqual(await policy.evaluate({
    ...policyInput,
    repositoryClass: "internal",
  }), {
    action: "require_approval",
    reasonCodes: ["internal-subscription"],
    approvalEligible: true,
    redactions: [],
  });
  assert.deepEqual(await policy.evaluate({
    ...policyInput,
    piiFindings: [{ category: "email", count: 1 }],
  }), redactDecision);
  assert.deepEqual(await policy.evaluate({
    ...policyInput,
    piiFindings: [{ category: "phone", count: 1 }],
  }), redactDecision);
});

test("policy runtime normalizes a signed policy that tries to approve confirmed sensitive input", async () => {
  const policy = await loadTestPolicy({ opa: unsafeSensitiveOpa });

  assert.deepEqual(await policy.evaluate({
    ...policyInput,
    secretFindings: [{ category: "private-key", count: 1 }],
  }), blockDecision);
  assert.deepEqual(await policy.evaluate({
    ...policyInput,
    pathClasses: ["terraform_state"],
  }), {
    action: "block",
    reasonCodes: ["restricted-data"],
    approvalEligible: false,
    redactions: [],
  });
});

test("Privacy Filter secret blocks managed redaction and subscription approval", async () => {
  const policy = await loadTestPolicy({ opa: {
    async loadPolicy() {
      return { evaluate(input) {
        if (input.piiFindings.some((finding) => finding.category === "secret")) {
          return [{ result: input.lane === "managed" ? redactDecision : {
            action: "require_approval", reasonCodes: ["unsafe-policy"], approvalEligible: true, redactions: [],
          } }];
        }
        return [{ result: allowDecision }];
      } };
    },
  } });
  for (const lane of ["managed", "subscription"]) {
    assert.deepEqual(await policy.evaluate({
      ...policyInput,
      lane,
      destinationClass: lane,
      piiFindings: [{ category: "secret", count: 1 }],
    }), {
      action: "block",
      reasonCodes: ["privacy-secret"],
      approvalEligible: false,
      redactions: [],
    });
  }
});

test("signed OPA policy can redact OPF-only secrets on the subscription destination", async () => {
  const policy = await loadShieldPolicy({ bundle: signedBundle({}, compiledWasm), publicKey: keyPair.publicKey });
  for (const piiFindings of [
    [{ category: "secret", count: 1 }],
    [{ category: "private_email", count: 1 }, { category: "secret", count: 1 }],
  ]) {
    assert.deepEqual(await policy.evaluate({ ...policyInput, piiFindings }), redactDecision);
  }
});

test("OPF secret redaction cannot bypass lane, action, Gitleaks, or restricted-data gates", async () => {
  const cases = [
    { name: "subscription redaction", action: "redact", want: "redact", reasons: ["pii-redaction"] },
    { name: "subscription allow", action: "allow", want: "block", reasons: ["privacy-secret"] },
    { name: "subscription approval", action: "require_approval", want: "block", reasons: ["privacy-secret"] },
    { name: "subscription block", action: "block", want: "block", reasons: ["privacy-secret"] },
    { name: "managed lane", action: "redact", input: { lane: "managed" }, want: "block", reasons: ["privacy-secret"] },
    { name: "managed destination", action: "redact", input: { destinationClass: "managed" }, want: "block", reasons: ["privacy-secret"] },
    { name: "Gitleaks plus OPF", action: "redact", input: { secretFindings: [{ category: "private-key", count: 1 }] }, want: "block", reasons: ["confirmed-secret", "privacy-secret"] },
    { name: "restricted repository", action: "redact", input: { repositoryClass: "restricted" }, want: "block", reasons: ["privacy-secret", "restricted-data"] },
    ...["environment", "terraform_state", "credential_store", "production_config"].map((pathClass) => ({
      name: pathClass, action: "redact", input: { pathClasses: [pathClass] }, want: "block", reasons: ["privacy-secret", "restricted-data"],
    })),
  ];
  for (const fixture of cases) {
    const policy = await loadTestPolicy({ opa: {
      async loadPolicy() {
        return { evaluate(input) {
          if (input.piiFindings.length === 0) return [{ result: allowDecision }];
          return [{ result: {
            action: fixture.action,
            reasonCodes: ["pii-redaction"],
            approvalEligible: fixture.action === "require_approval",
            redactions: [],
          } }];
        } };
      },
    } });
    assert.deepEqual(await policy.evaluate({
      ...policyInput, piiFindings: [{ category: "secret", count: 1 }], ...fixture.input,
    }), {
      action: fixture.want, reasonCodes: fixture.reasons, approvalEligible: false, redactions: [],
    }, fixture.name);
  }
});

test("policy passes bounded detector and classifier facts to OPA without a JavaScript allow path", async () => {
  const policy = await loadTestPolicy({ opa: detectorOpa });
  const decision = await policy.evaluate({
    ...policyInput,
    repositoryClass: "restricted",
    pathClasses: ["terraform_state"],
    secretFindings: [{ category: "private-key", count: 1 }],
  });

  assert.deepEqual(decision, {
    action: "block",
    reasonCodes: ["confirmed-secret", "restricted-data"],
    approvalEligible: false,
    redactions: [],
  });
  await assert.rejects(
    policy.evaluate({ ...policyInput, secretFindings: [{ category: "private-key", count: 1, raw: "fixture-secret" }] }),
    /input/i,
  );
});

test("OPA owns restricted-data blocks and internal subscription approval decisions", async () => {
  const policy = await loadTestPolicy({ opa: detectorOpa });

  assert.deepEqual(await policy.evaluate({
    ...policyInput,
    repositoryClass: "restricted",
    pathClasses: ["terraform_state"],
  }), {
    action: "block",
    reasonCodes: ["restricted-data"],
    approvalEligible: false,
    redactions: [],
  });
  assert.deepEqual(await policy.evaluate({
    ...policyInput,
    repositoryClass: "internal",
  }), {
    action: "require_approval",
    reasonCodes: ["internal-subscription"],
    approvalEligible: true,
    redactions: [],
  });
});

test("policy state exposes only version and detector versions", async () => {
  const homeDir = await mkdtemp(join(tmpdir(), "airkit-policy-state-"));
  const paths = shieldPaths({ homeDir, uid: process.getuid?.() });
  try {
    const { readShieldPolicyState, writeShieldPolicyState } = await import("../src/shield/paths.mjs");
    await writeShieldPolicyState({
      paths,
      state: { version: "2026.09.02.1", detectorVersions: { gitleaks: "8.24.0", privacy: "privacy-1" } },
    });
    assert.deepEqual(await readShieldPolicyState({ paths }), {
      version: "2026.09.02.1",
      detectorVersions: { gitleaks: "8.24.0", privacy: "privacy-1" },
    });
  } finally {
    await rm(homeDir, { recursive: true, force: true });
  }
});

const allowDecision = {
  action: "allow",
  reasonCodes: [],
  approvalEligible: false,
  redactions: [],
};

const policyInput = {
  lane: "subscription",
  destinationClass: "subscription",
  interactive: false,
  repositoryClass: "public",
  pathClasses: ["source"],
  secretFindings: [],
  piiFindings: [],
};

const blockDecision = {
  action: "block",
  reasonCodes: ["confirmed-secret"],
  approvalEligible: false,
  redactions: [],
};

const redactDecision = {
  action: "redact",
  reasonCodes: ["pii-redaction"],
  approvalEligible: false,
  redactions: [],
};

const allowOpa = fakeOpa(allowDecision);

const detectorOpa = {
  async loadPolicy() {
    return {
      evaluate(input) {
        if (input.secretFindings.length > 0) return [{ result: blockDecision }];
        if (input.pathClasses.includes("terraform_state")) {
          return [{ result: { action: "block", reasonCodes: ["restricted-data"], approvalEligible: false, redactions: [] } }];
        }
        if (input.repositoryClass === "internal" && input.destinationClass === "subscription") {
          return [{ result: { action: "require_approval", reasonCodes: ["internal-subscription"], approvalEligible: true, redactions: [] } }];
        }
        return [{ result: allowDecision }];
      },
    };
  },
};

const unsafeSensitiveOpa = {
  async loadPolicy() {
    return {
      evaluate(input) {
        if (input.secretFindings.length === 0 && !input.pathClasses.includes("terraform_state")) return [{ result: allowDecision }];
        return [{ result: { action: "require_approval", reasonCodes: ["unsafe-signed-policy"], approvalEligible: true, redactions: [] } }];
      },
    };
  },
};

function fakeOpa(result) {
  return {
    async loadPolicy(receivedWasm) {
      assert.deepEqual(Buffer.from(receivedWasm), wasm);
      return { evaluate: () => [{ result }] };
    },
  };
}

function signedBundle(overrides = {}, artifact = wasm) {
  const manifest = {
    formatVersion: 1,
    version: "2026.09.02.1",
    opaAbi: "1",
    opaWasmSdkVersion: "1.8.0",
    wasmSha256: createHash("sha256").update(artifact).digest("hex"),
    detectorVersions: { gitleaks: "8.24.0", privacy: "privacy-1" },
    selfTest: { input: policyInput, expected: allowDecision },
    ...overrides,
  };
  const signature = sign(null, Buffer.from(canonicalJson(manifest)), keyPair.privateKey).toString("base64");
  return {
    manifest,
    wasm: artifact,
    signature,
  };
}

async function loadTestPolicy({ bundle = signedBundle(), publicKey = keyPair.publicKey, opa = allowOpa } = {}) {
  return loadShieldPolicy({ bundle, publicKey, opa });
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
