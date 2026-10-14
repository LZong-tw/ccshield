import assert from "node:assert/strict";
import test from "node:test";

import { classifyShieldRequest } from "../src/shield/classify.mjs";

const remoteHash = "a".repeat(64);

test("classifies only bounded launcher facts", () => {
  const facts = classifyShieldRequest({
    body: Buffer.from("private source stays inside the classifier"),
    launcherContext: {
      repository: { remoteHash, trustClass: "internal" },
      pathClasses: ["source", "source"],
      destinationClass: "subscription",
      interactive: true,
    },
  });

  assert.deepEqual(facts, {
    repositoryClass: "internal",
    pathClasses: ["source"],
    destinationClass: "subscription",
    interactive: true,
  });
  assert.equal(Object.isFrozen(facts), true);
  assert.equal(Object.isFrozen(facts.pathClasses), true);
  assert.doesNotMatch(JSON.stringify(facts), /private source|aaaa/);
});

test("rejects raw repository and path material at the launcher boundary", () => {
  const launcherContext = {
    repository: { remoteHash, trustClass: "internal" },
    pathClasses: ["source"],
    destinationClass: "subscription",
    interactive: false,
  };

  for (const unsafe of [
    { ...launcherContext, repository: { ...launcherContext.repository, remote: "git@github.com:private/repo.git" } },
    { ...launcherContext, path: "/Users/example/private.tfstate" },
    { ...launcherContext, targetUrl: "https://api.example.test" },
    { ...launcherContext, pathClasses: ["/Users/example/.env"] },
  ]) {
    assert.throws(() => classifyShieldRequest({ body: Buffer.alloc(0), launcherContext: unsafe }), /launcher context/i);
  }
});

test("rejects unbounded bodies and untrusted classifier categories", () => {
  const launcherContext = {
    repository: { remoteHash, trustClass: "unknown" },
    pathClasses: ["unknown"],
    destinationClass: "managed",
    interactive: false,
  };

  assert.throws(() => classifyShieldRequest({ body: Buffer.alloc(1_048_576 + 1), launcherContext }), /body/i);
  assert.throws(() => classifyShieldRequest({ body: Buffer.alloc(0), launcherContext: { ...launcherContext, repository: { remoteHash, trustClass: "private" } } }), /launcher context/i);
  assert.throws(() => classifyShieldRequest({ body: Buffer.alloc(0), launcherContext: { ...launcherContext, destinationClass: "https://provider.test" } }), /launcher context/i);
});
