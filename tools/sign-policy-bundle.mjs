#!/usr/bin/env node
// Build and sign a ccshield policy bundle.
//
//   node tools/shield/sign-policy-bundle.mjs keygen --out <dir>
//   node tools/shield/sign-policy-bundle.mjs sign \
//     --wasm <policy.wasm> --private-key <dir>/policy-signing.key \
//     --version <id> --gitleaks-version <x.y.z> --privacy-version <id> \
//     --out <dir>/policy-bundle.json
//
// The private key never belongs in a repository, in Shield state, or in this
// tool's output. keygen writes it 0600 and prints only its fingerprint; store
// it outside the repository and delete the file.
//
// Compile the Wasm first:
//   opa build -t wasm -e ccshield/shield/decision policy/baseline.rego
//   tar -xzf bundle.tar.gz   # yields /policy.wasm

import { createHash, generateKeyPairSync, createPrivateKey, sign } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const [command, ...rest] = process.argv.slice(2);
const args = parseArgs(rest);

if (command === "keygen") keygen();
else if (command === "sign") signBundle();
else {
  process.stderr.write("usage: sign-policy-bundle.mjs <keygen|sign> [options]\n");
  process.exit(2);
}

function keygen() {
  const dir = resolve(required("out"));
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePath = resolve(dir, "policy-signing.key");
  const publicPath = resolve(dir, "policy-public.pem");
  writeFileSync(privatePath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  writeFileSync(publicPath, publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
  chmodSync(privatePath, 0o600);
  chmodSync(publicPath, 0o600);
  const fingerprint = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
  process.stdout.write(`${JSON.stringify({ privateKey: privatePath, publicKey: publicPath, publicKeyFingerprint: fingerprint }, null, 2)}\n`);
}

function signBundle() {
  const wasmPath = resolve(required("wasm"));
  const wasm = readFileSync(wasmPath);
  const privateKey = createPrivateKey(readFileSync(resolve(required("private-key"))));
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("policy signing key must be Ed25519");

  const manifest = {
    formatVersion: 1,
    version: required("version"),
    opaAbi: "1",
    // Pinned by SHIELD_OPA_WASM_SDK_VERSION in src/shield/policy-bundle.mjs.
    opaWasmSdkVersion: "1.8.0",
    wasmSha256: createHash("sha256").update(wasm).digest("hex"),
    detectorVersions: {
      // Must match what `gitleaks version` prints and the Privacy manifest's
      // own version. The daemon refuses to start on any mismatch.
      gitleaks: required("gitleaks-version"),
      privacy: required("privacy-version"),
    },
    // Proves the subscription policy and runtime agree on OPF-only secret
    // redaction, without a Gitleaks finding or restricted classification.
    selfTest: {
      input: {
        lane: "subscription",
        destinationClass: "subscription",
        interactive: false,
        repositoryClass: "unknown",
        pathClasses: ["unknown"],
        secretFindings: [],
        piiFindings: [{ category: "secret", count: 1 }],
      },
      expected: {
        action: "redact",
        reasonCodes: ["subscription-pii"],
        approvalEligible: false,
        redactions: [],
      },
    },
  };

  const signature = sign(null, Buffer.from(canonicalJson(manifest)), privateKey).toString("base64");
  const outPath = resolve(required("out"));
  writeFileSync(outPath, `${JSON.stringify({ manifest, signature, wasm: wasm.toString("base64") })}\n`, { mode: 0o600 });
  chmodSync(outPath, 0o600);
  process.stdout.write(`${JSON.stringify({ bundle: outPath, version: manifest.version, wasmSha256: manifest.wasmSha256, detectorVersions: manifest.detectorVersions }, null, 2)}\n`);
}

// Byte-identical to canonicalJson in src/shield/policy-bundle.mjs; the
// signature is over this exact serialization.
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function parseArgs(argv) {
  const parsed = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    if (!argv[index].startsWith("--")) continue;
    parsed.set(argv[index].slice(2), argv[index + 1]);
    index += 1;
  }
  return parsed;
}

function required(name) {
  const value = args.get(name);
  if (typeof value !== "string" || value === "") throw new Error(`--${name} is required`);
  return value;
}
