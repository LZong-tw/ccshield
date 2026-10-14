import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";

const VERSION = 1;
const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const PURPOSES = new Set(["evidence/v1"]);

export function deriveKey({ masterKey, purpose, identity }) {
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== KEY_BYTES) throw new TypeError("master key must be 32 bytes");
  if (!PURPOSES.has(purpose)) throw new TypeError(`unsupported key purpose: ${purpose}`);
  if (typeof identity !== "string" || identity.length === 0) throw new TypeError("key identity must be a non-empty string");
  return Buffer.from(hkdfSync("sha256", masterKey, Buffer.from("ccshield:audit:v1"), Buffer.from(`${purpose}:${identity}`), KEY_BYTES));
}

// Packed as compact JSON so a column holds one self-describing value.
export function encryptValue({ masterKey, purpose, identity, aad, plaintext }) {
  const key = deriveKey({ masterKey, purpose, identity });
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  return JSON.stringify({ v: VERSION, n: nonce.toString("base64"), c: ciphertext.toString("base64"), t: cipher.getAuthTag().toString("base64") });
}

export function decryptValue({ masterKey, purpose, identity, aad, packed }) {
  let value;
  try { value = JSON.parse(packed); } catch { throw new TypeError("encrypted value is not packed JSON"); }
  if (value?.v !== VERSION || typeof value.n !== "string" || typeof value.c !== "string" || typeof value.t !== "string") {
    throw new TypeError("encrypted value has an unsupported shape");
  }
  const key = deriveKey({ masterKey, purpose, identity });
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(value.n, "base64"));
  decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(Buffer.from(value.t, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(value.c, "base64")), decipher.final()]).toString("utf8");
}
