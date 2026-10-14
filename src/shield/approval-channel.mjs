import { randomBytes, timingSafeEqual } from "node:crypto";
import { createConnection, createServer } from "node:net";
import { join } from "node:path";
import { rm } from "node:fs/promises";

const MAX_MESSAGE_BYTES = 16 * 1024;

/**
 * A launcher owns the socket and the real approval broker.  The daemon only
 * receives a short-lived capability in a request header; a grant never leaves
 * this process or gets persisted.
 */
export async function createApprovalChannel({ broker, directory, capability = randomBytes(32).toString("hex") } = {}) {
  if (typeof broker?.request !== "function" || typeof broker?.consume !== "function") throw new TypeError("shield approval channel broker is invalid");
  if (typeof directory !== "string" || !directory.startsWith("/")) throw new TypeError("shield approval channel directory is invalid");
  assertCapability(capability);
  const socketPath = join(directory, "approval.sock");
  let consumed = false;
  const server = createServer({ allowHalfOpen: true }, (socket) => {
    let bytes = 0;
    let chunks = [];
    socket.setTimeout(30_000, () => socket.destroy());
    socket.on("data", (chunk) => {
      bytes += chunk.length;
      if (bytes > MAX_MESSAGE_BYTES) { socket.destroy(); return; }
      chunks.push(Buffer.from(chunk));
    });
    socket.once("end", async () => {
      let request;
      try { request = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { reply(socket, false); return; }
      chunks = [];
      if (consumed || !matchesCapability(request?.capability, capability)) { reply(socket, false); return; }
      consumed = true;
      try {
        const scope = assertWireScope(request.scope);
        const grant = await broker.request(scope);
        reply(socket, grant !== null && broker.consume(grant, scope) === true);
      } catch {
        reply(socket, false);
      }
    });
    socket.once("error", () => {});
  });
  await listen(server, socketPath);
  return Object.freeze({ socketPath, capability, close: async () => { await close(server); await rm(socketPath, { force: true }); } });
}

export async function requestApprovalChannel({ socketPath, capability, scope, timeoutMs = 30_000 } = {}) {
  if (typeof socketPath !== "string" || !socketPath.startsWith("/")) return false;
  let wireScope;
  try {
    assertCapability(capability);
    wireScope = assertWireScope({
      requestId: scope?.requestId,
      digest: scope?.digest,
      bundleVersion: scope?.bundleVersion,
      destinationClass: scope?.destinationClass,
      reasonCodes: scope?.reasonCodes,
    });
  } catch { return false; }
  return await new Promise((resolve) => {
    const socket = createConnection(socketPath);
    let result = null;
    let settled = false;
    const finish = (value) => { if (!settled) { settled = true; resolve(value); } };
    socket.setTimeout(timeoutMs, () => { socket.destroy(); finish(false); });
    socket.once("connect", () => socket.end(Buffer.from(JSON.stringify({ capability, scope: wireScope }), "utf8")));
    socket.on("data", (chunk) => {
      if (result !== null || chunk.length > 128) { socket.destroy(); finish(false); return; }
      try { result = JSON.parse(String(chunk)); } catch { socket.destroy(); finish(false); }
    });
    socket.once("error", () => finish(false));
    socket.once("close", () => finish(result?.approved === true));
  });
}

export function approvalChannelRegistration({ socketPath, capability } = {}) {
  if (typeof socketPath !== "string" || !socketPath.startsWith("/")) throw new TypeError("shield approval channel socket is invalid");
  assertCapability(capability);
  return Object.freeze({ socketPath, capability });
}

export function readApprovalChannelRegistration(value) {
  try { return approvalChannelRegistration(value); } catch { return null; }
}

function assertWireScope(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).some((key) => !["requestId", "digest", "bundleVersion", "destinationClass", "reasonCodes"].includes(key))
    || typeof value.requestId !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(value.requestId)
    || typeof value.digest !== "string" || !/^[a-f0-9]{64}$/.test(value.digest)
    || typeof value.bundleVersion !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(value.bundleVersion)
    || (value.destinationClass !== "managed" && value.destinationClass !== "subscription")
    || !Array.isArray(value.reasonCodes) || value.reasonCodes.length < 1 || value.reasonCodes.length > 32
    || value.reasonCodes.some((code) => typeof code !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(code))) {
    throw new TypeError("shield approval channel request is invalid");
  }
  return Object.freeze({ requestId: value.requestId, digest: value.digest, bundleVersion: value.bundleVersion, destinationClass: value.destinationClass, reasonCodes: Object.freeze([...value.reasonCodes]) });
}

function assertCapability(value) { if (typeof value !== "string" || !/^[a-f0-9]{32,128}$/.test(value)) throw new TypeError("shield approval channel capability is invalid"); }
function matchesCapability(value, expected) { const actual = Buffer.from(typeof value === "string" ? value : ""); const target = Buffer.from(expected); return actual.length === target.length && timingSafeEqual(actual, target); }
function reply(socket, approved) { socket.end(Buffer.from(JSON.stringify({ approved }), "utf8")); }
function listen(server, socketPath) { return new Promise((resolve, reject) => { server.once("error", reject); server.once("listening", () => { server.off("error", reject); resolve(); }); server.listen(socketPath); }); }
function close(server) { return new Promise((resolve) => server.close(() => resolve())); }
