// SPDX-License-Identifier: MPL-2.0
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";

import { SHIELD_IMAGE_LIMITS } from "./limits.mjs";

// Driver for the native image worker. Protocol: docs/superpowers/plans/
// 2026-10-27-shield-image-worker-protocol.md in ai-runtime-kit (v1).

const PROTOCOL_VERSION = 1;
const STDERR_CAP = 64 * 1024;
const WORKER_CODES = new Set([
  "bad_request", "unsupported_type", "multi_frame", "too_many_pixels",
  "decode_failed", "ocr_failed", "encode_failed", "output_too_large",
]);

export class ImageWorkerError extends Error {
  constructor(code) {
    super(`image worker: ${code}`);
    this.code = code;
  }
}

const fail = (code) => { throw new ImageWorkerError(code); };
const isPlainObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const hasExactKeys = (value, keys) => Object.keys(value).sort().join() === [...keys].sort().join();
const isCount = (value) => Number.isSafeInteger(value) && value >= 0;

// Same checks as the privacy worker: canonical absolute path, no symlink, our
// uid, not group/world writable, executable, pinned digest. The gap between
// this check and spawn is accepted; the binary lives in a 0700 directory.
export async function attestImageWorker(path, expectedSha256, io = { lstat, readFile, realpath }) {
  if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path) fail("worker_attestation");
  let entry;
  let canonical;
  let bytes;
  try { [entry, canonical, bytes] = await Promise.all([io.lstat(path), io.realpath(path), io.readFile(path)]); }
  catch { fail("worker_attestation"); }
  const ok = canonical === path && !entry.isSymbolicLink() && entry.isFile()
    && (typeof process.getuid !== "function" || entry.uid === process.getuid())
    && (entry.mode & 0o022) === 0 && (entry.mode & 0o100) !== 0
    && createHash("sha256").update(bytes).digest("hex") === expectedSha256;
  if (!ok) fail("worker_attestation");
}

function isRect(rect, width, height) {
  return isPlainObject(rect) && hasExactKeys(rect, ["x", "y", "w", "h"])
    && [rect.x, rect.y, rect.w, rect.h].every(isCount)
    && rect.x + rect.w <= width && rect.y + rect.h <= height;
}

function isRegion(region, width, height) {
  return isPlainObject(region) && hasExactKeys(region, ["text", "confidence", "rect"])
    && typeof region.text === "string" && !region.text.includes("\n")
    && Number.isFinite(region.confidence) && region.confidence >= 0 && region.confidence <= 1
    && isRect(region.rect, width, height);
}

function parseResponse(message, op, id, limits) {
  if (!isPlainObject(message) || message.v !== PROTOCOL_VERSION || message.id !== id || typeof message.ok !== "boolean") fail("worker_protocol");
  if (!message.ok) {
    if (!hasExactKeys(message, ["v", "id", "ok", "code"]) || !WORKER_CODES.has(message.code)) fail("worker_protocol");
    fail(message.code);
  }
  if (op === "probe") {
    const ok = hasExactKeys(message, ["v", "id", "ok", "worker", "languages"])
      && typeof message.worker === "string" && /^image-[0-9a-z]{12}$/.test(message.worker)
      && Array.isArray(message.languages) && message.languages.every((language) => typeof language === "string");
    if (!ok) fail("worker_protocol");
    return { worker: message.worker, languages: [...message.languages] };
  }
  const { width, height } = message;
  if (!Number.isSafeInteger(width) || width <= 0 || !Number.isSafeInteger(height) || height <= 0) fail("worker_protocol");
  if (op === "ocr") {
    const ok = hasExactKeys(message, ["v", "id", "ok", "width", "height", "regions"])
      && Array.isArray(message.regions) && message.regions.every((region) => isRegion(region, width, height));
    if (!ok) fail("worker_protocol");
    return { width, height, regions: message.regions.map(({ text, confidence, rect }) => ({ text, confidence, rect: { ...rect } })) };
  }
  if (!hasExactKeys(message, ["v", "id", "ok", "width", "height", "image"]) || typeof message.image !== "string") fail("worker_protocol");
  const image = Buffer.from(message.image, "base64");
  if (image.length === 0 || image.toString("base64") !== message.image) fail("worker_protocol");
  if (image.length > limits.maxOutput) fail("output_too_large");
  return { width, height, image };
}

export function createImageWorker({ path, sha256, timeoutMs = 10_000, probeTimeoutMs = 120_000, limits = SHIELD_IMAGE_LIMITS }) {
  let child = null;
  let pending = null;
  let nextId = 1;
  let queue = Promise.resolve();
  let closed = false;

  function settle(error, line) {
    const current = pending;
    if (!current) return;
    pending = null;
    clearTimeout(current.timer);
    if (error) return current.reject(error);
    try {
      let message;
      try { message = JSON.parse(line); } catch { fail("worker_protocol"); }
      current.resolve(parseResponse(message, current.op, current.id, limits));
    } catch (failure) {
      if (failure.code === "worker_protocol") stop();
      current.reject(failure);
    }
  }

  function stop() {
    if (!child) return;
    const dying = child;
    child = null;
    dying.kill("SIGKILL");
  }

  async function start() {
    await attestImageWorker(path, sha256);
    const proc = spawn(path, [], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = Buffer.alloc(0);
    let stderrBytes = 0;
    proc.stdout.on("data", (chunk) => {
      if (proc !== child) return;
      stdout = Buffer.concat([stdout, chunk]);
      let index;
      while ((index = stdout.indexOf(0x0a)) !== -1) {
        if (index > limits.maxFrame) break;
        const line = stdout.subarray(0, index).toString("utf8");
        stdout = stdout.subarray(index + 1);
        if (!pending) { stop(); return; }
        settle(null, line);
        if (proc !== child) return;
      }
      if (stdout.indexOf(0x0a) > limits.maxFrame || (stdout.indexOf(0x0a) === -1 && stdout.length > limits.maxFrame)) {
        stop();
        settle(new ImageWorkerError("worker_frame_too_large"));
      }
    });
    // Drained and capped, never parsed or forwarded: it may contain OCR text.
    proc.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > STDERR_CAP && proc === child) {
        stop();
        settle(new ImageWorkerError("worker_protocol"));
      }
    });
    proc.stdin.on("error", () => {});
    const onGone = () => {
      if (proc !== child) return;
      child = null;
      settle(new ImageWorkerError("worker_exited"));
    };
    proc.on("exit", onGone);
    proc.on("error", onGone);
    child = proc;
  }

  async function send(op, fields) {
    if (closed) fail("worker_closed");
    if (!child) await start();
    if (closed) { stop(); fail("worker_closed"); }
    const id = nextId++;
    const line = `${JSON.stringify({ v: PROTOCOL_VERSION, id, op, ...fields })}\n`;
    if (Buffer.byteLength(line) > limits.maxFrame) fail("bad_request");
    return new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => {
        stop();
        settle(new ImageWorkerError("worker_timeout"));
      }, op === "probe" ? probeTimeoutMs : timeoutMs);
      pending = { id, op, timer, resolve: resolvePromise, reject };
      child.stdin.write(line);
    });
  }

  function enqueue(op, fields) {
    const result = queue.then(() => send(op, fields));
    queue = result.catch(() => {});
    return result;
  }

  function imageField(bytes) {
    if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > limits.maxBytes) fail("bad_request");
    return bytes.toString("base64");
  }

  return {
    probe: () => enqueue("probe", {}),
    async ocr(bytes) { return enqueue("ocr", { image: imageField(bytes) }); },
    async mask(bytes, rects) {
      if (!Array.isArray(rects) || !rects.every((rect) => isRect(rect, Infinity, Infinity))) fail("bad_request");
      return enqueue("mask", { image: imageField(bytes), rects: rects.map((rect) => ({ ...rect })) });
    },
    kill() {
      stop();
      settle(new ImageWorkerError("worker_exited"));
    },
    close() {
      closed = true;
      this.kill();
    },
  };
}
