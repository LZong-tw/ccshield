#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, readFileSync } from "node:fs";
import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { availableParallelism } from "node:os";
import { createInterface } from "node:readline";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const PROTOCOL = "airkit-privacy-ndjson-v1";
const VERSION = "opf-1-client-exempt";
// model_timeout leaves Python and its window cache alive, so callers may keep the session ready.
const CAPABILITIES = ["cooperative-timeout"];
const MAX_FRAME_BYTES = 4 * 1_048_576; // base64 redacted body (≤1 MiB → ~1.4 MiB) plus findings must fit
const MAX_BODY_BYTES = 1_048_576;
const MAX_SCANS = 4;
const HELPERS = {
  "opf-cpu-grouped.py": "adb9dd7d6f47e482ccb0925e621a1375461b997833dfa5be6dfc67b9d58b6f0e",
  "opf-window-cache.py": "75ef80d5320cf25d6949154ec374dccc61e53038a42538ee907e9d8c70d9f9cc",
  "opf-mmap-weights.py": "8be0f49097d7317937ebe7572b09619925b0c10044f0376d6438f31400485bbc",
  "opf-viterbi-deadline.py": "6fbfb16aae67c6eecacc292f8d41dda13cbe7d6792d8c2be97b8d629cc590117",
};
// Threads per worker: at most 4, fewer when the CPU count or a cgroup v2 quota is smaller.
// Python takes this count from the cache namespace, so both sides always agree.
function workerThreads() {
  let quota = Infinity;
  try {
    const [max, period] = readFileSync("/sys/fs/cgroup/cpu.max", "utf8").trim().split(/\s+/);
    if (max !== "max" && Number(period) > 0) quota = Math.max(1, Math.floor(Number(max) / Number(period)));
  } catch {}
  return Math.min(4, availableParallelism(), quota);
}
const PYTHON = String.raw`
import importlib.util
import hashlib
import json
import os
import socket
import sys

def offline(*args, **kwargs):
    raise RuntimeError("network disabled")

socket.socket.connect = offline
socket.socket.connect_ex = offline
socket.create_connection = offline
sys.path.insert(0, os.path.dirname(sys.argv[2]))
try:
    import opf
    if os.path.realpath(os.path.dirname(opf.__file__)) != os.path.realpath(sys.argv[2]):
        raise RuntimeError("OPF source mismatch")
    from opf import OPF
    import torch
    from opf._model.model import AttentionBlock, MLPBlock, TransformerBlock
    from opf._model.weights import PARAM_NAME_MAP, Checkpoint
    from opf._core.decoding import ViterbiCRFDecoder
    THREADS = json.loads(sys.argv[5])["threads"]
    if type(THREADS) is not int or not 1 <= THREADS <= 4:
        raise RuntimeError("invalid thread count")
    torch.set_num_threads(THREADS)
    def load_helper(name, path):
        with open(path, "rb") as file:
            source = file.read()
        expected = json.loads(sys.argv[5])["helpers"][os.path.basename(path)]
        if hashlib.sha256(source).hexdigest() != expected:
            raise RuntimeError("helper digest mismatch")
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        exec(compile(source, path, "exec"), module.__dict__)
        return module
    grouped = load_helper("ccshield_opf_grouped", sys.argv[3])
    cache_module = load_helper("ccshield_opf_cache", sys.argv[4])
    weights_module = load_helper("ccshield_opf_mmap", sys.argv[7])
    viterbi_module = load_helper("ccshield_opf_viterbi", sys.argv[8])
    MLPBlock.forward = grouped.grouped_forward
    # OPF copies each tensor out of the checkpoint; serving mmap views avoids a second private read.
    weights = weights_module.MappedCheckpoint(sys.argv[1])
    weights.serve(Checkpoint)
    model = OPF(model=sys.argv[1], device="cpu", output_mode="typed", output_text_only=False,
                context_window_length=4096)
    runtime = model.get_runtime()
    if runtime.n_ctx != 4096 or torch.get_num_threads() != THREADS or torch.is_autocast_enabled("cpu"):
        raise RuntimeError("inference settings mismatch")
    runtime.model.eval()
    # Bit-identical weights move to file-backed pages the kernel can drop instead of compress or swap.
    weights.map_parameters(runtime.model, PARAM_NAME_MAP)
    # bf16 attention is emulated on this CPU and dominates the window cost; fp32 attention is ~2.5x faster
    # and closer to the reference. MLP experts stay mapped bf16. Casting copies only the small qkv/out weights.
    attention = [module for module in runtime.model.modules() if isinstance(module, AttentionBlock)]
    if not attention:
        raise RuntimeError("attention blocks unavailable")
    for module in attention:
        module.qkv.float()
        module.out.float()
    cache = cache_module.ExactWindowLogitsCache(runtime.model, namespace=sys.argv[5])
    runtime.model.forward = cache.forward
    blocks = [module for module in runtime.model.modules() if isinstance(module, (TransformerBlock, MLPBlock))]
    if not any(isinstance(module, TransformerBlock) for module in blocks) or not any(isinstance(module, MLPBlock) for module in blocks):
        raise RuntimeError("deadline hooks unavailable")
    # Pre-hooks fire only through Module.__call__; the warm-up proves both block kinds really reach them.
    hook_calls = {TransformerBlock: 0, MLPBlock: 0}
    def deadline_hook(kind):
        def hook(*_):
            hook_calls[kind] += 1
            cache.check_deadline()
        return hook
    for module in blocks:
        module.register_forward_pre_hook(deadline_hook(MLPBlock if isinstance(module, MLPBlock) else TransformerBlock))
    # Global Viterbi runs after the last forward, where no block hook can reach it.
    if type(model.get_prediction_components()[1]) is not ViterbiCRFDecoder:
        raise RuntimeError("viterbi decoder required")
    decode_calls = viterbi_module.install(ViterbiCRFDecoder, cache.check_deadline)
    # Known answer: weights served from the mapping must still find the probe, or startup is refused.
    probe = model.redact("alice@example.com").to_dict()
    spans = probe.get("detected_spans") if isinstance(probe, dict) else None
    if not isinstance(spans, list) or not any(isinstance(span, dict) and span.get("label") == "private_email"
            and span.get("text") == "alice@example.com" for span in spans):
        raise RuntimeError("warm-up known answer mismatch")
    if not all(hook_calls.values()):
        raise RuntimeError("deadline hooks not invoked")
    if not decode_calls[0]:
        raise RuntimeError("viterbi deadline decode not invoked")
    scan_budget_ms = int(sys.argv[6])
    cooperative_seconds = (scan_budget_ms - min(5000, scan_budget_ms / 5)) / 1000
    print(json.dumps({"ready": True}), flush=True)
except Exception:
    print(json.dumps({"ready": False}), flush=True)
    sys.exit(1)

def window_counts(before):
    after = cache.snapshot()
    return {"hits": after["hits"] - before["hits"], "misses": after["misses"] - before["misses"]}

import queue, threading
from math import isfinite
from time import monotonic

# A timed-out scan keeps warming its remaining windows while the worker is idle, so the caller's retry
# hits the cache. Only the latest timed-out text is kept, it yields to any new request between blocks,
# and it is dropped after WARM_SECONDS of compute. Warming caches logits only, never decisions.
# CCSHIELD_OPF_WARM_SECONDS sets that budget (0 disables warming, at most 3600).
try:
    WARM_SECONDS = float(os.environ.get("CCSHIELD_OPF_WARM_SECONDS", "600"))
except ValueError:
    raise RuntimeError("invalid warm budget")
if not isfinite(WARM_SECONDS) or not 0 <= WARM_SECONDS <= 3600:
    raise RuntimeError("invalid warm budget")
inbox = queue.Queue()

def read_requests():
    for line in sys.stdin:
        inbox.put(line)
    inbox.put(None)

threading.Thread(target=read_requests, daemon=True).start()
warming = None

def warm():
    global warming
    text, spent = warming
    started = monotonic()
    try:
        cache.begin_scan(WARM_SECONDS - spent, interrupt=lambda: not inbox.empty())
        model.redact(text)
        warming = None
    except cache_module.ScanInterrupted:
        warming = (text, spent + monotonic() - started)
    except Exception:
        warming = None
    finally:
        cache.end_scan()

while True:
    if warming is not None and inbox.empty():
        warm()
        continue
    line = inbox.get()
    if line is None:
        break
    request = None
    before = cache.snapshot()
    try:
        if torch.get_num_threads() != THREADS or torch.is_autocast_enabled("cpu"):
            raise RuntimeError("inference settings changed")
        request = json.loads(line)
        cache.begin_scan(cooperative_seconds)
        result = model.redact(request["text"]).to_dict()
        cache.check_deadline()
        reply = json.dumps({"id": request["id"], "prediction": result, "cache": window_counts(before)}, ensure_ascii=False)
        cache.check_deadline()
        print(reply, flush=True)
        if warming is not None and warming[0] == request["text"]:
            warming = None
    except cache_module.CooperativeScanTimeout:
        warming = (request["text"], 0.0) if WARM_SECONDS > 0 else None
        print(json.dumps({"id": request["id"], "error": "model_timeout", "warming": warming is not None, "cache": window_counts(before)}), flush=True)
    except Exception:
        print(json.dumps({"id": request.get("id") if isinstance(request, dict) else None, "error": "unavailable"}), flush=True)
    finally:
        cache.end_scan()
`;

function options(args) {
  if (args.length !== 22) throw new Error("invalid worker arguments");
  const names = ["--python", "--checkpoint", "--checkpoint-sha256", "--checkpoint-version", "--opf-source", "--opf-source-sha256", "--adapter-sha256", "--tokenizer", "--tokenizer-sha256", "--startup-timeout-ms", "--scan-timeout-ms"];
  const value = {};
  for (let i = 0; i < names.length; i += 1) {
    if (args[i * 2] !== names[i]) throw new Error("invalid worker arguments");
    value[names[i]] = args[i * 2 + 1];
  }
  for (const name of ["--python", "--checkpoint", "--opf-source", "--tokenizer"]) {
    if (!isAbsolute(value[name]) || resolve(value[name]) !== value[name]) throw new Error("invalid asset path");
  }
  for (const name of ["--checkpoint-sha256", "--opf-source-sha256", "--adapter-sha256", "--tokenizer-sha256"]) {
    if (!/^[a-f0-9]{64}$/.test(value[name])) throw new Error("invalid asset digest");
  }
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(value["--checkpoint-version"])) throw new Error("invalid checkpoint version");
  if (value["--tokenizer"].split("/").at(-1) !== "fb374d419588a4632f3f557e76b4b70aebbca790") throw new Error("invalid tokenizer name");
  for (const name of ["--startup-timeout-ms", "--scan-timeout-ms"]) {
    const timeout = Number(value[name]);
    if (!Number.isInteger(timeout) || timeout < 1 || timeout > (name === "--scan-timeout-ms" ? 60_000 : 30_000)) throw new Error("invalid worker timeout");
    value[name] = timeout;
  }
  return value;
}

function windowCounts(value) {
  const count = (n) => Number.isSafeInteger(n) && n >= 0 && n <= 65_536;
  return value && typeof value === "object" && count(value.hits) && count(value.misses)
    ? { cache: { hits: value.hits, misses: value.misses } } : {};
}

async function validateTokenizer(path, expected) {
  const entry = await lstat(path);
  if (!entry.isFile() || entry.isSymbolicLink() || await realpath(path) !== path
    || (entry.mode & 0o022) !== 0 || (process.getuid && entry.uid !== process.getuid())) throw new Error("invalid tokenizer asset");
  if (createHash("sha256").update(await readFile(path)).digest("hex") !== expected) throw new Error("tokenizer digest mismatch");
}

async function treeDigest(root) {
  const rootInfo = await lstat(root);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink() || await realpath(root) !== root) throw new Error("invalid asset directory");
  const files = [];
  const visit = async (dir, prefix) => {
    for (const name of (await readdir(dir)).sort()) {
      const path = join(dir, name);
      const relative = prefix ? `${prefix}/${name}` : name;
      const entry = await lstat(path);
      if (entry.isSymbolicLink() || (entry.mode & 0o022) !== 0 || (process.getuid && entry.uid !== process.getuid())) throw new Error("invalid asset entry");
      if (entry.isDirectory()) await visit(path, relative);
      else if (entry.isFile()) files.push({ path, relative, size: entry.size });
      else throw new Error("invalid asset entry");
    }
  };
  if ((rootInfo.mode & 0o022) !== 0 || (process.getuid && rootInfo.uid !== process.getuid())) throw new Error("invalid asset directory");
  await visit(root, "");
  const digest = createHash("sha256");
  for (const file of files.sort((a, b) => Buffer.compare(Buffer.from(a.relative), Buffer.from(b.relative)))) {
    digest.update(file.relative).update("\0").update(String(file.size)).update("\0");
    for await (const chunk of createReadStream(file.path)) digest.update(chunk);
    digest.update("\0");
  }
  return digest.digest("hex");
}

async function treeMetadata(root) {
  const entries = [];
  const visit = async (path, relative) => {
    const entry = await lstat(path, { bigint: true });
    if (entry.isSymbolicLink() || (entry.mode & 0o22n) !== 0n
      || (process.getuid && entry.uid !== BigInt(process.getuid()))) throw new Error("asset metadata invalid");
    const kind = entry.isDirectory() ? "directory" : entry.isFile() ? "file" : null;
    if (!kind) throw new Error("asset metadata invalid");
    entries.push([relative, kind, String(entry.dev), String(entry.ino), String(entry.size),
      String(entry.mtimeNs), String(entry.ctimeNs), String(entry.mode), String(entry.uid)]);
    if (kind === "directory") {
      for (const name of await readdir(path)) await visit(join(path, name), relative ? `${relative}/${name}` : name);
    }
  };
  if (await realpath(root) !== root) throw new Error("asset path changed");
  await visit(root, "");
  entries.sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
  return JSON.stringify(entries);
}

function validBase64(value) {
  return typeof value === "string" && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value);
}

function exited(child) {
  return child.exitCode !== null || child.signalCode !== null;
}

function stopPython(current) {
  if (!current) return Promise.resolve();
  if (current.stopping) return current.stopping;
  current.stopping = (async () => {
    const escalation = setTimeout(() => current.child.kill("SIGKILL"), 500);
    let deadline;
    try {
      if (current.child.exitCode !== null || current.child.signalCode !== null) {
        current.child.stdin.destroy();
        current.child.stdout.destroy();
      } else {
        current.child.kill("SIGTERM");
      }
      await Promise.race([current.exited, new Promise((_, reject) => {
        deadline = setTimeout(() => {
          current.child.kill("SIGKILL");
          current.child.stdin.destroy();
          current.child.stdout.destroy();
          current.child.unref();
          reject(new Error("model shutdown failed"));
        }, 1500);
      })]);
    } finally {
      clearTimeout(escalation);
      clearTimeout(deadline);
    }
  })();
  return current.stopping;
}

async function main() {
  const config = options(process.argv.slice(2));
  let session;
  let input;
  let fatal = false;
  let stop;
  const stopped = new Promise((resolve) => { stop = resolve; });
  const fail = () => {
    fatal = true;
    stop();
    session?.fail();
    input?.close();
    process.stdin.destroy();
    process.exitCode = 1;
  };
  process.on("SIGTERM", fail);
  process.on("SIGINT", fail);
  const workerDir = dirname(fileURLToPath(import.meta.url));
  const adapterPath = join(workerDir, "opf-adapter.mjs");
  const attestHelpers = async () => {
    await validateTokenizer(adapterPath, config["--adapter-sha256"]);
    for (const [name, digest] of Object.entries(HELPERS)) await validateTokenizer(join(workerDir, name), digest);
  };
  const attestAssets = async () => {
    await attestHelpers();
    const [checkpointMetadata, sourceMetadata] = await Promise.all([
      treeMetadata(config["--checkpoint"]), treeMetadata(config["--opf-source"]),
    ]);
    const [checkpointDigest, sourceDigest] = await Promise.all([
      treeDigest(config["--checkpoint"]), treeDigest(config["--opf-source"]),
    ]);
    if (checkpointDigest !== config["--checkpoint-sha256"] || sourceDigest !== config["--opf-source-sha256"]) throw new Error("asset digest mismatch");
    if (await treeMetadata(config["--checkpoint"]) !== checkpointMetadata
      || await treeMetadata(config["--opf-source"]) !== sourceMetadata) throw new Error("asset changed while hashing");
    await validateTokenizer(config["--tokenizer"], config["--tokenizer-sha256"]);
    return { checkpointMetadata, sourceMetadata };
  };
  const { checkpointMetadata, sourceMetadata } = await attestAssets();
  const { prepareOpfScan, adaptOpfPrediction } = await import(pathToFileURL(adapterPath));
  const threads = workerThreads();
  const namespace = JSON.stringify({ checkpoint: config["--checkpoint-sha256"],
    checkpointVersion: config["--checkpoint-version"], source: config["--opf-source-sha256"],
    adapter: config["--adapter-sha256"], tokenizer: config["--tokenizer-sha256"], helpers: HELPERS,
    policy: VERSION, threads, settings: `cpu:threads${threads}:ctx4096:eval:no-autocast:attention-fp32` });
  let starting;
  const startPython = async () => {
    if (fatal) throw new Error("worker unavailable");
    const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("OPF_")));
    env.TIKTOKEN_CACHE_DIR = dirname(config["--tokenizer"]);
    const child = spawn(config["--python"], ["-I", "-B", "-u", "-c", PYTHON, config["--checkpoint"], config["--opf-source"],
      join(workerDir, "opf-cpu-grouped.py"), join(workerDir, "opf-window-cache.py"), namespace, String(config["--scan-timeout-ms"]),
      join(workerDir, "opf-mmap-weights.py"), join(workerDir, "opf-viterbi-deadline.py")],
      { stdio: ["pipe", "pipe", "ignore"], env });
    const current = { child, ready: false, dead: false, waiting: null };
    current.exited = new Promise((resolve) => child.once("close", resolve));
    current.gone = new Promise((resolve) => child.once("exit", resolve));
    session = current;
    let finishStartup;
    const started = new Promise((resolve) => { finishStartup = resolve; });
    const startupTimer = setTimeout(() => failChild(), config["--startup-timeout-ms"]);
    const failChild = () => {
      if (current.dead) return;
      current.dead = true;
      clearTimeout(startupTimer);
      finishStartup(false);
      if (current.waiting) { const finish = current.waiting; current.waiting = null; finish(null); }
      stopPython(current).catch(() => {});
    };
    current.fail = failChild;
    const childLines = createInterface({ input: child.stdout });
    childLines.on("line", (line) => {
      if (current.dead) return;
      if (Buffer.byteLength(line) > MAX_FRAME_BYTES) { failChild(); return; }
      let result;
      try { result = JSON.parse(line); } catch { failChild(); return; }
      if (!current.ready) {
        if (result?.ready !== true) { failChild(); return; }
        current.ready = true;
        clearTimeout(startupTimer);
        finishStartup(true);
        return;
      }
      if (!current.waiting) { failChild(); return; }
      const finish = current.waiting;
      current.waiting = null;
      finish(result);
    });
    childLines.on("close", failChild);
    child.on("exit", failChild);
    child.on("error", failChild);
    child.stdin.on("error", failChild);
    if (!await started) throw new Error("model startup failed");
    return current;
  };
  const checkAssets = async () => {
    await attestHelpers();
    if (await treeMetadata(config["--checkpoint"]) !== checkpointMetadata
      || await treeMetadata(config["--opf-source"]) !== sourceMetadata) throw new Error("asset drift");
    await validateTokenizer(config["--tokenizer"], config["--tokenizer-sha256"]);
    if (fatal) throw new Error("worker unavailable");
  };
  let retryAt = 0;
  let startupFailures = 0;
  // Resolves null while Python is unavailable; only asset or worker failures reject.
  const restart = async () => {
    await stopPython(session).catch(() => {});
    if (session && !exited(session.child)) return null;
    if (Date.now() < retryAt) return null;
    if (await treeMetadata(config["--checkpoint"]) !== checkpointMetadata
      || await treeMetadata(config["--opf-source"]) !== sourceMetadata) await attestAssets();
    await attestHelpers();
    await validateTokenizer(config["--tokenizer"], config["--tokenizer-sha256"]);
    const current = await startPython().catch(() => null);
    startupFailures = current ? 0 : startupFailures + 1;
    if (!current) retryAt = Date.now() + Math.min(30_000, 1_000 * 2 ** (startupFailures - 1));
    return current;
  };
  // Health may wait for a slow reap so a hard kill does not end in a not-ready reply; scans never wait.
  const ensureReady = async (awaitReap = false) => {
    if (fatal) throw new Error("worker unavailable");
    await checkAssets();
    if (session?.ready && !session.dead) return session;
    if (awaitReap && session?.dead && !exited(session.child)) {
      let timer;
      await Promise.race([session.gone, stopped, new Promise((resolve) => { timer = setTimeout(resolve, 15_000); })]);
      clearTimeout(timer);
      await checkAssets();
    }
    starting ??= restart().finally(() => { starting = null; });
    return starting;
  };
  const query = (current, text) => new Promise((resolve) => {
    if (current.dead) { resolve(null); return; }
    const id = createHash("sha256").update(String(Date.now())).update(String(Math.random())).digest("hex");
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; current.fail(); }, config["--scan-timeout-ms"]);
    current.waiting = (reply) => {
      clearTimeout(timer);
      if (reply && reply.id !== id) current.fail();
      resolve(reply?.id === id ? reply : { error: timedOut ? "model_killed" : "model_error" });
    };
    current.child.stdin.write(`${JSON.stringify({ id, text })}\n`);
  });
  const handle = async (request, current) => {
    if (request.type !== "scan" || !validBase64(request.body)) return { type: request.type, id: request.id, status: "unknown" };
    try {
      const original = Buffer.from(request.body, "base64");
      if (original.length === 0 || original.length > MAX_BODY_BYTES) throw new Error("invalid body");
      const scan = prepareOpfScan(original);
      if (scan.text === "") return { type: "scan", id: request.id, status: "ok", findings: [] };
      const reply = current ? await query(current, scan.text) : null;
      // Window cache hits and misses per scan, so retry convergence is visible without any request content.
      const cache = windowCounts(reply?.cache);
      if (reply?.error || !reply?.prediction) return { type: "scan", id: request.id, status: "unknown",
        reason: ["model_timeout", "model_killed"].includes(reply?.error) ? reply.error : "model_error", ...cache };
      return { type: "scan", id: request.id, ...adaptOpfPrediction(original, scan, reply.prediction), ...cache };
    } catch { return { type: "scan", id: request.id, status: "unknown" }; }
  };
  const pending = new Set();
  let scans = 0;
  let scanQueue = Promise.resolve();
  const emit = (reply) => {
    if (fatal) return;
    let frame = `${JSON.stringify(reply)}\n`;
    if (Buffer.byteLength(frame) > MAX_FRAME_BYTES) {
      frame = `${JSON.stringify({ type: reply.type, id: reply.id, status: "unknown", findings: [], reason: "redaction-frame-limit" })}\n`;
      if (Buffer.byteLength(frame) > MAX_FRAME_BYTES) { fail(); return; }
    }
    process.stdout.write(frame);
  };
  try {
    await startPython();
    input = createInterface({ input: process.stdin });
    for await (const line of input) {
      if (fatal) break;
      if (Buffer.byteLength(line) > MAX_FRAME_BYTES) { fail(); break; }
      let request;
      try { request = JSON.parse(line); } catch { continue; }
      if (!request || typeof request.id !== "string" || typeof request.type !== "string" || request.protocol !== PROTOCOL) continue;
      let task;
      if (request.type === "health") {
        task = (async () => {
          const current = await ensureReady(true);
          if (fatal) throw new Error("worker unavailable");
          emit(current && !current.dead ? { type: "health", id: request.id, protocol: PROTOCOL, version: VERSION, capabilities: CAPABILITIES }
            : { type: "health", id: request.id, status: "unknown" });
        })();
      } else if (request.type !== "scan" || !validBase64(request.body) || scans >= MAX_SCANS) {
        emit({ type: request.type, id: request.id, status: "unknown" });
        continue;
      } else {
        scans += 1;
        task = scanQueue.then(async () => {
          const reply = await handle(request, await ensureReady());
          if (reply.status === "unknown") {
            emit(reply);
            await ensureReady();
          } else {
            await checkAssets();
            emit(reply);
          }
        }).finally(() => { scans -= 1; });
        scanQueue = task.catch(fail);
      }
      const tracked = task.catch(fail).finally(() => pending.delete(tracked));
      pending.add(tracked);
    }
    await Promise.all(pending);
  } finally {
    session?.fail();
    await stopPython(session);
    process.off("SIGTERM", fail);
    process.off("SIGINT", fail);
  }
}

main().catch(() => { process.stdin.destroy(); process.exitCode = 1; });
