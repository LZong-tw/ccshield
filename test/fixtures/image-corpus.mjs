import { chmod, mkdtemp, realpath, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Header-only PNG: enough for limits/dimension checks, never decoded.
export function png(width, height, extra = 0) {
  const b = Buffer.alloc(33 + extra);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(b);
  b.writeUInt32BE(13, 8);
  b.write("IHDR", 12, "latin1");
  b.writeUInt32BE(width, 16);
  b.writeUInt32BE(height, 20);
  return b;
}

// Body of a fake image worker. `reply(request)` returns the line(s) to write,
// as an object, a raw string, or null for silence.
const behaviours = {
  echo: `(req) => {
    if (req.op === "probe") return { v: 1, id: req.id, ok: true, worker: "image-fake00000000", languages: ["en-US"] };
    if (req.op === "ocr") return { v: 1, id: req.id, ok: true, width: 4, height: 2, regions: [{ text: "alice@example.invalid", confidence: 0.9, rect: { x: 0, y: 0, w: 4, h: 2 } }] };
    if (req.op === "mask") return { v: 1, id: req.id, ok: true, width: 4, height: 2, image: req.image };
  }`,
  error: `(req) => ({ v: 1, id: req.id, ok: false, code: "multi_frame" })`,
  huge: `(req) => "x".repeat(3 * 1024 * 1024)`,
  silent: `() => null`,
  wrongId: `(req) => ({ v: 1, id: req.id + 100, ok: true, worker: "image-fake00000000", languages: [] })`,
  garbage: `() => "not json"`,
  leaky: `(req) => ({ v: 1, id: req.id, ok: false, code: "ocr_failed", message: "alice@example.invalid" })`,
  exit: `() => process.exit(3)`,
  badRect: `(req) => ({ v: 1, id: req.id, ok: true, width: 4, height: 2, regions: [{ text: "a", confidence: 0.9, rect: { x: 0.5, y: 0, w: 1, h: 1 } }] })`,
  pid: `(req) => ({ v: 1, id: req.id, ok: true, worker: "image-" + String(process.pid).padStart(12, "0"), languages: [] })`,
};

export async function fakeWorker(behaviour = "echo") {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "shield-image-worker-")));
  await chmod(dir, 0o700);
  const path = join(dir, "image-worker");
  const source = `#!${process.execPath}
const reply = ${behaviours[behaviour]};
let buffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  let index;
  while ((index = buffer.indexOf("\\n")) !== -1) {
    const line = buffer.slice(0, index);
    buffer = buffer.slice(index + 1);
    const out = reply(JSON.parse(line));
    if (out == null) continue;
    process.stdout.write((typeof out === "string" ? out : JSON.stringify(out)) + "\\n");
  }
});
`;
  await writeFile(path, source, { mode: 0o755 });
  await chmod(path, 0o755);
  return { dir, path };
}
