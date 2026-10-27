#!/usr/bin/env node
// SPDX-License-Identifier: MPL-2.0
// Synthetic-only eval of the image pipeline: detection and masking per corpus
// case, then inspect() latency and RSS at k = 1, 3 and 8 images per request.
//
//   HOME=<temp> node tools/image-eval.mjs <workdir> [<assets-provision.json>]
//
// With a provision path, the privacy filter runs from its `privacy` entry (OPF)
// and that install is only read. Without one, the regex worker is used. Needs
// xcrun and Vision, so it runs outside the sandbox. Prints Markdown.
import { execFileSync } from "node:child_process";
import { mkdir, readFile, realpath } from "node:fs/promises";
import { join } from "node:path";

import { createImageInspector } from "../shield-image/inspector.mjs";
import { CORPUS, openNativeHarness, reads, renderCorpus } from "../test/fixtures/image-corpus/native-corpus.mjs";

const [workArg, provisionPath] = process.argv.slice(2);
if (!workArg) throw new Error("usage: image-eval.mjs <workdir> [<assets-provision.json>]");
await mkdir(workArg, { recursive: true, mode: 0o700 });
const work = await realpath(workArg);
const corpusDir = await renderCorpus(join(work, "corpus"));
const privacyProvision = provisionPath ? JSON.parse(await readFile(provisionPath, "utf8")).privacy : undefined;
const harness = await openNativeHarness(work, { privacyProvision });
await harness.worker.probe();
const inspector = () => createImageInspector({ ...harness, timeoutMs: 60_000 });
const out = (line = "") => process.stdout.write(`${line}\n`);

// OPF names its labels differently from the regex worker. Scoring maps them onto
// the corpus vocabulary; anything unmapped (e.g. private_date) counts as a false
// positive. The card number is the corpus's only account number.
const SAME_AS = { private_email: "email", private_person: "person", private_phone: "phone", private_address: "address", account_number: "credit-card" };

out(`Privacy detector: \`${harness.versions.privacy}\`. Gitleaks ${harness.versions.gitleaks}. Synthetic only.`);
if (privacyProvision) out(`Label mapping for scoring: ${Object.entries(SAME_AS).map(([from, to]) => `\`${from}\` = \`${to}\``).join(", ")}.`);
out();
out("| Case | Truth | Detected | Masked and re-OCR clean | Kept text readable | Outcome |");
out("| --- | --- | --- | --- | --- | --- |");
let tp = 0, fn = 0, fp = 0, masked = 0, maskedOf = 0, rejectOk = 0, rejectOf = 0;
for (const entry of CORPUS) {
  const bytes = await readFile(join(corpusDir, entry.file));
  if (entry.rejected) {
    rejectOf += 1;
    let code;
    try { await inspector().inspect([{ bytes, lastTurn: true }]); code = "accepted"; } catch (error) { code = error.code; }
    if (code === "image_rejected") rejectOk += 1;
    out(`| ${entry.file} | refuse | – | – | – | ${code === "image_rejected" ? "rejected" : `**${code}**`} |`);
    continue;
  }
  const truth = entry.secret ? ["secret"] : (entry.truth ?? entry.pii);
  const [result] = await inspector().inspect([{ bytes, lastTurn: true }]);
  const detected = result.status === "secret" ? ["secret"] : result.piiFindings.map((finding) => SAME_AS[finding.label] ?? finding.label);
  const hits = truth.filter((label) => detected.includes(label));
  tp += hits.length;
  fn += truth.length - hits.length;
  fp += detected.filter((label) => !truth.includes(label)).length;
  let clean = "–";
  let kept = "–";
  if (result.status === "ok") {
    const page = await harness.worker.ocr(result.bytes);
    if (entry.gone.length) {
      maskedOf += 1;
      const ok = entry.gone.every((text) => !reads(page.regions, text));
      if (ok) masked += 1;
      clean = ok ? "yes" : "**no**";
    }
    if (entry.kept.length) kept = entry.kept.every((text) => reads(page.regions, text)) ? "yes" : "**no**";
  }
  const miss = truth.length !== hits.length || detected.length !== hits.length;
  out(`| ${entry.file} | ${truth.join(", ") || "none"} | ${detected.join(", ") || "none"} | ${clean} | ${kept} | ${result.status === "secret" ? "blocked" : result.maskCount > 0 ? "forwarded masked" : "forwarded, normalized only"}${miss ? " (mismatch)" : ""} |`);
}
out();
const ratio = (a, b) => (b === 0 ? "n/a" : `${a}/${b} = ${(a / b).toFixed(2)}`);
out(`Precision ${ratio(tp, tp + fp)}. Recall ${ratio(tp, tp + fn)}. Masking verified ${ratio(masked, maskedOf)}. Refusals ${ratio(rejectOk, rejectOf)}.`);
out();

// Latency: distinct PII images, a fresh inspector per request so nothing is cached.
const pool = await Promise.all(["english.png", "chinese.png", "rotated.png", "exif.jpg", "alpha.png", "dark.png", "ui-12.png", "card.png"].map((file) => readFile(join(corpusDir, file))));
// Every descendant of this process: the image worker, and the privacy worker
// with its children (OPF keeps the model in a Python child, not the Node adapter).
const rss = () => {
  const rows = execFileSync("/bin/ps", ["-axo", "pid=,ppid=,rss=,command="], { encoding: "utf8" }).trim().split("\n")
    .map((row) => { const [pid, ppid, kb, ...command] = row.trim().split(/\s+/); return { pid, ppid, kb: Number(kb), command: command.join(" ") }; });
  const tree = new Set([String(process.pid)]);
  for (let grew = true; grew;) {
    grew = false;
    for (const row of rows) if (tree.has(row.ppid) && !tree.has(row.pid)) { tree.add(row.pid); grew = true; }
  }
  tree.delete(String(process.pid));
  const mine = rows.filter((row) => tree.has(row.pid) && !row.command.startsWith("/bin/ps"));
  const worker = mine.filter((row) => row.command.startsWith(join(work, "bin")));
  const total = (list) => Math.round(list.reduce((sum, row) => sum + row.kb, 0) / 1024);
  return { worker: total(worker), privacy: total(mine.filter((row) => !worker.includes(row))) };
};
const percentile = (values, p) => [...values].sort((a, b) => a - b)[Math.min(values.length - 1, Math.ceil((p / 100) * values.length) - 1)];
out("| k | Runs | p50 ms | p95 ms | Max ms | Worker RSS MB | Privacy RSS MB |");
out("| --- | --- | --- | --- | --- | --- | --- |");
for (const k of [1, 3, 8]) {
  const times = [];
  let peak = { worker: 0, privacy: 0 };
  for (let run = 0; run < 20; run += 1) {
    const images = Array.from({ length: k }, (_, index) => ({ bytes: pool[(run + index) % pool.length], lastTurn: true }));
    const started = performance.now();
    await inspector().inspect(images);
    times.push(performance.now() - started);
    const now = rss();
    peak = { worker: Math.max(peak.worker, now.worker), privacy: Math.max(peak.privacy, now.privacy) };
  }
  out(`| ${k} | ${times.length} | ${percentile(times, 50).toFixed(0)} | ${percentile(times, 95).toFixed(0)} | ${Math.max(...times).toFixed(0)} | ${peak.worker} | ${peak.privacy} |`);
}
harness.close();
