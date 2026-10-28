import assert from "node:assert/strict";
import test from "node:test";
import { Writable } from "node:stream";

import { runSessionCheck, shieldSessionCheck } from "../src/plugin/session-check.mjs";

const behind = {
  ANTHROPIC_BASE_URL: "http://127.0.0.1:48211",
  ANTHROPIC_CUSTOM_HEADERS: "x-other: 1\nx-airkit-shield: secret-cap",
};

test("a session launched through ccshield passes the check", () => {
  assert.deepEqual(shieldSessionCheck(behind), { behind: true });
});

test("a session without the shield capability header is not behind ccshield", () => {
  const result = shieldSessionCheck({ ANTHROPIC_BASE_URL: "http://127.0.0.1:48211" });
  assert.equal(result.behind, false);
  assert.match(result.message, /not behind ccshield/);
});

test("a remote base URL is not behind ccshield even with the header", () => {
  for (const url of [undefined, "", "https://api.anthropic.com", "http://127.0.0.1.evil.test:80", "not a url"]) {
    assert.equal(shieldSessionCheck({ ...behind, ANTHROPIC_BASE_URL: url }).behind, false, String(url));
  }
});

test("loopback forms are accepted", () => {
  for (const url of ["http://localhost:1", "http://[::1]:2"]) {
    assert.equal(shieldSessionCheck({ ...behind, ANTHROPIC_BASE_URL: url }).behind, true, url);
  }
});

test("an empty capability header does not count", () => {
  assert.equal(shieldSessionCheck({ ...behind, ANTHROPIC_CUSTOM_HEADERS: "x-airkit-shield:   " }).behind, false);
});

function sink() {
  let text = "";
  return { stream: new Writable({ write(chunk, _e, done) { text += chunk; done(); } }), read: () => text };
}

test("the hook prints one systemMessage warning and never the capability", async () => {
  const out = sink();
  const code = await runSessionCheck({ env: { ANTHROPIC_CUSTOM_HEADERS: "x-airkit-shield: secret-cap" }, output: out.stream });
  assert.equal(code, 0);
  const reply = JSON.parse(out.read());
  assert.deepEqual(Object.keys(reply), ["systemMessage"]);
  assert.match(reply.systemMessage, /not behind ccshield/);
  assert.doesNotMatch(out.read(), /secret-cap/);
});

test("the hook is silent when the session is behind ccshield", async () => {
  const out = sink();
  assert.equal(await runSessionCheck({ env: behind, output: out.stream }), 0);
  assert.equal(out.read(), "");
});
