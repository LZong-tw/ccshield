import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { createServer } from "node:net";
import test from "node:test";

import { startPxpipeHop } from "../src/shield/pxpipe-hop.mjs";

function fakeSpawn(record) {
  return (command, args, options) => {
    const child = new EventEmitter();
    const server = createServer().listen(Number(options.env.PORT), "127.0.0.1");
    child.kill = () => { record.killed = true; server.close(); };
    Object.assign(record, { command, args, env: options.env });
    return child;
  };
}

test("pxpipe hop forwards to the given loopback upstream and closes", async () => {
  const record = {};
  const hop = await startPxpipeHop({ upstream: "http://127.0.0.1:4000/x", env: {}, spawnProcess: fakeSpawn(record) });
  assert.equal(record.env.PXPIPE_UPSTREAM, "http://127.0.0.1:4000");
  assert.equal(record.env.ANTHROPIC_UPSTREAM, "http://127.0.0.1:4000");
  assert.equal(record.env.HOST, "127.0.0.1");
  assert.equal(hop.origin, `http://127.0.0.1:${record.env.PORT}`);
  await hop.close();
  assert.equal(record.killed, true);
});

test("pxpipe hop refuses arbitrary remote upstreams", async () => {
  await assert.rejects(startPxpipeHop({ upstream: "https://example.com", spawnProcess: () => assert.fail("spawned") }), /loopback http origin or the Anthropic API/);
});

test("pxpipe hop reports an early exit", async () => {
  const spawnProcess = () => {
    const child = new EventEmitter();
    child.kill = () => {};
    setImmediate(() => child.emit("exit", 2));
    return child;
  };
  await assert.rejects(startPxpipeHop({ upstream: "http://127.0.0.1:4000", spawnProcess }), /exited before listening \(code 2\)/);
});

test("pxpipe hop reaps pxpipe when the launcher is signalled, then re-raises", async () => {
  const record = {};
  const owner = new EventEmitter();
  owner.pid = 4242;
  const raised = [];
  owner.kill = (pid, signal) => raised.push([pid, signal]);
  await startPxpipeHop({ upstream: "http://127.0.0.1:4000", env: {}, spawnProcess: fakeSpawn(record), owner });
  owner.emit("SIGTERM", "SIGTERM");
  assert.equal(record.killed, true);
  assert.deepEqual(raised, [[4242, "SIGTERM"]]);
  assert.equal(owner.listenerCount("SIGTERM"), 0);
  assert.equal(owner.listenerCount("exit"), 0);
});

test("pxpipe hop close drops its process listeners", async () => {
  const owner = new EventEmitter();
  owner.kill = () => assert.fail("re-raised");
  const hop = await startPxpipeHop({ upstream: "http://127.0.0.1:4000", env: {}, spawnProcess: fakeSpawn({}), owner });
  await hop.close();
  assert.equal(owner.listenerCount("SIGINT"), 0);
  assert.equal(owner.listenerCount("exit"), 0);
});
