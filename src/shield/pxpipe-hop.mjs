import { spawn } from "node:child_process";
import { createServer, connect } from "node:net";

export const ANTHROPIC_ORIGIN = "https://api.anthropic.com";

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function probe(port) {
  return new Promise((resolve) => {
    const socket = connect({ host: "127.0.0.1", port });
    socket.once("connect", () => { socket.destroy(); resolve(true); });
    socket.once("error", () => resolve(false));
  });
}

// Starts a per-launch pxpipe between Shield and the gateway. Shield sees the
// pxpipe origin as its fixed target; pxpipe forwards to `upstream`. pxpipe
// only ever receives traffic Shield already redacted.
export async function startPxpipeHop({ upstream, command = "pxpipe", env = process.env, spawnProcess = spawn, timeoutMs = 10_000, owner = process } = {}) {
  const target = new URL(upstream);
  const loopback = target.hostname === "127.0.0.1" && target.protocol === "http:";
  if (!loopback && target.origin !== ANTHROPIC_ORIGIN) {
    throw new Error("pxpipe hop upstream must be a loopback http origin or the Anthropic API");
  }
  const port = await freePort();
  const child = spawnProcess(command, [], {
    env: {
      ...env,
      HOST: "127.0.0.1",
      PORT: String(port),
      PXPIPE_UPSTREAM: target.origin,
      ANTHROPIC_UPSTREAM: target.origin,
    },
    stdio: "ignore",
  });
  let exited = null;
  // A killed launcher never reaches its finally block, so the hop reaps
  // pxpipe itself and then lets the signal take its normal course.
  const reap = () => { if (exited === null) child.kill("SIGTERM"); };
  const signals = ["SIGTERM", "SIGINT", "SIGHUP"];
  const onSignal = (signal) => {
    detach();
    reap();
    owner.kill(owner.pid, signal);
  };
  const detach = () => {
    owner.off("exit", reap);
    for (const signal of signals) owner.off(signal, onSignal);
  };
  owner.on("exit", reap);
  for (const signal of signals) owner.on(signal, onSignal);
  child.once("exit", (code) => { exited = code ?? -1; detach(); });
  child.once("error", () => { exited = -1; detach(); });
  const deadline = Date.now() + timeoutMs;
  while (!(await probe(port))) {
    if (exited !== null) throw new Error(`pxpipe exited before listening (code ${exited})`);
    if (Date.now() > deadline) {
      detach();
      reap();
      throw new Error("pxpipe did not start listening in time");
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  return {
    origin: `http://127.0.0.1:${port}`,
    async close() {
      detach();
      reap();
    },
  };
}
