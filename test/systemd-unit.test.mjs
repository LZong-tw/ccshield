import assert from "node:assert/strict";
import test from "node:test";
import { describeUnitDrift, renderUnit, unitExecArgs, unitLabel } from "../src/systemd-unit.mjs";

const base = { nodePath: "/usr/bin/node", daemonPath: "/opt/ccshield/src/shieldd.mjs", configPath: "/home/u/.local/share/ccshield/subscription/config.json", label: "com.ccshield.subscription" };

test("unit runs shieldd as a simple service that restarts on failure", () => {
  const unit = renderUnit(base);
  assert.match(unit, /^\[Service\]$/m);
  assert.match(unit, /^Type=simple$/m);
  assert.match(unit, /^Restart=on-failure$/m);
  assert.match(unit, /^WantedBy=default\.target$/m);
  assert.equal(unitLabel(unit), base.label);
  assert.doesNotMatch(unit, /^Environment/m);
  assert.deepEqual(unitExecArgs(unit), [base.nodePath, base.daemonPath, "--config", base.configPath]);
});

test("unit arguments survive systemd quoting, specifiers and variable expansion", () => {
  const daemonPath = "/opt/odd dir/100% \"quoted\" $HOME\\x/shieldd.mjs";
  const unit = renderUnit({ ...base, daemonPath });
  assert.match(unit, /100%% /);
  assert.match(unit, /\$\$HOME/);
  assert.deepEqual(unitExecArgs(unit), [base.nodePath, daemonPath, "--config", base.configPath]);
});

test("unit rendering rejects control characters and missing fields", () => {
  assert.throws(() => renderUnit({ ...base, daemonPath: "/opt/a\nExecStartPre=/bin/sh" }), /control characters/);
  assert.throws(() => renderUnit({ ...base, label: "x\nUser=root" }), /control characters/);
  assert.throws(() => renderUnit({ ...base, configPath: undefined }), /configPath is required/);
});

test("unit drift names the program path that differs", () => {
  const message = describeUnitDrift(renderUnit(base), renderUnit({ ...base, daemonPath: "/pkg/node_modules/ccshield/src/shieldd.mjs" }));
  assert.equal(message, "installed unit runs \"/opt/ccshield/src/shieldd.mjs\", this runtime expects \"/pkg/node_modules/ccshield/src/shieldd.mjs\"");
});

test("unit drift outside ExecStart says so", () => {
  const unit = renderUnit(base);
  assert.equal(describeUnitDrift(unit.replace("Restart=on-failure", "Restart=always"), unit), "installed unit differs from this runtime's unit outside ExecStart");
  assert.match(describeUnitDrift("garbage", unit), /installed unit runs \(nothing\)/);
});

test("unit pins XDG_DATA_HOME so the daemon recomputes the CLI's state root", () => {
  const unit = renderUnit({ ...base, dataHome: "/data/100% $x" });
  assert.match(unit, /^Environment="XDG_DATA_HOME=\/data\/100%% \$x"$/m);
  assert.deepEqual(unitExecArgs(unit), [base.nodePath, base.daemonPath, "--config", base.configPath]);
  assert.throws(() => renderUnit({ ...base, dataHome: "/data\nExecStartPre=/bin/sh" }), /control characters/);
});
