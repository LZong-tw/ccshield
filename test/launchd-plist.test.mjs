import assert from "node:assert/strict";
import test from "node:test";
import { describePlistDrift } from "../src/launchd-plist.mjs";

const plist = (...args) => `<?xml version="1.0"?>
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.ccshield</string>
  <key>ProgramArguments</key>
  <array>
    ${args.map((arg) => `<string>${arg}</string>`).join("\n    ")}
  </array>
</dict>
</plist>`;

test("plist drift names the program path that differs", () => {
  const message = describePlistDrift(
    plist("/usr/bin/node", "/repo/oss/src/shieldd.mjs"),
    plist("/usr/bin/node", "/pkg/node_modules/@untionglim/shield/src/shieldd.mjs"),
  );
  assert.equal(message, 'installed job runs "/repo/oss/src/shieldd.mjs", this runtime expects "/pkg/node_modules/@untionglim/shield/src/shieldd.mjs"');
});

test("plist drift decodes escaped arguments and reports missing ones", () => {
  assert.match(describePlistDrift(plist("/a&amp;b"), plist("/a&amp;b", "--x")), /runs \(nothing\), this runtime expects "--x"/);
  assert.match(describePlistDrift(plist("/a&amp;b"), plist("/c")), /runs "\/a&b"/);
});

test("plist drift outside ProgramArguments and unparseable plists stay descriptive", () => {
  assert.equal(describePlistDrift(plist("/x") + "\n", plist("/x")), "installed job differs from this runtime's plist outside ProgramArguments");
  assert.match(describePlistDrift("garbage", plist("/x")), /runs \(nothing\), this runtime expects "\/x"/);
});
