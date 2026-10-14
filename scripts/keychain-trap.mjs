// Preloaded by `npm test`. It puts a `security` that refuses to run first on
// PATH, so a test that forgets to inject its own fails the suite instead of
// reaching the real macOS Keychain (and prompting the user).
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";

if (!process.env.CCSHIELD_KEYCHAIN_TRAP) {
  const dir = mkdtempSync(join(tmpdir(), "ccshield-keychain-trap-"));
  const log = join(dir, "calls.log");
  writeFileSync(join(dir, "security"), `#!/bin/sh\nprintf '%s\\n' "$*" >> '${log}'\nexit 1\n`);
  chmodSync(join(dir, "security"), 0o755);
  process.env.PATH = [dir, process.env.PATH].filter(Boolean).join(delimiter);
  process.env.CCSHIELD_KEYCHAIN_TRAP = log;
  process.on("exit", () => {
    if (existsSync(log)) {
      process.stderr.write(`a test ran \`security\` without injecting a fake; calls:\n${readFileSync(log, "utf8")}`);
      process.exitCode = 1;
    }
    rmSync(dir, { recursive: true, force: true });
  });
}
