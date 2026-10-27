// Preloaded by `npm test`. It puts a `security` and a `secret-tool` that
// refuse to run first on PATH, so a test that forgets to inject its own fails
// the suite instead of reaching the real macOS Keychain or Linux Secret Service.
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";

if (!process.env.CCSHIELD_KEYCHAIN_TRAP) {
  const dir = mkdtempSync(join(tmpdir(), "ccshield-keychain-trap-"));
  const log = join(dir, "calls.log");
  for (const name of ["security", "secret-tool"]) {
    writeFileSync(join(dir, name), `#!/bin/sh\nprintf '%s %s\\n' '${name}' "$*" >> '${log}'\nexit 1\n`);
    chmodSync(join(dir, name), 0o755);
  }
  process.env.PATH = [dir, process.env.PATH].filter(Boolean).join(delimiter);
  process.env.CCSHIELD_KEYCHAIN_TRAP = log;
  process.on("exit", () => {
    if (existsSync(log)) {
      process.stderr.write(`a test ran \`security\` or \`secret-tool\` without injecting a fake; calls:\n${readFileSync(log, "utf8")}`);
      process.exitCode = 1;
    }
    rmSync(dir, { recursive: true, force: true });
  });
}
