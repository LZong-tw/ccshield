#!/usr/bin/env node

import "./quiet-sqlite.mjs";

import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { runShieldCli } from "./shield/cli.mjs";

export async function main(argv = process.argv.slice(2)) {
  return runShieldCli(argv);
}

function isDirectEntrypoint() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

if (isDirectEntrypoint()) {
  main()
    .then((exitCode) => { process.exitCode = exitCode; })
    .catch((error) => {
      process.stderr.write(`ccshield: ${error.message}\n`);
      process.exitCode = 1;
    });
}
