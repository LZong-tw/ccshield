#!/usr/bin/env node
import { runShieldStatusline } from "../shield/statusline-state.mjs";

runShieldStatusline().catch(() => process.stdout.write("Shield unavailable\n"));
