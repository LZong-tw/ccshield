import { readShieldOperationalStatus } from "./shield/operational-status.mjs";
import { shieldStatuslineState, shieldStatuslineSuffix } from "./shield/statusline-state.mjs";
import { readAuditHealth } from "./store.mjs";

const UNAVAILABLE = Object.freeze({ state: "unavailable", lanes: [] });

// One status read for every consumer: operational detail, the neutral
// statusline projection and its rendered suffix. Never throws; a failed read
// reports both lanes unavailable.
export async function readShieldStatus({
  env = process.env,
  audit = readAuditHealth,
  readOperationalStatus = readShieldOperationalStatus,
} = {}) {
  let operational;
  try {
    operational = await readOperationalStatus({ env, audit });
  } catch {
    operational = UNAVAILABLE;
  }
  const statusline = shieldStatuslineState(operational);
  return Object.freeze({
    ...operational,
    statusline,
    statuslineSuffix: shieldStatuslineSuffix(statusline),
  });
}
