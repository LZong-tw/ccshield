import { readShieldOperationalStatus } from "./operational-status.mjs";

const STATUSLINE_LANES = Object.freeze(["subscription", "managed"]);
const STATUSLINE_STATES = Object.freeze(["protected", "blocked", "unavailable"]);
const STATUSLINE_DEADLINE_MS = 750;

export async function readShieldStatuslineState(options = {}) {
  const operational = await (options.readOperationalStatus ?? readShieldOperationalStatus)(options);
  return shieldStatuslineState(operational);
}

export function shieldStatuslineState(operational) {
  const lanes = Array.isArray(operational?.lanes) ? operational.lanes : [];
  const state = STATUSLINE_STATES.includes(operational?.state) ? operational.state : "unavailable";
  return Object.freeze({
    shield: state,
    lanes: Object.freeze(lanes.map((lane) => Object.freeze({
      lane: lane.lane,
      state: lane.state,
      approval: lane.state === "protected" ? "available" : "blocked",
    }))),
  });
}

// The suffix reports each lane separately. The aggregate `shield` field is
// "protected" as soon as any lane is, so printing it beside a session that
// runs on an unprotected lane would assert protection the lane does not have.
// Approval is a restatement of the same per-lane predicate, so it is not
// printed as if it were an independent signal. Lane and state names are read
// back through fixed enums: a corrupt operational payload cannot widen this.
export function shieldStatuslineSuffix(state) {
  const lanes = Array.isArray(state?.lanes) ? state.lanes : [];
  const rendered = STATUSLINE_LANES.map((lane) => {
    const entry = lanes.find((candidate) => candidate?.lane === lane);
    return ` ${lane}:${STATUSLINE_STATES.includes(entry?.state) ? entry.state : "unavailable"}`;
  }).join("");
  return ` · Shield${rendered}`;
}

export async function runShieldStatusline({
  env = process.env,
  input = process.stdin,
  output = process.stdout,
  readOperationalStatus = readShieldOperationalStatus,
  runSubagentStatusLine,
  deadlineMs = STATUSLINE_DEADLINE_MS,
} = {}) {
  const state = await withStatuslineDeadline(readShieldStatuslineState({ env, readOperationalStatus }), deadlineMs);
  const runner = runSubagentStatusLine ?? (await import("../subagent-observability.mjs")).runSubagentStatusLine;
  return runner({ env, input, output, statuslineSuffix: shieldStatuslineSuffix(state) });
}

// Reading operational status spawns launchctl per lane, and the statusline
// refreshes every second. Bound it: a stalled probe degrades the suffix to
// "unavailable" instead of holding back the task rows that already render.
async function withStatuslineDeadline(pending, deadlineMs) {
  const budget = Number.isFinite(deadlineMs) && deadlineMs > 0 ? deadlineMs : STATUSLINE_DEADLINE_MS;
  let timer = null;
  const expired = new Promise((settle) => {
    timer = setTimeout(() => settle(null), budget);
    timer.unref?.();
  });
  try {
    return (await Promise.race([pending.catch(() => null), expired])) ?? shieldStatuslineState(null);
  } finally {
    clearTimeout(timer);
  }
}
