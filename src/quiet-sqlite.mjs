// node:sqlite is still experimental on Node 22-24 and warns once on load.
// Entry points import this module first so the warning never reaches CLI
// output or the daemon's stderr, which carries only fixed diagnostics.
// Every other warning still goes through.
const emitWarning = process.emitWarning.bind(process);

process.emitWarning = (warning, ...rest) => {
  const type = typeof rest[0] === "string" ? rest[0] : rest[0]?.type;
  const message = typeof warning === "string" ? warning : warning?.message;
  if ((type === "ExperimentalWarning" || warning?.name === "ExperimentalWarning") && /SQLite/.test(String(message))) return;
  emitWarning(warning, ...rest);
};
