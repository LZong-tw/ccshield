// Explains why an installed launchd plist differs from the one this runtime would write.
// The common cause is a job installed by a different ccshield checkout, package or an older AirKit install, so the
// message names both program paths instead of leaving the operator to diff the files.
export function describePlistDrift(existing, expected) {
  const found = programArguments(existing);
  const wanted = programArguments(expected);
  for (let index = 0; index < Math.max(found.length, wanted.length); index += 1) {
    if (found[index] !== wanted[index]) {
      return `installed job runs ${quote(found[index])}, this runtime expects ${quote(wanted[index])}`;
    }
  }
  return "installed job differs from this runtime's plist outside ProgramArguments";
}

function programArguments(xml) {
  if (typeof xml !== "string") return [];
  const match = /<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/.exec(xml);
  if (!match) return [];
  return [...match[1].matchAll(/<string>([\s\S]*?)<\/string>/g)].map((entry) => decode(entry[1]));
}

function decode(value) {
  return value.replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&quot;", "\"").replaceAll("&apos;", "'").replaceAll("&amp;", "&");
}

function quote(value) {
  return value === undefined ? "(nothing)" : JSON.stringify(value);
}
