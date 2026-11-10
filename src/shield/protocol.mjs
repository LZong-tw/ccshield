// Wire protocol between the daemon and its privacy workers. The value keeps the
// AirKit name so existing workers keep working; it is renamed in P5.
// The worker scripts are pinned by sha256 and run standalone, so they carry
// the literal too; test/shield-protocol.test.mjs checks they match.
export const PRIVACY_PROTOCOL = "airkit-privacy-ndjson-v1";

// Which protocol-graph rule the adapter tripped. Control details are the structural name of the field,
// built from fixed vocabularies, so they carry no request text and may be logged. Signed details name the
// finding's label (or "-") and the messageIndex.blockIndex of the signed block.
const CONTROL_DETAIL = /^control:[a-z]+:[a-z]+:(?:[a-z_]+|-)$/;
const SIGNED_DETAIL = /^signed:(?:[a-z_]+|-):\d{1,6}\.\d{1,6}$/;
const GRAPH_DETAILS = new Set(["orphan", "duplicate", "role", "id", "limit"]);

export function isGraphFailureDetail(detail) {
  return typeof detail === "string" && (GRAPH_DETAILS.has(detail) || CONTROL_DETAIL.test(detail) || SIGNED_DETAIL.test(detail));
}

// Where a hit was left untouched inside signed thinking: label, messageIndex.blockIndex and a count, never text.
export const BLOCK_LOCATION = /^\d{1,6}\.\d{1,6}$/;
