// Wire protocol between the daemon and its privacy workers. The value keeps the
// AirKit name so existing workers keep working; it is renamed in P5.
// The worker scripts are pinned by sha256 and run standalone, so they carry
// the literal too; test/shield-protocol.test.mjs checks they match.
export const PRIVACY_PROTOCOL = "airkit-privacy-ndjson-v1";
