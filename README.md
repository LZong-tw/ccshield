# ccshield

> **Not usable yet.** This is the phase-1 package skeleton. There is no
> installer, no detector assets and no Claude Code plugin yet. Do not install it.

`@untionglim/shield` (`ccshield`) is a local proxy that sits between Claude Code
and the Anthropic API. It blocks or redacts secrets and personal data before a
request leaves the machine and keeps an encrypted local audit log of what it
changed.

## Terms of Service

On the subscription lane, ccshield rewrites the body of Claude Pro/Max OAuth
requests. Doing so **may** conflict with Anthropic's Consumer Terms. You decide
whether to use it there.

## Library API

The package entry point (`import … from "@untionglim/shield"`) exports only
what launchers need. Every other module under `src/` is internal and may change.

| Export | Purpose |
| --- | --- |
| `ensureShieldReady({ lane, env })` | Check that the lane's daemon is installed, running and bound to the current policy; returns its loopback identity. |
| `buildShieldChildEnv(ready, env)` | Environment for a Claude Code child that sends its traffic through the shield. Strips shield capabilities from the child. |
| `startPxpipeHop({ upstream, env })` | Start a local `pxpipe` hop in front of the shield. |
| `resolveShieldLauncher(options)`, `resolveShieldLauncherMarker(env)`, `shieldLauncherDescriptors(options)` | Declared launcher coverage and bypasses. |
| `readShieldStatus({ env })` | Per-lane operational status plus the status-line projection and suffix. Never throws. |

Environment variables use the `CCSHIELD_` prefix. The older `AIRKIT_SHIELD_*`
names are still read for one release, with a deprecation warning.

## Audit log and key storage

Every decision is written to a per-lane SQLite database. For redactions it also
stores the original and forwarded text, encrypted with AES-256-GCM, and deletes
that text after 30 days by default (`auditRetentionDays` in the lane config).
The metadata is kept.

The master key lives in the macOS Keychain (item `ccshield` /
`audit-master-key`), written through the built-in `security` tool. The first
time a new `node` binary reads it, macOS may show an access prompt; choose
"Always Allow". If the Keychain is unavailable, the key goes to
`~/.config/ccshield/master.key` (mode 0600) and `doctor` warns about it. A key
file with looser permissions is refused. Linux Secret Service support is
planned.

## Threat model: OPF window cache

The OPF detector can keep model logits for complete 4096-token windows on disk,
so a restarted worker does not rescan the same conversation prefix. The cache
stores logits only, never a privacy decision; every scan still runs the full
detector over them.

- Entries are plaintext logits in files of mode 0600 inside a 0700 directory
  owned by the current user. Anyone running as that user can read or replace
  them.
- There is no HMAC or Keychain key. Forging an entry already requires the same
  uid, and that uid can bypass the Shield outright by changing
  `ANTHROPIC_BASE_URL`, so a key would add management cost without adding
  protection. A trailing SHA-256 checksum catches truncation and corruption.
- Each entry is keyed by the model namespace, a fingerprint of the numeric
  runtime (torch, Python, NumPy, CPU capability, build config), and the exact
  tokens and mask. Any mismatch is a miss.
- A damaged, misplaced, symlinked or loosely permissioned entry is deleted and
  recomputed. An unsafe cache directory disables the disk tier. Either way the
  cost is speed, never a different result.
- The partial tail window of a conversation is never written to disk.
- root and administrator accounts are out of scope: they can change the Shield
  itself.

## License

MIT. See `LICENSE` and `NOTICE`.
