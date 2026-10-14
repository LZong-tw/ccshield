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

## License

MIT. See `LICENSE` and `NOTICE`.
