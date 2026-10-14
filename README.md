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

## License

MIT. See `LICENSE` and `NOTICE`.
