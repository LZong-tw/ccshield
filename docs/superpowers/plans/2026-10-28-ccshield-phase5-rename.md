# ccshield Phase 5 — drop the AirKit names (plan only)

Status: plan, no code. Written 2026-10-28 (Asia/Taipei) against these heads:
ccshield `main` 1d27c60, ai-runtime-kit-oss `main` 1255074, ai-runtime-kit
`main` 64f0de9. Every line number below is from those heads and will drift; the
appendix has the command that regenerates the inventory.

**Precondition: this lands after the cold-scan branches merge** (see "Ordering").

## Goal

ccshield is its own product, but it still speaks AirKit's names on the wire, on
disk and in its environment. Phase 5 replaces them with `ccshield` names without
a flag day: every running daemon, every installed launcher, every provisioned
worker and every live Claude session keeps working at each step, and every step
can be rolled back on its own.

This is the rename half of spec Phase 5 ("remove Shield from AirKit", see
`ai-runtime-kit/docs/superpowers/specs/2026-10-14-shield-standalone-product-design.md`
and `.../plans/2026-10-27-ccshield-phase4-plugin.md:29`). The phase-1 plan already
did the env half (`CCSHIELD_*` plus `src/compat-env.mjs`) and left `TODO(P5)`
markers for the rest.

## Scope decision the user has to make first (D1)

The literal task text says "remove `x-airkit-*` headers and `AIRKIT_*` env names
across ccshield, ai-runtime-kit-oss and ai-runtime-kit". The grep finds two
different families, and they should not be treated alike:

| Family | What it is | Where | Count (code + tests + user docs) |
| --- | --- | --- | --- |
| **A. Shield names** | AirKit names that ccshield inherited when Shield was split out | ccshield (all), ai-runtime-kit `tools/shield`, `docs/shield.md`, `docs/install.md:85`, `test/claude-sub.test.mjs:22` | ~150 lines, almost all in ccshield tests |
| **B. AirKit's own names** | `x-airkit-mode`, `x-airkit-request-id`, `x-airkit-audit-control`, `AIRKIT_AUDIT_*`, `AIRKIT_OSS_ENTRY`, `AIRKIT_CONFIG_DIR`, `AIRKIT_CLIENT_*`, ~40 `AIRKIT_*` *error codes* | ai-runtime-kit-oss (278 lines), ai-runtime-kit | ~300 lines |

Family B uses the product's own name. "airkit" there is not a leftover, and
most of the `AIRKIT_*` hits are not environment variables at all: they are error
codes such as `AIRKIT_AUDIT_QUERY_FAILED` [VERIFIED: `git grep -o -h -E
'AIRKIT_[A-Z0-9_]+'` in ai-runtime-kit-oss].

**Recommendation:** Phase 5 renames family A only. Family B is listed in the
appendix so it is visible. If the user wants B too, it becomes Phase 6, using
the `x-airkit-mode` sequence in §6. That sequence is the riskiest one because it
drives live routing.

The rest of this plan assumes family A unless it says otherwise.

## 1. Inventory (family A)

The full `file:line` list is in Appendix A. Summary by surface:

| Surface | Old name | Producers | Consumers | Notes |
| --- | --- | --- | --- | --- |
| Launch capability header (client → daemon) | `x-airkit-shield` | `service.mjs:482` (written into the child's `ANTHROPIC_CUSTOM_HEADERS`) | `proxy.mjs:156`, `plugin/session-check.mjs:7`, `service.mjs:804` (ready probe) | Lives in every running Claude session's environment |
| Launch id header | `x-airkit-shield-launch` | `service.mjs:483` | `proxy.mjs:282,320` | Same lifetime as above |
| Control header (CLI → daemon) | `x-airkit-shield-control` | `service.mjs:386,401,421,434,446,457` | `proxy.mjs:109,121,139,223` | The CLI and the daemon can be different builds (§3) |
| Strip-only legacy headers | `x-airkit-shield-approval`, `x-airkit-shield-approval-socket` | none in `src/` | `proxy.mjs:49-50` (stripped before upstream) | Defensive only |
| Upstream strip list | all five above | — | `proxy.mjs:47-51` | Stops a capability reaching Anthropic |
| Child-env scrub | `/^x-airkit-shield(?:-\|:)/` | — | `service.mjs:474` | Drops stale capability lines from an outer session |
| Control paths | `/_airkit/shield/{ready,diagnostics,approval-channel,image-override,destination-lease}` | `service.mjs:384,399,419,432,444,455,803` | `proxy.mjs:7,119,120,137,168` | The `/_airkit/` prefix is not in the task text but has the same problem, so it is included |
| Worker protocol | `airkit-privacy-ndjson-v1` | `protocol.mjs:5` → `privacy.mjs:119`, `opf-privacy.mjs:99` (written into `privacy-manifest.json`) | `provision.mjs:170` (exact match on the manifest), `privacy.mjs:385` (health reply), `detectors/opf/privacy-opf-worker.mjs:12,504` (drops a mismatched request without replying), `detectors/regex/privacy-worker.mjs:39,287` | Workers are pinned by sha256 in the manifest, so a byte change forces a re-provision |
| On-disk manifest | `"protocol": "airkit-privacy-ndjson-v1"` | — | live `~/.local/share/ccshield/assets/opf/<commit>-<rev>/privacy-manifest.json` | [VERIFIED: `jq .protocol` on the live manifest, read-only] |
| OPF alias placeholder | `airkit_id_<n>` | `detectors/opf/opf-adapter.mjs:304` | sent upstream inside redacted bodies and mapped back on the reply | A rename changes request bytes once; see §4 Stage A |
| Probe sentinel | `(?:CCSHIELD\|AIRKIT)_PRIVACY_PROTOCOL_PROBE_EMAIL` | `privacy.mjs:358` sends the `CCSHIELD_` form | `detectors/regex/privacy-worker.mjs:63` | Old alternation is accept-only |
| Env (old names) | `AIRKIT_SHIELD_{ROOT_DIR,LAUNCHER,SUBSCRIPTION,CAPABILITY,CONTROL_CAPABILITY,APPROVAL_CAPABILITY,APPROVAL_SOCKET,OPF_WARM_SECONDS}`, `AIRKIT_GUI_UID` | — | `compat-env.mjs:4-14` read with a warning; scrubbed via `envNamesFor` (`service.mjs:485-487`, `privacy.mjs:625-630`) | Already renamed to `CCSHIELD_*`. The map is the compatibility window, marked `TODO(P5)` |
| Constant name | `AIRKIT_LAUNCHER_ENDPOINT_ENV` | `compat-env.mjs:19` | `launchers.mjs:1,51,56,79` | Reads AirKit's `AIRCLAUDE_*_BASE_URL`; those values stay AirKit's names (`TODO(P5)` at `compat-env.mjs:18`) |
| AirKit copy of the workers | `airkit-privacy-ndjson-v1`, `AIRKIT_SHIELD_OPF_WARM_SECONDS`, `AIRKIT_PRIVACY_PROTOCOL_PROBE_EMAIL`, `airkit_id_` | `ai-runtime-kit/tools/shield/{privacy-worker,privacy-opf-worker,opf-adapter}.mjs` | `ai-runtime-kit/test/shield-privacy-worker.test.mjs` only | Stale fork. ccshield `detectors/` is the source of truth. **Delete, don't rename** |
| AirKit docs | `AIRKIT_SHIELD_SUBSCRIPTION=1` | — | `ai-runtime-kit/docs/shield.md:93,94,106,107`, `docs/install.md:85` | Already wrong: `claude-sub` now goes through `ccshield launch` unless `--no-shield` (`src/claude-sub.zsh:49-64`) |
| AirKit test fixture | `x-airkit-shield: synthetic` | — | `ai-runtime-kit/test/claude-sub.test.mjs:22` | Checks that `claude-sub` unsets inherited headers (`claude-sub.zsh:97`). Rename the fixture together with the emitter |

Out of scope (intentional "AirKit" mentions that stay):
- `src/plugin/migrate.mjs`, the README "Moving from AirKit Shield" section, and
  `src/shield/cli.mjs:74,288`. These detect or describe a real AirKit install.
- The signed policy-bundle version `airkit-subscription-opf-2026.09.30-…` in
  the live `assets-provision.json`, and AirKit's `tools/shield/airkit-*.rego`.
  Renaming them means re-signing with the company key, which is kept only in
  1Password. That needs a separate, user-gated policy release (D5).
- `docs/superpowers/**` and `reports/**` in all three repos are historical
  records (ai-runtime-kit: 38 files / 108 lines; oss: 5 files / 8 lines). They
  are not rewritten.

## 2. New names

| Old | New |
| --- | --- |
| `x-airkit-shield` | `x-ccshield-capability` |
| `x-airkit-shield-launch` | `x-ccshield-launch` |
| `x-airkit-shield-control` | `x-ccshield-control` |
| `x-airkit-shield-approval`, `-approval-socket` | no new name; kept only in the strip rule |
| `/_airkit/shield/<x>` | `/_ccshield/<x>` |
| `airkit-privacy-ndjson-v1` | `ccshield-privacy-ndjson-v1` |
| `airkit_id_<n>` | `ccshield_id_<n>` |
| `AIRKIT_SHIELD_*`, `AIRKIT_GUI_UID` | `CCSHIELD_*` (already done; only the map is removed) |
| `AIRKIT_LAUNCHER_ENDPOINT_ENV` | `LAUNCHER_ENDPOINT_ENV` (constant only; the `AIRCLAUDE_*` values stay) |

Strip rule: replace the exact list at `proxy.mjs:47-51` with a prefix rule
`/^x-(?:airkit-shield|ccshield)(?:-|$)/i` and keep it **permanently**. Stripping
the old prefix costs nothing, and it keeps an old session's capability from ever
reaching upstream. `service.mjs:474` gets the same rule.

## 3. Why the order matters: version skew in the live setup

Three parts can run different builds at the same moment:

1. **The daemon.** launchd runs the tree named in
   `~/Library/LaunchAgents/com.ccshield.subscription.plist`, currently
   `~/.local/lib/ccshield/ad346b2` [VERIFIED: grep of the plist, read-only].
   That tree is 42 commits behind ccshield `main` [VERIFIED: `git log
   --oneline ad346b2..main | wc -l`].
2. **The launcher and CLI.** `claude-sub` uses `$CCSHIELD_BIN`, then `ccshield`
   on PATH, then the **newest-mtime** install under `~/.local/lib/ccshield/*`
   (`ai-runtime-kit/src/claude-sub.zsh:53-57`). Two trees are installed now
   (`01b49e8`, `ad346b2`). If a new tree is installed and the daemon is not
   restarted, a new launcher talks to an old daemon.
3. **Running Claude sessions.** Each one holds the header names that existed
   when it was launched, baked into `ANTHROPIC_CUSTOM_HEADERS`, for as long as
   it lives.

What happens when the parts disagree:
- New launcher + old daemon: the old daemon does not know `x-ccshield-capability`.
  It answers 401 `shield_unauthorized` (`proxy.mjs:160-163`), **and it does not strip the new header**, so on any path that
  does get forwarded, the capability leaks upstream. A launcher must never emit
  a new name until it knows the daemon strips it.
- New daemon + old session: the session sends `x-airkit-shield`. If the daemon
  only accepts new names, the session breaks partway through.
- New provision + old daemon: `privacy-manifest.json` sits at a fixed path in
  the shared asset directory and is rewritten in place (`opf-privacy.mjs:21-28`).
  An old daemon that re-reads it finds a protocol it rejects
  (`provision.mjs:170`) and fails closed.

**Gate:** add a field `wire: 2` to the identity file the daemon publishes
(`shieldd.mjs:254-267`). `assertShieldIdentity` (`paths.mjs:102-135`) rebuilds a
validated object field by field, so an old CLI ignores the new field. A new CLI
emits new header names and paths **only when `identity.wire >= 2`**. Otherwise
it emits the old names. `ensureShieldReady` already reads the identity before
every launch (`service.mjs:289-321`), so no extra I/O is needed.

## 4. Stages and the compatibility window

Each stage is one branch, merged and installed separately. Every install and
daemon restart needs the user's approval. Nothing here is done by an agent.

**Stage A — accept both, emit old** (ccshield release R)
- Daemon accepts both header names on every check: `proxy.mjs:109,121,139,156,223,282,320`.
- Daemon serves both path sets.
- Prefix strip rule (§2) in the proxy and the child-env scrub.
- `session-check.mjs:7` accepts both.
- Identity publishes `wire: 2`.
- CLI and launcher emit new names only behind the gate. Against R's own daemon
  that means new names. Against an older daemon, old names.
- Protocol: `provision.mjs` and `privacy.mjs:385` accept either protocol string.
  The daemon sends **the protocol named in the manifest it loaded**, not a
  constant.
- Both workers accept either request protocol and echo it back. The worker bytes
  change, so a re-provision is needed. Provisioning **still writes the old
  string** in R, so an old daemon reading the rewritten manifest keeps working.
- `airkit_id_` → `ccshield_id_` in the adapter. It is never parsed back by name,
  so there is nothing to accept twice. Rehydration uses the per-request alias map
  [INFERENCE: read `aliasFor` (`opf-adapter.mjs:298-310`), not the reverse path;
  Stage A test 6 must confirm]. Expected cost: the redacted bytes change once,
  so each live conversation takes one prompt-cache miss on its first request
  after the install.
- Old env names are still mapped (unchanged).

**Stage B — write the new names** (release R+1; needs R's daemon running everywhere)
- Provisioning writes `ccshield-privacy-ndjson-v1` into the manifest. Worker
  bytes are unchanged from R, so the content-addressed worker directory
  (`opf-privacy.mjs:56`) is reused and only the manifest changes.
- Drop the gate fallback: the CLI refuses a daemon with `wire < 2` and says
  "restart the shield service", the same way the other identity mismatches do
  (`service.mjs:297-317`).

**Stage C — remove the old names** (release ≥ R+2)
- The daemon stops accepting `x-airkit-shield*` and `/_airkit/shield/*` on
  input. The **strip rule stays**.
- Workers and the daemon accept only the new protocol (worker bytes change, so
  another re-provision).
- Delete the `LEGACY_ENV_NAMES` map, `envNamesFor`'s second name, the
  `AIRKIT_PRIVACY_PROTOCOL_PROBE_EMAIL` alternation, and every `TODO(P5)`.
- README §"Environment variables" (`README.md:56`) loses the old-name sentence.

**Window length (D2):** at least two ccshield releases (R and R+1) **and** all
three of these conditions before C ships. `ccshield doctor` checks (a) and (b):
- (a) the launchd tree is ≥ R+1;
- (b) the provisioned manifest declares the new protocol;
- (c) no Claude session launched before R is still running. The user confirms
  this. An automatic check would have to read other processes' environments
  (`ps -E`), which is not reliable on macOS [INFERENCE: not tested].

The phase-1 plan said env names get "one release". That is too short now: the
same window covers wire names, and those last as long as a session lives.

## 5. Ordering relative to other work and live routing

1. **After cold-scan.** `feat/cold-scan-p2` (ff12a17) changes exactly this
   surface: `src/shield/{privacy,opf-privacy,proxy,opf-args,privacy-detector,paths}.mjs`,
   `detectors/opf/privacy-opf-worker.mjs`, and the adapter, privacy, proxy and
   provision tests [VERIFIED: `git diff --name-only main...feat/cold-scan-p2`].
   `feat/cold-scan-p3` does not exist as a branch yet [VERIFIED: `git branch -a`].
   Stage A branches from `main` only after p2 (and p3, if it is still planned)
   merge. Both change worker bytes, so if their installs are back to back,
   Stage A's re-provision can be the same install event (D4).
2. **Tagger.** `ai-runtime-kit` `exp/tagger-stage1` writes a prototype worker
   that speaks `airkit-privacy-ndjson-v1`
   (`docs/superpowers/plans/2026-10-19-ccshield-tagger-complement.md:71-72`).
   From Stage A on, it should read the protocol from the request it gets and
   echo it back, not hard-code either string. If it ships in ccshield before
   Stage C, the old literal still works.
3. **`x-airkit-mode` and live routing.** The live subscription path is
   `claude-sub` → ccshield → `api.anthropic.com`. `airclaude` modes go straight
   to CCR, and the managed lane has no Shield (user decision, 2026-10-05). So
   family-A renames are not on the `x-airkit-mode` routing path today
   [INFERENCE: from `claude-sub.zsh:53-64` and the managed-lane memory; not
   traced through a live request]. If the managed lane ever comes back, ccshield
   sits in front of CCR and must forward `x-airkit-mode` unchanged. The prefix
   strip rule in §2 deliberately does not match `x-airkit-mode`. Stage A adds a
   test for that.
4. **AirKit side of family A** (ai-runtime-kit, one branch, after ccshield R is installed):
   - delete the `tools/shield/` worker copies and `test/shield-privacy-worker.test.mjs`;
   - keep the `.rego` files and `sign-policy-bundle.mjs`;
   - rewrite `docs/shield.md:93-107` and `docs/install.md:85` to describe
     `ccshield launch` and `--no-shield`;
   - rename the fixture at `test/claude-sub.test.mjs:22`.

   ai-runtime-kit-oss has no family-A code left [VERIFIED: `git ls-files | grep
   -i shield` is empty in oss `src/`; its only Shield code is the audit table
   migrations, which name tables, not wire names].

## 6. If D1 includes family B: the `x-airkit-mode` sequence

Family B is not part of this phase. It is written down so the risk is visible:

- `requestedMode` (`oss src/compat/config.mjs:356-363`) returns `null` when the
  header is missing. The plugin then falls back to default routing **silently**:
  every request in a mode moves to the default lane, with no error.
- B1, the plugin accepts both: read the new name, then the old. This needs a
  CCR plugin redeploy and a CCR daemon restart. Both are user-approved, and both
  go through the runtime-update `--write` flow in the internal CLAUDE.md.
- B2: `mergedCustomHeaders` (`oss src/airkit.mjs:1220-1226`) strips both names
  and emits the new one. Check that the gateway's safe-header allowlist does not
  forward the new name upstream, as the comment at `middleware.mjs:131-135` says.
- B3: the OpenCode and Pi provider fragments printed by `airkit client`
  (`oss src/airkit.mjs:2959,2968`) live in **user-owned config that no release
  can update**. The old name has to be accepted indefinitely, or the user
  migrates those configs by hand.
- `x-airkit-request-id` and `x-airkit-audit-control` follow the same pattern:
  emit both, then drop.
- The ~40 `AIRKIT_*` error codes are an API that clients match on. Leave them.

## 7. Test plan (TDD, failing test first, per stage)

Baseline on ccshield `main` 1d27c60: 720 tests, 718 pass, 0 fail, 2 skipped;
`npm run check` 123 files, 0 failed [VERIFIED: `npm test`, `npm run check` in
the plan worktree, 2026-10-28]. Tests that pin old literals today (Appendix A has line numbers):
`test/shield-proxy.test.mjs` (~100 lines), `shield-service.test.mjs:469-493,741-761,1092,1545`,
`shieldd.test.mjs:304-789`, `shield-opf-adapter.test.mjs:205-298,930-2072`,
`shield-privacy.test.mjs:41,869,1428,1462-1463`, `shield-provision.test.mjs:25`,
`shieldd-startup.test.mjs:145`, `shield-privacy-worker.test.mjs:43`,
`plugin-session-check.test.mjs:9,35,45`, `compat-env.test.mjs:18-29`.

Stage A, red first:
1. `test/shield-wire-names.test.mjs` (new). For each control route and header,
   a request with the old name passes, a request with the new name passes, and a
   request with no name is rejected. Both header spellings are stripped before
   upstream, checked against a recording fake upstream. `x-airkit-mode` is
   forwarded.
2. Child env. `buildShieldChildEnv` with `identity.wire = 2` emits only the new
   names. Without it, only the old names. An inherited line under either name is
   scrubbed.
3. Session check. Both header spellings count as "behind ccshield".
4. Protocol. A manifest that declares either string provisions. The health reply
   must echo the declared string, and a mismatch fails closed. Each worker
   (regex and OPF) answers both request protocols. Add a negative case: an
   unknown protocol is still dropped with no reply.
5. Skew. A daemon fixture without `wire` plus the new CLI: old names are sent
   and nothing new reaches upstream.
6. Alias. A redacted body carries `ccshield_id_a`, and rehydration round-trips.
   The collision test at `shield-opf-adapter.test.mjs:205-218` is repeated with
   both prefixes in the input text.
7. Keep every existing old-literal test as it is in Stage A. Those tests are the
   proof that the old names still work.

Stage B: provision writes the new protocol. The CLI refuses `wire < 2` with the
restart message.

Stage C:
- flip the Stage A old-name "passes" cases to 401/403 (whatever the route returns today for a missing capability) (strip cases stay);
- delete `compat-env.test.mjs` legacy cases;
- run `git grep -n -E 'x-airkit-shield|/_airkit/|airkit-privacy-ndjson|airkit_id_|AIRKIT_SHIELD_|AIRKIT_GUI_UID'`
  over `src detectors test README.md` and expect only the strip rule and its
  tests.

Every stage:
- run `npm run check` and `npm test` in ccshield;
- for AirKit-side changes, run `npm test` and `npm run check` in ai-runtime-kit;
- no live daemon, no `~/.local/share/ccshield`, no paid calls: service tests use
  the injected launchctl fake.

Live smoke after each user-approved install (done by the user):
- `ccshield doctor`;
- `claude-sub -p 'Reply with exactly: OK'`;
- a session started **before** the install keeps working: send one more prompt
  in it.

## 8. Rollback

- Installs are per-commit trees (`~/.local/lib/ccshield/<sha>`). Rolling back
  means running the previous tree's own `ccshield` service install `--write`,
  which regenerates the plist and restarts the daemon (user-approved; nobody
  edits the plist by hand), and then re-provisioning OPF **from the previous
  tree**. Re-provisioning is required:
  the manifest is rewritten in place (§3), so an older daemon needs it rewritten
  with its own worker and protocol. Old worker directories are content-addressed
  and never replaced (`opf-privacy.mjs:31-37`), so their bytes are still on
  disk [VERIFIED: code comment and `stageOpfWorker`; the live directory still
  holds `worker-2130c963e012de6a`].
- Roll back from A to the previous release: safe. A emits new names only to a
  `wire: 2` daemon, so after a rollback the launcher sees no `wire` and emits old
  names. Sessions started under A carry new names that the old daemon does not
  recognise, so they lose their capability (401) and must be relaunched. The
  old daemon does not strip the new names, so this is only safe if a request
  with no recognised capability is rejected before anything is forwarded.
  [INFERENCE: `proxy.mjs:156` reads the capability before forwarding; Stage A
  test 1 must prove reject-before-forward on every route of the *previous*
  release, not just the new one.]
- Roll back from B to A: safe. A accepts both manifest protocols.
- Roll back from C to B: safe as long as the §4 conditions held when C shipped.
- AirKit-side branch: plain `git revert`. Deleting `tools/shield` copies has no
  runtime consumer [VERIFIED: `git grep 'tools/shield'` in `src/` is empty; only
  tests reference it].

## 9. Decisions for the user

- **D1.** Phase 5 = family A only (recommended), or include AirKit's own
  `x-airkit-mode` / `AIRKIT_*` (§6)?
- **D2.** Window = two releases plus the three doctor conditions (§4), or a fixed
  count?
- **D3.** New header names: `x-ccshield-capability` / `-launch` / `-control`, or
  shorter (`x-ccshield`)?
- **D4.** Should Stage A's re-provision share the same install as cold-scan's
  re-provision?
- **D5.** Rename the signed policy IDs (`airkit-subscription-…`, `airkit-*.rego`)
  later as a separate re-signed policy release, or leave them?

---

## Appendix A — family A inventory (`file:line`)

Regenerate with:

```sh
git grep -n -o -I -E 'x-airkit-[a-z0-9-]+|AIRKIT_[A-Z0-9_]+|airkit-privacy-ndjson-v[0-9]+|/_airkit/shield/[a-z-]*|airkit_id_' -- ':!docs/superpowers' ':!reports'
```

### ccshield (main 1d27c60)

- `README.md` — `AIRKIT_SHIELD_` 56
- `detectors/opf/opf-adapter.mjs` — `airkit_id_` 304
- `detectors/opf/privacy-opf-worker.mjs` — `airkit-privacy-ndjson-v1` 12
- `detectors/regex/privacy-worker.mjs` — `airkit-privacy-ndjson-v1` 4,39
- `src/compat-env.mjs` — `AIRKIT_SHIELD_ROOT_DIR` 5; `AIRKIT_GUI_UID` 6; `AIRKIT_SHIELD_LAUNCHER` 7; `AIRKIT_SHIELD_SUBSCRIPTION` 8; `AIRKIT_SHIELD_CAPABILITY` 9; `AIRKIT_SHIELD_CONTROL_CAPABILITY` 10; `AIRKIT_SHIELD_APPROVAL_CAPABILITY` 11; `AIRKIT_SHIELD_APPROVAL_SOCKET` 12; `AIRKIT_SHIELD_OPF_WARM_SECONDS` 13; `AIRKIT_LAUNCHER_ENDPOINT_ENV` 19
- `src/plugin/session-check.mjs` — `x-airkit-shield` 6,7
- `src/shield/launchers.mjs` — `AIRKIT_LAUNCHER_ENDPOINT_ENV` 1,51,56,79
- `src/shield/protocol.mjs` — `airkit-privacy-ndjson-v1` 5
- `src/shield/proxy.mjs` — `/_airkit/shield/diagnostics` 7; `x-airkit-shield` 47,156; `x-airkit-shield-control` 48,109,121,139,223; `x-airkit-shield-approval` 49; `x-airkit-shield-approval-socket` 50; `x-airkit-shield-launch` 51,282,320; `/_airkit/shield/approval-channel` 119; `/_airkit/shield/image-override` 120; `/_airkit/shield/destination-lease` 137; `/_airkit/shield/ready` 168
- `src/shield/service.mjs` — `/_airkit/shield/approval-channel` 384,399; `x-airkit-shield-control` 386,401,421,434,446,457; `/_airkit/shield/image-override` 419; `/_airkit/shield/destination-lease` 432,444,455; `x-airkit-shield` 474,482,804; `x-airkit-shield-launch` 483; `/_airkit/shield/ready` 803
- `test/compat-env.test.mjs` — `AIRKIT_SHIELD_ROOT_DIR` 18,20,21,22; `AIRKIT_SHIELD_CAPABILITY` 28,29
- `test/plugin-session-check.test.mjs` — `x-airkit-shield` 9,35,45
- `test/shield-opf-adapter.test.mjs` — `airkit_id_` 205,210,218,293,298; `airkit-privacy-ndjson-v1` 930,1594,1595,1610,1629,1640,1647,1665,1680,1708,1709,1710,1766,1834,2069,2072
- `test/shield-privacy-worker.test.mjs` — `airkit-privacy-ndjson-v1` 43
- `test/shield-privacy.test.mjs` — `airkit-privacy-ndjson-v1` 41,869,1428; `AIRKIT_SHIELD_OPF_WARM_SECONDS` 1462,1463
- `test/shield-provision.test.mjs` — `airkit-privacy-ndjson-v1` 25
- `test/shield-proxy.test.mjs` — `/_airkit/shield/destination-lease` 43,1323,1331,1335,1339,1357,1365,1369,1384,1386,1388; `x-airkit-shield-control` 44,47,54,57,65,339,1287,1295,1324,1332,1336,1339,1358,1366,1370,1383,1476; `x-airkit-shield` 47,57,61,70,162,168,218,257,286,304,318,355,373,406,436,463,546,570,573,591,617,633,665,673,695,720,739,761,786,815,856,893,921,950,985,1022,1041,1067,1078,1112,1153,1182,1187,1194,1223,1225,1253,1321,1327,1341,1362,1469,1487; `/_airkit/shield/diagnostics` 48,54,56,60,339; `/_airkit/shield/diagnostics-extra` 56; `/_airkit/shield/` 56,60; `/_airkit/shield/ready` 168,569,572,590; `x-airkit-shield-launch` 1153,1158,1195,1257,1258,1260,1264,1265,1487; `x-airkit-shield-approval` 1156,1197; `x-airkit-shield-approval-socket` 1157,1196; `/_airkit/shield/approval-channel` 1180,1288,1296; `/_airkit/shield/image-override` 1477
- `test/shield-service.test.mjs` — `x-airkit-shield` 469,474,493,758; `/_airkit/shield/ready` 474; `x-airkit-shield-launch` 741,758,1092,1545; `AIRKIT_SHIELD_CAPABILITY` 761
- `test/shieldd-startup.test.mjs` — `airkit-privacy-ndjson-v1` 145
- `test/shieldd.test.mjs` — `x-airkit-shield` 304,366,406,512,598,649,752; `/_airkit/shield/destination-lease` 359; `x-airkit-shield-control` 361; `airkit-privacy-ndjson-v1` 789
- `detectors/regex/privacy-worker.mjs` — `(?:CCSHIELD|AIRKIT)_PRIVACY_PROTOCOL_PROBE_EMAIL` 63 (alternation; not matched by the pattern above)

### ai-runtime-kit (main 64f0de9) — family A rows are `tools/shield/*`, `docs/shield.md`, `docs/install.md:85`, `test/shield-privacy-worker.test.mjs`, `test/claude-sub.test.mjs:22`; the rest is family B

- `AGENTS.md` — `AIRKIT_OSS_ENTRY` 36
- `CLAUDE.md` — `AIRKIT_OSS_ENTRY` 35,66; `x-airkit-mode` 156
- `README.md` — `AIRKIT_OSS_ENTRY` 36
- `ROADMAP.md` — `x-airkit-mode` 18
- `docs/install.md` — `AIRKIT_OSS_ENTRY` 19,425; `AIRKIT_SHIELD_SUBSCRIPTION` 85
- `docs/profile-schema.md` — `x-airkit-mode` 204
- `docs/shield.md` — `AIRKIT_SHIELD_SUBSCRIPTION` 93,94,106,107
- `gotchas.md` — `x-airkit-mode` 39,64
- `package.json` — `AIRKIT_VERIFY_PUBLISHED_INSTALL` 16
- `scripts/verify-install-dependency.mjs` — `AIRKIT_OSS_ENTRY` 19
- `src/airkit.mjs` — `AIRKIT_OSS_ENTRY` 90,92,93
- `src/claude-sub.zsh` — `AIRKIT_AUDIT_PLUGIN_DIR` 14; `AIRKIT_AUDIT_ENABLED` 101
- `src/install.mjs` — `AIRKIT_CONFIG_DIR` 42
- `test/airkit.test.mjs` — `AIRKIT_OSS_ENTRY` 20,1431; `x-airkit-mode` 915,1345
- `test/claude-sub.test.mjs` — `AIRKIT_AUDIT_ENABLED` 15; `x-airkit-shield` 22
- `test/install-dependency.test.mjs` — `AIRKIT_VERIFY_PUBLISHED_INSTALL` 6; `AIRKIT_OSS_ENTRY` 11
- `test/install.test.mjs` — `AIRKIT_CONFIG_DIR` 218
- `test/shield-privacy-worker.test.mjs` — `airkit-privacy-ndjson-v1` 43; `AIRKIT_PRIVACY_PROTOCOL_PROBE_EMAIL` 309
- `tools/shield/gitleaks-rules.toml` — `AIRKIT_SHIELD_SEMANTIC_SENTINEL` 13,22
- `tools/shield/opf-adapter.mjs` — `airkit_id_` 304
- `tools/shield/privacy-opf-worker.mjs` — `airkit-privacy-ndjson-v1` 11; `AIRKIT_SHIELD_OPF_WARM_SECONDS` 129,131
- `tools/shield/privacy-worker.mjs` — `airkit-privacy-ndjson-v1` 4,39; `AIRKIT_PRIVACY_PROTOCOL_PROBE_EMAIL` 63

## Appendix B — family B inventory, ai-runtime-kit-oss (main 1255074)

Listed for D1 only; nothing here is renamed in Phase 5. `AIRKIT_*` entries in `src/audit/*` and `src/auditd.mjs` are mostly error codes, not env names.

- `README.md` — `AIRKIT_CLIENT_TOKEN` 125; `x-airkit-mode` 243
- `docs/audit.md` — `AIRKIT_AUDIT_DATABASE_PATH` 96; `AIRKIT_AUDIT_BACKUP_DIR` 96
- `docs/completion-guard.md` — `AIRKIT_VERIFY_COMPLETION_HOST` 49
- `docs/install.md` — `x-airkit-request-id` 232
- `docs/profile-schema.md` — `AIRKIT_COMPATIBILITY_MCP_URL` 276; `AIRKIT_COMPATIBILITY_MCP_TOKEN` 277; `x-airkit-mode` 399; `AIRKIT_TASK_CAPSULE` 411
- `docs/runtime-lessons.md` — `AIRKIT_CONFIG_DIR` 36
- `native/airkit-audit-auth.swift` — `AIRKIT_AUDIT_REVEAL_UNAVAILABLE` 16
- `native/airkit-audit-keychain.swift` — `AIRKIT_AUDIT_KEYCHAIN_UNAVAILABLE` 7
- `scripts/capture-completion-contract.mjs` — `AIRKIT_VERIFY_COMPLETION_HOST` 239
- `scripts/verify-audit-core.mjs` — `AIRKIT_AUDIT` 20; `AIRKIT_GUI_UID` 27; `AIRKIT_AUDIT_DATABASE_PATH` 185; `AIRKIT_AUDIT_BACKUP_DIR` 186
- `scripts/verify-ccr3-e2e.mjs` — `AIRKIT_CONFIG_DIR` 76,90,380; `AIRKIT_E2E_SANDBOX_NONCE` 253,604; `AIRKIT_CCR_E2E_VERSION` 282; `AIRKIT_CCR_E2E_STAGED_PACKAGE` 295; `AIRKIT_E2E_EXPECTED_CLAUDE_HOME` 302,1179; `AIRKIT_E2E_AMBIENT_SENTINEL` 603,1392; `AIRKIT_COMPATIBILITY_MCP_URL` 1157,1370; `AIRKIT_COMPATIBILITY_MCP_TOKEN` 1160,1373; `x-airkit-mode` 1174,1193
- `src/airkit.mjs` — `AIRKIT_MODE_HEADER` 20,191,326,1224,1225; `x-airkit-mode` 1218,2959,2968; `AIRKIT_CLIENT_BASE_URL` 1825,2950; `AIRKIT_CLIENT_TOKEN` 1826,2951,2958,2967; `AIRKIT_COMPATIBILITY_MCP_TOKEN` 2179,2189; `AIRKIT_COMPATIBILITY_MCP_URL` 2181,2190; `AIRKIT_CONFIG_DIR` 2848; `AIRKIT_TASK_CAPSULE` 3596
- `src/audit/adapters/pi-extension.mjs` — `AIRKIT_PI_AUDIT_EVENTS_PATH` 7
- `src/audit/ccr-plugin.mjs` — `x-airkit-audit-control` 52
- `src/audit/claude-hook-runtime.mjs` — `AIRKIT_AUDIT_ROOT_DIR` 20; `AIRKIT_AUDIT_SOCKET_PATH` 21,32; `AIRKIT_AUDIT_CAPABILITY_FILE` 25; `AIRKIT_AUDIT_KEYCHAIN_HELPER` 47; `AIRKIT_SECURITY_PATH` 51; `AIRKIT_SWIFT_PATH` 52
- `src/audit/cli.mjs` — `AIRKIT_AUDIT_DATABASE_PATH` 132; `AIRKIT_AUDIT_BACKUP_DIR` 133; `AIRKIT_AUDIT_AUTH_HELPER` 136; `AIRKIT_AUDIT_KEYCHAIN_HELPER` 137; `AIRKIT_SECURITY_PATH` 139; `x-airkit-audit-control` 560
- `src/audit/daemon.mjs` — `AIRKIT_AUDIT_AUTHORIZATION_FAILED` 163; `AIRKIT_AUDIT_INVALID_PAYLOAD` 178,181; `AIRKIT_AUDIT_INVALID_STORE_RESULT` 186; `AIRKIT_AUDIT_INCOMPLETE_FRAME` 230; `AIRKIT_AUDIT_FRAME_TIMEOUT` 231; `AIRKIT_AUDITD` 251; `AIRKIT_AUDITD_TRANSPORT_ERROR` 255
- `src/audit/event.mjs` — `AIRKIT_AUDIT_INVALID_EVENT` 45
- `src/audit/export.mjs` — `AIRKIT_AUDIT_REVEAL_NONINTERACTIVE` 32,37; `AIRKIT_AUDIT_EXPORT_UNAVAILABLE` 42
- `src/audit/keychain.mjs` — `AIRKIT_AUDIT_KEYCHAIN_UNAVAILABLE` 8,50,55,75,84,88; `AIRKIT_SECURITY_PATH` 32
- `src/audit/paths.mjs` — `AIRKIT_GUI_UID` 34
- `src/audit/query.mjs` — `AIRKIT_AUDIT_QUERY_AUTHORIZATION_FAILED` 136,146; `AIRKIT_AUDIT_QUERY_INVALID_RESULT` 138; `AIRKIT_AUDIT_QUERY_INVALID_REQUEST` 146,225,228,230,233,238,253; `AIRKIT_AUDIT_QUERY_FAILED` 154,190; `AIRKIT_AUDIT_QUERY_RESPONSE_MISMATCH` 189; `AIRKIT_AUDIT_QUERY_INVALID_RESPONSE` 191; `AIRKIT_AUDIT_QUERY_TIMEOUT` 198,295; `AIRKIT_AUDIT_QUERY_CONNECTION_CLOSED` 200; `AIRKIT_AUDIT_QUERY_OPERATION_NOT_ALLOWED` 237,249; `AIRKIT_AUDIT_QUERY_LIMIT_INVALID` 261; `AIRKIT_AUDIT_QUERY_INCOMPLETE_FRAME` 294
- `src/audit/retention.mjs` — `AIRKIT_AUDIT_RETENTION_UNAVAILABLE` 23
- `src/audit/reveal-export.mjs` — `AIRKIT_AUDIT_REVEAL_UNAVAILABLE` 45,48,51,68,102,104,106,110,116; `AIRKIT_AUDIT_AUTH_HELPER` 103
- `src/audit/reveal.mjs` — `AIRKIT_AUDIT_REVEAL_UNAVAILABLE` 3; `AIRKIT_AUDIT_AUTH_HELPER` 39
- `src/audit/service.mjs` — `AIRKIT_AUDIT_CAPABILITY_FILE` 24; `AIRKIT_AUDIT_ROOT_DIR` 25; `AIRKIT_AUDIT_SOCKET_PATH` 26; `AIRKIT_AUDIT_QUERY_SOCKET_PATH` 27; `AIRKIT_AUDIT_DATABASE_PATH` 28
- `src/audit/store.mjs` — `AIRKIT_AUDIT_STORE_ERROR` 44; `AIRKIT_AUDIT_WRITER_BUSY` 71; `AIRKIT_AUDIT_VERIFY_FAILED` 373,380; `AIRKIT_AUDIT_STORE_CLOSED` 822; `AIRKIT_AUDIT_READ_ONLY` 831; `AIRKIT_AUDIT_DATABASE_CORRUPT` 900,1103; `AIRKIT_AUDIT_MIGRATION_INTERRUPTED` 911,953; `AIRKIT_AUDIT_MIGRATION_CHECKSUM_MISMATCH` 921,965; `AIRKIT_AUDIT_NEEDS_MIGRATION` 946,960; `AIRKIT_AUDIT_INVALID_REPOSITORY` 1055; `AIRKIT_AUDIT_INVALID_ENCRYPTED_PATH` 1072,1095; `AIRKIT_AUDIT_QUERY_READ_ONLY` 1124,1135
- `src/auditd.mjs` — `AIRKIT_AUDIT_CAPABILITY_FILE` 18,19; `AIRKIT_AUDIT_KEYCHAIN_HELPER` 24; `AIRKIT_AUDIT_ROOT_DIR` 29; `AIRKIT_AUDIT_SOCKET_PATH` 30; `AIRKIT_AUDIT_QUERY_SOCKET_PATH` 31; `AIRKIT_AUDIT_SPOOL_DIR` 32; `AIRKIT_AUDIT_DATABASE_PATH` 45; `AIRKIT_AUDIT_BACKUP_DIR` 46; `AIRKIT_AUDITD` 59,106; `AIRKIT_AUDITD_STOP_FAILED` 59; `AIRKIT_SECURITY_PATH` 76; `AIRKIT_SWIFT_PATH` 80; `AIRKIT_AUDITD_BOOT_FAILED` 106
- `src/codex-takeover-guard.mjs` — `AIRKIT_REPAIR_CAPTURE_FAILED` 251; `AIRKIT_REPAIR_CONFLICT` 258,281,292; `AIRKIT_REPAIR_REPLACE_FAILED` 292
- `src/codex-transcript-guard.mjs` — `AIRKIT_CODEX_TRANSCRIPT_CONFLICT` 176
- `src/compat/config.mjs` — `AIRKIT_MODE_HEADER` 62,358; `x-airkit-mode` 62
- `src/compat/gateway.mjs` — `x-airkit-request-id` 1819,1820
- `src/compat/middleware.mjs` — `AIRKIT_MODE_HEADER` 12,131,135
- `src/compat/plugin.mjs` — `x-airkit-request-id` 101,167,627
- `src/context-heartbeat.mjs` — `AIRKIT_TASK_CAPSULE` 55,56; `AIRKIT_AUDIT_ENABLED` 93,377
- `test/airkit.test.mjs` — `x-airkit-mode` 1093,1262,1281,1420,1442,1532,6026,6541,7067; `AIRKIT_NOTE` 2214,2233; `AIRKIT_HOME_MARK` 2215,2234; `AIRKIT_TASK_CAPSULE` 2832,5035,5063,5071,5088,5090,5099,5100,5115,5123,5174,5182; `AIRKIT_COMPATIBILITY_MCP_TOKEN` 3211,6165,6173,7065; `AIRKIT_COMPATIBILITY_MCP_URL` 6167,6171,7066; `AIRKIT_CLIENT_TOKEN` 7354
- `test/audit-ccr-plugin.test.mjs` — `x-airkit-audit-control` 132,138
- `test/audit-claude-ccr.test.mjs` — `AIRKIT_AUDIT_ENABLED` 97,118,162,170; `AIRKIT_AUDIT_CAPABILITY_FILE` 133; `AIRKIT_AUDIT_SOCKET_PATH` 134
- `test/audit-cli.test.mjs` — `x-airkit-audit-control` 261
- `test/audit-core-e2e.test.mjs` — `AIRKIT_AUDIT` 24
- `test/audit-core.test.mjs` — `AIRKIT_AUDIT_INVALID_EVENT` 44,53,92,100,122
- `test/audit-export.test.mjs` — `AIRKIT_AUDIT_REVEAL_UNAVAILABLE` 135; `AIRKIT_AUDIT_DATABASE_PATH` 197; `AIRKIT_AUDIT_BACKUP_DIR` 197; `AIRKIT_GUI_UID` 197
- `test/audit-keychain-reveal.test.mjs` — `AIRKIT_AUDIT_KEYCHAIN_HELPER` 51; `AIRKIT_AUDIT_REVEAL_UNAVAILABLE` 72,75,78,79,84,88,90,91
- `test/audit-pi-integration.test.mjs` — `AIRKIT_PI_AUDIT_EVENTS_PATH` 80,116,145
- `test/audit-service.test.mjs` — `AIRKIT_AUDIT_CAPABILITY_FILE` 85; `AIRKIT_AUDIT_MASTER_KEY_HEX` 86
- `test/audit-store.test.mjs` — `AIRKIT_AUDIT_MIGRATION_CHECKSUM_MISMATCH` 537; `AIRKIT_AUDIT_MIGRATION_INTERRUPTED` 562; `AIRKIT_AUDIT_VERIFY_FAILED` 606; `AIRKIT_AUDIT_WRITER_BUSY` 622; `AIRKIT_AUDIT_DATABASE_CORRUPT` 683
- `test/ccr3-e2e.test.mjs` — `AIRKIT_E2E_AMBIENT_SENTINEL` 19; `AIRKIT_E2E_SANDBOX_NONCE` 20; `AIRKIT_E2E_CONTROLLER_GUARD` 21; `AIRKIT_COMPATIBILITY_MCP_URL` 27; `AIRKIT_COMPATIBILITY_MCP_TOKEN` 28; `AIRKIT_CONFIG_DIR` 172
- `test/compat-config.test.mjs` — `AIRKIT_MODE_HEADER` 5,476,478,479,480,481,485; `x-airkit-mode` 476
- `test/compat-middleware.test.mjs` — `x-airkit-mode` 280; `x-airkit-request-id` 425
- `test/compat-plugin.test.mjs` — `x-airkit-mode` 3539,3543,3585,3640
- `test/compat-request-errors.test.mjs` — `x-airkit-request-id` 74,102,156,260,265,310,357,374,397
- `test/completion-host.test.mjs` — `AIRKIT_VERIFY_COMPLETION_HOST` 47,95
- `test/completion-install.test.mjs` — `AIRKIT_COMPLETION_MODE` 64

## Corrections and Stage A decisions (2026-10-28, Asia/Taipei)

Review corrections:

- OPF aliases are never mapped back to the original text, so there is no "rehydration". The rehydration wording and test 6 are dropped.
- Renaming the regex worker protocol (`airkit-privacy-ndjson-v1`) belongs to Stage C (D5), not Stage A/B.
- `service.mjs:803` emits the capability header (it is the probe) and does not consume it.
- No `protocol` key goes into `assets-provision.json`, because the live `ad346b2` daemon would reject it.

Stage A as implemented:

- The proxy accepts both `x-ccshield-*` and `x-airkit-shield*`, and both `/_ccshield/` and `/_airkit/shield/`. It strips both header families before forwarding upstream. If the two capability spellings arrive with different values, the request gets 401.
- The daemon writes `wire: 2` into its identity. Old CLIs ignore that field.
- The CLI uses the new names only when the identity says `wire >= 2`. Otherwise it uses the old names, so a new CLI still works with an old running daemon.
- session-check accepts either spelling.
- Verification: full suite outside the sandbox with a temp HOME. Baseline 1665d17 had 737 tests and 0 failures. This branch has 748 tests and 0 failures.
