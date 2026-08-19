# pwnkit mobile support issue drafts

Date: 2026-05-31

`gh` authentication was unavailable in this workspace, so these are ready-to-file
GitHub issue drafts rather than created GitHub issues.

## Issue 1: Add a CLI mobile static intake mode for APK/IPA artifacts

Status update: the core passive extractor now exists as
`runMobileStaticIntake()` in `packages/core/src/mobile/intake.ts`. This issue is
now about wiring it into the CLI and expanding artifact support beyond extracted
directories/manifests.

### Problem

pwnkit can audit web apps, APIs, packages, source trees, and kernel artifacts,
but it has no first-class intake path for native mobile app artifacts. Bug bounty
programs commonly list iOS/Android apps alongside backend API wildcard scopes,
so pwnkit needs a mobile entry point that can safely extract metadata and network
indicators without executing the app.

### Proposed scope

- Add a `mobile` scan target type for local `.apk`, `.aab`, `.ipa`, and
  extracted app directories.
- Extract app metadata:
  - Android package id, version, SDK targets, permissions, exported components,
    intent filters, deep links.
  - iOS bundle id, version, entitlements, URL schemes, associated domains.
- Extract candidate network indicators:
  - hostnames, URLs, certificate pinning libraries/config hints, API path
    constants, GraphQL endpoints, websocket endpoints.
- Write extracted endpoints into the existing scope-aware web/API audit handoff.
- Flag indicators that are out of scope instead of probing them.

### Non-goals

- No jailbreak/root-only runtime exploitation.
- No automated bypass of certificate pinning.
- No broad live scanning of extracted endpoints.
- No submission-ready findings from static extraction alone.

### Likely files/modules

- `packages/cli/src/commands/run.ts` for CLI option plumbing.
- `packages/core/src/targets/*` or a new `packages/core/src/mobile/*` module for
  target classification and artifact parsing.
- `packages/core/src/scope/*` for endpoint-to-scope handoff.
- `packages/core/src/agent/prompts.ts` or mode-specific prompt construction for
  mobile static-review instructions.
- `docs/src/content/docs/commands.md` and `docs/src/content/docs/recipes.md`.

### Acceptance criteria

- `pwnkit scan --target ./app.apk --mode mobile --scope ./scope.json` runs a
  static-only mobile intake.
- Out-of-scope extracted hosts are recorded but never requested. The core helper
  already classifies endpoints with `ScopePolicy`; the CLI must preserve that
  fail-closed behavior.
- In-scope extracted hosts can be handed to web/API audit only after explicit
  user confirmation or a dedicated flag.
- Unit tests cover Android/iOS metadata extraction from fixtures.
- Docs warn that mobile static intake is not a full mobile pentest.

## Issue 2: Add mobile endpoint extraction fixtures and scope-gate tests

### Problem

Mobile support must prove that extracted hosts cannot escape the engagement
scope. The existing web scope gate is strong, but mobile extraction creates many
candidate endpoints from untrusted binaries and config files.

### Proposed scope

- Add small synthetic Android and iOS fixture directories with manifests/plists
  and string resources containing mixed in-scope/out-of-scope endpoints.
- Test wildcard matching for extracted `*.sbbmobile.ch`-style hosts.
- Test that out-of-scope endpoints are included in passive evidence but blocked
  from HTTP tools and shell URL preflight.
- Test attribution headers/UA still apply only to in-scope requests.

### Likely files/modules

- `packages/core/src/mobile/__fixtures__/`.
- `packages/core/src/mobile/*.test.ts`.
- Existing scope tests in `packages/core/src/scope/*.test.ts`.

### Acceptance criteria

- Fixture extraction returns both in-scope and out-of-scope indicators.
- Any attempted request to an out-of-scope extracted host fails before network
  execution.
- Tests run under `pnpm --filter @pwnkit/core test`.

## Issue 3: Add a bug-bounty-safe mobile-to-backend workflow

### Problem

Programs like SBB's Intigriti scope allow mobile/API testing but forbid automatic
scanner behavior. pwnkit needs a workflow that keeps mobile-derived backend
testing explicit, rate-limited, attributed, and human-gated.

### Proposed scope

- Add a `--mobile-endpoint-report <path>` output from static intake.
- Add a separate command or flag to import selected endpoints into a web/API
  audit.
- Require a scope file for any live request generated from mobile extraction.
- Default to `max 2 RPS` for mobile-derived live checks unless overridden lower
  than the program limit.
- Add a summary that records:
  - extracted hosts;
  - in-scope selected hosts;
  - blocked hosts;
  - RPS cap;
  - attribution identity;
  - whether generic-scanner suppression was active.

### Acceptance criteria

- Mobile intake never sends live requests by default.
- Live backend audit requires explicit endpoint selection.
- Summary is suitable for manual report QA, but does not imply report readiness.

## Issue 4: Research dynamic mobile instrumentation as a separate phase

### Problem

Full mobile pentesting needs emulator/simulator operation, proxy capture, and
optional instrumentation. That is materially different from pwnkit's current
web/source/package architecture and should not be bolted into the first static
intake PR.

### Proposed scope

- Compare Android emulator + mitmproxy + Frida/objection integration options.
- Compare iOS simulator limitations vs physical device workflows.
- Design an evidence model for captured requests and user actions.
- Define policy safeguards:
  - no certificate pinning bypass unless explicitly authorized;
  - no root/jailbreak-only exploit reports when a program excludes them;
  - no credential harvesting or third-party token leakage.

### Deliverable

A design document with architecture, constraints, and a staged implementation
plan. No code in this issue.
