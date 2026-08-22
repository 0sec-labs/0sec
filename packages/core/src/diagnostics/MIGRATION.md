# Migrating core's raw terminal writes to the diagnostics channel

`packages/core` used to talk to the operator by writing straight to the
terminal. The interactive console is a full-screen OpenTUI app that owns every
cell on screen and repaints differentially, so any write it did not originate
desynchronizes its model of the display: ghost header rows, characters from one
widget appearing inside another, a garbled status line.

`packages/cli/src/tui/output-guard.ts` contains the damage while the TUI is
mounted. `src/diagnostics/channel.ts` removes the cause. This file tracks the
migration from the former to the latter.

## Status

| | count |
|---|---|
| Grep matches in non-test core code before the migration | 68 |
| Migrated (`runtime/llm-api.ts`, `agentic-scanner.ts`) | 17 |
| Grep matches now (outside `src/diagnostics/`) | 51 |
| — of those, comments / string literals, not writes | 13 |
| — of those, deliberate protocol writes that must stay raw | 3 |
| **Real sites remaining** | **35** |

`35` is the number that has to reach zero. The `13` false positives are listed
at the bottom so nobody re-greps and re-triages them; the `3` protocol writes
are listed as permanent exclusions.

Reproduce the count:

```sh
grep -rn --include='*.ts' -E 'process\.(stderr|stdout)\.write|console\.(log|warn|error|info|debug|trace)' \
  packages/core/src | grep -v '\.test\.ts:' | grep -v '/__tests__/' | grep -v '/diagnostics/'
```

## How to migrate one site

```ts
import { diag } from "../diagnostics/channel.js";   // adjust depth

// before
process.stderr.write(`[0sec] ${provider} HTTP ${status} — backoff ${delay}ms (retry ${n}/${max})\n`);

// after
diag.warn("retry_backoff", `${provider} HTTP ${status} — backoff ${delay}ms`, {
  provider, status, delay_ms: delay, attempt: n, max_retries: max,
});
```

Rules:

- **The `code` is the API.** Consumers switch on it; the prose is free to
  change. Reuse a slug already in this file rather than inventing a synonym.
- **Detail goes in `fields`, not in the message.** Anything a consumer might
  want to read programmatically — an id, a count, a duration, a status — is a
  field. The message is the one-line human summary.
- **No `\n`, no ANSI, no `[0sec]` prefix.** The channel adds the prefix and the
  newline, and strips escapes. Drop them from the message.
- **Level.** `error` = the run is degraded or a capability is gone.
  `warn` = something was skipped, retried, or dropped and the run continues.
  `info` = banners, debug traces, and anything already behind an env gate.
- **Keep existing env gates.** `if (process.env["0SEC_DEBUG"])` stays exactly
  where it is; the channel changes the destination, not the policy.
- Behaviour for non-TUI users is unchanged: with nobody claiming the channel,
  every level still lands on stderr as `[0sec] <message> (k=v k=v)`.

Injectable-logger sites (`opts.logger ?? ((line) => console.log(line))`) are a
different fix: leave the injection point alone and change only the *default*
from `console.log` to a `diag`-backed function. Callers that already pass a
logger are unaffected.

## Remaining sites

Grouped by file, `file:line` as of this commit.

### `agent/native-loop.ts` — 4

- `agent/native-loop.ts:816` — per-turn heartbeat line (env-gated) — `agent_heartbeat` (`info`)
- `agent/native-loop.ts:1078` — context overflow: pruned N old messages — `context_overflow_pruned`
- `agent/native-loop.ts:1099` — transient LLM error, retry N/M with backoff — `transient_llm_retry`
- `agent/native-loop.ts:1105` — agent loop error on turn N — `agent_loop_error` (`error`)

### `triage/kernel-vm-runner.ts` — 3 *(injectable-logger defaults)*

- `triage/kernel-vm-runner.ts:377` — `opts.logger` default — `kernel_vm_log` (`info`)
- `triage/kernel-vm-runner.ts:1576` — `opts.logger` default — `kernel_vm_log` (`info`)
- `triage/kernel-vm-runner.ts:1855` — `opts.logger` default — `kernel_vm_log` (`info`)

### `stages/appsec-catalog.ts` — 3

- `stages/appsec-catalog.ts:240` — runtime-lenses env var is not valid JSON — `runtime_lenses_invalid_json`
- `stages/appsec-catalog.ts:244` — runtime-lenses env var is not a JSON array — `runtime_lenses_not_array`
- `stages/appsec-catalog.ts:251` — skipping a malformed runtime lens entry — `runtime_lens_entry_malformed`

### `scanner.ts` — 3

- `scanner.ts:45` — recovered a corrupt local scan DB (with backup path) — `scan_db_recovered`
- `scanner.ts:55` — DB unavailable, results will not be persisted — `scan_db_unavailable` (`error`)
- `scanner.ts:56` — the cause object for the line above — fold into `scan_db_unavailable`'s `error` field, delete the separate write

### `cloud-sink.ts` — 3

- `cloud-sink.ts:129` — sink POST returned a non-2xx, body preview — `cloud_sink_post_rejected`
- `cloud-sink.ts:135` — sink POST threw (transport) — `cloud_sink_post_failed`
- `cloud-sink.ts:478` — dropping a finding that failed normalization — `cloud_sink_finding_dropped`

### `seed-findings.ts` — 2

- `seed-findings.ts:40` — seed line N is invalid JSON, skipped — `seed_finding_invalid_json`
- `seed-findings.ts:45` — seed line N missing required fields, skipped — `seed_finding_incomplete`

### `agent-runner.ts` — 2

- `agent-runner.ts:271` — runtime-selection debug line (CI / `0SEC_DEBUG`) — `runtime_selection` (`info`)
- `agent-runner.ts:448` — API runtime capability debug line (CI / `0SEC_DEBUG`) — `runtime_capabilities` (`info`)

### `stages/novelty-check.ts` — 2

- `stages/novelty-check.ts:457` — judge attempt N/M returned no usable text — `novelty_judge_retry`
- `stages/novelty-check.ts:463` — judge attempt N JSON parse failed (debug-gated) — `novelty_judge_parse_failed`

### `triage/userspace-fuzz-runner.ts` — 1 *(injectable-logger default)*

- `triage/userspace-fuzz-runner.ts:497` — `opts.logger` default — `userspace_fuzz_log` (`info`)

### `verify/patch-validate.ts` — 1 *(injectable-logger default)*

- `verify/patch-validate.ts:172` — `opts.logger` default — `patch_validate_log` (`info`)

### `stages/memsafety-scan.ts` — 1 *(injectable-logger default)*

- `stages/memsafety-scan.ts:228` — `opts.logger` default — `memsafety_scan_log` (`info`)

### `kernel/exploit/harness.ts` — 1 *(injectable-logger default)*

- `kernel/exploit/harness.ts:216` — `opts.logger` default — `kernel_exploit_log` (`info`)

### `emit/pr-emitter.ts` — 1 *(injectable-logger default)*

- `emit/pr-emitter.ts:413` — `options.log` default — `pr_emitter_log` (`info`). Note the doc comment says tests assert on captured lines; keep the injection point.

### `shared-analysis.ts` — 1 *(injectable-logger default)*

- `shared-analysis.ts:264` — `opts.logger` default for the missing-binary warning — `analysis_binary_missing`

### `cloud/credentials.ts` — 1 *(injectable-logger default)*

- `cloud/credentials.ts:70` — `opts.warn` default — `cloud_credentials_warning`

### `h1/credentials.ts` — 1 *(injectable-logger default)*

- `h1/credentials.ts:55` — `opts.warn` default — `h1_credentials_warning`

### `agent/loop.ts` — 1

- `agent/loop.ts:223` — per-turn heartbeat line (env-gated) — `agent_heartbeat` (`info`); share the slug with `native-loop.ts:816`

### `unified-pipeline.ts` — 1

- `unified-pipeline.ts:1820` — research-stage runtime availability debug line — `research_runtime_selection` (`info`)

### `intel/index.ts` — 1

- `intel/index.ts:195` — an intel source failed, with reason + context — `intel_source_failed`

### `events/bus.ts` — 1

- `events/bus.ts:571` — an `EventSink` threw while handling an event — `event_sink_threw`. **Migrate last.** The diagnostics channel is the lower-level primitive of the two, so routing the bus's own failure reporting into it is safe — but do it as its own change so a cycle (a diagnostics sink that emits bus events) is easy to spot and revert.

### `runtime/process.ts` — 1

- `runtime/process.ts:47` — dimmed tool-call echo, guarded by `process.stderr.isTTY && !onToolCall` — `tool_call_echo` (`info`). **This one carries ANSI** (`dim(...)`) and the channel strips it, so the line loses its dimming. That is the correct outcome — a raw SGR sequence is exactly what corrupts the renderer — but it is a deliberate visual change, so land it separately from the mechanical batch.

## Permanent exclusions — do NOT migrate

These are wire protocols and IPC, not operator messages. Routing them through
the diagnostics channel would corrupt a parser on the other end.

- `events/bus.ts:680` — `cloudEventSink` writes `0SEC_EVENT_<TYPE> {json}` lines on **stdout**; the cloud worker-controller's `parseEventLines` reads them.
- `stages/npm-detectors/sandbox-harness.ts:75` — the harness subprocess writes one JSON line on **stdout**; the parent parses the last `{…}` line.
- `stages/npm-detectors/sandbox-harness.ts:79` — the same subprocess's top-level fault handler, immediately before `process.exit(1)`. It runs in a child process with no diagnostics sinks installed, and stderr is what the parent captures.
- `src/diagnostics/channel.ts:338` — the channel's own built-in stderr sink. This is the one write in core that is supposed to exist.

## Not real call sites

Grep matches inside doc comments, type-member documentation, or string
literals. Left here so they do not get re-triaged.

- `emit/pr-emitter.ts:76` — doc comment on the `log` option
- `events/bus.ts:678` — comment explaining why `process.stdout.write` is used
- `file-review/matchers-default.ts:232` — `"console.log('token', authToken)"` is a **detection pattern** for finding leaked secrets in a target
- `integrations/herdr.ts:38` — doc comment describing this very hazard
- `kernel/exploit/harness.ts:48` — doc comment on the `logger` option
- `remediation.ts:285` — `console.error(err)` inside a remediation code *template* shown to users
- `review/evm-verify.ts:88` — doc comment; the field documents a *target contract's* forge `console.log` output, not a write of ours
- `seed-findings.ts:23` — module doc comment
- `shared-analysis.ts:246` — doc comment on the `logger` option
- `stages/memsafety-scan.ts:67` — doc comment on the `logger` option
- `triage/kernel-vm-runner.ts:1503` — doc comment on the `logger` option
- `triage/userspace-fuzz-runner.ts:100` — doc comment on the `logger` option
- `verify/patch-validate.ts:126` — doc comment on the `logger` option

## Already migrated

### `runtime/llm-api.ts` — 12 sites

| slug | level | was |
|---|---|---|
| `provider_initialized` | info | non-Azure startup banner (`console.error`) |
| `provider_initialized` | info | Azure startup banner incl. probed region |
| `fallback_chain_malformed_entry` | warn | `0SEC_LLM_FALLBACK` entry without `provider:model` |
| `fallback_chain_unknown_provider` | warn | `0SEC_LLM_FALLBACK` names an unknown provider |
| `fallback_chain_empty_model` | warn | `0SEC_LLM_FALLBACK` entry with an empty model |
| `prompt_cache_usage` | info | `0SEC_DEBUG_PROMPT_CACHE` hit-rate line |
| `failover_provider_skipped` | warn | fallback entry skipped, auth env missing |
| `failover_engaged` | warn | switched to the next provider in the chain |
| `transport_retry` | warn | ECONNRESET-class transport retry with backoff |
| `quota_exhausted` | **error** | plan quota exhausted; retry deliberately skipped |
| `retry_backoff` | warn | retryable HTTP status, backing off |
| `stream_stalled` | warn | SSE stream held open with no events |

The two Azure/non-Azure banners share `provider_initialized` on purpose: a
consumer wants "a provider came up", and the `provider` field distinguishes
them.

### `agentic-scanner.ts` — 5 sites

| slug | level | was |
|---|---|---|
| `web_recon_prepass_failed` | warn | `[web-recon-prepass] failed: …` |
| `pre_recon_cve_failed` | warn | `[pre-recon-cve] failed: …` |
| `pre_recon_wordpress_failed` | warn | `[pre-recon-wp] failed: …` |
| `layer_verdicts_dropped` | warn | corrupt `layerVerdicts` row, schema mismatch |
| `layer_verdicts_dropped` | warn | corrupt `layerVerdicts` row, invalid JSON |

The two `layer_verdicts_dropped` sites share a slug and are told apart by
`cause: "schema-mismatch" | "invalid-json"` — a consumer counting dropped
verdict rows wants one bucket, and the cause is a field.

## Wiring the TUI

Core-side work is done; the TUI claims the channel where it already installs
the output guard:

```ts
import { claimDiagnostics } from "@0sec/core";

const releaseDiag = claimDiagnostics(
  { emit: (e) => appendTranscriptLine({ level: e.level, code: e.code, text: e.message, fields: e.fields }) },
  { replay: true },   // render anything core said before the TUI mounted
);
// on unmount:
releaseDiag();
```

While claimed, the built-in stderr sink is bypassed entirely, so migrated code
cannot reach the terminal. Un-migrated code still can — which is why the output
guard stays installed until this file's remaining count reaches zero.

`packages/core/src/index.ts` needs one line to export it (owned by another
worker):

```ts
export * from "./diagnostics/channel.js";
```
