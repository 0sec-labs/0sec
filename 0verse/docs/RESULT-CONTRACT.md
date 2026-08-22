# 0verse machine result contract (v1.5)

> Status: 2026-07-25. Living document.

> The versioned, embeddable seam a managed scan platform or an external
> agent ingests. Produced by `zeroverse.api.scan()` and the CLI
> `0verse scan <binary> --format json|ndjson|sarif`. The internal
> `serialize.finding_dict` shape is free to evolve; **this** contract is the
> compatibility boundary.

## Versioning

`contract_version` is `MAJOR.MINOR` (currently **1.5**).

- **MINOR** bumps add back-compatible fields. A consumer pinned to a MAJOR keeps working.
- **MAJOR** bumps remove/rename/repurpose fields. A consumer **must** reject a MAJOR it
  does not understand (the reference adapter does exactly this).

The header carries the version *before* any finding, so a streaming consumer
validates compatibility first.

### Changelog

- **1.5** — additive, back-compatible MINOR. `terminal_state` assigns exactly one
  fail-closed scan outcome, `status_reason` explains it concisely, and
  `stage_outcomes` records each stage's status, required/optional role, reason, and
  producing component/backend provenance. No existing top-level or finding field
  changed.
- **1.4** — additive, back-compatible MINOR. One optional top-level
  `ScanResult.execution` object identifies an explicitly injected target-execution
  backend, its independent execution-contract version, and its declared formats,
  input vectors, oracles, stateful flag, and default timeout. `null` means the ordinary built-in
  execution path. No finding fields changed.
- **1.3** — additive, back-compatible MINOR (M7 #44, the scheduler). One optional
  top-level `ScanResult.scheduler` object carrying per-lane LLM budget, cache, and
  epoch-plan stats when a run used `ZEROVERSE_SCHEDULER=1`. Omitted/null for the
  default sequential path. No finding fields were removed, renamed, or reordered;
  a consumer pinned to MAJOR `1` keeps working.
- **1.2** — additive, back-compatible MINOR (M7 #45/#46, the patch stage). Six
  optional `Finding` fields: `patch_available`, `patch_verified`, `patch_mode`,
  `patch_path`, `patch_recommendation`, `patch_regression`. No field removed,
  renamed, or reordered; a consumer pinned to MAJOR `1` keeps working.
  **PoV-is-truth's sibling joins the contract:** `patch_verified` is true *only*
  when a re-run confirms the PoV no longer reproduces **and** no regression is
  observed (the same discipline as `confirmed`).
- **1.1** — additive, back-compatible MINOR. Two optional `Finding` fields:
  `crash_output` (the oracle's captured sanitizer/crash text for a confirmed PoV)
  and `confidence` (an optional per-finding signal — CASR exploitability when the
  oracle ran it, `null` otherwise). No field removed, renamed, or reordered; a
  consumer pinned to MAJOR `1` keeps working. The cloud sink compat-gates on MAJOR
  only, so this is fully backward-compatible.
- **1.0** — initial locked contract.

## Top-level (`ScanResult`)

| field              | type            | meaning |
|--------------------|-----------------|---------|
| `contract_version` | str             | `MAJOR.MINOR` of this contract |
| `tool`             | {name, version} | producing engine |
| `binary`           | str             | scanned path |
| `format`           | str             | ELF / PE / Mach-O / unknown |
| `arch`             | str             | recovered architecture |
| `backend`          | str             | decompiler backend (auto/ghidra/rizin/angr) |
| `triage`           | str             | one-line triage summary |
| `stages_run`       | str[]           | pipeline stages that executed |
| `findings`         | Finding[]       | see below |
| `note`             | str             | honest degradation / backend notes |
| `scheduler`        | object?         | **(v1.3)** scheduler budget/cache/epoch stats, or `null` |
| `execution`        | object?         | **(v1.4)** explicit execution-contract/backend/capability identity, or `null` |
| `terminal_state`   | str             | **(v1.5)** one of `confirmed`, `no-findings`, `unsupported`, `skipped`, `infra-failed`, `cancelled` |
| `status_reason`    | str             | **(v1.5)** concise reason for the terminal state |
| `stage_outcomes`   | StageOutcome[]  | **(v1.5)** per-stage status, required flag, reason, and provenance |
| `confirmed_count`  | int             | findings with a reproducing PoV (json only) |

### Terminal semantics

- `confirmed` if and only if at least one PoV replay reproduced.
- `no-findings` only after every required requested stage completed without a
  replay-confirmed PoV.
- `unsupported` when the target or requested profile is unsupported.
- `skipped` only when policy declined the entire scan.
- `infra-failed` when a required backend, tool, executor, build, artifact, or timeout
  prevented completion.
- `cancelled` only for explicit cancellation or a caller deadline.

Optional lanes may be `skipped` or `unavailable` in `stage_outcomes` without changing
an otherwise complete scan to `infra-failed`. Consumers must not infer success from
an empty `findings` array; only `confirmed` and `no-findings` are successful terminal
states.

Each `StageOutcome` has `stage`, `status` (`completed`, `skipped`, `unavailable`,
`failed`, or `cancelled`), `required`, `reason`, and a string-valued `provenance`
object identifying the component and, when applicable, backend.

## Finding (`ScanFinding`) — fixed field set

| field         | type | meaning |
|---------------|------|---------|
| `id`          | str  | stable hash (binary, function, sink, offset, class) |
| `bug_class`   | str  | CWE / class id |
| `severity`    | str  | low / medium / high / … |
| `file`        | str  | scanned binary |
| `function`    | str  | containing function |
| `offset`      | str  | sink address (hex) |
| `source`      | str  | taint source symbol |
| `sink`        | str  | dangerous-sink symbol |
| `confirmed`   | bool | **PoV-is-truth**: true ⇔ a reproducing PoV is attached |
| `hypothesis`  | bool | cheap/LLM verdict thinks it could be real |
| `pruned`      | bool | angr proved the sink unreachable (rejected) |
| `capability`  | str  | oracle capability rung (oob-write / crash / …) |
| `pov_path`    | str  | standalone replay script, or "" |
| `repro_cmd`   | str  | exact reproduce command, or "" |
| `dedup_bucket`| str  | crash-state key for dedup, or "" |
| `explanation` | str  | human rationale |
| `crash_output`| str? | **(v1.1)** oracle-captured sanitizer/crash blob for a confirmed PoV, or `null` |
| `confidence`  | float? | **(v1.1)** per-finding confidence (CASR exploitability when available), or `null` |
| `patch_available` | bool | **(v1.2)** a patch artifact (any mode) is attached |
| `patch_verified`  | bool | **(v1.2)** **patch-is-truth**: PoV no longer reproduces AND no regression |
| `patch_mode`  | str  | **(v1.2)** `none`/`recommendation`/`source-diff`/`binary-micropatch` |
| `patch_path`  | str? | **(v1.2)** path to the patched binary / persisted diff, or `null` |
| `patch_recommendation` | str? | **(v1.2)** located fix text (always set in binary/recommendation mode), or `null` |
| `patch_regression` | str? | **(v1.2)** regression-oracle result summary, or `null` |

**PoV-is-truth is part of the contract:** `confirmed` is true *only* when a
reproducing PoV exists. A hypothesis is `confirmed=false, hypothesis=true` and is
never silently promoted. A platform that wants "verified vulnerabilities" filters
on `confirmed == true`.

**Patch-is-truth (v1.2, its strict sibling):** `patch_verified` is true *only* when
the oracle re-ran the confirmed PoV against the patched artifact and it **no longer
reproduced** *and* no regression was observed. An unverified candidate is reported
with `patch_verified=false` and a `patch_recommendation` — guidance, never "fixed".
A patch is labelled "closes-the-PoV-and-passes-tests", never "correct". A platform
that wants "verified fixes" filters on `patch_verified == true`.

## Wire formats

- **json** — the whole `ScanResult` as one object (+ `confirmed_count`).
- **ndjson** — line 1 is `{"_meta": {...}}` (version + run context + terminal and
  stage outcomes + `confirmed_count`), then one finding object per line. The
  streaming ingestion format.
- **sarif** — SARIF 2.1.0; `confirmed → level:error`, hypothesis `→ level:warning`;
  `runs[].tool.driver.properties.contract_version` carries the version and
  `runs[].properties` carries the terminal and stage outcomes.

## Backends (`--backend`)

`auto` (default) prefers Ghidra (High P-Code SSA, highest fidelity) and falls back
to `rizin` (radare2 + r2ghidra `pdg`, no Java) then `angr` (pure-Python) when a
higher backend is unavailable. The non-Ghidra backends mine a lower-fidelity IL
from pseudo-C — `note` says so, and the angr reachability stage is skipped for
them (no per-sink addresses).
