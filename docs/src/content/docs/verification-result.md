---
title: Verification Results
description: Stable JSON contract emitted by deterministic replay verifiers.
---

Deterministic verification emits a `verification_result` JSON object. The object
is evidence produced by the open-source engine after it runs a replay harness and
checks concrete assertions. It is separate from human triage and finding
lifecycle state.

The schema is designed to be stored by local CI, reproduced by maintainers, and
ingested by cloud systems without reimplementing the exploit logic.

## Result schema

The first version uses this shape:

```typescript
type VerificationStatus =
  | "reproduced"
  | "not_reproduced"
  | "inconclusive"
  | "error";

interface VerificationCommand {
  argv: string[];
  exit_code: number | null;
  stdout_excerpt: string;
  stderr_excerpt: string;
}

interface VerificationAssertion {
  kind: string;
  passed: boolean;
  detail: string;
}

interface VerificationResult {
  status: VerificationStatus;
  mode: "deterministic_replay";
  finding_id: string;
  engine_version: string;
  started_at: string;
  completed_at: string;
  commands: VerificationCommand[];
  assertions: VerificationAssertion[];
  artifacts: Record<string, string>;
  summary: string;
  error_reason: string | null;
}
```

Fields may be added over time. Consumers should treat the fields above as the
minimum stable contract and ignore unknown fields.

## Status semantics

| Status | Meaning |
|--------|---------|
| `reproduced` | The replay ran far enough to evaluate the verifier's concrete assertions, and the required exploit assertions passed. |
| `not_reproduced` | The replay ran far enough to evaluate the verifier's concrete assertions, but the exploit condition was not observed. A secure CLI that rejects malicious input can still exit non-zero and produce this status when filesystem assertions prove no escape happened. |
| `inconclusive` | The verifier reached the target but did not have enough assertion evidence to prove or disprove the finding. |
| `error` | The verifier failed before it could produce a reliable assertion result, for example malformed input, setup failure, an unlaunchable command, or a timeout before useful assertions were available. |

Do not use `verification_result.status` as the finding's human triage state.
It is an automated proof signal. A maintainer can still accept, suppress, or
reopen a finding after reviewing the evidence.

## Commands

Each command record captures the real command that the verifier executed:

```json
{
  "argv": [
    "paperclip",
    "company",
    "export",
    "--api",
    "http://127.0.0.1:50345",
    "--output",
    "/tmp/pwnkit-verify-a1b2/export"
  ],
  "exit_code": 0,
  "stdout_excerpt": "wrote /tmp/pwnkit-verify-a1b2/escaped-marker\n",
  "stderr_excerpt": ""
}
```

`argv` must point at the implementation under test. A deterministic fixture may
provide servers, files, directories, and placeholders, but it must not synthesize
the vulnerable behavior that the finding is supposed to verify.

## Assertions

Assertions are the machine-checkable facts that turn a replay into a verdict.
The CLI path traversal fixture uses filesystem assertions such as:

| Kind | Purpose |
|------|---------|
| `filesystem_exists` | A marker file exists at the escaped path. |
| `filesystem_not_exists` | The marker was not written inside the selected export root. |
| `path_outside_export_root` | The escaped marker realpath is outside the export directory. |
| `path_inside_sandbox` | The escaped marker stayed inside the verifier sandbox. |
| `no_home_profile_touch` | The replay did not write to the user's home directory or shell profile files. |

The final assertion phase is deterministic code, not an LLM judgement.

## Artifacts

`artifacts` contains references that let a maintainer inspect or reproduce the
run. For local runs these are paths; for cloud runs they can be storage keys or
other retrievable references.

Common artifact keys are:

| Key | Meaning |
|-----|---------|
| `sandbox_ref` | Root directory for the isolated replay sandbox. |
| `harness_ref` | Harness metadata, including fixture name and expanded command argv. |
| `stdout_ref` | Full stdout log for the executed command. |
| `stderr_ref` | Full stderr log for the executed command. |
| `export_ref` | Fixture-specific export directory or output root. |

The CLI cleans temporary sandboxes by default. Use `--retain-artifacts` or
`--artifact-dir` when full logs and harness files need to survive after the run.

## CLI path traversal example

The `cli-path-traversal` fixture starts a malicious local API, creates a
sandboxed export directory, and runs the real CLI argv supplied through
`--fixture-command`.

```bash
pwnkit verify --fixture cli-path-traversal \
  --fixture-command '["paperclip","company","export","--api","{{apiUrl}}","--output","{{exportDir}}"]' \
  --retain-artifacts
```

Example result:

```json
{
  "status": "reproduced",
  "mode": "deterministic_replay",
  "finding_id": "fixture:cli-path-traversal",
  "engine_version": "0.7.13",
  "started_at": "2026-05-06T07:23:02.223Z",
  "completed_at": "2026-05-06T07:23:02.510Z",
  "commands": [
    {
      "argv": [
        "paperclip",
        "company",
        "export",
        "--api",
        "http://127.0.0.1:50345",
        "--output",
        "/tmp/pwnkit-verify-a1b2/export"
      ],
      "exit_code": 0,
      "stdout_excerpt": "wrote /tmp/pwnkit-verify-a1b2/escaped-marker\n",
      "stderr_excerpt": ""
    }
  ],
  "assertions": [
    {
      "kind": "filesystem_exists",
      "passed": true,
      "detail": "escaped marker exists at /tmp/pwnkit-verify-a1b2/escaped-marker"
    },
    {
      "kind": "path_outside_export_root",
      "passed": true,
      "detail": "escaped marker realpath /tmp/pwnkit-verify-a1b2/escaped-marker is outside export root /tmp/pwnkit-verify-a1b2/export"
    },
    {
      "kind": "path_inside_sandbox",
      "passed": true,
      "detail": "escaped marker stayed inside sandbox /tmp/pwnkit-verify-a1b2"
    }
  ],
  "artifacts": {
    "sandbox_ref": "/tmp/pwnkit-verify-a1b2",
    "harness_ref": "/tmp/pwnkit-verify-a1b2/harness/harness.json",
    "stdout_ref": "/tmp/pwnkit-verify-a1b2/stdout.log",
    "stderr_ref": "/tmp/pwnkit-verify-a1b2/stderr.log",
    "export_ref": "/tmp/pwnkit-verify-a1b2/export"
  },
  "summary": "CLI path traversal replay wrote a marker outside the selected export directory inside the sandbox.",
  "error_reason": null
}
```

## Cloud ingestion

Cloud systems should schedule runs, persist `verification_result` payloads, show
the commands, assertions, and artifact references, and gate downstream workflows
on explicit proof signals. They should treat this OSS schema as the source of
truth for verifier semantics instead of implementing separate replay logic.
