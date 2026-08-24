---
title: Verification Results
description: Stable JSON contract emitted by deterministic replay verifiers.
---

Deterministic verification emits a `verification_result` JSON object. This
object is evidence: the open-source engine runs a replay harness, checks
concrete assertions, and records the outcome here. It is separate from human
triage and a finding's lifecycle state.

The schema is meant to be stored by local CI, reproduced by maintainers, and
ingested by cloud systems without reimplementing the exploit logic.

## Result schema

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

Fields may be added over time. Treat the fields above as the minimum stable
contract and ignore unknown fields.

## Status semantics

| Status | Meaning |
|--------|---------|
| `reproduced` | Replay ran far enough to evaluate the concrete assertions, and the required exploit assertions passed. |
| `not_reproduced` | Replay evaluated the assertions, but the exploit condition wasn't observed. A secure CLI that rejects malicious input can exit non-zero and still land here when filesystem assertions prove no escape happened. |
| `inconclusive` | The verifier reached the target but lacked assertion evidence to prove or disprove the finding. |
| `error` | The verifier failed before a reliable assertion result — malformed input, setup failure, an unlaunchable command, or a timeout. |

**`status` is not the finding's human triage state.** It's an automated proof
signal; a maintainer can still accept, suppress, or reopen after reviewing the
evidence.

## Commands

Each record captures the real command the verifier ran:

```json
{
  "argv": [
    "paperclip",
    "company",
    "export",
    "--api",
    "http://127.0.0.1:50345",
    "--output",
    "/tmp/0sec-verify-a1b2/export"
  ],
  "exit_code": 0,
  "stdout_excerpt": "wrote /tmp/0sec-verify-a1b2/escaped-marker\n",
  "stderr_excerpt": ""
}
```

`argv` must point at the implementation under test. A fixture may provide
servers, files, directories, and placeholders, but it must not synthesize the
vulnerable behavior the finding is supposed to verify.

## Assertions

Assertions are the machine-checkable facts that turn a replay into a verdict. The
CLI path-traversal fixture uses filesystem assertions:

| Kind | Purpose |
|------|---------|
| `filesystem_exists` | A marker file exists at the escaped path. |
| `filesystem_not_exists` | The marker was not written inside the selected export root. |
| `path_outside_export_root` | The escaped marker realpath is outside the export directory. |
| `path_inside_sandbox` | The escaped marker stayed inside the verifier sandbox. |
| `no_home_profile_touch` | The replay didn't write to the home directory or shell profile files. |

The final assertion phase is deterministic code, not an LLM judgement.

## Artifacts

`artifacts` holds references a maintainer can use to inspect or reproduce the
run — paths for local runs, storage keys or other references for cloud runs:

| Key | Meaning |
|-----|---------|
| `sandbox_ref` | Root directory for the isolated replay sandbox. |
| `harness_ref` | Harness metadata (fixture name, expanded command argv). |
| `stdout_ref` | Full stdout log. |
| `stderr_ref` | Full stderr log. |
| `export_ref` | Fixture-specific export directory or output root. |

The CLI cleans temporary sandboxes by default. Use `--retain-artifacts` or
`--artifact-dir` when logs and harness files need to survive the run.

## CLI path traversal example

The `cli-path-traversal` fixture starts a malicious local API, creates a
sandboxed export directory, and runs the real CLI argv from `--fixture-command`.

```bash
0sec verify --fixture cli-path-traversal \
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
        "/tmp/0sec-verify-a1b2/export"
      ],
      "exit_code": 0,
      "stdout_excerpt": "wrote /tmp/0sec-verify-a1b2/escaped-marker\n",
      "stderr_excerpt": ""
    }
  ],
  "assertions": [
    {
      "kind": "filesystem_exists",
      "passed": true,
      "detail": "escaped marker exists at /tmp/0sec-verify-a1b2/escaped-marker"
    },
    {
      "kind": "path_outside_export_root",
      "passed": true,
      "detail": "escaped marker realpath /tmp/0sec-verify-a1b2/escaped-marker is outside export root /tmp/0sec-verify-a1b2/export"
    },
    {
      "kind": "path_inside_sandbox",
      "passed": true,
      "detail": "escaped marker stayed inside sandbox /tmp/0sec-verify-a1b2"
    }
  ],
  "artifacts": {
    "sandbox_ref": "/tmp/0sec-verify-a1b2",
    "harness_ref": "/tmp/0sec-verify-a1b2/harness/harness.json",
    "stdout_ref": "/tmp/0sec-verify-a1b2/stdout.log",
    "stderr_ref": "/tmp/0sec-verify-a1b2/stderr.log",
    "export_ref": "/tmp/0sec-verify-a1b2/export"
  },
  "summary": "CLI path traversal replay wrote a marker outside the selected export directory inside the sandbox.",
  "error_reason": null
}
```

## Cloud ingestion

Cloud systems should schedule runs, persist `verification_result` payloads, show
the commands, assertions, and artifacts, and gate downstream workflows on
explicit proof signals. Treat this OSS schema as the source of truth for verifier
semantics — don't reimplement replay logic.
