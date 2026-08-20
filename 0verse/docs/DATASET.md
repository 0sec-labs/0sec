# 0verse labeled-PoV dataset (v1.2) — the moat's capture mechanism

> The versioned schema + append-only emitter that turn each pipeline run into a
> labeled record. Produced by `zeroverse.dataset` (and, opt-in, by every
> `api.scan()` when `ZEROVERSE_DATASET_PATH` is set). **The OSS ships the capture
> mechanism, not the corpus.** See [INTEGRATION.md](INTEGRATION.md) for why the
> labeled dataset is pwnkit-cloud's moat and 0verse's job is to emit clean,
> capturable rows.

## What a record is

One row per finding of a run: a labeled datapoint mapping **binary features** →
**(bug_class, source, sink)** → **PoV (path + repro command)** → **verdict + the
oracle that decided it**. It is the foxguard-style data moat, for binaries.

```jsonc
{
  "record_id": "5c2a9ebd777d",          // stable hash(name, function, sink, offset, bug_class)
  "dataset_version": "1.2",
  "created_at": "2026-06-28T00:00:00+00:00",
  "tool": {"name": "0verse", "version": "0.0.1"},
  "backend": "ghidra",                   // decompiler backend that produced the IL
  "binary_name": "parser_x64",           // basename only — never a full path, never bytes
  "features": {                          // the FEATURE side (what was known pre-finding)
    "format": "ELF", "arch": "x86-64", "bits": 64, "endian": "little",
    "size_bytes": 15784, "stripped": true, "symbols_present": false,
    "mitigations": {"nx": true, "pie": false, "canary": false}
  },
  "label": {                             // the LABEL side
    "bug_class": "CWE-787", "source": "fuzz:stdin", "sink": "parse_record",
    "function": "parse_record", "offset": "0x4011a0"
  },
  "verdict": "confirmed",                // confirmed | pruned | hypothesis
  "oracle": "differential-allocator",    // the deterministic stage that DECIDED it
  "pov": {                               // POINTERS ONLY — never raw crash bytes
    "path": "0verse-out/fuzz/pov_parse_record.py",
    "repro_cmd": "python3 0verse-out/fuzz/pov_parse_record.py",
    "capability": "oob-write", "dedup_bucket": "a1b2c3"
  },
  "explanation": "silent heap OOB; faults only under the guard allocator (clean->crash)",
  "synthetic": false                     // true ONLY for the committed example rows
}
```

## The two invariants (contract, not convention)

`zeroverse.dataset.validate_record` enforces both — it runs before every write and
on every read:

1. **PoV-is-truth.** `verdict == "confirmed"` ⇒ a non-empty `pov.path`. A confirmed
   record with no reproducing PoV is rejected — the same rule the engine uses to
   refuse a finding. `pruned` (angr UNSAT) and `hypothesis` records carry no PoV.
2. **No raw exploit bytes.** The schema has **no field** for crash input bytes, and
   `validate_record` additionally rejects any record that smuggles a payload-bearing
   key (`input_bytes` / `crash_input` / `pov_bytes` / `payload` / `exploit_bytes` /
   `stdin_bytes`). The OSS captures *labels and pointers*; the bytes are the moat.

## Verdict → oracle attribution

The `oracle` is the **deterministic** stage that decided the verdict (an LLM never
decides truth — see [INTEGRATION.md](INTEGRATION.md)). Attributed from the evidence
the finding carries:

| verdict      | oracle                       | when |
|--------------|------------------------------|------|
| `confirmed`  | `differential-allocator`     | silent heap OOB that faults only under the guard allocator |
| `confirmed`  | `canary-marker`              | capability proven by a token-bound marker (e.g. cmd-injection) |
| `confirmed`  | `differential-crash`         | crashes under target, clean control |
| `pruned`     | `angr-reachability(UNSAT)`   | angr proved the sink unreachable — rejected, never a finding |
| `hypothesis` | `llm-triage`                 | a lead surfaced, no oracle confirmed it (never promoted) |

## Versioning

`dataset_version` is `MAJOR.MINOR` (currently **1.2**), mirroring the result
contract (`api.CONTRACT_VERSION`):

- **MINOR** adds back-compatible fields; a pinned consumer keeps working.
- **MAJOR** removes/renames/repurposes; a consumer **must reject** a MAJOR it does
  not understand (`validate_record` does exactly this).

## The OSS ↔ moat split (enforced)

| | OSS (this repo) | MOAT (private) |
|---|---|---|
| schema (`dataset.py`, this doc) | ✅ shipped | — |
| emitter (`emit_run` / `emit_records`) | ✅ shipped | — |
| example records (`examples/dataset/sample.ndjson`) | ✅ **synthetic-only** | — |
| real corpus of paid-scan records | ❌ never | ✅ the moat |
| raw crash/exploit bytes | ❌ never (schema has no field) | ✅ operator-private |

Enforcement is mechanical, not a promise:

- The emitter **never** writes bytes (no field exists; `validate_record` rejects
  bytes-bearing keys).
- Real capture lands wherever the operator points `ZEROVERSE_DATASET_PATH`; that
  path is **git-ignored** (`*.0verse-dataset.ndjson`, `dataset-out/`).
- A test (`tests/test_dataset.py::test_committed_example_corpus_is_synthetic_and_payload_free`)
  asserts the only `*.ndjson` in the repo are the `examples/dataset/` rows, every
  one `synthetic: true`, schema-valid, and payload-free. CI fails if a real corpus
  or raw bytes are ever committed.

## Emitting

```python
from zeroverse import api, dataset
from zeroverse.pipeline import run

# Opt-in via the scan API (append-only NDJSON; one record per finding):
#   ZEROVERSE_DATASET_PATH=corpus.ndjson  0verse scan ./target --format ndjson

# Or directly from a RunResult:
rr = run("./target")
dataset.emit_run(rr, "corpus.ndjson", binary="./target", backend="ghidra")
```

Read back (validates each row):

```python
from zeroverse import dataset
for row in dataset.iter_records("corpus.ndjson"):
    ...
```

## 0research production learning

The scan API can close the flywheel into a separate, mutable production-learning
ledger:

```sh
ZEROVERSE_LEARNING_PATH=/private/0research/0verse-learning.ndjson \
  0verse scan ./target --format ndjson
```

This ledger admits only deterministic reachability refutations (`angr` UNSAT)
and oracle-confirmed PoVs whose replay scripts are bounded regular files. A
confirmed learning row retains an absolute replay-script path plus its SHA-256;
missing, symlinked, empty, oversized, or concurrently changed scripts are not
learned. Unresolved model hypotheses are excluded. A cross-process ledger lock
makes the read/deduplicate/append transaction idempotent by record/outcome
identity even when completed scans race.

`ZEROVERSE_DATASET_PATH` remains the frozen recall/evaluation input. The learning
path must be different; 0verse refuses to write when both resolve to the same
file. Set `ZEROVERSE_EVALUATION=1` as an additional fail-closed guard for held-out
or benchmark runs. Promotion from the learning ledger into a later immutable
recall corpus is a separate, human-reviewed step.

### Importing scheduler-bound feedback

0brain may project a completed `zeroverse_evidence_replay` item into an exact,
sanitized feedback projection. Import it only with the private output tree that
contains the exact `0verse-learning-bundle-v1` bytes, relative replay scripts,
oracle evidence, and detached oracle-result receipts:

```sh
0verse research-feedback-import \
  --projection /private/0brain/zeroverse-feedback.json \
  --bundle /private/runs/run-1/item-1/attempt-1/learning-bundle.json \
  --output-root /private/runs/run-1/item-1/attempt-1 \
  --ledger /private/0research/0verse-learning.ndjson
```

The importer recomputes 0brain's complete output-tree digest, verifies the exact
bundle SHA-256, rejects symlinks and path traversal, and re-hashes every bounded
confirmed replay script. Every row must reference an exact
`0verse-oracle-result-receipt-v1` signed under the
`0verse-0research-oracle-result-v1` SSHSIG namespace by the separate authority in
`/etc/0verse/0research-oracle-result.allowed_signers`; the receipt binds the
complete source record, verdict, oracle, PoV, and a content-addressed result
artifact. It admits only signed oracle-confirmed PoVs and signed exact
`angr-reachability(UNSAT)` refutations. A scheduler `pass`, `reject`, or
`draft_pr` is transport state—not scientific truth—and cannot create a learning
row. Each retained row gains a content-addressed `event_id` and the sanitized
terminal/projection provenance needed to reproduce its origin.

Writes use a locked atomic replacement with file and directory `fsync`; retries
are idempotent by `event_id`. A ledger segment is capped at 32 MiB and fails
before mutation when full; operators then rotate to a new private segment.
`ledgerDigest` always identifies the exact unchanged or post-write bytes,
including in evaluation mode. `ZEROVERSE_EVALUATION=1` still performs all binding
and signature checks but writes nothing; this is the only mode that admits
signed synthetic calibration rows, and they can never enter the ledger. The
command emits a content-addressed write receipt
whose authority flags make explicit that importing feedback cannot grade,
promote, publish, deploy, or write to GitHub.

### Issuing evidence admissions

The downstream source-attestor can call
`zeroverse.research_admission.issue_feedback_admissions` to turn an exact batch
of retained native events into one signed `zeroverse_scientific_event`
admission per event. This is deliberately a library boundary rather than an
operator CLI: it replays the projection, sealed output tree, learning bundle,
oracle receipt, PoV, and oracle evidence before signing anything, then requires
each replayed event to match the ledger configured by the absolute
`ZEROVERSE_LEARNING_PATH`. Confirmed deterministic PoVs map to `confirmed`;
exact `angr-reachability(UNSAT)` outcomes map to `refuted`. Scheduler provenance
does not affect scientific identity.

Each admission binds the native `event_id` as its source-artifact digest, a new
verification sidecar, the oracle receipt and evidence, the normalized PoV
digest, and a separately signed `0verse-target-snapshot-v1`. That snapshot
attests the exact repository commit and tree plus five required artifacts:
source tree, package, lockfile, toolchain, and runtime configuration. Oracle,
target-snapshot, and evidence-admission policies must use pairwise-distinct
files and SSH keys.

The v2 admission bundle is self-contained for historical replay. Its
content-addressed `payload/source/` tree retains the exact feedback projection, complete
sealed output tree, learning bundle, target snapshot and all five snapshot
artifacts, the complete byte-exact locked production-ledger NDJSON snapshot plus
event-to-line membership digests, and the exact oracle, target-snapshot, and
evidence allowed-signers policy bytes. The manifest binds the complete
source-tree and package-payload digests, every historical policy digest, every
verification-receipt preimage, and the exact signature-bearing admission bytes.
The evidence authority also signs the canonical manifest body as the package
root. Every consumer must call the package verifier with its independently
trusted evidence allowed-signers policy and consume only the authenticated
bytes returned by that verifier, never reopen package paths. A delayed
same-user mutation therefore cannot alter the consumer's captured view. File,
directory-entry, tree-depth, and aggregate byte limits are enforced during
source capture and include generated ledger, membership, admission, receipt,
and manifest artifacts.
Relocated PoV paths and reproduction commands are treated as transport fields;
the PoV content digest and all scientific fields remain exact.

The final destination is first reserved as an empty owner-only directory before
any native verifier or evidence signer runs. The reservation and retained source
tree are checked around every verifier and signer callback. The
production-ledger lock is held while its exact rows are rechecked, throughout
signing, and until publication; a signer-side ledger mutation aborts. Batch
files are written through a pinned staging-directory descriptor, replayed again
from retained bytes, and published through an fd-relative atomic directory
exchange plus directory `fsync`. A concurrent writer is never overwritten. A
crash before exchange can leave only an empty reservation and a hidden
`.<name>.tmp-*` staging directory; recovery is fail-closed and
operator-controlled: verify that neither contains a `manifest.json`, then
remove both before retrying. A committed destination is never treated as stale
or auto-replaced. The resulting private bundle is inert evidence custody only:
its authority denies execution, provider access, spend, promotion, training,
model writes, GitHub writes, deployment, merging, and external publication.
Human-reviewed corpus retention remains a separate 0brain decision.
