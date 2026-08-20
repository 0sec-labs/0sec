# 0verse CRS-API / SARIF adapter (M7 #47)

> The pipe that runs 0verse on a **real external scoreboard** — the public
> AIxCyberChallenge `example-crs-architecture` OSS-Fuzz corpus — instead of only
> 0verse's own self-benchmarks, and the load-bearing **foxguard → 0verse** seam
> ("a source scanner broadcasts a SARIF location; the binary engine proves it with
> a PoV"). Implemented in `src/zeroverse/crs_api.py`.

## What this is

A faithful adapter for the AIxCC CRS-API (`docs/api/*-swagger-v1.4.0.yaml`, v1.4.0)
An independent implementation — no AIxCC finalist code is vendored or ported.
Every routine is original, guided by the public AIxCC CRS-API spec.

1. **Task ingestion** — parse the task server's `Task` / `TaskDetail` envelope
   (`full` | `delta`, `project_name`, `focus`, `source[]` = `repo` / `fuzz-tooling`
   / `diff`, `deadline`). `delta` mode surfaces the diff's changed files as priority
   target hints (`delta_files`).
2. **Run 0verse** — drive `zeroverse.pipeline.run` on the task's fuzz-target and
   project the result into the versioned `api.ScanResult`.
3. **Emit CRS-API results** — `POVSubmission` records (base64 `testcase`,
   `fuzzer_name`, `sanitizer`, `architecture=x86_64`, `engine=libfuzzer`) and a
   `SarifMatcher` that confirms whether a 0verse finding matches a broker SARIF.

## The SARIF matcher

`match_frame(frame, info)` compares five booleans and matches on **one** of:

```
(matches_lines AND (matches_filename OR matches_full_path))   # location
OR matches_function                                           # exact function
OR matches_stripped_function                                  # after dropping OSS_FUZZ_
```

- `matches_lines` — frame line ∈ `[startLine, endLine]`
- `matches_filename` — basename(frame.file) == basename(sarif.file)
- `matches_full_path` — full paths equal
- `matches_function` / `matches_stripped_function` — exact / `OSS_FUZZ_`-stripped

`SarifMatcher.match(sarif, frames)` returns the first frame↔location match, or
`None` (reject). 0verse frames come from `parse_frame` over the oracle's recovered
backtrace; SARIF locations from `extract_sarif_infos` over `runs[].results[]`.

## Conservative assessment = PoV-is-truth

`assess_broadcast` calls a SARIF **`correct` only when a confirmed 0verse PoV's
backtrace matches it** (ATLANTIS's conservative-assessment policy, which is just
PoV-is-truth restated). `incorrect` here means "0verse did not independently
confirm it with a PoV" — **not** a strong refutation; the honest framing is in the
assessment `note`. A matched-but-unconfirmed SARIF is never asserted as correct.

## Pointing it at the real public corpus

The adapter is **fixture-proven end to end** (schema round-trips, matcher
match/reject, PoV emit, `run_task` with an injected runner — see
`tests/test_crs_api.py`). The only step it does NOT do for you is fetch + build the
live OSS-Fuzz challenge — it accepts a pre-built `ResolvedTask.target_binary` so the
exact same code path runs locally and against the real corpus. To go live:

1. **Get a task.** Either take a `Task` JSON from the task server, or synthesize one
   from an `example-crs-architecture` challenge under `challenges/` (each has the
   `project_name` + harness names). `Task.from_dict(json.load(...))`.
2. **Resolve the sources.** For each `SourceDetail`, download `url` (a gzip tarball),
   verify `sha256`, and untar. `repo` = project source at `focus`; `fuzz-tooling` =
   the OSS-Fuzz `projects/<project_name>` build files; `diff` (delta mode) = the
   unified diff — feed it to `delta_files(detail, diff_text)` for priority hints.
3. **Build the harness.** Run the OSS-Fuzz build (`infra/helper.py build_fuzzers
   <project>`), then point `ResolvedTask.target_binary` at the built fuzz target in
   `build/out/<project>/<harness>` and set `harness_name` to that target's name.
   (This is the one shell-out the bench fixture stubs; it is standard OSS-Fuzz.)
4. **Run.** `run_task(resolved, broadcast=SARIFBroadcast.from_dict(b))` →
   `CRSRunResult` with `pov_submissions` (POST to `/v1/task/<id>/pov/`) and
   `sarif_assessments` (the broker SARIF verdicts). `CRSRunResult.scan_sarif()`
   emits the scan as a SARIF 2.1.0 document.
5. **Submit.** POST each `POVSubmission.to_dict()` to the competition API
   (`POVSubmissionResponse` returns `pov_id` + `SubmissionStatus`). PoV-is-truth:
   only confirmed, byte-carrying PoVs are ever emitted as submissions.

### Fixture-proven vs live-corpus-pending

| Component | Status |
|---|---|
| `Task` / `TaskDetail` / `SourceDetail` parse, `delta_files` | fixture-proven |
| `POVSubmission` emit (base64 testcase, confirmed-only) | fixture-proven |
| `extract_sarif_infos`, `parse_frame`, `match_frame`, `SarifMatcher` | fixture-proven |
| `assess_broadcast` (conservative, PoV-backed) | fixture-proven |
| `run_task` end-to-end (injected runner) | fixture-proven |
| Source tarball fetch + `sha256` verify + OSS-Fuzz harness build | **live-pending** (step 2–3 above; standard OSS-Fuzz, intentionally out of the engine) |
| Live competition API POST (`pov_id`, bundle submission) | **live-pending** (the HTTP client is a thin shell over `POVSubmission.to_dict()`) |
