# Good first issue: add a benchmark

**Labels:** `good first issue`, `benchmark`, `M6`
**Difficulty:** ⭐⭐ (medium) · **Area:** `benchmarks/`

## What

Grow the ground-truth corpus, or extend the 0verse-vs-baseline-AFL++ comparison.
Two flavors:

- **A PoV-gate benchmark:** a `benchmarks/<name>.c` with a known, reproducing bug,
  wired into `benchmarks/run.sh` so CI asserts the pipeline confirms it with a PoV.
- **A comparison target:** a new target in `benchmarks/fuzzbench/compare.py::TARGETS`
  — ideally one that probes a *different* gate shape (checksum gate, length-prefix
  framing, a state machine) so we learn where 0verse helps and where it doesn't.

## Why

Benchmarks are the project's honesty anchor. More targets = a clearer, less
cherry-picked picture of where the engine wins, ties, or loses to plain AFL++.

## How

1. Write the target C with a clearly-commented bug (heap buffer so the
   differential-allocator oracle can confirm — see `benchmarks/fuzzbench/targets/`).
2. For a PoV-gate benchmark: add it to `benchmarks/run.sh` with its expected
   `source:sink`. For a comparison target: add `(name, func, decl)` to `TARGETS`.
3. Run it and record the **honest** numbers in `docs/BENCHMARKS.md`. If baseline
   AFL++ ties or wins, that's a valid result — say so, and note it in
   `NEGATIVE-RESULTS.md`.

## Definition of done

- [ ] Target compiles and the bug reproduces.
- [ ] Wired into `run.sh` (PoV gate) **or** `compare.py::TARGETS` (comparison).
- [ ] `docs/BENCHMARKS.md` updated with honest numbers + caveats — **no
      cherry-picking**.

See [CONTRIBUTING.md](../../CONTRIBUTING.md#add-a-benchmark-benchmarks) and
[docs/BENCHMARKS.md](../BENCHMARKS.md).
