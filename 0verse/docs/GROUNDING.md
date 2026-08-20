# Structural grounding

0verse can optionally check the structural premises behind an LLM severity
rating against the call graph already recovered from the binary. Enable the G1
gate with:

```sh
ZEROVERSE_GROUND=1 0verse target.bin
```

The gate is disabled when the variable is unset, empty, `0`, `false`, or `no`.
It does not run Ghidra a second time and it does not replace dynamic
confirmation.

## Decision contract

- `GROUNDED`: recovered binary structure supports the load-bearing premise; the
  proposed severity is retained.
- `REFUTED`: a complete recovered fact contradicts a load-bearing premise; the
  unconfirmed finding is floored to `info`.
- `UNKNOWN`: the available oracle cannot decide a load-bearing premise; severity
  above `low` is capped to `low`.
- A reproducing PoV overrides a static cap or floor. The serialized grounding
  record remains attached so the disagreement is visible.

Positive recovered facts can still ground a claim when a function also has an
unresolved indirect call. Negative facts cannot: any negative path that crosses
a caller with an unresolved edge is `UNKNOWN`, not `REFUTED`. Malformed
model-authored `@claim` lines are dropped rather than aborting analysis.

## Evidence and rollout

Each serialized finding includes the proposed and final severity, adjudicated
claims, recovered facts, and re-prompt facts in a `grounding` object. The current
benchmark is in `benchmarks/grounding/`; it is a small regression corpus, not a
claim of production-wide precision. Keep the gate opt-in until prospective runs
on captured Windows, Linux, browser, and hypervisor graphs show acceptable true
positive preservation.
