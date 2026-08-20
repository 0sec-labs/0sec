# 0verse benchmarks — 0verse lane vs baseline AFL++

> Status: 2026-07-25. Historical, condition-specific benchmark record. The
> numerical results below are retained unchanged from the 2026-06-28 campaigns
> and apply only to the recorded targets, host, lane configuration, budgets, and
> single-trial design. They do not establish live-proven or operational maturity.
>
> **Honest, bounded, on real bugs.** Two complementary comparisons, both on the
> `bench` box, both rendered from machine-readable NDJSON by `zeroverse.benchmark`
> (no hand-edited numbers). **(1) Real Magma targets** — 0verse's CMPLOG/redqueen
> lane vs baseline AFL++ on real upstream libraries, scored against Magma's
> ground-truth fatal canaries. **(2) A controlled gate-cracking ablation** on three
> synthetic targets that isolates *exactly* what the slice-mined dictionary + CMPLOG
> add over plain AFL++. Where baseline ties or wins, we say so.

## 1. Real Magma targets (0verse-CMPLOG vs baseline AFL++)

Magma (github.com/HexHive/magma) targets are real upstream libraries carrying real,
catalogued bugs. We build each target **`-O0` with fatal canaries** (`isan=1`) so a
Magma-bug trigger **aborts the process — a ground-truth confirmation**. Two AFL++
lanes fuzz the **same** Magma driver from the **same** Magma seed corpus, changing
only what 0verse adds:

| lane | CMPLOG/redqueen | else |
|------|-----------------|------|
| **0verse**   | ✅ (`-c` cmplog binary) | Magma driver + seeds |
| **baseline** | ❌ | Magma driver + seeds |

- **Metric:** wall-clock **time-to-first-Magma-canary-trigger** (TTE);
  `AFL_BENCH_UNTIL_CRASH` stops at the first trigger. A lane that does not trigger
  within the budget is recorded as `none`, never a silent loss. A trigger is a
  **real-CVE-class bug confirmation** (the fatal canary), not a raw AFL signal.
- **Budget:** 300 s per lane. **Targets:** the built C/C++ subset. **Trials:** 1 per
  (target, lane). **Host:** `bench` (the container's own AFL++ `++3.14a`).

### Results (300 s budget, run 2026-06-28)

| target | 0verse-CMPLOG TTE | baseline AFL++ TTE | winner | margin |
|--------|------------------|--------------------|--------|--------|
| `magma/libpng` (ungated easy bug) | 27.7 s | **9.0 s** | **baseline** | −18.7 s |
| `magma/libxml2` (structure-gated) | **17.0 s** | 191.1 s | **0verse** | +174.0 s |
| `magma/libsndfile` | **13.9 s** | none (>300 s) | **0verse** | — |
| `magma/libtiff` | **28.1 s** | 38.4 s | **0verse** | +10.4 s |

**Scoreboard: 0verse 3 · baseline 1 · tie 0 · neither 0 (n=4).** Every TTE is a
**real Magma ground-truth canary trigger** (a real CVE-class bug), not a raw AFL
signal. Raw machine output: `benchmarks/magma/results-magma-afl.ndjson`.

- **`libxml2` is the headline win** — CMPLOG/redqueen cracks the XML structure to the
  vulnerable path in **17 s** where baseline AFL++ took **191 s** (~11×), and
  **`libsndfile` baseline never triggered in 300 s** while the 0verse lane did at 14 s.
- **`libpng` is the honest control loss** — its bug is ungated, so plain AFL++ grows
  the seed to it faster (9 s) and CMPLOG is pure overhead (27.7 s). Reported as a
  baseline win, not hidden.

### Reading the Magma campaign honestly

- A trigger here is a **real, catalogued Magma bug** firing its ground-truth canary —
  this is where **confirmed bugs at scale** live (the binary-native static/LLM
  pipeline *reaches* bug-sites but rarely synthesizes the deep trigger; the fuzzer
  does — see [EVAL-GROUNDTRUTH.md](EVAL-GROUNDTRUTH.md)).
- On targets whose easy bug needs **no gate**, both lanes trigger fast and it is an
  honest **tie/control** — CMPLOG adds nothing without a structural barrier to crack.
- 1 trial each, single budget, shared box (a concurrent scan ran during some lanes):
  treat TTE as order-of-magnitude, not a variance-controlled measurement.

## 2. Controlled gate-cracking ablation (synthetic, isolates dict+CMPLOG)

This isolates the slice-mined-dictionary + CMPLOG contribution with zero confound:
both lanes fuzz the **same** `#16`-synthesized harness from the **identical single
`\x00` seed**; only {dictionary + CMPLOG} varies.

| lane | CMPLOG/redqueen | dictionary | seed |
|------|-----------------|------------|------|
| **0verse**   | ✅ | slice-mined tokens (`tokens_from_context`) | `\x00` |
| **baseline** | ❌ | none | `\x00` |

Each crash is run through 0verse's differential-allocator oracle, so a reported
crash is a **confirmed PoV** (PoV-is-truth).

### Targets

| target | gate | why it's here |
|--------|------|---------------|
| `ungated`      | none | trivial heap OOB — the honest **control** where 0verse should NOT win |
| `magic_gated`  | 4-byte `REC0` header | a string gate the mined dictionary + CMPLOG crack |
| `nested_gated` | `FMW1` + 32-bit `0xCAFEBABE` | a string gate **and** an integer gate |

### Results (60 s budget, run 2026-06-28)

| target | 0verse TTE | baseline TTE | 0verse execs | baseline execs | winner |
|--------|-----------|--------------|--------------|----------------|--------|
| `ungated`      | 0.8 s | **0.5 s** | 453 | 568 | **tie** |
| `magic_gated`  | **0.8 s** | none (>60 s) | 7 472 | 2 024 675 | **0verse** |
| `nested_gated` | **0.8 s** | none (>60 s) | 3 548 | 1 993 118 | **0verse** |

**Scoreboard: 0verse 2 · baseline 0 · tie 1 · neither 0 (n=3).**

- **`ungated` is a tie** (baseline marginally faster, 0.5 s vs 0.8 s) — with no gate,
  the dictionary/CMPLOG machinery is pure overhead. Reported as a tie inside the
  noise floor, not spun as a win.
- **`magic_gated` / `nested_gated` are real 0verse wins** — baseline burned ~2 M execs
  and never cracked the atomic 4-byte (and 32-bit) compares in 60 s; the 0verse lane
  cracked them in **< 1 s** with the slice-mined dictionary + CMPLOG.

## What this does NOT measure (caveats — read before citing)

- **Tiny scale, single trial.** No statistical significance or variance bars; treat
  TTE as order-of-magnitude.
- **The Magma campaign is bounded** (300 s, 1 trial, shared box, fatal-canary →
  first-bug-only). It is **not** the multi-day, multi-trial, non-fatal-canary
  `bug-count-over-24h` study Magma's paper methodology prescribes — that is the
  documented path-to-full-run.
- **The synthetic ablation holds the harness constant** (plain AFL++ cannot fuzz an
  internal function without *some* harness), so it isolates seed/dict/CMPLOG, not the
  value of harness synthesis itself.
- **`execs_per_sec` is not captured** (shown as 0 in the NDJSON); only total `execs`.

## Reproduce

```sh
# Real Magma targets (build the isan images first — see EVAL-GROUNDTRUTH.md):
BUDGET=300 ./magma-afl-campaign.sh    # -> magma-afl-results.ndjson

# Controlled synthetic ablation (inside the engine env with AFL++):
python benchmarks/fuzzbench/compare.py --budget 60 --out benchmarks/fuzzbench/results.ndjson

# Render either table:
python - <<'PY'
from zeroverse.benchmark import parse_results, summarize, format_table
print(format_table(summarize(parse_results(open("benchmarks/fuzzbench/results.ndjson").read()))))
PY
```

Schemas: `zeroverse.benchmark.BenchTrial` (v1.0). The Magma campaign's NDJSON uses
the same schema (`lane` ∈ {`0verse`, `baseline`}).
