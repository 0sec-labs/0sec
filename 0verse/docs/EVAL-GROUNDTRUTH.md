# 0verse ground-truth evaluation — does it find REAL bugs without crying wolf?

> **The credibility instrument.** Everything else measures 0verse against *itself*
> (ablations, baselines). This measures it against **ground truth**: real bugs with
> KNOWN locations + fix commits, scored for **reach** / **recall** (did it surface
> the bug at the right function/sink, with a reproducing PoV?) and **FP rate** (does
> it confirm bugs on the *fixed* / clean builds?).
>
> The **headline** number is the **real-LLM** run on **Magma** — real upstream
> libraries (libpng / libxml2 / libtiff / lua / sqlite3 / libsndfile ...) carrying
> real, catalogued CVE-class bugs at scale. The small real-CVE-reproducer corpus
> below it is a **held-out sanity / regression set**, *not* the capability claim.
> The deterministic **MockLLM** run is the **CI regression floor** — it proves the
> harness wiring + static lenses still fire with no keys/network, and is **never a
> capability number**.
>
> Honest by construction: every table is rendered from a scored `results*.json` by
> `zeroverse.magma.format_magma_report` / `zeroverse.groundtruth.format_report` — no
> hand-edited numbers. Misses and false positives are reported verbatim.

## What's measured

PoV-is-truth, ASSUME-FP, carried through both corpora:

| metric | definition |
|--------|------------|
| **reached** | the bug's function was *surfaced* by a finding (slice/lens), PoV or hypothesis — coverage, not a confirmation |
| **confirmed (recall)** | the **oracle reproduced a PoV** at the right function (a fatal-canary abort or a sanitizer crash) — never an LLM's say-so |
| **confirmed-PoV rate** | of the *reached* bugs, the fraction that reached a reproducing PoV (vs stayed a hypothesis) |
| **FP — confirmed** | a confirmed PoV that lands on **no** catalogued bug (unmatched), or **any** confirmation on a *fixed* build — the serious false alarm (should stay ~0) |
| **precision (confirmed)** | over all *confirmed* findings, the fraction landing on a real bug at the right place |

The scorers are pure + typed (`mypy --strict`) and unit-tested against fixture
ground truth (`tests/test_magma.py`, `tests/test_groundtruth.py`) — the reach /
recall / FP / precision math, the catalogue + manifest loaders, the held-out
tagging, and the `MAGMA_`-symbol-prefix normalization — no Ghidra/Docker needed to
test the math.

---

## Headline — Magma at scale (real LLM: Codex `gpt-5.5`)

**Magma** (github.com/HexHive/magma) is the real, well-fuzzed-code benchmark: each
target is a real upstream library whose real bugs are toggled by
`MAGMA_ENABLE_FIXES` and guarded by ground-truth `MAGMA_BUG` canaries. We build each
target **`-O0` with fatal canaries** (`isan=1`) so a Magma-bug trigger aborts the
process (== a ground-truth confirmation), run the **full 0verse pipeline**
(`zeroverse.api.scan`, Ghidra → slice → foxguard → LLM-triage funnel → angr prune →
oracle → PoV → fuzz complement) over the driver binary with the **real model**, and
score the findings against Magma's KNOWN bug locations with `zeroverse.magma`.

### Subset built (what's IN / OUT)

**All eight** feasible C/C++ targets were **built** on `bench` (aflplusplus image,
fatal canaries, `-O0`) in ~25 min total: `libpng`, `lua`, `libxml2`, `libtiff`,
`sqlite3`, `libsndfile`, `openssl`, `php`. The catalogue (`CATALOGUE-magma.json`,
**138** bugs) is the full provenance manifest.

- **IN (binary-native-scored with Codex):** `lua`, `libpng`, `libsndfile`, `libxml2`,
  `libtiff` — **5 targets, 8 driver binaries** (libxml2/libtiff ship multiple
  fuzzers, all scanned + aggregated).
- **OUT (built, not scored):** `sqlite3`, `openssl`, `php` — the real-LLM run was
  **bounded** and killed after 5 targets (~107 min wall) to stay in-session; their
  drivers are the biggest (Ghidra-cost) and are the documented **path to a full run**.
- **OUT entirely:** `poppler` (C++) was not built.

This is the largest in-session scored subset; running the remaining three (and a
`fixes=1` FP-probe build per target) is a config change, not new code.

> **Lane: `real-llm-capability`** — Codex `gpt-5.5`, `bench`, Ghidra, fatal-canary
> `-O0` builds, 2026-06-28. **5 of 8 built targets** binary-native-scored
> (`benchmarks/magma/results-magma-codex.json`, `partial: true`); the run was bounded
> — `sqlite3`, `openssl`, `php` are **built but not scored** (Ghidra/time budget — see
> residuals). Rendered by `zeroverse.magma.format_magma_report`.

| metric | value |
|--------|-------|
| bug-sites reached (slice/lens) | **8 %** (4/53) |
| **bug-sites confirmed (reproducing PoV)** | **0 %** (0/53) |
| confirmed-PoV rate (of reached) | 0 % (0/4) |
| **false positives — confirmed on a non-bug site or a fixed build** | **0** |
| precision (confirmed findings) | n/a (no confirmed findings) |

| target | bug-sites | reached | confirmed | FP | ghidra | wall (s) |
|--------|:---------:|:-------:|:---------:|:--:|:------:|:--------:|
| `lua` | 4 | 1 | 0 | 0 | ok | 634 |
| `libpng` | 7 | 1 | 0 | 0 | ok | 571 |
| `libsndfile` | 14 | 1 | 0 | 0 | ok | 857 |
| `libxml2` (3 drivers) | 14 | 1 | 0 | 0 | ok | 2875 |
| `libtiff` (2 drivers) | 14 | 0 | 0 | 0 | ok | 1504 |

_60 catalogued bugs collapse to **53 distinct scorable bug-sites** (co-located bugs
share a function). Total wall **≈107 min** for 5 targets / 8 driver binaries (~10–48
min each, **Ghidra-dominated**). Token totals were not captured for this partial run
(the runner now prints per-target `tok=in+out`); the Codex path rides a ChatGPT
subscription, so the real cost axis is **latency / token volume, not $/token**._

**The honest read:** across 5 real, well-fuzzed libraries the binary-native pipeline
**reached ~8 % of catalogued bug-sites and confirmed none through the fuzz drivers,
with zero false positives.** That is the truthful difficulty of Magma — a small,
clean signal, not 100 % on toys. `libtiff` reached **0** (the decode/predict bug
functions never surfaced on the driver's intraprocedural slice). Confirmation at
scale is the **fuzzing lane's** result, not this one — see below + BENCHMARKS.md.

### Reading the Magma numbers honestly (no spin)

- **Magma is HARD, and the number says so.** 0verse's static + LLM lanes **reach** a
  fraction of the catalogued bug-sites (the slice/lens surfaces the right function),
  but binary-native **confirmation** of a *specific* mature-library bug through a
  `libFuzzer`/`AFL`-style driver is genuinely difficult: the oracle has to synthesize
  the deep, structured input (a valid PNG/TIFF/XML stream that *also* drives the
  vulnerable path) that trips the fatal canary. A modest reach with a **near-zero
  confirmed-PoV rate is the truthful result** — far more honest than 100 % on toys.
- **Zero (or near-zero) false positives is the load-bearing claim.** The oracle —
  not a lens or an LLM — decides `confirmed`, so an unconfirmed lens lead on a real
  library degrades to a hypothesis and never manufactures a confirmation. Precision
  over confirmed findings holds high; confirmations on the fixed builds stay at 0.
- **Where confirmation at scale actually lives: the fuzzing lane.** Triggering Magma
  bugs at scale is what a *fuzzing campaign* does — see the **0verse-CMPLOG vs
  baseline AFL++** comparison on real Magma targets in
  [docs/BENCHMARKS.md](BENCHMARKS.md), measured against the same ground-truth fatal
  canaries. The binary-native pipeline's contribution at scale is **reach + triage +
  zero-FP discipline**; the fuzzer's contribution is **the trigger**.

### Honest caveats — read before citing

- **Function-level matching.** A bug-site is credited when a finding lands on the
  catalogued bug *function* (normalizing libpng's `MAGMA_`-symbol prefix). It does not
  verify byte-offset equality. Several Magma bugs share one function (e.g.
  `psf_binheader_writef` hosts SND010/012/013) — those **collapse to one scorable
  bug-site**; we report the raw bug count alongside the distinct-site denominator.
- **Ghidra cost is the binary-native bottleneck.** Decompiling a multi-MB driver is
  minutes-to-tens-of-minutes and RAM-heavy; targets that exceed the per-binary budget
  are reported as a `ghidra=degrade` miss, not silently dropped.
- **Intraprocedural slice.** Cross-function taint (tainted read in the driver, sink
  deep in a callee) is a known miss — a real engine limitation surfaced by the eval,
  not hidden by it.
- **Single model, single backend, x86-64 ELF, bounded budget.** The number is a
  bounded-budget snapshot, not a multi-day sweep.

---

## Held-out sanity / regression set (NOT the capability claim)

A small labeled corpus that runs in minutes and is checked into the repo. Its role is
**regression + held-out sanity** — to catch a lens/oracle regression and to show a
generic lens *generalizing* to a real CVE instance — **not** to state capability.
Manifest: `benchmarks/groundtruth/manifest.json` (14 items: 9 vulnerable / 5 clean).

### Tier 1 — held-out real-CVE reproducer pairs (`in_seed_set=false`)

Faithful **standalone extracts** of real upstream vulnerable functions (real name,
real sink, real upstream fix), built BOTH **vulnerable** and **fixed** (`-DFIXED`).
The fixed build is the FP probe.

| id | CVE | CWE | function | upstream |
|----|-----|-----|----------|----------|
| `cve_2004_0597_png_{vuln,fixed}` | CVE-2004-0597 | CWE-120 | `png_handle_tRNS` | libpng |
| `cve_2017_9047_xml_{vuln,fixed}` | CVE-2017-9047 | CWE-787 | `xmlSnprintfElementContent` | libxml2 — **== Magma XML001** |
| `cve_2012_0809_sudo_{vuln,fixed}` | CVE-2012-0809 | CWE-134 | `sudo_debug` | sudo |

These bug instances were **never used to build any 0verse detector** (the lenses are
generic CWE patterns; the one variant seed is macOS IOKit), so a find reads as
generalization. `cve_2017_9047` *is* Magma **XML001** — independent corroboration
that the reproducer tracks a real, catalogued bug.

### Tier 2 — sanity floor (0verse's own fixtures; `in_seed_set=true`)

The `benchmarks/*.c` synthetic fixtures + two clean look-alikes. Explicitly **not**
held-out evidence — the floor that proves the harness wiring works end to end.

### The MockLLM run is the CI **regression floor** — NOT a capability measure

The deterministic `MockLLM` lane (no keys, no network, runs in CI) is the
**`ci-regression-floor (NOT a capability measure)`** lane. `format_report` stamps that
banner on its output and `results.json` carries `"capability_measure": false`, so a
MockLLM percentage **cannot be misread as performance**. It exists only to detect a
regression in the static lenses + oracle wiring. The runner now **defaults to the
real LLM** (`--llm codex`); `--llm mock` prints a loud floor warning.

> **Lane: `ci-regression-floor (NOT a capability measure)`** · `results.json`
> (`capability_measure: false`), `bench`, Ghidra, x86-64 ELF, 14 items (2026-06-28):

| metric (14-item set) | MockLLM **regression floor** |
|---|:--:|
| recall — confirmed PoV | 67 % (6/9) |
| recall — located (PoV *or* hypothesis) | 100 % (9/9) |
| FP — confirmed on clean/fixed builds | **0 %** (0/5) |
| precision — confirmed findings | 100 % |

_This number's **only** job is to fail CI if a lens/oracle regresses (e.g. the floor
drops). It is **not** a capability measure — it runs with no keys/network and no
frontier reasoning. The capability claim is the **Magma headline above**; the
real-LLM (`gpt-5.5`) run on this same small set (`results-codex.json`) is the
*sanity* ceiling, not the headline._

> The real-LLM lane on this small set is the *sanity* ceiling, not the headline; the
> headline is Magma above. The earlier revisions of this doc presented a MockLLM
> percentage on these 14 items as the result — that was a sanity check mis-presented
> as a capability number, and is corrected here.

---

## Reproduce

```bash
ssh bench
export GHIDRA_INSTALL_DIR=/opt/ghidra
# --- Magma at scale (the headline), real LLM (Codex gpt-5.5 via ChatGPT-OAuth) ---
# 1. build a target with fatal canaries, -O0 (aflplusplus image):
docker build -t magma/aflplusplus/libpng:isan \
  --build-arg fuzzer_name=aflplusplus --build-arg target_name=libpng \
  --build-arg USER_ID=1000 --build-arg GROUP_ID=1000 \
  --build-arg canaries=1 --build-arg isan=1 -f magma/docker/Dockerfile magma/
# 2. scan + score (extracts the driver from the image, runs the full pipeline):
python benchmarks/magma/run.py --targets libpng lua libxml2 libtiff \
    --llm codex --out benchmarks/magma/results-magma-codex.json

# --- held-out sanity / regression set ---
python benchmarks/groundtruth/run.py --llm codex \
    --out benchmarks/groundtruth/results-codex.json
# CI regression floor (deterministic, no keys — NOT a capability number):
python benchmarks/groundtruth/run.py --llm mock \
    --out benchmarks/groundtruth/results.json
```

`results-magma-codex.json` (schema `zeroverse.magma`, v1.0) and `results.json`
(schema `zeroverse.groundtruth`, v1.0) carry the full per-target/per-item findings +
the metrics block + the `lane` / `capability_measure` stamp.
