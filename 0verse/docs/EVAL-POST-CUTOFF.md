# 0verse post-training-cutoff CVE evaluation — discovery, not memorization (#49)

> **The discovery-vs-memorization proof.** Every other 0verse benchmark uses bugs
> the model could, in principle, have seen during training. A find on those cannot
> distinguish *discovery* from *recall*. This corpus is built **only** from real
> `CVE-2026-*` memory-safety bugs **published after current frontier models' training
> cutoff**, so confirming one is genuine discovery: a model cannot have memorized a
> bug that was disclosed after it was trained.
>
> Honest by construction. Numbers below are rendered by
> `zeroverse.groundtruth.format_report` from the scored result — no hand-edited
> cells. Misses, mislocations and hypothesis-noise are reported verbatim. Re-run:
> `python benchmarks/cve2026/run.py --llm codex`.

## The cutoff argument (why this is *provably* post-training)

A benchmark answers "discovery vs memorization" only if the bug instances are
disjoint from the model's training data. We make that **checkable**, not assumed:

* Every item is a **real CVE assigned in 2026** with an **authoritative NVD entry**
  and an **upstream fix reference** (commit / advisory / release). The publish date
  is recorded per item and machine-validated.
* The corpus declares a **conservative training cutoff of `2026-01-31`** — an upper
  bound on the training cutoff of the current frontier-model generation
  (GPT-5.5-class models report cutoffs in late-2025 / very-early-2026). Four of the
  five CVEs were **published in Q2 2026 (Apr–Jun)**, which is *unambiguously* after
  any plausible cutoff; the fifth (libtiff, 2026-03-24) is the weakest-guarantee
  item and is flagged as such.
* `zeroverse.groundtruth.validate_post_cutoff()` **gates the run**: it refuses to
  score any `real-cve` item that is missing an NVD URL / fix reference / publish
  date, or whose publish date is not strictly after the cutoff. The runner aborts
  on a violation unless `--no-cutoff-gate` is passed. This is enforced in CI by
  `tests/test_cve2026.py`.

The runner prints `post-cutoff gate OK: all real-cve items published after
2026-01-31` before any scan — so the post-cutoff property is asserted, not narrated.

### What "discovery" does and does not claim here

Honest scoping of the claim:

* The **vulnerability instance** (the specific overflow + its fix) is post-cutoff and
  cannot have been memorized. The **function names** (`opj_pi_initialise_encode`,
  `putcontig8bitYCbCr44tile`, …) are older and *were* in the training data — so this
  is not a claim that the model has never seen the symbol, only that it has never
  seen *this bug*.
* PoV-is-truth keeps it honest regardless: a finding is `confirmed` only when the
  **oracle reproduces a crash** (a real PoV), never on the model's say-so. A
  reproducing PoV on a post-cutoff bug is mechanical discovery, not recall.

## Methodology

* **Faithful standalone extracts.** Each item is a minimal C reproducer of the real
  upstream function: real function name, the real attacker→sink dataflow
  (`read(2)` → `memcpy`), and the **real upstream bound as the fix**, guarded by
  `#ifdef FIXED`. These are extracts, **not** full library builds (see Limitations).
  Provenance — CVE id, NVD URL, fix commit/advisory, publish date — is recorded in
  `benchmarks/cve2026/manifest.json` and `benchmarks/cve2026/provenance.json`.
* **Vulnerable + fixed pair.** Every CVE compiles to a *vulnerable* build and a
  *fixed* build (`-DFIXED`, the upstream patch). The fixed build is the
  **false-positive control**: any confirmed PoV on it is a false positive. We
  verified out-of-band (ASan) that every vulnerable build faults on a trigger input
  and every fixed build is clean before benchmarking.
* **Full pipeline, real model.** `zeroverse.api.scan` runs the whole CRS
  (ingest → decompile → slice → foxguard/bugclass lens → LLM reason → dynamic/PoV →
  fuzz). The LLM is the **real frontier model** via the operator's ChatGPT-OAuth
  Codex backend (`gpt-5.5`); no mock, no external sends.
* **Same typed scorer** as the ground-truth eval (`zeroverse.groundtruth`):
  recall (located / confirmed), FP rate (confirmed / hypothesis), precision. Held-out
  by construction (every item `in_seed_set=false`).

## Corpus provenance (5 CVEs · 10 builds)

| CVE | Library | Function | Class | Published | NVD | Upstream fix |
|-----|---------|----------|-------|:---------:|-----|--------------|
| **CVE-2026-6192** | OpenJPEG | `opj_pi_initialise_encode` | int-overflow → OOB write (CWE-190) | **2026-04-13** | [link](https://nvd.nist.gov/vuln/detail/CVE-2026-6192) | commit [`839936aa`](https://github.com/uclouvain/openjpeg/commit/839936aa33eb8899bbbd80fda02796bb65068951) |
| **CVE-2026-32740** | libheif | `copy_image_to` | heap OOB write (CWE-787) | **2026-05-19** | [link](https://nvd.nist.gov/vuln/detail/CVE-2026-32740) | [GHSA-frfr-f3vg-2g6j](https://github.com/strukturag/libheif/security/advisories/GHSA-frfr-f3vg-2g6j), fixed v1.22.0 |
| **CVE-2026-8461** ("PixelSmash") | FFmpeg | `magy_decode_slice` | heap OOB write (CWE-787) | **2026-06-18** | [link](https://nvd.nist.gov/vuln/detail/CVE-2026-8461) | FFmpeg commit `374b726f` (shipped 8.1.2) |
| **CVE-2026-58049** | FFmpeg | `decode_dlta` | heap OOB write (CWE-787) | **2026-06-27** | [link](https://nvd.nist.gov/vuln/detail/CVE-2026-58049) | `libavcodec/rasc.c` byte-unit bound ([VulnCheck](https://www.vulncheck.com/advisories/ffmpeg-out-of-bounds-write-in-rasc-decoder-decode-dlta)) |
| CVE-2026-4775 | libtiff | `putcontig8bitYCbCr44tile` | signed int-overflow → OOB write (CWE-190) | 2026-03-24 ⚠ | [link](https://nvd.nist.gov/vuln/detail/CVE-2026-4775) | [Red Hat RHSA](https://access.redhat.com/security/cve/CVE-2026-4775), `tif_getimage.c` |

⚠ libtiff is Q1-tail (Mar 2026): after the conservative cutoff, but the four Q2
CVEs are the strongest post-cutoff guarantee.

The CVEs were selected after rejecting any that could not be confirmed against **both**
an NVD entry **and** a real upstream fix reference — the project has previously been
burned by hallucinated, AI-aggregator-only CVE ids, so unverifiable candidates were
dropped.

## Results — the real numbers (Codex / `gpt-5.5`, full pipeline)

Two independent runs on two decompiler backends. Both are reported (no
cherry-picking); the spread is real run-to-run variance (stochastic fuzzing + LLM).

| metric | Ghidra backend | rizin backend |
|--------|:--------------:|:-------------:|
| vulnerable / clean items | 5 / 5 | 5 / 5 |
| **recall (located at correct function)** | **80% (4/5)** | **80% (4/5)** |
| recall (confirmed PoV, *function-localized*) | 0% (0/5) | 20% (1/5) |
| **program-level discovery** (vuln builds with a reproducing PoV) | **40% (2/5)** | **60% (3/5)** |
| **FP rate (confirmed PoV on fixed builds)** | **0% (0/5)** | **0% (0/5)** |
| FP rate (hypothesis-only noise on fixed builds) | 100% (5/5) | 20% (1/5) |

### How to read this honestly

* **Localization is strong and stable: 4/5.** The static + foxguard + LLM lens put a
  finding on the *correct upstream function* for OpenJPEG, libheif, FFmpeg-MagicYUV
  and libtiff in both runs. **FFmpeg-RASC `decode_dlta` was missed in both runs** —
  its delta-run loop did not surface a clean source→sink slice. Reported as a miss.
* **Discovery is real but modest: 2–3 of 5 vulnerable builds produced a reproducing
  PoV** — a genuinely crashing input the oracle replayed, on a bug published after the
  model was trained. This is exactly the "expect a modest confirmed rate, and that's
  the point" regime: a real ~40–60% reproducing-PoV rate on never-seen bugs is a
  meaningful discovery signal, not recall.
* **Zero confirmed false positives — 0/5 on the fixed controls in both runs.** This is
  the load-bearing credibility number: PoV-is-truth never fired on a patched build, so
  every reproducing PoV discriminated the vulnerable build from its fix.
* **The function-localized `recall_confirmed` undercounts discovery.** Most confirmed
  PoVs came from the **fuzz lane**, which reports the crash as `<whole-program>`
  rather than attributing the faulting PC to the function; the strict scorer then
  files a real reproducing PoV as "located-hypothesis" (or, if the function was not
  also located, "miss"). The **program-level discovery** row is the truer measure of
  reproducing discovery here.
* **Hypothesis-noise on fixed builds is high (up to 5/5 with Ghidra).** The fix is a
  *guard*; the `memcpy` sink still exists in the patched source, so the static/LLM
  lens raises the same hypothesis on the fixed build. These are **hypothesis-level,
  not confirmed** — no PoV reproduced — but they show the static lens alone cannot
  separate vulnerable from fixed; only the PoV stage does (and it does, cleanly).

Raw scored results: `benchmarks/cve2026/results-codex-ghidra.json`,
`benchmarks/cve2026/results-codex-rizin.json`.

## Limitations (read before quoting a number)

* **Faithful extracts, not full builds.** Each item models the real function, its
  real source→sink path and the real fix, but is a standalone reproducer — not the
  shipping OpenJPEG/libheif/FFmpeg/libtiff binary. It measures whether 0verse finds
  *the bug's pattern in post-cutoff code*, not end-to-end whole-library triage.
  libheif's function is originally C++ (`pixelimage.cc`); it is extracted as C.
* **Function names predate the cutoff; the bugs do not.** See "What discovery claims".
* **Fuzz confirms are whole-program-attributed**, deflating the strict
  function-localized recall — see above.
* **Stochastic.** Two runs differ (libtiff was a function-localized `confirmed-find`
  on rizin, only program-level on Ghidra). Treat single-run cells as samples.
* **One CVE (libtiff) is Q1-tail (March).** The four Q2 CVEs carry the airtight
  post-cutoff guarantee.

## Reproduce

```bash
# real model, full pipeline, post-cutoff gate enforced:
python benchmarks/cve2026/run.py --llm codex \
    --out benchmarks/cve2026/results-codex.json
# a single CVE pair:
python benchmarks/cve2026/run.py --llm codex \
    --only ffmpeg_magicyuv_vuln ffmpeg_magicyuv_fixed
# deterministic offline floor (no model, no sends):
python benchmarks/cve2026/run.py --llm mock
```

The post-cutoff provenance gate, the manifest loader and the scorer reuse are
unit-tested in `tests/test_cve2026.py` (`pytest -q tests/test_cve2026.py`).
