# 0verse real-LLM evaluation

> **Honest, measured, reproducible.** This is the end-to-end evaluation of 0verse
> driven by a **real frontier model** (not `MockLLM`) over a labeled corpus. No
> cherry-picking: misses, false positives, and the places the model does *not*
> help are reported alongside the wins. Re-run it with
> `python benchmarks/llm_eval.py` (writes `benchmarks/llm_eval_results.json`,
> committed alongside this doc).

## Setup

| | |
|---|---|
| **Model** | `gpt-5.5` via the ChatGPT-OAuth **Codex** Responses API (`CodexOAuthLLM`) |
| **Host** | `bench` (Ryzen 3900, 62 GB) — Ghidra 11 (PyGhidra), angr, AFL++, gcc |
| **Backend** | Ghidra (default), x86-64 ELF |
| **Baseline** | the deterministic `MockLLM` — the static lenses + oracle with **no** frontier reasoning: the **CI regression floor** (what the lenses alone do), **never a capability number**. The capability column is the real model. |
| **Billing** | the Codex path is a ChatGPT **subscription**, not a metered key — so the real cost axis is **latency + token volume**, not dollars-per-token |

Each target is run through the **full pipeline** (`pipeline.run`) twice — once with
`MockLLM`, once with the live model — recording findings, confirmed PoVs, triage
escalations, wall-time, and token volume each. Token counts include **both** the
LLM triage funnel **and** in-pipeline harness synthesis (#16), which fires on the
fuzz complement when the static slice confirms nothing.

### Corpus

- **6 vulnerable** programs — one per confirmable class plus the hypothesis-only
  logic class: `cmdi` (CWE-78), `overflow` (CWE-120), `fmtstring` (CWE-134),
  `intoverflow` (CWE-190), `uaf` (CWE-416), `auth_bypass` (CWE-287, logic).
- **2 clean look-alikes** that deliberately **trip the static lenses but are
  safe** — `clean_safe_malloc` (a `count*elem` multiply into `malloc`+`memcpy`,
  but bounded *before* the multiply) and `clean_bounded_copy` (a `read`→`strncpy`
  bounded copy). These probe **hypothesis-level false positives**.
- **1 real known-good binary** — `/usr/bin/true` — probes **confirmed-PoV false
  positives** on a real, libc-linked coreutils binary.

## Results

**Vulnerable corpus** (`confirmed` = a reproducing PoV from the oracle):

| target | expected | mock confirmed | real confirmed | class the real model assigned | real wall | real tokens (in/out) |
|---|---|:--:|:--:|---|--:|--:|
| `cmdi` | CWE-78 | **2** | **2** | CWE-78 OS Command Injection | 21 s | 750 / 430 |
| `overflow` | CWE-120 | **1** | **1** | CWE-121 stack overflow via unbounded `strcpy` | 13 s | 586 / 276 |
| `fmtstring` | CWE-134 | **1** | **1** | CWE-134 externally-controlled format string | 14 s | 3834 / 291 |
| `intoverflow` | CWE-190 | 2 | **3** | CWE-190→CWE-122 integer truncation → heap overflow | 69 s | 2051 / 1359 |
| `uaf` | CWE-416 | **0** | **1** | CWE-416 Use After Free | 40 s | 1472 / 1027 |
| `auth_bypass` | CWE-287 logic | 0 (hyp-only) | 0 (hyp-only) | — surfaced an honest hypothesis, no PoV | 167 s | 1573 / 3666 |

**Clean corpus** (any confirmed PoV here is a false positive):

| target | confirmed FP (mock / real) | hypothesis noise (mock / real) | real wall | real tokens (in/out) |
|---|:--:|:--:|--:|--:|
| `clean_safe_malloc` | 0 / 0 | **2 / 0** | 129 s | 2697 / 2581 |
| `clean_bounded_copy` | 0 / 0 | 0 / 0 | 73 s | 379 / 1137 |
| `/usr/bin/true` | 0 / 0 | 0 / 0 | 331 s | 4544 / 8106 |

## Headline

| metric | static lenses only (MockLLM) | + real model (`gpt-5.5`) |
|---|:--:|:--:|
| **confirmable classes with a reproducing PoV** | **4 / 5** | **5 / 5** |
| confirmed false positives on clean binaries | 0 / 3 | **0 / 3** |
| hypothesis-level false positives on clean code | 2 | **0** |
| logic/auth-bypass (hypothesis-only, never auto-confirmed) | hypothesis | honest hypothesis |
| total wall-time, 9 targets ×2 lanes | 175 s | 857 s |
| total output tokens (triage + harness-synth) | 0 | ~18.9 k |

**PoV-is-truth held under the real model:** zero false confirmations on three clean
binaries in **both** lanes. The oracle, not the LLM, decides `confirmed`, so a
hallucinating model cannot manufacture a finding — at worst it degrades to a
hypothesis.

## Where the LLM earns its latency

Three concrete, measured wins over the static lenses alone:

1. **Trigger synthesis unlocks UAF (the headline).** The use-after-free is silent
   under the stock allocator and confirms only when something supplies the
   triggering input (first byte `X`). The static/structural baseline never
   proposes it (`uaf[mock]`: 0 confirmed), so the bug stays a dead hypothesis. The
   real model reads the decompiled branch, proposes the trigger, and the
   quarantine-guard oracle confirms a real CWE-416 (`uaf[real]`: 1 confirmed). The
   same mechanism is why the integer-overflow lane goes from 2→3 confirmed slices.
2. **It kills the lens false positives.** `clean_safe_malloc` is built to trip the
   #22 integer-overflow lens (a `count*elem` multiply feeding `malloc`/`memcpy`).
   The structural baseline flags **2** hypotheses as real; the model reads the
   `if (count > 1024 || elem > 64) return` guard and the `size_t` widening and
   marks all of them **not real** — hypothesis-level FPs drop **2 → 0**, with no
   loss of true-positive recall.
3. **Sharper classification.** The model assigns precise, chained CWEs
   (CWE-190→CWE-122 truncation→heap-overflow; CWE-121 vs the baseline's generic
   CWE-120) — better triage signal for a downstream analyst or the 0cloud contract.

## Harness synthesis (#16)

On `parse_record` (the slice-blind, magic-gated heap overflow in `parser.c`):

| synthesizer | compiles | attempts | from LLM | wall |
|---|:--:|:--:|:--:|--:|
| deterministic template | ✅ | 1 | no | 0.0 s |
| real `gpt-5.5` | ✅ | **1** | yes | 54.5 s |

The model emitted a **first-try-compiling** harness that correctly read stdin into
a buffer and passed `(buf, len)` to the target with an ABI-matched `extern`. The
compile→error-feedback→repair loop was therefore **not exercised on this target**
(nothing to repair); its iteration is covered by the unit tests
(`test_build_harness_repairs_compile_errors`, and the new degrade tests). Net: the
real synthesizer matched the template's 100% compile-success here while producing a
function-specific harness rather than the generic one.

## Honest misses & caveats

- **The logic / auth-bypass class never auto-confirms** — by design there is no
  generic binary oracle for it. The model spent the single most expensive call of
  the run (167 s, 3.7 k output tokens) to surface *one* honest hypothesis on
  `auth_bypass`, with **no** PoV. That is correct behavior, but it is also the
  worst cost-per-signal in the corpus.
- **Cost is dominated by in-pipeline harness synthesis on clean/libc binaries.**
  `/usr/bin/true` confirmed nothing (correctly) yet cost 331 s / 8.1 k output
  tokens, because the fuzz complement synthesizes a harness per fuzzable libc
  function with the live model. For a clean target this is pure overhead — a
  production deployment should gate LLM harness-synth behind a slice signal or cap
  the number of synthesized functions.
- **Small corpus, single backend, single model.** This is a bounded ablation on
  hand-built fixtures (mirroring `docs/BENCHMARKS.md`'s methodology), not a
  multi-day Magma/FuzzBench sweep, and it is x86-64 ELF / Ghidra only. It isolates
  what the model adds; it is not a claim about real-world CVE yield.
- **`gpt-5.5` via Codex is slow** (10–170 s per escalation). The path exists
  because it needs no metered key (a ChatGPT subscription), not because it is the
  cheapest option — a metered Claude/GLM key would cut latency. See
  `src/zeroverse/llm/codex_llm.py`.

## Reproduce

```bash
ssh bench
cd /root/0verse && . .venv/bin/activate && export GHIDRA_INSTALL_DIR=/opt/ghidra
python benchmarks/llm_eval.py --out benchmarks/llm_eval_results.json
```

The harness compiles the corpus, runs the full pipeline under both `MockLLM` and
`CodexOAuthLLM`, and writes per-target findings + a summary to JSON. Token volume
is read from `CodexOAuthLLM.total_usage` (the Responses API `usage` events).
