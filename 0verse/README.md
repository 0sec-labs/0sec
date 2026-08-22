<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/0verse-mark-white.png">
    <img src="assets/0verse-mark-ink.png" alt="0verse" width="88">
  </picture>
</p>

<h1 align="center">0verse</h1>

<p align="center">
  <strong>Evidence-first binary analysis — it produces and notarizes proof-of-vulnerability artifacts from compiled programs, and confirms a finding only when a reproducing oracle agrees.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-evidence%20producer%20·%20scope%20frozen-d97706" alt="status" />
  <img src="https://img.shields.io/badge/license-Apache--2.0-3fb950" alt="license" />
  <img src="https://img.shields.io/badge/core-Python-3572A5" alt="python" />
  <img src="https://img.shields.io/badge/PoV-is--truth-d97706" alt="pov-is-truth" />
</p>

---

> **Status — 2026-08-20 (0sec ADR-066).** 0verse is scope-frozen as an
> **evidence producer / notary**: it finds, proves, patches, and verifies bugs in
> binaries. The generic dispatch-engine role stays **parked** until the blind
> known-CVE stripped-ELF gate passes. Ships publicly as part of
> [`0sec-labs/0sec`](https://github.com/0sec-labs/0sec) under `0verse/`, Apache-2.0.
> Maturity terms (`implemented → fixture-proven → live-proven → operational`,
> plus `parked` / `unsupported`) are defined in
> [ARCHITECTURE.md](ARCHITECTURE.md#scope-decision-and-maturity-vocabulary).

## What it is

`0verse` is a **binary-native Cyber Reasoning System** for compiled programs with
no source. It runs a **find → prove → patch → verify** loop:

- **finds** memory-safety and logic bug *hypotheses* via static slicing, bug-class
  lenses, and a mined seed registry;
- **proves** each one by reproducing a crash — a runnable **proof-of-vulnerability
  (PoV)**;
- **patches** the confirmed bug with a fix that closes the PoV; and
- **verifies** the patch deterministically (the PoV no longer reproduces, no
  regression).

It's the binary counterpart to a source scanner: when you have source, use SAST
([foxguard](https://github.com/0sec-labs)); when all you have is a compiled
artifact, use `0verse`. DARPA AIxCC scored on **source-available** programs;
0verse targets the harder **binary-only** setting — no sanitizers, no
ground-truth types, no symbols.

**The one rule — PoV-is-truth.** A finding without a reproducing input + crash
trace is a *hypothesis*, not a finding. `confirmed` is true **only** when a
deterministic oracle reproduces a PoV. The LLM proposes; the oracle disposes. A
hallucinating or rate-limited model can never manufacture a false confirmation —
at worst it degrades a finding to an honest hypothesis.

## Quickstart

The core install is dependency-free, so `triage` works anywhere; the heavy
engines (Ghidra / angr / AFL++) are optional extras or come with the Docker
image. No PyPI or public image channel is published yet — use the locked source
checkout or build the image locally.

```bash
# Day-one triage from a locked checkout — format / arch / mitigations, no deps.
uv sync --frozen
uv run --frozen 0verse triage ./target

# Full pipeline (decompile → slice → reason → prove → PoV) with a mock LLM.
uv run --frozen 0verse run ./target --bug-class memory-safety

# Drive it with a real model on the triage funnel + harness synthesis.
uv run --frozen 0verse run ./target --llm codex     # ChatGPT-OAuth, ~/.codex/auth.json
uv run --frozen 0verse run ./target --llm claude    # ANTHROPIC_API_KEY
uv run --frozen 0verse run ./target --model glm-4.6  # Z_AI_API_KEY

# Emit the versioned machine contract for a platform/agent to ingest.
uv run --frozen 0verse scan ./target --format ndjson [--backend rizin]

# Sweep a fleet from one known seed; confirmations still require a PoV per target.
uv run --frozen 0verse fleet --seed-archetype cmdi --fleet ./vendor-bins
```

For the full toolchain (Ghidra/angr/AFL++), build the image locally:

```bash
docker build --platform linux/amd64 -t 0verse:local .
docker run --rm -v "$PWD:/work" 0verse:local run /work/target
```

Dynamic execution of a target is **opt-in and fail-closed** — never a silent host
subprocess. It's disabled unless you choose an executor:

```bash
ZEROVERSE_EXECUTOR=local 0verse run ./target   # run natively on this host (explicit trust)
ZEROVERSE_EXECUTOR=msb   0verse run ./target   # run inside a microsandbox microVM (recommended)
```

Embed it, or expose it to an agent over MCP:

```python
from zeroverse import api
result = api.scan("/path/to/binary")            # -> versioned ScanResult (PoV-is-truth)
print(api.format_result(result, "ndjson"))
```

```bash
python -m zeroverse.mcp   # stdio MCP: scan_binary / list_findings / get_pov / get_report
```

## Capability matrix

Read a row as **implemented / fixture-proven** unless a higher maturity is
stated; parked and unsupported boundaries are called out under *Honest
limitations*. Numbers are historical and condition-specific, not operational
claims.

| Axis | Coverage |
|---|---|
| **Container formats** | ELF · Mach-O (thin + FAT, exec/dylib/kext) · PE / PE32+ · Linux `.ko` · MIPS/ARM firmware (binwalk carve) |
| **Architectures** | x86-64 · arm64 · arm · mips o32 — ABI-aware slicing + cross-arch QEMU-mode fuzzing |
| **Confirmable bug classes** | buffer-overflow (stack/heap) · integer-overflow · format-string · use-after-free / double-free · command-injection — **all PoV-confirmable** |
| **Hypothesis-only classes** | auth-bypass / logic · kernel `.ko` LPE families · IOKit/XNU `externalMethod` dispatch — ranked **leads**, never auto-confirmed |
| **Discovery** | source→sink **slice** → foxguard static pre-pass → cheap→expensive **LLM triage funnel** → **angr** concolic prune → **AFL++** harness-synth fuzz (QEMU-mode, CMPLOG, directed) → **crash oracle** → **PoV** → **patch + verify** |
| **Seed registry** | 90 mined bug archetypes (kernel/userland/firmware, 2023–2025 CVE-grounded) — generalized patterns, no exploit code |
| **Decompiler backends** | **Ghidra** (default, free) · **rizin** (no-JVM fallback) · **angr** (pure-Python) — `ZEROVERSE_BACKEND=auto\|ghidra\|rizin\|angr` |
| **Isolated execution** | microsandbox (libkrun/KVM microVM) over ssh, opt-in & fail-closed: `ZEROVERSE_EXECUTOR=local\|msb` (unset = disabled) · `ZEROVERSE_MSB_HOST` (default `fuzzer`) · `ZEROVERSE_MSB_IMAGE` (digest-pinned Ubuntu 24.04) · `ZEROVERSE_MSB_SANDBOX` (per-lane names) |
| **LLM providers** | Anthropic Claude · ChatGPT-OAuth **Codex** (no API key) · GLM (z-ai) · any OpenAI-compatible gateway · deterministic **MockLLM** (the CI regression floor, never a capability lane) |
| **Integration** | embeddable `zeroverse.api.scan()` · `0verse` CLI · **MCP** stdio bridge · **versioned machine contract** (JSON/NDJSON/SARIF) · CRS-API / SARIF adapter |

Opt-in lanes stay flag-gated even though they're merged and tested:
`ZEROVERSE_DIRECTED=1` (sink-scored fuzzing), `ZEROVERSE_PATCH=1` (patch + verify),
`ZEROVERSE_SCHEDULER=1` (epoch scheduler + budget), `ZEROVERSE_FLYWHEEL=1`
(preseeded memory priming). None can create a confirmation — only the oracle can.

## Measured results

> **Historical, condition-specific measurements** from the 2026-06-28 campaigns.
> Not a current operational-capability claim; do not generalize beyond the stated
> target, host, model, budget, and trial count.

The instrument is a ground-truth evaluation on
[Magma](https://github.com/HexHive/magma) — real upstream libraries (libpng,
libxml2, libtiff, lua, libsndfile …) carrying catalogued CVE-class bugs guarded
by fatal canaries.

**Speed vs. baseline AFL++ (real Magma, same canaries, 300 s/lane, 1 trial).**
0verse-CMPLOG wins **3 of 4** targets and loses the ungated control honestly:

| Target | 0verse | baseline AFL++ | |
|---|---|---|---|
| `libxml2` | **17 s** | 191 s | ~11× |
| `libsndfile` | **14 s** | never (>300 s) | — |
| `libtiff` | **28 s** | 38 s | win |
| `libpng` (ungated control) | 28 s | **9 s** | honest loss — CMPLOG is overhead with no gate to crack |

**Binary-native pipeline (real `gpt-5.5`, `-O0` fatal-canary builds, 5 C targets,
53 catalogued bug-sites, median of 3 runs on `c38878d`):** reaches a **median
8/53 sites (15%)** and confirms a **median 4/53 through the fuzz drivers (range
3–4)**, with **zero false positives in every run** — no confirmed PoV on a non-bug
site or a fixed build.

**Regression floor (not a capability number).** A 14-item held-out corpus of
real-CVE reproducer pairs (built vulnerable *and* fixed) runs under the
deterministic **MockLLM** as the CI floor (`capability_measure: false`): located
9/9, confirmed 6/9, **0 false positives on the 5 clean/fixed controls**. The
report stamps a floor banner so it can't be misread as performance.

**Honest caveats — read before citing.** Bounded budget, single model
(`gpt-5.5`), single backend (Ghidra), x86-64 ELF, 1 trial. Binary-native Magma
confirmation is bottlenecked by Ghidra cost on multi-MB drivers, the
intraprocedural slice, and libFuzzer-driver input synthesis — all surfaced, not
hidden. The fuzzing campaign is a 300 s/lane snapshot, not the multi-day paper
methodology. Full method and misses:
[docs/EVAL-GROUNDTRUTH.md](docs/EVAL-GROUNDTRUTH.md) ·
[docs/BENCHMARKS.md](docs/BENCHMARKS.md) · negative results in
[NEGATIVE-RESULTS.md](NEGATIVE-RESULTS.md).

## Architecture (in words)

A deterministic scheduler runs a best-effort stage spine; every optional engine
degrades gracefully rather than blocking the run:

```
ingest → decompile → lift → slice → foxguard pre-pass → seed-prime → bug-class lenses
       → LLM triage funnel → angr concolic prune → crash oracle → PoV → patch + verify → report
                                         ↘ fuzz complement (when the slice confirmed nothing):
                          harness-synth → AFL++ (QEMU/CMPLOG, directed) → oracle → PoV
```

- **ingest** routes ELF / Mach-O / PE / `.ko` / firmware and resolves arch/ABI
  (pure-Python, no deps).
- **decompile/lift** recover functions, pseudo-C, and an IL via the selected
  backend (Ghidra, else rizin/angr at lower fidelity).
- **slice + lenses + seeds** union many hypotheses (high recall by design);
  **angr** prunes the ones it proves unreachable.
- the **crash oracle** confirms the rest with a reproducing PoV; **patch + verify**
  (opt-in) marks a fix `verified` only when the PoV stops reproducing with no
  regression — the deterministic, LLM-free adjudicator.
- the **fuzz complement** catches bugs the slice structurally misses: the LLM
  synthesizes a harness, a compile→repair loop hardens it, and AFL++ fuzzes —
  optionally steered toward the suspected sinks.

Each stage is a module behind a typed interface, so backends swap cleanly and
stages run standalone (`0verse triage` is just stage 1). Full design:
[ARCHITECTURE.md](ARCHITECTURE.md) · [docs/DESIGN-NOTES.md](docs/DESIGN-NOTES.md).

## Honest limitations

Binary-only analysis is materially harder than the source-available setting, and
several lanes are honest degrades. We publish the misses in
[NEGATIVE-RESULTS.md](NEGATIVE-RESULTS.md), not hidden.

- **Kernel `.ko` / IOKit findings are hypotheses.** A bare `.ko` has no dynamic
  oracle on a userland host, so kernel seed findings stay `confirmed = false` and
  are never upgraded without a PoV — route the lead to a kernelCTF/KASAN harness.
- **Mach-O dynamic confirmation is unsupported; expansion is parked.** Static
  ingest and fixtures remain; no Mac/XNU live-proof is claimed.
- **PE execution expansion is parked** (adapter + fixtures in-tree, WinAFL not
  wired); **MIPS/ARM firmware** uses Qiling emulation, not native execution.
- **rizin/angr fallbacks are lower-fidelity** (no SSA def-use, no per-sink
  addresses → the angr reachability prune is skipped).
- **logic / auth-bypass is hypothesis-only** — no generic binary oracle.
- **foxguard and Ghidra are optional** external tools; the pipeline degrades when
  they're absent.
- The headline runs on real Magma libraries but under **bounded budget / single
  model / single trial**; the held-out set is a sanity/regression check, not the
  capability claim.

Per-issue status: [ROADMAP.md](ROADMAP.md). Reproducible baseline:
[docs/BASELINE.md](docs/BASELINE.md).

## License

Apache-2.0. Built on Apache/BSD-licensed engines (Ghidra, angr, capa, LIEF,
AFL++, Driller). Copyleft tools (Unicorn, Qiling, SymCC, rizin) are invoked as
subprocesses, never linked; Binary Ninja is an optional adapter, never bundled.

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Rule #1:
**PoV-is-truth** — no reproducing crash, no finding.
