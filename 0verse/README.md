<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/0verse-mark-white.png">
    <img src="assets/0verse-mark-ink.png" alt="0verse" width="88">
  </picture>
</p>

<h1 align="center">0verse</h1>

<p align="center">
  <strong>Evidence-first binary analysis: produce and notarize proof-of-vulnerability artifacts from compiled programs, with confirmation decided only by a reproducing oracle.</strong><br/>
  <em>A binary-native research system. Current platform role: evidence producer, not dispatch engine.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-evidence%20producer%20·%20scope%20frozen-d97706" alt="status" />
  <img src="https://img.shields.io/badge/license-Apache--2.0-3fb950" alt="license" />
  <img src="https://img.shields.io/badge/core-Python-3572A5" alt="python" />
  <img src="https://img.shields.io/badge/PoV-is--truth-d97706" alt="pov-is-truth" />
</p>

---

> Status: 2026-08-20. Scope frozen under 0sec ADR-066: 0verse is an
> evidence-producer/notary, not a generic pwnkit/0cloud dispatch engine.
> Dispatch stays parked until the blind known-CVE stripped-ELF gate passes.
> The Apache-2.0 codebase ships publicly as part of
> [`0sec-labs/0sec`](https://github.com/0sec-labs/0sec) under `0verse/`. See
> [ARCHITECTURE.md](ARCHITECTURE.md#scope-decision-and-maturity-vocabulary)
> for the maturity terms used below.

## What it is

`0verse` is a **binary-native Cyber Reasoning System (CRS) research codebase** for
compiled programs with no source. Its fixture-proven core implements a
find → prove → patch → verify loop for controlled targets. Format ingest or a
research adapter for a firmware blob, Mach-O kext, Windows `.dll`, or Linux `.ko`
does **not** mean the full loop is live-proven or operational for that format:

- <img height="14" src="https://raw.githubusercontent.com/0sec-labs/.github/main/profile/assets/icons/search.png" alt="">&nbsp; **finds** memory-safety and logic bug *hypotheses* via static slicing, bug-class lenses, and a mined seed registry;
- <img height="14" src="https://raw.githubusercontent.com/0sec-labs/.github/main/profile/assets/icons/check-circle.png" alt="">&nbsp; **proves** each one by reproducing a crash — a runnable **proof-of-vulnerability (PoV)**;
- <img height="14" src="https://raw.githubusercontent.com/0sec-labs/.github/main/profile/assets/icons/git-pull-request.png" alt="">&nbsp; **patches** the confirmed bug with a fix that closes the PoV; and
- <img height="14" src="https://raw.githubusercontent.com/0sec-labs/.github/main/profile/assets/icons/verified.png" alt="">&nbsp; **verifies** the patch deterministically (the PoV no longer reproduces, no regression).

It is the **binary counterpart to source-level scanners**: when there *is* source, use a SAST tool ([foxguard](https://github.com/0sec-labs)); when all you have is a compiled artifact, use `0verse`. The DARPA AIxCC systems that defined the CRS category scored on **source-available** challenge programs; `0verse` targets the materially harder **binary-only** setting where there are no sanitizers, no ground-truth types, and no symbols.

**The one rule — PoV-is-truth:** a finding without a reproducing input + crash trace is a *hypothesis*, not a finding. `confirmed` is true **only** when a deterministic oracle reproduces a PoV. The LLM proposes; the oracle disposes. A hallucinating or rate-limited model can never manufacture a false confirmation — at worst it degrades a finding to an honest hypothesis.

## What makes it different

| | Most "AI finds bugs" tools | **0verse** |
|---|---|---|
| **Input** | source code, or a binary + an LLM "reading" the disassembly | a **compiled binary, no source** — Ghidra/angr/AFL++ recover the structure the LLM reasons over |
| **Unit of truth** | the model *names* a bug (floods you with false positives) | a **reproducing PoV** — no crash, no finding; oracles decide `confirmed`, not the LLM |
| **Loop depth** | find (and stop) | **find → prove → patch → verify** — the second half AIxCC scored, in-tree |
| **Engine** | often decompiler-locked behind a $1,499+ commercial license | **free** Ghidra/angr/AFL++ core; Ghidra-free rizin/angr fallback so it runs with no JVM |
| **Moat** | the model | a **labeled-PoV dataset flywheel**: capture mechanism + preseeded memory + honest benchmarks + a published negative-results log |

The proven wins from Google Big Sleep, OSS-Fuzz-Gen, and DARPA AIxCC are all *around* a fuzzing + symbolic core — harness synthesis, seed generation, directed scheduling, triage — with a runnable crash as ground truth. `0verse` is built on that evidence, not the hype: the LLM **guides discovery and synthesizes fuzz harnesses**; it never adjudicates.

## Capability matrix

The table inventories in-tree code and committed proofs. It does not claim every
row is live-proven or operational. Unless a higher maturity is stated, read a row
as **implemented**, **unit-tested**, or **fixture-proven**; parked and unsupported
boundaries are called out explicitly below and in
[ARCHITECTURE.md](ARCHITECTURE.md#scope-decision-and-maturity-vocabulary).
Numerical proof results are historical and condition-specific, not operational
capability claims.

| Axis | Coverage |
|---|---|
| **Container formats** | ELF · Mach-O (thin + FAT, exec/dylib/**kext**) · PE / PE32+ · Linux `.ko` · MIPS/ARM firmware images (binwalk carve) |
| **Architectures** | x86-64 · arm64 (AAPCS64) · arm (AAPCS32) · mips o32 — ABI-aware slice + cross-arch QEMU-mode fuzzing |
| **Confirmable bug classes** | buffer-overflow (stack/heap) · integer-overflow · format-string · use-after-free / double-free · command-injection — **all PoV-confirmable** |
| **Hypothesis-only classes** | auth-bypass / logic (no generic binary oracle) · kernel `.ko` LPE families (copy-from-user, ioctl-dispatch, kmalloc-overflow, user-deref, missing-capable) · IOKit/XNU `externalMethod` dispatch — surfaced as ranked **leads**, never auto-confirmed |
| **Discovery lanes** | static source→sink **slice** → foxguard static pre-pass → cheap→expensive **LLM triage funnel** → **angr concolic** reachability prune → **AFL++** harness-synth fuzz (QEMU-mode, CMPLOG) + **directed fuzzing** (UniAFL-style sink-scored scheduling + DistanceDriller) → **CASR/differential-allocator/exec-trap oracle** → **PoV** → **patch + verify** |
| **Seed registry** | **90 mined bug archetypes** (kernel 34 / userland 30 / firmware 26, 2023–2025 CVE-grounded) as vendored data, cross-referenced to the lens/seed-class that implements each — generalized patterns only, no exploit code |
| **Fleet variant analysis** | one seed → cross-target sweep → per-target confirmation + tiered dedup + dataset rows; proof harness confirms **5/5 vulnerable variants** with **0 false confirmations** on patched controls |
| **Scheduler / budget** | deterministic epoch scheduler, per-lane LLM budgets, content-hash cache, no-signal fuzz skip under tight budgets; proof keeps the same confirmed findings while avoiding wasted no-signal spend |
| **Dataset flywheel** | preseeded 5-layer memory from the 90 archetypes (**251 memories**), corpus capture, MCP recall, RAG priming, and cost-routing; proof moves a similar known bug from escalation #5 cold to #1 primed, with no lift on the unrelated control and no change to confirmations |
| **Decompiler backends** | **Ghidra** (default, free) · **rizin**/radare2 (no-JVM fallback) · **angr** (pure-Python fallback) — `ZEROVERSE_BACKEND=auto\|ghidra\|rizin\|angr` |
| **Isolated execution** | untrusted targets/PoVs run inside a **microsandbox** (libkrun/KVM microVM) on a remote host over ssh, never as a native host subprocess — opt-in, fail-closed: `ZEROVERSE_EXECUTOR=local|msb` (unset/unknown = execution disabled) · `ZEROVERSE_MSB_HOST` (default `fuzzer`) · `ZEROVERSE_MSB_IMAGE` (default `ubuntu:24.04`) · `ZEROVERSE_MSB_SANDBOX` (per-lane names for parallelism). Confirmation-grade (warm exec ~30 ms into a detached sandbox), infra failure never reads as a clean run |
| **LLM providers** | Anthropic Claude · ChatGPT-OAuth **Codex** (no API key) · GLM (z-ai) · any OpenAI-compatible router/gateway · deterministic **MockLLM** (no network — the **CI regression floor**, never a capability lane) |
| **Integration** | embeddable `zeroverse.api.scan()` · `0verse` CLI · **MCP** stdio bridge · **versioned machine contract** (JSON/NDJSON/SARIF) · **CRS-API / SARIF adapter** · reference cloud sink. **Generic pwnkit/0cloud dispatch is parked and operationally unsupported.** |

Dynamic confirmation degrades **honestly** where a host can't run or emulate the target — it never fabricates a crash. See [NEGATIVE-RESULTS.md](NEGATIVE-RESULTS.md).

## Measured results

> **Historical, condition-specific measurements.** The numbers below record the
> 2026-06-28 campaigns under their stated target, host, model, budget, and trial
> count. They are not a current operational-capability claim and must not be
> generalized beyond those conditions.

The evaluation instrument is a **ground-truth evaluation** ([docs/EVAL-GROUNDTRUTH.md](docs/EVAL-GROUNDTRUTH.md)). [Magma](https://github.com/HexHive/magma) uses real upstream libraries (libpng / libxml2 / libtiff / lua / sqlite3 / libsndfile ...) carrying catalogued CVE-class bugs guarded by ground-truth canaries.

**1) Binary-native pipeline on Magma (real `gpt-5.5`, fatal-canary `-O0` builds).** Over the 5 built C targets (`lua`/`libpng`/`libsndfile`/`libxml2`/`libtiff`, scored against `CATALOGUE-magma.json`, 53 catalogued bug-sites), measured **over 3 runs** on `c38878d`: the pipeline **reaches a median 8/53 bug-sites (15 %)** and **confirms a median 4/53 through the fuzz drivers (range 3–4), with zero false positives in every run** (no confirmed PoV on a non-bug site or a fixed build). Confirmed targets: `libpng`, `libsndfile`, `libxml2`, `libtiff`. Reported as a median over 3 runs rather than a single figure because the instrument carries roughly ±1–2 sites of run-to-run variance, so a lone number implies precision it does not have. Full per-target table (incl. misses + Ghidra-cost degrades) in [docs/EVAL-GROUNDTRUTH.md](docs/EVAL-GROUNDTRUTH.md).

**2) Where confirmation at scale lives — 0verse-CMPLOG vs baseline AFL++ on Magma** ([docs/BENCHMARKS.md](docs/BENCHMARKS.md)), scored on the **same ground-truth canaries** (every trigger is a real CVE-class bug): **0verse wins 3 of 4 targets** — `libxml2` in **17 s vs baseline's 191 s (~11×)**, `libsndfile` in 14 s where **baseline never triggered in 300 s**, `libtiff` 28 s vs 38 s — and **honestly loses the ungated `libpng` control** (baseline 9 s vs 0verse 27 s: CMPLOG is overhead with no gate to crack). Scoreboard **0verse 3 · baseline 1**.

**Held-out sanity / regression set (NOT the capability claim).** A small 14-item corpus (held-out real-CVE reproducer pairs — `png_handle_tRNS`/CVE-2004-0597, `xmlSnprintfElementContent`/CVE-2017-9047 = Magma **XML001**, `sudo_debug`/CVE-2012-0809, built vulnerable *and* fixed — plus a synthetic sanity floor) runs in minutes to catch lens/oracle regressions and show a generic lens *generalizing* to a real CVE. The deterministic **MockLLM** run on it is the **CI regression floor** (`capability_measure: false`), **never a performance number** — `format_report` stamps the floor banner so it can't be misread.

> **Honest caveats — read before citing.** Bounded budget, single model (`gpt-5.5`), single backend (Ghidra), x86-64 ELF, 1 trial. Binary-native Magma confirmation is bottlenecked by Ghidra cost (multi-MB drivers) + the intraprocedural slice + libFuzzer-driver input synthesis — all surfaced, not hidden. The Magma fuzzing campaign is a 300 s/lane snapshot, not the multi-day paper methodology (the documented path-to-full-run). Full method, per-target outcomes, misses, and residuals in [docs/EVAL-GROUNDTRUTH.md](docs/EVAL-GROUNDTRUTH.md) + [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## Quickstart

> No PyPI release or mutable GHCR channel is published yet. Use the locked source
> checkout for triage, or build the repository Dockerfile locally for the heavy
> Ghidra/angr/AFL++ toolchain. Provisioning Ghidra on a bare host instead? Read
> [docs/GHIDRA-SETUP.md](docs/GHIDRA-SETUP.md) first — the Java install and the
> `pyghidra` bridge are separate, and a benchmark run on a host with only one of
> them is not a measurement.

```bash
# Day-one triage from this checkout.
uv sync --frozen
uv run --frozen 0verse triage ./target

# Full pipeline from a locally built image.
docker build --platform linux/amd64 -t 0verse:local .
docker run --rm -v "$PWD:/work" 0verse:local run /work/target
```

```bash
# 1. Identify format / arch / compiler hints / mitigations — no deps required:
uv run --frozen 0verse triage ./vuln

# 2. Full discovery pipeline (decompile → slice → reason → prove → PoV), mock LLM:
uv run --frozen 0verse run ./vuln --bug-class memory-safety

# 3. Drive it with a REAL model on the triage funnel + harness synthesis:
uv run --frozen 0verse run ./vuln --llm codex   # ChatGPT-OAuth, ~/.codex/auth.json
uv run --frozen 0verse run ./vuln --llm claude  # ANTHROPIC_API_KEY
uv run --frozen 0verse run ./vuln --model glm-4.6  # Z_AI_API_KEY

# 4. The versioned machine contract for a platform/agent to ingest:
uv run --frozen 0verse scan ./vuln --format ndjson [--backend rizin] [--llm codex]

# 5. Exercise the reference cloud sink contract (not a dispatched platform lane):
uv run --frozen 0verse scan ./vuln --cloud --scan-id <id>  # dispatch remains parked
```

M7 lanes that can spend extra time or mutate artifacts remain **opt-in by flag** even though they are merged and tested:

```bash
ZEROVERSE_DIRECTED=1  0verse run ./vuln      # directed (sink-scored) fuzzing lane
ZEROVERSE_PATCH=1     0verse run ./vuln      # patch + verify loop on confirmed PoVs
ZEROVERSE_SCHEDULER=1 0verse run ./vuln      # epoch scheduler + LLM budget/cache stats
ZEROVERSE_FLYWHEEL=1  0verse run ./vuln      # preseeded memory primes ordering/cost only
```

Dynamic execution of the target (the oracle's PoV/PoC runs) is **opt-in
by env** and fail-closed when unset — never a silent host subprocess:

```bash
ZEROVERSE_EXECUTOR=local 0verse run ./vuln   # explicit trust: run targets natively on this host
ZEROVERSE_EXECUTOR=msb   0verse run ./vuln   # run targets inside a microsandbox microVM (recommended)
                                             # (+ ZEROVERSE_MSB_HOST / _IMAGE / _SANDBOX for host, image, lane)
```

```bash
# Sweep a related fleet from one known seed; confirmations still require PoVs.
0verse fleet --seed-archetype cmdi --fleet ./vendor-bins --format text
```

Embed it as a library, or expose it to an agent over MCP:

```python
from zeroverse import api
result = api.scan("/path/to/binary")          # -> versioned ScanResult (PoV-is-truth)
print(api.format_result(result, "ndjson"))
```

```bash
python -m zeroverse.mcp                         # stdio MCP server: scan_binary / list_findings / get_pov / get_report
```

## Architecture (in words)

A **deterministic scheduler** runs a swappable, best-effort stage spine; every optional engine degrades gracefully rather than blocking the run:

```
ingest → decompile → lift → analyze (slice) → foxguard pre-pass → seed-prime → bug-class lenses
       → flywheel-prime → LLM triage funnel → angr concolic prune → crash oracle → PoV emit → patch + verify → report
                                                          ↘ fuzz complement (when the slice confirmed nothing):
                       harness-synth → AFL++ (QEMU/CMPLOG) [ + directed scheduling + DistanceDriller ] → oracle → PoV
```

- **ingest** classifies + routes ELF / Mach-O / PE / `.ko` / firmware and resolves arch/ABI (pure-Python, no deps).
- **decompile/lift** recover functions, pseudo-C, and a P-Code/VEX IL via the selected backend (Ghidra, else rizin/angr at lower fidelity).
- **analyze** builds a backward source→sink **slice**; **foxguard**, the **90-archetype seed registry**, and the **bug-class lenses** union more hypotheses (high recall by design).
- **flywheel-prime** optionally recalls similar confirmed PoVs and archetypes to adjust ranking, framing, and cost route; it cannot confirm anything.
- **triage funnel** ranks the whole queue with a free deterministic classifier and escalates only the top slices to the **LLM**, which proposes a verdict (class, severity, candidate trigger) — never an adjudication.
- **angr** prunes hypotheses it proves unreachable; the **crash oracle** confirms the rest with a reproducing PoV; **PoV emit** writes a standalone pwntools replay.
- the **patch stage** (opt-in) proposes a fix for each confirmed PoV and marks it `verified` only when the PoV no longer reproduces and no regression appears — the deterministic, LLM-free adjudicator.
- the **fuzz complement** catches bugs the slice structurally misses (hand-rolled copy loops behind magic gates): the LLM **synthesizes a harness**, a compile→error-feedback→repair loop hardens it, AFL++ (QEMU-mode, cross-arch, CMPLOG) fuzzes — optionally **steered toward the suspected sinks** — and the same oracle confirms.

Each stage is a module behind a typed interface so backends swap cleanly and stages run standalone (`0verse triage` is just stage 1). Full design rationale in [ARCHITECTURE.md](ARCHITECTURE.md) and [docs/DESIGN-NOTES.md](docs/DESIGN-NOTES.md); the kernel lane in [docs/KERNEL-INTEGRATION.md](docs/KERNEL-INTEGRATION.md); the cloud/embedding contract in [docs/INTEGRATION.md](docs/INTEGRATION.md) and [docs/RESULT-CONTRACT.md](docs/RESULT-CONTRACT.md).

Firmware acquisition crosses a separate, hardware-free
[`AcquisitionManifest` and safety boundary](docs/FIRMWARE-SCOUT-SAFETY.md).
Retained directories enter through the fail-closed
[firmware bundle intake](docs/FIRMWARE-BUNDLE-INTAKE.md), then verified opaque
bytes can produce a canonical, evidence-backed
[firmware inspection report](docs/FIRMWARE-INSPECTION.md) without hardware,
unpacking, or execution. Passive observations can be retained and reproduced
through the dependency-free
[Scout evidence and replay boundary](docs/FIRMWARE-SCOUT-EVIDENCE-REPLAY.md),
including a deterministic virtual ECU used by CI; #78 adds an optional,
library-only, receive-only classical-CAN SocketCAN adapter. It remains
hardware-gated and non-operational pending authorized Linux acceptance.

Firmware Scout remains an independent ordered program: R0–R5 are tracked in
[issue #84](https://github.com/0sec-labs/0verse/issues/84) and are not parked by
the stripped-ELF dispatch gate.

Windows, browser, and Mach-O dynamic-execution expansion is **parked**. Existing
scope manifests, adapters, ingest support, tests, and fixture proofs remain useful
evidence; none makes those lanes live-proven or operational. Their fail-closed
research boundaries remain documented in
[docs/CAMPAIGNS-WINDOWS.md](docs/CAMPAIGNS-WINDOWS.md),
[docs/BROWSER-CAMPAIGNS.md](docs/BROWSER-CAMPAIGNS.md), and
[docs/MACHO-CAMPAIGNS.md](docs/MACHO-CAMPAIGNS.md).

## Honest limitations

Binary-only analysis (no source, no sanitizers, no ground-truth types) is *materially harder* than the source-available setting AIxCC scored on. Several lanes are honest degrades, and we publish the misses in **[NEGATIVE-RESULTS.md](NEGATIVE-RESULTS.md)** (human-curated) plus an append-only machine log — not hidden:

- **Kernel `.ko` / IOKit findings are rank-and-verify hypotheses.** A bare `.ko` has no dynamic oracle on a userland host, so every kernel seed finding stays a **hypothesis** (`confirmed = false`) and is **never** upgraded without a PoV — route the ranked lead to a kernelCTF/KASAN PoV harness to confirm.
- **Mach-O dynamic confirmation is unsupported and expansion is parked.** Static
  ingest and fixture work remain; no Mac/XNU live-proof or operational lane is
  claimed. Findings stay hypotheses.
- **PE execution expansion is parked.** The explicit Windows adapter and fixture
  evidence remain in-tree, but no live-proven or operational Windows lane is
  claimed. WinAFL discovery is not wired. **MIPS/ARM firmware** uses Qiling rather
  than native execution.
- **rizin/angr fallbacks are lower-fidelity** (pseudo-C IL, no SSA def-use, no per-sink addresses → the angr reachability prune is skipped).
- the **logic / auth-bypass** class is hypothesis-only — no generic binary oracle, so it never auto-confirms.
- **foxguard and Ghidra are optional external tools**; the pipeline degrades (rizin/angr, foxguard-stub) when they're absent.
- the **headline runs on real Magma libraries** (real upstream code, real catalogued bugs) but under a **bounded budget / single model / single trial**; the small held-out reproducer set is a *sanity/regression* check, not the capability claim (see the caveats above and in [docs/EVAL-GROUNDTRUTH.md](docs/EVAL-GROUNDTRUTH.md)).

Per-issue status: [ROADMAP.md](ROADMAP.md). Reproducible development and
capability baseline: [docs/BASELINE.md](docs/BASELINE.md). Benchmarks:
[docs/BENCHMARKS.md](docs/BENCHMARKS.md). Dataset/flywheel moat:
[docs/DATASET.md](docs/DATASET.md).

## Roadmap

`0verse` has M1–M7 implementation, unit-test, and controlled-proof work in-tree.
Those milestone labels do not mean every lane is live-proven or operational:

- **M1–M6 — implemented through controlled proofs.** The PoV-backed vertical slice (M1), the AFL++ + harness-synthesis + Driller fuzzing backbone (M2), format/ABI breadth (M3), five bug-class lenses + confirming oracles (M4), non-Ghidra backends + embeddable API + MCP + machine contract (M5), and the rigor layer — benchmark vs plain AFL++, negative-results log, labeled-PoV dataset schema, contributor guide (M6).
- **M7 — implemented through tests/proof harnesses.** Directed fuzzing; patch + verify; fleet-scale variant analysis; deterministic scheduler + per-lane LLM budget/cache; CRS-API/SARIF + tiered crash dedup; and the preseeded PoV-dataset flywheel. Expensive/mutating lanes stay flag-gated by default.
- **Scope freeze.** Windows/browser/Mach-O dynamic expansion and generic cloud
  dispatch are parked. Firmware Scout continues independently in R0–R5 order.

See [ROADMAP.md](ROADMAP.md) for the per-issue breakdown and what is explicitly out of scope.

## Contributing & license

Apache-2.0. Built on Apache/BSD-licensed engines (Ghidra, angr, capa, LIEF, AFL++, Driller). Copyleft tools (Unicorn, Qiling, SymCC, rizin) are invoked as subprocesses, never linked. Binary Ninja is an optional adapter and is never bundled.

Contributions welcome — start with the [good first issues](docs/good-first-issues/) and [CONTRIBUTING.md](CONTRIBUTING.md). Rule #1 for every contribution: **PoV-is-truth** — no reproducing crash, no finding.
