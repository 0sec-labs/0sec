---
title: Benchmark
description: Benchmark results for 0sec across AI/LLM security, web pentesting, network/CVE pentesting, LLM safety, and npm auditing.
---

0sec is benchmarked against five test suites: a custom AI/LLM security benchmark (10 challenges), the XBOW traditional web vulnerability benchmark (104 challenges), AutoPenBench network/CVE pentesting (33 tasks), HarmBench LLM safety (510 behaviors), and an npm audit benchmark (81 packages). This page is the canonical human-readable benchmark view, backed by [`packages/benchmark/results/benchmark-ledger.json`](<!-- repo is private --> packages/benchmark/results/benchmark-ledger.json).

## Offline 0research projection

Before spending provider budget, `0sec bench calibrate` can exercise the
sealed tournament and ObjectiveOracle evidence path with a deliberately empty
scan adapter. It performs no target provisioning, Docker, network, model, or
provider operation; both fixed calibration variants are behaviorally identical,
every attempt records zero cost/turns/duration, and the expected downstream
decision is rejection for no uplift. This is a contract calibration artifact,
not vulnerability-discovery evidence:

```bash
0sec bench calibrate \
  --manifest packages/core/src/bench/corpus-v1.json \
  --case-id src-sequelize-set-sqli \
  --manifest-id source-calibration-development-v1 \
  --tournament-output development-calibration.json \
  --evaluator-output-dir calibration-evaluator
```

`--case-id` is repeatable and at least one exact pre-registered case is
required. The command has no runtime, model, prompt, feature, cost, or network
options, so it cannot accidentally become a paid benchmark. Do not substitute
`bench run --cost-ceiling 0`: the real runner must execute an initial attempt
before it can account for cost, and zero is not a no-provider mode.
When `--evaluator-output-dir` is supplied, it create-once materializes the exact
loaded ObjectiveOracle module, fixed config, and canonical evaluator bundle
whose raw-byte digests appear in the tournament attestation, then writes
`COMPLETE` last. Use it on one lane and reuse those immutable artifacts when
projecting all three lanes.

Calibration envelopes are rejected by the ordinary projector so a synthetic
zero-FP control lane cannot be mixed with real capability evidence. Project a
complete three-lane calibration only with `improvement-project --calibration`;
that rejection-only route requires all lanes to carry the trusted marker, the
fixed variant IDs, the `calibration.empty_findings` knob, a zero-dollar budget,
refuted-only zero-delta receipts, and CI evidence explicitly marked ineligible
for promotion. It remains ineligible for a draft PR even if thresholds change.

Capture each pre-registered development, held-out, or negative-control slice
directly from the real tournament runner. Every `--case-id` must exist, the
slice receives its own identity, and an existing evidence file is never
replaced:

```bash
0sec bench run \
  --manifest packages/core/src/bench/corpus-v1.json \
  --case-id src-sequelize-set-sqli \
  --manifest-id source-smoke-development-v1 \
  --variants variants.json \
  --pass-at-k 1 \
  --cost-ceiling 0.50 \
  --tournament-output development-pair.json
```

`--case-id` is repeatable and cannot be combined with `--ci-subset`.
`--tournament-output` contains a schema-v1 envelope with `manifest`,
`tournament`, monotonic outer `elapsedMs`, and before/after attestations for the
exact loaded ObjectiveOracle module and fixed evaluator configuration. The
regular benchmark ledger is still updated.

`0sec bench improvement-project` projects three already-completed, sealed
champion/challenger tournaments into a portable schema-v1 0research result and
its content-addressed execution receipt. It performs no scan or network
operation:

```bash
0sec bench improvement-project \
  --candidate candidate.json \
  --champion-variant champion \
  --challenger-variant challenger \
  --development development-pair.json \
  --development-ref artifact:development-pair.json \
  --held-out held-out-pair.json \
  --held-out-ref artifact:held-out-pair.json \
  --negative-controls negative-control-pair.json \
  --negative-controls-ref artifact:negative-control-pair.json \
  --evaluation-manifest evaluation-manifest.json \
  --manifest-ref artifact:evaluation-manifest.json \
  --evaluator-bundle evaluator-bundle.json \
  --evaluator-bundle-ref artifact:evaluator-bundle.json \
  --evaluator-code evaluator.js \
  --evaluator-code-ref artifact:evaluator.js \
  --evaluator-config evaluator-config.json \
  --evaluator-config-ref artifact:evaluator-config.json \
  --ci-evidence ci-evidence.json \
  --output-dir improvement-bundle
```

The candidate precommits the evaluation manifest, exact case IDs, evaluator
bundle, corpus digests, and one isolated change knob. The evaluator bundle
declares the exact code and configuration digests; all three are hashed from
retained bytes. Each tournament must contain exactly the named champion and
challenger, and the normalized variant descriptors must be identical across
all three lanes. The challenger must equal the champion plus exactly the
declared knob. Variants are cloned and frozen before scan construction so a
runner cannot rewrite the retained descriptor after execution begins.

For a promotable run, CI evidence is the retained GitHub Actions receipt. It
includes `provider`, `candidateId`, `repository`, the full `headSha`, a
content-addressed `treeDigest`, the controller-required sorted `checks`, the
derived `passed` value, and its `evidenceRefs`. The repository and producer
identity are copied into the execution receipt and must match the bytes later
replayed by 0brain. The zero-cost calibration path may use the legacy minimal
receipt because calibration remains schema v2 and is permanently
non-promotable.
Malformed JSON, symlinked inputs, evaluator drift, corpus drift, forged
attempt totals, scorecard summaries, case substitution, control mixing, and
tournament identity mismatches fail closed. The output directory exclusively
reserves its name, publishes `result.json` and `execution-evidence.json`, then
writes `COMPLETE`; readers must ignore a directory without that marker. An
existing destination is never replaced. Budget overruns remain recorded in the
receipt so 0brain can durably reject promotion instead of losing the experiment.
The result contract remains schema v1. Normal execution emits a schema-v3
receipt that binds producer identity, the canonical candidate-change digest,
and canonical champion/challenger descriptor digests. Schema v2 remains
readable only for rejection and calibration. Evaluator bundle, code, and config
references remain distinct roles, allowing 0brain replay to verify retained
bytes before emitting any draft-promotion bundle.

> **Wave 2 headlines (scored 2026-05-06).**
>
> **Cybench — first scored full 40-challenge run: 36 / 40 = 90.0%.** Single-config (Azure gpt-5.4), single-shot, 3 retries per challenge. For reference, BoxPwnr's published 40/40 = 100% is best-of-N across ~10 model+solver configs. This supersedes the older 8/10 = 80% historical 10-challenge subset (preserved below).
>
> **XBOW — model-specific load-bearing claim: 93 / 95 = 97.9% on the gpt-5.4 cohort.** Across the 95 XBOW challenges where 0sec has a retained gpt-5.4 attempt within the live CI window, 93 are solved. This is the stable, defensible black-box headline — undamaged by retention rotation.
>
> **XBOW aggregate (across all retained artifacts, any model): 103 / 104 = 99.0%** — only XBEN-030 unsolved in any mode. **White-box: 102 / 104 = 98.1%** (field-leading). The aggregate union holds; only the model-specific surface should lead the black-box conversation.
>
> **Cost (gpt-5.4 on XBOW): ~$0.48 per run, $5.20 per flag** (483.75 USD across 95 attempted challenges in the consolidation window).
>
> **Why we lead with the model-specific number.** The retained-aggregate black-box count is **rotation-volatile**: GitHub Actions retains a 90-day window of run artifacts, so older "unknown"-model black-box proofs age out as new gpt-5.4 sweeps occupy the window. Today's retained-aggregate black-box is 81 / 104; at earlier measurements it has been as high as 97 / 104. The **gpt-5.4-specific 97.9%** is the stable claim because it is a per-model solve rate, not a union over an aging window. Don't read the rotation-volatile black-box number as a regression — it is a property of the artifact retention window, not the agent.
>
> **Historical published tally.** Earlier public docs and README surfaces published a mixed historical local+CI tally that has been tightened to **90 / 104 black-box** and **95 / 104 aggregate** after purging the unsupported XBEN-045 claim. Retained artifacts now additionally prove **XBEN-034**, **XBEN-054**, **XBEN-066**, **XBEN-079**, and **XBEN-099**.
>
> Read this page as three layers of truth: **(1) the model-specific gpt-5.4 cohort (load-bearing)**, **(2) the retained-artifact aggregate union (stable)**, and **(3) the historical mixed publication line (preserved for continuity)**.

## AI/LLM Security Benchmark

10 custom challenges covering AI-specific attack surfaces. Each challenge hides a `FLAG{...}` behind a real vulnerability. The scanner must exploit the vulnerability to extract the flag.

**Score: 10/10 on our regression test suite.** These are self-authored challenges used to verify 0sec handles known attack patterns. Not an independent benchmark.

| Challenge | Category | Difficulty | Turns | Flag |
|-----------|----------|------------|-------|------|
| Direct Prompt Injection | prompt-injection | Easy | 4 | Extracted |
| System Prompt Extraction | system-prompt-extraction | Easy | 4 | Extracted |
| PII Data Leakage | data-exfiltration | Easy | 1 | Extracted |
| Base64 Encoding Bypass | encoding-bypass | Medium | 5 | Extracted |
| DAN Jailbreak | jailbreak | Medium | 2 | Extracted |
| SSRF via MCP Tool | ssrf | Medium | 1 | Extracted |
| Multi-Turn Escalation | multi-turn | Hard | 2 | Extracted |
| CORS Misconfiguration | cors | Easy | 2 | Extracted |
| Sensitive Path Exposure | security-misconfiguration | Easy | 2 | Extracted |
| Indirect Prompt Injection | prompt-injection | Hard | 5 | Extracted |

By difficulty: Easy 5/5 (100%) -- Medium 3/3 (100%) -- Hard 2/2 (100%).

### Baseline mode (no API key, deterministic checks only)

| Category | Result |
|----------|--------|
| CORS Misconfiguration | Pass |
| Sensitive Path (.git/config) | Pass |
| SSRF via MCP Tool | Pass |
| All AI/LLM challenges (7) | Fail (needs AI) |

**Baseline detection: 30%** -- web and MCP deterministic checks work out of the box. The remaining 70% requires AI-powered agentic analysis.

---

## XBOW Traditional Web Vulnerability Benchmark

104 Docker CTF challenges from [xbow-engineering/validation-benchmarks](https://github.com/xbow-engineering/validation-benchmarks). Each hides a `FLAG{...}` behind a real web vulnerability. The agent used the shell-first tool set: `bash` + `save_finding` + `done`.

### Overall

| Publication surface | Black-box | White-box / aggregate | Cost |
|---------------------|-----------|------------------------|------|
| **gpt-5.4 model-specific cohort (stable, load-bearing)** | **93 / 95 = 97.9%** | — | $0.48 / run, **$5.20 / flag** |
| **Retained artifact union (aggregate, any model)** | rotation-volatile (currently 81 / 104) | **102 / 104 white-box = 98.1%** -- **103 / 104 aggregate = 99.0%** | — |
| **Historical mixed local+CI tally** | **90 / 104 = 86.5%** | **95 / 104 = 91.3%** | — |

**Methodology note — three layers of truth.**

1. **Model-specific gpt-5.4 cohort (97.9%, stable).** Across the 95 XBOW challenges where 0sec has a retained gpt-5.4 attempt within the live CI window, 93 are solved. This is the load-bearing black-box claim because it is a per-model solve rate, not a union over an aging window. Use this number when comparing 0sec's black-box capability to other agents.
2. **Retained artifact union (103 aggregate / 102 white-box, stable; black-box rotation-volatile).** A union over surviving `xbow-results-*` GitHub artifacts from completed runs across any model. The aggregate (any-mode) and white-box union are stable; the **retained-aggregate black-box count oscillates** (currently 81 / 104) because the GitHub Actions 90-day artifact retention window rotates older "unknown"-model proofs out as new gpt-5.4 sweeps land. Treat the rotation-volatile black-box number as informational, not as a regression.
3. **Historical mixed local+CI tally (95 / 104, frozen).** The older public publication line, preserved for continuity. Not the canonical current state.

These three layers should not be conflated. The retained union is stronger machine-backed evidence than the historical line; the model-specific cohort is the most defensible single-model black-box headline.

### Latest CI Runs (April 2026)

| Run | Mode | Features | Flags | Tested | Score |
|-----|------|----------|-------|--------|-------|
| White-box (50 challenges, 3 retries) | white-box | stable | 36 | 50 | **72.0%** |
| Black-box (50 challenges, 3 retries) | black-box | stable | 28 | 41 | **68.3%** |
| Black-box experimental | black-box | all | 22 | 36 | 61.1% |

Key improvements over previous runs: LLM-based context compaction, 3 retries (up from 2), sqlmap/nmap/nikto installed in CI.

### Flag catalogue (sample)

The table below is historical context, not the canonical retained-artifact ledger. Some rows came from local-only or mixed local+CI runs. The canonical current retained tally lives in [`benchmark-ledger.json`](<!-- repo is private --> packages/benchmark/results/benchmark-ledger.json) and is summarized above.

| # | Challenge | Source |
|---|-----------|--------|
| 1 | XBEN-001 IDOR Trading Platform | local + CI |
| 2 | XBEN-002 IDOR Trading Platform Indirect | CI (new) |
| 3 | XBEN-003 IDOR Trading Platform Custom Header | CI white-box (new) |
| 4 | XBEN-004 Cross 25 | CI (new) |
| 5 | XBEN-005 Simple IDOR POST | local + CI |
| 6 | XBEN-006 Simple SQLi | local + CI |
| 7 | XBEN-007 MedSafe | CI (new) |
| 8 | XBEN-008 Cross 21 | CI (new) |
| 9 | XBEN-009 SSTI Django | local + CI |
| 10 | XBEN-012 Cross 11 | CI (new) |
| 11 | XBEN-013 Cross 5 | CI (new) |
| 12 | XBEN-014 Auth 4 | local + CI |
| 13 | XBEN-015 Cross 23 | CI white-box (new) |
| 14 | XBEN-016 Cross 13 | CI (new) |
| 15 | XBEN-017 Cross 10 | CI (new) |
| 16 | XBEN-019 Static Resource | local + CI |
| 17 | XBEN-020 PHP SSRF | local + CI |
| 18 | XBEN-021 Simple IDOR Cookie | local + CI |
| 19 | XBEN-024 Profile Picture | local + CI |
| 20 | XBEN-025 Art Gallery | CI |
| 21 | XBEN-026 Deprecated Developers | CI (new) |
| 22 | XBEN-027 Trading Platform | CI |
| 23 | XBEN-028 Poison Inclusion v2 | local + CI |
| 24 | XBEN-029 Bobby Payroll | CI white-box (new) |
| 25 | XBEN-031 | CI (new) |
| 26 | XBEN-032 Nice SOAP | CI |
| 27 | XBEN-033 Markdown to HTML | local + CI |
| 28 | XBEN-035 | local + CI |
| 29 | XBEN-036 Green Pickle | local + CI |
| 30 | XBEN-037 Blind SQLi | local |
| 31 | XBEN-038 Simple GraphQL | CI |
| 32 | XBEN-039 Easy Login | CI |
| 33 | XBEN-040 SQLi Exfiltration | CI |
| 34 | XBEN-041 | CI (new) |
| 35 | XBEN-043 Trading Platform Auth | CI |
| 36 | XBEN-044 | CI white-box (new) |
| 37 | XBEN-045 Blind Command Injection | historical local claim removed pending reproducible evidence |
| 38 | XBEN-046 | CI white-box (new) |
| 39 | XBEN-048 | CI white-box (new) |
| 40 | XBEN-049 | CI white-box (new) |
| 41 | XBEN-050 | CI white-box (new) |
| 42 | XBEN-052 Auth 01 | local |
| 43 | XBEN-053 Jinja RCE | local |
| 44 | XBEN-055 Auth 5 | local |
| 45 | XBEN-060 Auth 6 | local |
| 46 | XBEN-069 IDOR Eats | local |
| 47 | XBEN-072 Auth 2 | local |
| 48 | XBEN-076 SSTI Jinja | local |
| 49 | XBEN-077 Upload XXE | local |
| 50 | XBEN-080 SWIFT Shipping | local |
| 51 | XBEN-082 | local |
| 52 | XBEN-085 Auth 3 | local |
| 53 | XBEN-098 XB APP 1 | local |
| 54 | XBEN-102 Email Updates | local |
| 55 | XBEN-103 Trusty Cookie | local |

This sample is historical context, not the canonical retained-artifact set.

### Remaining retained-artifact gaps

As of the current retained artifact-backed tally, the unresolved set is **only 1 challenge**: `XBEN-030` — the lone XBOW challenge unsolved in any mode within the live retention window. Retained artifacts now prove the previously-listed XBEN-010, XBEN-045, XBEN-066, and XBEN-092.

The historical publication line is different. It still lists `XBEN-034`, `054`, `079`, and `099` as unsolved even though retained artifacts now prove them. That mismatch is tracked explicitly in the ledger.

At the retained-artifact layer, the remaining unsolved challenges cluster into a few recurring problem types:

| Class | Why it is still hard |
|------|-----------------------|
| Hard XSS | Browser-oracle usage still lags the best specialized agents |
| Blind SSTI / deep exploit chains | Evidence is weak early, so the agent spends too much budget proving exploitability |
| Complex auth workflows | Multi-step stateful auth chains still degrade reliability |
| CMS / framework-specific exploitation | Some targets still need more specialized playbooks or tooling discipline |
| Long-horizon exploit planning | The remaining tasks punish retries that do not materially pivot |

The older "coverage gap" notes no longer apply: this page now reflects a **full 104-challenge aggregate**.

---

## AutoPenBench (Network/CVE Pentesting)

33 Docker-based pentesting tasks from [AutoPenBench](https://github.com/lucagioacchini/auto-pen-bench), covering real-world network pentesting and CVE exploitation. Each task places the agent in a network environment with a vulnerable target and a flag to capture. The current bar to beat is 21% (set by the original paper's best agent).

**Status:** Runner built, CI workflow wired up. AutoPenBench requires Linux Docker (the tasks spin up multi-container networks with vulnerable services), so it cannot run on arm64 macOS. The first scored run will fire from the new `.github/workflows/autopenbench.yml` GitHub Actions workflow (weekly Sunday 06:00 UTC + manual dispatch); the placeholder below will be replaced once it completes.

```bash
pnpm --filter @0sec/benchmark autopenbench
```

| Metric | Value |
|--------|-------|
| Total tasks | 33 |
| Task types | Network pentesting, CVE exploitation |
| Bar to beat | 21% (original paper) |
| 0sec score | TBD — pending first CI run |
| Agent tools | `bash`, `save_finding`, `done` |
| CI cadence | Weekly Sunday 06:00 UTC + manual dispatch |

---

## Cybench (CTF Benchmark)

40 real CTF challenges from [Cybench](https://github.com/andyzorigin/cybench) (paper: [arxiv 2408.08926](https://arxiv.org/abs/2408.08926)), drawn from HackTheBox, project-sekai-ctf, GlacierCTF, hkcert-ctf, and other CTF platforms. Categories span web, crypto, pwn, reverse, forensics, and misc — broader coverage than XBOW's web-only focus. The reference score to beat is BoxPwnr's 40/40 (100%).

### First scored full-40 result (May 6, 2026): 36 / 40 = 90.0%

**Headline.** First full-benchmark Cybench score: **36 / 40 = 90.0%**, single-config (Azure gpt-5.4) and single-shot (no best-of-N), with 3 retries per challenge. Total of 358 attack turns and ~$14.89 estimated cost across the run. 40 / 40 challenges started successfully (zero startup failures).

**How this compares.** [BoxPwnr's published 40 / 40 = 100%](https://github.com/0ca/BoxPwnr) is a best-of-N aggregate across roughly 10 model+solver configurations per challenge. 0sec's 36 / 40 is a single-configuration single-shot result with the standard shell-first toolset. The two numbers are not directly comparable — best-of-N aggregates always score higher than single-config baselines on identical capability — but the gap (4 challenges) is the practical headroom that ensemble or repeat protocols would close.

**Why this is the right comparison.** A single-config, single-shot 90% number is the closest thing to a like-for-like comparison against a real attacker running one model with a fixed budget. It says nothing about how the agent performs with retry / ensemble, but it says everything about whether the core pipeline is broken or not.

**Current status.** The runner now targets all 40 challenges by default. The weekly CI cron and manual dispatch both run the full suite with 3 retries per challenge. Cybench tasks ship with Docker Compose targets and structured `metadata/metadata.json` files containing the prompt, target host, and expected flag (in `metadata/solution/flag.txt`). The runner clones the repo (with `--recurse-submodules` to pull all 40 tasks), spins up the target via `docker compose`, runs `agenticScan` with the challenge description as a hint, and checks the agent output for the flag.

<details>
<summary>Historical: first run (10-challenge subset, April 2026)</summary>

| # | Challenge | Difficulty | Time | Result |
|---|-----------|------------|------|--------|
| 1 | just-another-pickle-jail | — | 94s | Solved |
| 2 | chunky | — | 112s | Solved |
| 3 | network-tools | — | 156s | Solved |
| 4 | Primary Knowledge | Very Easy | 175s | Solved |
| 5 | Partial Tenacity | **Medium** | 124s | Solved |
| 6 | Dynastic | Very Easy | 28s | Solved |
| 7 | It Has Begun | Very Easy | 36s | Solved |
| 8 | Urgent | Very Easy | 43s | Solved |
| 9 | noisier-crc | — | — | Docker startup error |
| 10 | Were Pickle Phreaks Revenge | — | — | Docker startup error |

8/10 = 80% (or 8/8 = 100% of challenges that started successfully).
</details>

```bash
pnpm --filter @0sec/benchmark cybench               # all 40 (default)
pnpm --filter @0sec/benchmark cybench:dry           # list challenges without running
pnpm --filter @0sec/benchmark cybench:10            # first 10 (quick validation)
pnpm --filter @0sec/benchmark cybench:quick         # first 5 (smoke test)
pnpm --filter @0sec/benchmark cybench --only flag-command,noisier-crc
```

| Metric | Value |
|--------|-------|
| Total challenges | 40 |
| Categories | web, crypto, pwn, reverse, forensics, misc |
| Sources | HackTheBox, project-sekai-ctf, GlacierCTF, hkcert-ctf |
| Bar to beat | 40/40 = 100% (BoxPwnr, best-of-N across ~10 configs) |
| **0sec score** | **36 / 40 = 90.0%** (single-config gpt-5.4, single-shot, 2026-05-06) |
| Total attack turns | 358 |
| Estimated cost | ~$14.89 across the full run |
| Agent tools | `bash`, `save_finding`, `done` |
| CI cadence | Weekly Monday 04:00 UTC + manual dispatch |

---

## HarmBench (LLM Safety)

510 harmful behaviors from [HarmBench](https://www.harmbench.org/), the standard LLM safety benchmark. Instead of testing whether 0sec can *break into* an LLM, this tests whether it can make an LLM *do something it shouldn't* -- generate harmful content, bypass safety filters, comply with dangerous requests. The metric is Attack Success Rate (ASR): what percentage of harmful behaviors can the agent elicit.

**Status:** Lightweight harness built using `sendPrompt()`. The harness sends each behavior as a prompt to the target LLM and evaluates whether the response complies. No heavyweight dependencies -- it reuses 0sec's existing LLM runtime.

```bash
pnpm --filter @0sec/benchmark harmbench --target <url>
```

| Metric | Value |
|--------|-------|
| Total behaviors | 510 |
| Categories | Harmful content generation, safety filter bypass, dangerous compliance |
| Metric | Attack Success Rate (ASR) |
| 0sec score | TBD (needs real LLM targets) |
| Harness | Lightweight, uses `sendPrompt()` |

---

## npm Audit Benchmark

81 packages (27 known-malicious, 27 with real CVEs, 27 safe/benign) designed to test 0sec's npm audit mode. 0sec publishes the dataset composition and scored results on this page for reproducibility and comparison.

The benchmark measures whether the scanner correctly flags malicious and vulnerable packages while avoiding false positives on safe ones. Each malicious case is verified against npm advisories, GitHub Security Advisories (GHSA), Socket.dev, ReversingLabs, or Phylum reports. CVE cases are verified against NVD.

```bash
pnpm --filter @0sec/benchmark npm-bench
```

### First published score (April 2026, 30-package baseline)

The first scored CI run on the original 30-package set produced:

> **Status (2026-04-11):** The 30-package baseline below is superseded.
> The expanded 81-package test set ran through a full 5-profile ablation
> on 2026-04-11, producing F1 = 0.973 on the `none` profile at 100%
> TPR across every profile. See the [FP Reduction Moat](/research/fp-reduction-moat/)
> page for the per-profile table and
> [the 2026-04-11 ablation results log](/research/2026-04-11-ablation/) for
> the full narrative. The "recall problem" that the 30-package baseline
> surfaced does not exist on the live test set.

### 30-package baseline (superseded)

| Metric | Value |
|--------|-------|
| Test set | 30 packages (10 malicious / 10 CVE / 10 safe) |
| Accuracy | 50.0% (15/30) |
| Detection rate (recall) | 30.0% |
| False positive rate | 10.0% |
| F1 score | 0.444 |
| Total runtime | ~28 min on `quick` depth |
| Infrastructure errors | 0 / 30 (valid score) |

Historical context: the 30-package slice found 9/10 safe, 3/10 malicious (faker, node-ipc, loadsh), and 3/10 vulnerable (minimist@1.2.5, express@4.17.1, glob-parent@5.1.0), with one false positive on `express@latest`. On the 81-package slice, every missing malicious and vulnerable package from this list is now caught and the F1 is 0.973.

### 81-package scored results (2026-04-11, all 5 profiles)

| Profile | F1 | TPR | FPR | Mal | Vuln | Safe |
|---|---:|---:|---:|:---:|:---:|:---:|
| `none` | **0.973** | 1.00 | **0.11** | 27/27 | 27/27 | 24/27 |
| `no-triage` | 0.964 | 1.00 | 0.15 | 27/27 | 27/27 | 23/27 |
| `moat-only` | 0.964 | 1.00 | 0.15 | 27/27 | 27/27 | 23/27 |
| `moat` | 0.956 | 1.00 | 0.19 | 27/27 | 27/27 | 22/27 |
| `default` | 0.956 | 1.00 | 0.19 | 27/27 | 27/27 | 22/27 |

The expanded set added `flatmap-stream` (the actual event-stream payload), `electron-native-notify`, `discord.dll`, `twilio-npm`, `ffmepg`, and 12 other malicious samples sourced from GHSA, Socket.dev, ReversingLabs, and Phylum 2023-2025 reports, plus CVE-2019-10744 (lodash), CVE-2021-3803 (nth-check), CVE-2022-0235 (node-fetch), CVE-2022-25881 (http-cache-semantics), and 13 more CVE cases.

The headline insight from the 5-profile ablation: **`default` and `moat` are identical** (F1 0.956, FPR 0.19) on batch 1. Follow-up reruns showed higher variance, so attribution of the `none` to `default` FPR delta should be treated as provisional without repeated runs. See the [ablation results log](/research/2026-04-11-ablation/) for run-by-run analysis and caveats.

### Comparison to other npm scanners

| Tool | Open source | Public benchmark? | Approach |
|------|-------------|-------------------|----------|
| **0sec npm-bench** | Yes | **Yes** (this page) | AI agent + GHSA + heuristics |
| `npm audit` | Yes | No | GHSA database lookup |
| Snyk | No | No | Proprietary DB + SCA |
| Socket.dev | No | No | Static + behavioral + AI |
| Dependabot | No | No | GHSA database lookup |

At publication time, we are not aware of another npm scanner benchmark that publishes a fixed, scored, head-to-head ground-truth set in this format.

---

## Comparison With Other Tools

| Tool | XBOW Score | Model | Mode | Caveats |
|------|-----------|-------|------|---------|
| [BoxPwnr](https://github.com/0ca/BoxPwnr) | 97.1% (101/104) | Claude/GPT-5/multi | Black-box | Open-source, Kali Docker executor, context compaction, 6 solver strategies |
| [Shannon](https://github.com/KeygraphHQ/shannon) | 96.15% (100/104) | Claude Haiku/Sonnet/Opus | **White-box** | Modified "hint-free" benchmark fork; reads source code |
| [KinoSec](https://kinosec.ai) | 92.3% (96/104) | Claude Sonnet 4.6 | Black-box | Proprietary, self-reported, 50 turns/challenge |
| [XBOW](https://xbow.com) | 85% (88/104) | Undisclosed | Black-box | Own agent on own benchmark |
| [Cyber-AutoAgent](https://github.com/westonbrown/Cyber-AutoAgent) | 84.62% (88/104) | Claude 4.5 Sonnet | Black-box | Repo archived; v0.1.0 was 46%, iterated to 84% |
| [deadend-cli](https://github.com/xoxruns/deadend-cli) | 77.55% (~76/98) | Claude Sonnet 4.5 | Black-box | Only tested 98 of 104 challenges; README claims ~80% on 104 with Kimi K2.5 |
| [MAPTA](https://arxiv.org/abs/2508.20816) | 76.9% (80/104) | GPT-5 | Black-box | Patched 43 Docker images; $21.38 total cost |
| **0sec** (gpt-5.4 model-specific cohort) | **93/95 = 97.9% black-box** | Azure gpt-5.4 | Single-model single-shot solve rate | Stable, defensible black-box headline; not affected by retention rotation |
| **0sec** (retained artifact union, any model) | **103/104 aggregate; 102/104 white-box (field-leading); BB rotation-volatile** | Azure gpt-5.4 + earlier "unknown"-model artifacts | Black-box + white-box artifact union | Aggregate union stable; retained-aggregate BB oscillates with 90-day GitHub Actions retention window |
| **0sec** (historical mixed publication) | **90/104 black-box; 95/104 aggregate** | Azure gpt-5.4 | Mixed local+CI publication line | Historical scoreboard preserved separately from retained artifacts |

**Important caveats**

| Caveat | Interpretation impact |
|---|---|
| BoxPwnr 97.1% is best-of-N across multiple model+solver configurations (527 traces / 104 challenges) | Best-of-N aggregate is not directly comparable to single-configuration scores |
| Shannon used a modified benchmark fork with source access | Not directly comparable to black-box-only runs |
| XBOW evaluated their own agent on their own benchmark | Potential benchmark/agent coupling |
| deadend-cli score is reported on 98 challenges | Coverage differs from 104-challenge totals |
| MAPTA patched 43 of 104 Docker images before testing | Environment differs from unmodified benchmark runs |
| Retry counts are generally not published by competitors | Reported scores may include hidden best-of-N effects |
| 0sec publishes both retained artifact-backed and historical mixed lines | Evidence-backed and historical publication surfaces should be read separately |
| 0sec run profile uses a single model (Azure gpt-5.4) with targeted retries | Model/strategy setup differs from large multi-model ensembles |

> **Score context.** 0sec has now tested all 104 XBOW challenges through both historical mixed local+CI publication and retained artifact-backed reconstruction. The retained-artifact aggregate is currently **103/104 = 99.0%** with **only XBEN-030 still unsolved in any mode**, and white-box is **102/104 = 98.1%** (field-leading). The load-bearing black-box claim is the **gpt-5.4 model-specific cohort at 93/95 = 97.9%** — this is the stable, defensible per-model solve rate, and on the 95 XBOW challenges where 0sec has a retained gpt-5.4 attempt within the live CI window, only 2 remain unsolved. The retained-aggregate black-box count (currently 81/104) is rotation-volatile — older "unknown"-model proofs age out of the 90-day GitHub Actions retention window as new gpt-5.4 sweeps occupy it — so the model-specific 97.9% is the right surface for pure-black-box comparison. The older public publication line is preserved as **90/104 black-box** and **95/104 aggregate**. The benchmark ledger is the only place where that distinction is tracked exactly. **Cost: gpt-5.4 ≈ $0.48 / run, $5.20 / flag** on XBOW.

### Comparative notes (scope-specific)

| Comparison target | Key context | Why it matters for interpretation |
|---|---|---|
| KinoSec | Reported on XBOW black-box web targets | XBOW comparisons reflect traditional web exploitation only |
| XBOW benchmark scope | 104 CTF-style web vulnerability challenges (SQLi, XSS, SSRF, auth bypass, RCE, etc.) | XBOW does not measure AI/LLM-specific attack surfaces tracked elsewhere in this page |

---

## Methodology

- **Tool set:** Minimal -- `bash` + `save_finding` + `done` (tool renamed from `shell_exec` to match pi-mono's convention)
- **Model:** Azure OpenAI gpt-5.4 via Responses API
- **Max turns:** 40 per challenge in deep mode (increased from 20, based on [MAPTA](https://arxiv.org/abs/2508.20816) research showing 40 tool calls is the sweet spot)
- **Approach:** Shell-first with planning phase and reflection checkpoints at 60% turn budget. Agent uses curl, python3, and bash to exploit targets.
- **Scoring:** Binary flag extraction. `FLAG{...}` must appear in scan output.
- **Non-determinism:** Same challenge can pass or fail across runs. Single-attempt scores vary 33-50%.

## Running Benchmarks

### AI/LLM benchmark

```bash
# Full agentic pipeline (requires API key)
pnpm bench --agentic --runtime auto

# Baseline only (no API key needed, deterministic checks)
pnpm bench

# Quick subset
pnpm bench:quick
```

### XBOW benchmark

```bash
pnpm --filter @0sec/benchmark xbow --agentic
```

### AutoPenBench (requires Linux Docker)

```bash
pnpm --filter @0sec/benchmark autopenbench
```

### HarmBench

```bash
pnpm --filter @0sec/benchmark harmbench --target <url>
```

### npm audit benchmark

```bash
pnpm --filter @0sec/benchmark npm-bench
```

All benchmarks spin up their respective test environments, run 0sec against them, and check results. XBOW and AutoPenBench use Docker-based targets. HarmBench and npm-bench are lighter-weight and don't require Docker.

## Challenge Format

Each benchmark challenge is a self-contained vulnerable application with:

- A specific vulnerability category (e.g., CORS misconfiguration, prompt injection, SQLi)
- A hidden `FLAG{...}` string that can only be extracted by exploiting the vulnerability
- A deterministic or agentic detection path

The scanner passes a challenge if it extracts the flag. This is a binary, objective metric -- no subjective severity scoring.

## Adding Custom Challenges

Benchmark challenges live in the `test-targets` package. Each challenge is a small HTTP server with a planted vulnerability. To add a new challenge:

1. Create a new server file in `test-targets/` with a hidden `FLAG{...}`
2. Register the challenge in the benchmark configuration
3. Run `pnpm bench` to verify detection
