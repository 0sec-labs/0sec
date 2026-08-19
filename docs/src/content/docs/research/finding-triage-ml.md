---
title: Finding Triage ML
description: Research synthesis — ML-based finding triage to maximize accuracy of vulnerability classification.
---

## Problem

pwnkit's agent produces findings (potential vulnerabilities). Some are real, some are false positives. Currently a "blind verify agent" (full LLM call) re-tests each finding independently. This works but is a single-shot binary judgment. We want to maximize accuracy — catch every real vulnerability while eliminating false positives.

> **Status (April 2026):** Every layer of the design below has shipped. See the [FP Reduction Moat](/research/fp-reduction-moat/) page for the full stack and the expected FP reduction from each technique.

## Research Landscape (April 2026)

### What production systems do

Every production security triage system that discloses its architecture uses **LLM pipelines with structured decomposition**, not fine-tuned small models:

| System | Architecture | FP Reduction | Open-Source |
|--------|-------------|-------------|-------------|
| GitHub Security Lab taskflow-agent | GPT-4.1, 7+ YAML subtasks per alert | ~30 real vulns found | Yes |
| Semgrep Assistant (Multimodal) | LLM (OpenAI + Bedrock), per-finding context + assistant memories | **~96% of true FPs auto-triaged** | No |
| Endor Labs AI SAST | Rules + reachability dataflow + LLM reasoning | **~95% FP elimination** (their "Code API" moat) | No |
| Snyk DeepCode AI | Symbolic AI + multiple fine-tuned models | 84% MTTR reduction | No |
| GitHub Copilot Autofix | GPT-5.1, SARIF + code context | Fix generation, not triage | No |

**Key insight from GitHub Security Lab:** The differentiator is **prompt specificity** — their prompts encode 200+ lines of domain-specific edge cases per vulnerability class. Generic "is this a real vulnerability?" prompts don't work well.

### What VulnBERT teaches us (hybrid approach)

VulnBERT (Guanni Qu, Pebblebed Ventures) predicts vulnerability-introducing commits in the Linux kernel.

**Architecture:** CodeBERT embeddings + 51 handcrafted features, fused via cross-attention.

**Ablation results:**
- Random Forest on handcrafted features alone: **76.8% recall / 15.9% FPR**
- CodeBERT embeddings alone: **84.3% recall / 4.2% FPR**
- Hybrid (features + CodeBERT): **92.2% recall / 1.2% FPR**

**The critical insight:** "Neither neural networks nor hand-crafted rules alone achieve the best results. The combination does." — Guanni Qu

### Open models with public weights

| Model | Size | HuggingFace | Best for |
|-------|------|-------------|----------|
| CodeBERT | 125M | `microsoft/codebert-base` | Code understanding backbone |
| VulBERTa | 125M | `claudios/VulBERTa-MLP-Devign` | Vulnerability classification |
| LineVul | 125M | `MickyMike/LineVul` | Line-level vuln localization |
| VulnBERT v8 | 493M | `pebblebed/vulnbert-v8` | Kernel commits (weights only, no model code) |

### Key datasets

- **D2A (IBM)** — static analyzer findings labeled as true/false positive via differential analysis. Closest to our use case. [github.com/IBM/D2A](https://github.com/IBM/D2A)
- **BigVul** — 188K labeled C/C++ functions from CVEs
- **pwnkit's own data** — XBOW benchmark runs with flag extraction as ground truth

## Our Approach: Hybrid Triage Model

Inspired by VulnBERT's hybrid architecture and GitHub Security Lab's structured triage pipelines. **All layers below now ship.** File paths identify the exact module in the pwnkit monorepo.

### Layer 1: Feature Extraction (45 handcrafted features) — SHIPPED

Pure regex/string operations on finding data. No LLM, no network calls. Produces a 45-element numeric vector per finding.

**Response features (13):**
- HTTP status code (numeric)
- Response contains SQL error patterns (boolean)
- Response contains stack trace (boolean)
- Response contains error message (boolean)
- Payload reflected in response — exact match (boolean)
- Payload reflected in response — partial match (boolean)
- Response contains sensitive data patterns (boolean)
- Response contains FLAG pattern (boolean)
- Response content-type matches expected (boolean)
- Response length (numeric)
- Response contains WAF/block signature (boolean)
- Response contains redirect (boolean)
- Response status is server error 5xx (boolean)

**Request features (10):**
- Request contains SQL syntax (boolean)
- Request contains XSS payloads (boolean)
- Request contains SSTI syntax (boolean)
- Request contains path traversal (boolean)
- Request contains command injection (boolean)
- Request uses encoding (URL, base64, etc.) (boolean)
- HTTP method (categorical: GET=0, POST=1, PUT=2, etc.)
- Request has authorization header (boolean)
- Number of parameters (numeric)
- Request body length (numeric)

**Metadata features (8):**
- Severity ordinal (0-4: info, low, medium, high, critical)
- Agent confidence score (0.0-1.0)
- Category is high-confidence type (boolean: sqli, ssti = high; logic, race = low)
- Category is injection-class (boolean)
- Category is access-control-class (boolean)
- Finding has template ID (boolean)
- Finding has CWE reference (boolean)
- Finding has CVE reference (boolean)

**Text quality features (10):**
- Description length (numeric)
- Description contains reproduction steps (boolean)
- Description contains impact statement (boolean)
- Description contains hedging language — "possible", "might", "could be" (boolean)
- Description contains verification language — "confirmed", "verified", "reproduced" (boolean)
- Analysis text length (numeric)
- Analysis contains code blocks (boolean)
- Evidence request is non-empty (boolean)
- Evidence response is non-empty (boolean)
- Evidence analysis is non-empty (boolean)

**Cross-field features (4):**
- Payload type matches category (boolean: e.g., SQL syntax + sqli category = consistent)
- Severity-confidence interaction (severity_ordinal * confidence)
- Response/request length ratio (numeric)
- Evidence completeness score (count of non-empty evidence fields / 3)

**Implementation:** `packages/core/src/triage/feature-extractor.ts` — pure regex/string ops, zero LLM calls, exposed via `extractFeatures(finding): number[]` plus the `FEATURE_NAMES` vector. Used as a fast first-pass signal before any paid verification.

### Layer 1.5: "Holding It Wrong" Filter — SHIPPED

A blocklist-driven filter that rejects findings where the "vulnerability" is simply the documented behaviour of the called function (e.g. `eval`, `writeFile`, `compile`, `toFunction`). Inspired by the CVE-hunt false-positive analysis that showed many LLM scanners flag library APIs for doing exactly what their docs say they do.

**Implementation:** `packages/core/src/triage/holding-it-wrong.ts`. Findings that match are downgraded to `info` severity and skipped from further verification.

### Layer 1.75: Reachability Gate ("Endor Labs moat") — SHIPPED

For every finding, check whether the vulnerable sink is actually reachable from an application entry point (HTTP handler, CLI main, user-facing API). Dead code and test-only paths are not exploitable. Endor Labs' 95% FP elimination rate depends on their proprietary "Code API" for this signal; pwnkit implements it open-source.

**Implementation:** `packages/core/src/triage/reachability.ts` — zero-dependency grep/pattern-based first pass. Conservative: when uncertain it returns `reachable: true` with low confidence so the rest of the pipeline still runs. Public API: `checkReachability(finding, repoPath)` returning a `ReachabilityResult`.

### Layer 1.9: Per-Class Oracles — SHIPPED

Deterministic, category-specific exploit oracles: SQLi, reflected XSS, SSRF, RCE, path traversal, IDOR. Each oracle attempts to **prove** the exploit actually works — SQL error, timing delta, rendered alert with a unique token, `/etc/passwd` exfiltration, SSRF callback to a local HTTP server — and only flags a finding as `verified` when concrete evidence is observed. This is the "no exploit, no report" principle.

**Implementation:** `packages/core/src/triage/oracles.ts` plus the dispatcher `verifyOracleByCategory(finding, target)`. Oracles bypass the LLM entirely on the happy path; the LLM verify pipeline is the fallback.

### Layer 1.95: Multi-Modal Agreement (foxguard × pwnkit) — SHIPPED

Cross-validate every pwnkit finding against [foxguard](https://github.com/0sec-labs/foxguard), the Rust pattern scanner. If foxguard fires on the same file (and ideally the same category) → strong signal the finding is real. If foxguard scanned the file but was silent → likely false positive. This is the open-source mirror of Endor Labs' "neural + rules must agree" architecture.

**Implementation:** `packages/core/src/triage/multi-modal.ts` — `checkMultiModalAgreement`, `fuseTriageSignals`, `parseFoxguardSarif`, `detectFoxguard`. **Unique to pwnkit: no other open-source agent runs a second, independent scanner for cross-validation.**

### Layer 2: Neural Classification (CodeBERT)

Fine-tune `microsoft/codebert-base` (125M params) on finding text:
- Input: concatenation of [title] [category] [description] [request] [response]
- Output: binary classification (true_positive / false_positive)
- Training: MLX on Apple Silicon (M4), QLoRA for efficient fine-tuning

### Layer 3: Cross-Attention Fusion (VulnBERT-style)

Fuse the 45-feature vector with CodeBERT embeddings via cross-attention:
- Feature vector → linear projection → attention with CodeBERT [CLS] token
- Final classification head on fused representation
- This is what gets VulnBERT from 76.8% (features alone) to 92.2% (hybrid)

### Layer 4: Structured LLM Verification (GitHub Security Lab-style) — SHIPPED

For findings that the hybrid model classifies as "likely true positive" (high confidence), we run a structured multi-step LLM verification:
1. **Reachability analysis** — can the vulnerability actually be triggered from user input?
2. **Payload validation** — does the PoC actually demonstrate the claimed vulnerability?
3. **Impact assessment** — what's the real-world impact? Information disclosure vs RCE?
4. **Exploit confirmation** — independently reproduce the exploit (the original blind verify).

Each step uses domain-specific prompts with category-specific addendums (SQLi, XSS, SSTI, IDOR, SSRF, command injection, file upload, deserialization, auth bypass). Any step failure marks the finding as a false positive.

**Implementation:** `packages/core/src/triage/verify-pipeline.ts` — `runStructuredVerify(finding, target, runtime, memoryOptions)`.

### Layer 4.5: Self-Consistency Consensus Verification — SHIPPED

Because LLM sampling is non-deterministic, any single run of the structured verify pipeline may produce a false positive or false negative. We run the pipeline N times (default 5) in parallel and take the majority vote, with early termination as soon as a verdict locks up an unreachable lead.

**Implementation:** `runSelfConsistencyVerify(finding, target, runtime, opts)` and `tallyConsensus(runs)` in `verify-pipeline.ts`. Feature flag: `PWNKIT_FEATURE_CONSENSUS_VERIFY`.

### Layer 4.75: PoV (Proof-of-Vulnerability) Gate — SHIPPED

Empirical ground truth from "All You Need Is A Fuzzing Brain" (arXiv:2509.07225): if the agent cannot build a working PoC in N turns, the finding is almost certainly a false positive. A narrowly-scoped mini agent loop runs with a minimal `bash` + `http_request` tool set and must produce a concrete executable exploit whose response contains category-specific proof. No PoV → severity downgrade to `info`, `triageNote = "no_pov"`.

**Implementation:** `packages/core/src/triage/pov-gate.ts` — `generatePov` and `judgePovEvidence`. Feature flag: `PWNKIT_FEATURE_POV_GATE`.

### Layer 5: Triage Memories (Semgrep-style) — SHIPPED

Per-target persistent FP context that learns from human triage decisions. When a user marks a finding as a false positive and gives a reason, the reason is stored as a `TriageMemory` scoped to `global`, `package`, or `target`. On future scans, memories are injected as few-shot examples into the verify prompt; a sufficiently strong match auto-rejects the finding without spending a verification call.

**Implementation:** `packages/core/src/triage/memories.ts` — `MemoryStore`, `scoreMemory`, `inferPackage`. Feature flag: `PWNKIT_FEATURE_TRIAGE_MEMORIES`.

### Layer 6: Adversarial Debate — SHIPPED

Prosecutor vs. defender agents debate each finding with fresh contexts, and a skeptical judge picks the winner. Based on Anthropic's debate paper (arXiv:2402.06782). The point is error decorrelation: single-pass verify shares priors with the discovery agent, whereas explicitly opposing debaters have uncorrelated error modes.

**Implementation:** `packages/core/src/triage/adversarial.ts`. Feature flag: `PWNKIT_FEATURE_DEBATE`.

### Training Data Pipeline

1. **XBOW benchmark runs** — flag extraction provides ground truth (flag found = finding is real)
2. **Blind verify agent labels** — distill the verify agent's judgments across thousands of findings
3. **D2A dataset (IBM)** — static analysis finding labels for pre-training
4. **Accumulation** — every CI benchmark run with `--save-findings` adds to the training set

### Target Performance

> **Update 2026-04-11 — the aspirational table below was contradicted by measurement.** The 21-run ablation posted on [pwnkit#72](https://github.com/0sec-labs/0sec/issues/72#issuecomment-4229956469) and documented on the [FP Reduction Moat](/research/fp-reduction-moat/) page shows the real effect is mode- and slice-dependent, not a monotonic 50% → under 5% progression. See that page for the measured numbers across XBOW white-box, XBOW black-box, and npm-bench.

The stack was *designed* so each layer strips out a fraction of the false positives that survived the previous layer. The aspirational table below was derived from published reference numbers for SAST systems (Endor Labs, Semgrep Assistant) evaluated on differentially-labeled static findings — a different problem from agent-generated findings on exploitation benchmarks. It is preserved here only as design intent:

| Metric (design target, NOT measured) | Features only (est.) | + Oracles + Reachability | + Consensus LLM verify | + Memories + PoV gate |
|--------|---------------------|--------------------------|------------------------|------------------------|
| Recall | ~77% | ~90% | ~95% | ~97% |
| FPR | ~50% (raw) | ~20% | ~5% | ~5% |
| Latency | <1ms | ~100ms | ~20s (parallel) | ~30s |
| Cost | $0 | $0 | ~$0.05/finding | ~$0.10/finding |

The actual measured effect on pwnkit (2026-04-11 ablation, gpt-5.4):
- XBOW white-box @ limit=50: `moat` profile cuts findings 63% (67 → 25) at the cost of 2 flags (44 → 41) and 1.6× $/flag vs `no-triage`. Recall stays at ~82%.
- XBOW black-box @ limit=25: `moat` strictly dominates `none` — more flags (19 vs 18), 52% fewer findings (14 vs 27), cheaper per flag ($0.53 vs $0.76).
- npm-bench (81 packages): 100% TPR across every profile. `default` and `moat` are F1-identical (0.956). The moat layers add zero FPR reduction on top of default; the FPR increase from `none` (0.11) to `default` (0.19) comes entirely from the stable features (early-stop, script templates, progress handoff), not from the moat layers.

The honest end-to-end story is *not* "50% → under 5% FPR." It is "depending on mode and slice, the moat is either a Pareto tradeoff you choose to take (white-box XBOW) or a strict dominance result (black-box XBOW) or a no-op (npm-bench). A static feature-flag system applied at the scan level can't optimize all three slices simultaneously — which is the direct motivation for the [learned dynamic routing](https://github.com/0sec-labs/0sec/issues/113) paper."

## Related Work

### Research papers driving the design

| Paper | Reference | What we took |
|-------|-----------|--------------|
| FalseCrashReducer | [arXiv:2510.02185](https://arxiv.org/abs/2510.02185) | Crash validation via an agent that must reproduce the crash — motivated the PoV gate's "no executable exploit = no finding" rule. |
| All You Need Is A Fuzzing Brain | [arXiv:2509.07225](https://arxiv.org/abs/2509.07225) | Empirical ground truth that agents failing to build a working PoC in N turns are almost always looking at a false positive. Direct basis for `pov-gate.ts`. |
| MAPTA | [arXiv:2508.20816](https://arxiv.org/abs/2508.20816) | Evidence-gated branching: don't expand an exploitation path without concrete prior-step evidence. Basis for EGATS and the "no speculation" posture. |
| Anthropic Debate | [arXiv:2402.06782](https://arxiv.org/abs/2402.06782) | Adversarial verification — two agents argue, a weaker judge decides. Reserved for the planned debate layer. |
| IBM D2A | [arXiv:2102.07995](https://arxiv.org/abs/2102.07995) | Differential-analysis-derived TP/FP labels for static analysis findings. The training corpus target for the Layer 2 CodeBERT fine-tune. |
| VulnBERT (Guanni Qu, Pebblebed) | [Pebblebed blog](https://pebblebed.com/blog/kernel-bugs) | Hybrid neural + handcrafted features with cross-attention (92.2% recall / 1.2% FPR on kernel commits). Basis for Layers 1–3. |

### Commercial reference points

| System | Disclosed metric |
|--------|-----------------|
| Endor Labs AI SAST | ~95% false-positive elimination via rules + reachability + LLM |
| Semgrep Assistant | ~96% of true FPs auto-triaged via per-finding context + assistant memories |
| Snyk DeepCode AI | 84% MTTR reduction via symbolic AI + multiple fine-tuned models |
| GitHub Security Lab taskflow-agent | ~30 real vulns surfaced; open-source reference for structured decomposition |

### Other

- [VulnBERT dataset](https://huggingface.co/datasets/quguanni/kernel-vuln-dataset) — 125K kernel bug-fix pairs
- [GitHub Security Lab taskflow-agent](https://github.com/GitHubSecurityLab/seclab-taskflow-agent) — open-source LLM triage pipeline
- [GitHub Security Lab taskflows](https://github.com/GitHubSecurityLab/seclab-taskflows) — YAML-defined triage workflows
- [IBM D2A dataset](https://github.com/IBM/D2A) — static analysis finding labels
- [Awesome-LLMs-for-Vulnerability-Detection](https://github.com/huhusmang/Awesome-LLMs-for-Vulnerability-Detection) — paper tracker
- [VulBERTa](https://github.com/ICL-ml4csec/VulBERTa) — RoBERTa for vulnerability classification

## Collaboration

Met Guanni Qu (Pebblebed Ventures) in Zurich, April 2026. Her VulnBERT pipeline (data collection, feature engineering, hybrid model training) maps directly to pwnkit's finding triage problem. Potential joint work on adapting the approach from kernel commits to web pentesting findings.
