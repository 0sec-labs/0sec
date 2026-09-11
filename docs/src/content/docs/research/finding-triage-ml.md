---
title: Finding Triage ML
description: Triage research, implemented gates, planned classifiers, and measured ablation results.
---

## Problem

Independent verification re-tests candidate findings. This design investigates
how features, classifiers, and additional checks affect recall, false positives,
and cost.

> **April 2026 record:** implementation and planning coexist below. Neural fusion
> and adversarial debate remain proposals. See [measured triage results](/research/fp-reduction-moat/).

## Research Landscape (April 2026)

### What production systems do

The disclosed systems below use structured LLM triage pipelines:

| System | Architecture | FP Reduction | Open-Source |
|--------|-------------|-------------|-------------|
| GitHub Security Lab taskflow-agent | GPT-4.1, 7+ YAML subtasks per alert | ~30 real vulns found | Yes |
| Semgrep Assistant (Multimodal) | LLM (OpenAI + Bedrock), per-finding context + assistant memories | **~96% of true FPs auto-triaged** | No |
| Endor Labs AI SAST | Rules + reachability dataflow + LLM reasoning | **~95% FP elimination** (their "Code API" moat) | No |
| Snyk DeepCode AI | Symbolic AI + multiple fine-tuned models | 84% MTTR reduction | No |
| GitHub Copilot Autofix | GPT-5.1, SARIF + code context | Fix generation, not triage | No |

GitHub Security Lab uses vulnerability-specific prompts with over 200 lines of edge cases per class.

### What VulnBERT teaches us (hybrid approach)

VulnBERT (Guanni Qu, Pebblebed Ventures) predicts vulnerability-introducing commits in the Linux kernel.

**Architecture:** CodeBERT embeddings + 51 handcrafted features, fused via cross-attention.

**Ablation results:**
- Random Forest on handcrafted features alone: **76.8% recall / 15.9% FPR**
- CodeBERT embeddings alone: **84.3% recall / 4.2% FPR**
- Hybrid (features + CodeBERT): **92.2% recall / 1.2% FPR**

The hybrid achieved the best reported result in that ablation.

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
- **0sec's own data** — XBOW benchmark runs with flag extraction as ground truth

## Our Approach: Hybrid Triage Model

The design combines VulnBERT-style classification and structured LLM verification. Implemented components have source pointers; planned components are identified separately.

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

Reachability checks assess paths from application entry points to vulnerable sinks. Endor Labs reports 95% false-positive elimination with its proprietary Code API; 0sec's pattern-based implementation has separate evidence.

**Implementation:** `packages/core/src/triage/reachability.ts` — zero-dependency grep/pattern-based first pass. Conservative: when uncertain it returns `reachable: true` with low confidence so the rest of the pipeline still runs. Public API: `checkReachability(finding, repoPath)` returning a `ReachabilityResult`.

### Layer 1.9: Per-Class Oracles — SHIPPED

Category-specific oracles check SQLi, reflected XSS, SSRF, RCE, path traversal, and IDOR using observed signals: SQL errors, timing differences, tokenized browser alerts, file contents, or callback requests.

**Implementation:** `packages/core/src/triage/oracles.ts` plus the dispatcher `verifyOracleByCategory(finding, target)`. Oracles bypass the LLM entirely on the happy path; the LLM verify pipeline is the fallback.

### Layer 1.95: Multi-Modal Agreement (foxguard × 0sec) — SHIPPED

The optional [foxguard](https://github.com/0sec-labs/foxguard) check adds evidence
from a second scanner on the same tree. Agreement and silence feed the triage
decision; either outcome still needs interpretation.

Implementation: `packages/core/src/triage/multi-modal.ts`, exposing
`checkMultiModalAgreement`, `fuseTriageSignals`, `parseFoxguardSarif`, and `detectFoxguard`.

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

**Implementation:** `packages/core/src/triage/structured-verify.ts` — `runStructuredVerify(finding, target, runtime, memoryOptions)`.

### Layer 4.5: Self-Consistency Consensus Verification — SHIPPED

Because LLM sampling is non-deterministic, any single run of the structured verify pipeline may produce a false positive or false negative. We run the pipeline N times (default 5) in parallel and take the majority vote, with early termination as soon as a verdict locks up an unreachable lead.

**Implementation:** `runSelfConsistencyVerify(finding, target, runtime, opts)` and `tallyConsensus(runs)` in `structured-verify.ts`. Feature flag: `0SEC_FEATURE_CONSENSUS_VERIFY`.

### Layer 4.75: PoV (Proof-of-Vulnerability) Gate — SHIPPED

Following *All You Need Is A Fuzzing Brain* (arXiv:2509.07225), a scoped `bash` / `http_request` loop attempts a working PoC. Missing PoV downgrades severity to `info` and sets `triageNote = "no_pov"`.

**Implementation:** `packages/core/src/triage/pov-gate.ts` — `generatePov` and `judgePovEvidence`. Feature flag: `0SEC_FEATURE_POV_GATE`.

### Layer 5: Triage Memories (Semgrep-style) — SHIPPED

Per-target persistent FP context that learns from human triage decisions. When a user marks a finding as a false positive and gives a reason, the reason is stored as a `TriageMemory` scoped to `global`, `package`, or `target`. On future scans, memories are injected as few-shot examples into the verify prompt; a sufficiently strong match auto-rejects the finding without spending a verification call.

**Implementation:** `packages/core/src/triage/memories.ts` — `MemoryStore`, `scoreMemory`, `inferPackage`. Feature flag: `0SEC_FEATURE_TRIAGE_MEMORIES`.

<span id="layer-6-adversarial-debate--shipped"></span>
### Layer 6: Adversarial debate (planned)

The proposed prosecutor/defender design uses fresh contexts and a judge, inspired by arXiv:2402.06782. Reduced error correlation would require measurement.

**Status: planned, not implemented.** There is no `triage/adversarial.ts` and no `0SEC_FEATURE_DEBATE` flag in the engine today. The closest shipped mechanism is the cross-family refuter (`stages/hunt-cross-family.ts`), which pursues the same error-decorrelation goal by forcing the refute pass onto a different model family than the finder.

### Training Data Pipeline

1. **XBOW benchmark runs** — flag extraction provides ground truth (flag found = finding is real)
2. **Blind verify agent labels** — distill the verify agent's judgments across thousands of findings
3. **D2A dataset (IBM)** — static analysis finding labels for pre-training
4. **Accumulation** — every CI benchmark run with `--save-findings` adds to the training set

### Target Performance

> **Measured update, 2026-04-11:** the [21-run ablation](https://github.com/0sec-labs/0sec/issues/72#issuecomment-4229956469) found mode- and slice-dependent effects. See [results](/research/fp-reduction-moat/).

The table below preserves historical design targets drawn from SAST references.
It contains no measured 0sec performance:

| Metric (design target, NOT measured) | Features only (est.) | + Oracles + Reachability | + Consensus LLM verify | + Memories + PoV gate |
|--------|---------------------|--------------------------|------------------------|------------------------|
| Recall | ~77% | ~90% | ~95% | ~97% |
| FPR | ~50% (raw) | ~20% | ~5% | ~5% |
| Latency | <1ms | ~100ms | ~20s (parallel) | ~30s |
| Cost | $0 | $0 | ~$0.05/finding | ~$0.10/finding |

The actual measured effect on 0sec (2026-04-11 ablation, gpt-5.4):
- XBOW white-box @ limit=50: `moat` reduced findings 63% (67 → 25), with 41/50 flags (82%) versus `none` at 43/50 and `no-triage` at 44/50. Cost per flag was $0.53 versus `none` at $0.33 (1.6×).
- XBOW black-box @ limit=25: `moat` produced 19 versus 18 flags, 14 versus 27 findings (48% fewer), and $0.53 versus $0.76 per flag.
- npm-bench (81 packages): TPR was 100% across profiles; `default` and `moat` matched at F1=0.956. FPR rose from 0.11 (`none`) to 0.19 (`default`) in batch 1. Batch-2 variation prevents confident subsystem attribution.

The measured tradeoffs motivate [learned dynamic routing](https://github.com/0sec-labs/0sec/issues/113): preserve recall while selecting useful layers per finding and benchmark slice.

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

Met Guanni Qu (Pebblebed Ventures) in Zurich, April 2026. Her VulnBERT pipeline (data collection, feature engineering, hybrid model training) maps directly to 0sec's finding triage problem. Potential joint work on adapting the approach from kernel commits to web pentesting findings.
