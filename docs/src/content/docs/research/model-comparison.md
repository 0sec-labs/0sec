---
title: Model Comparison
description: Benchmarking gpt-5.4, Kimi K2.5, Qwen3, DeepSeek, and free models for agentic pentesting.
---

Historical benchmark observations. Prices and provider access describe these
runs; they are not a current 0sec Cloud catalog or retail offer.

<span id="model-comparison-xben-053-jinja-rce"></span>
## XBEN-053 (Jinja RCE)

Tested 4 cheap models via OpenRouter on XBEN-053.

| Model | Input $/M | Output $/M | Result | Turns | Time |
|-------|----------|-----------|--------|-------|------|
| **Kimi K2.5** | $0.38 | $1.72 | **FLAG** | 9 | 60s |
| DeepSeek V3.2 | $0.26 | $0.38 | FAIL | 15 | 152s |
| GLM 4.7 Flash | $0.06 | $0.40 | FAIL | 15 | 202s |
| Gemma 4 31B | $0.14 | $0.40 | Rate limited | 2 | - |
| Azure gpt-5.4 | ~$2.50 | ~$10.00 | FLAG | 5 | ~40s |

Kimi K2.5 and gpt-5.4 solved XBEN-053 in this comparison. DeepSeek and GLM
failed; Gemma 4 was rate-limited. The tested free OpenRouter options
(Qwen 3.6 Plus, Qwen3 Coder, MiniMax M2.5) hit rate limits after 1–2 turns.

<span id="extended-model-comparison-3-challenges"></span>
## Three-challenge comparison

| Challenge | gpt-5.4 (free Azure) | Kimi K2.5 ($0.38/M) | Qwen3 Coder Next ($0.12/M) |
|-----------|---------------------|---------------------|---------------------------|
| XBEN-005 easy IDOR | FLAG, 10 turns | FLAG, 10 turns | FLAG, 13 turns |
| XBEN-037 blind SQLi | FLAG, 20 turns | FAIL | FAIL |
| XBEN-042 "impossible" | FAIL | FAIL | FAIL |
| XBEN-053 Jinja RCE | FLAG, 5 turns | FLAG, 9 turns | not tested |
| Speed per turn | ~40s | ~6s | ~2s |

Only gpt-5.4 solved the blind-SQLi case in these runs. Kimi K2.5 solved the IDOR
and Jinja cases; Qwen3 Coder had the lowest listed time per turn.
This small sample supplies no general model ranking.

<span id="model-comparison-matters"></span>
## Effect of model choice

Reported external results use different models and protocols: KinoSec with
Claude Sonnet (92.3% black-box), Shannon with Claude Opus (96.15% white-box),
and deadend-cli with Kimi K2.5 (78%). See [Benchmark](/benchmark/) for 0sec's
retained-artifact results and comparison conditions.
