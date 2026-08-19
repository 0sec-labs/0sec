---
title: Features
description: Comprehensive feature list for 0sec, organized by category.
---

0sec is a fully autonomous agentic pentesting framework. This page is a
complete, category-organized inventory of what ships in the current release.
For deep dives, follow the linked pages.

## Target coverage

| Target | Command | What 0sec finds |
|--------|---------|-------------------|
| Web apps | `scan --target <url> --mode web` | SQLi, IDOR, SSTI, XSS, auth bypass, SSRF, LFI, RCE, file upload, deserialization, request smuggling |
| AI / LLM apps | `scan --target <url>` | Prompt injection, jailbreaks, system-prompt extraction, PII leakage, MCP tool abuse |
| Package registries | `audit <pkg>` / `audit <pkg> --ecosystem pypi` | Malicious code, known CVEs, supply-chain attacks |
| Source code | `review <path>` | SAST-style vulnerabilities via static analysis + AI review |
| White-box | `scan --target <url> --repo <path>` | Source-aware scanning — reads code before attacking |
| MCP servers | `scan --target mcp://…` | Tool poisoning and schema abuse |

## CLI flags (scan)

| Flag | Description |
|------|-------------|
| `--target <url>` | Target URL or `mcp://` endpoint (required) |
| `--mode <m>` | `probe`, `deep`, `mcp`, or `web` |
| `--depth <d>` | `quick`, `default`, or `deep` |
| `--runtime <rt>` | `api`, `claude`, `codex`, `gemini`, or `auto` |
| `--format <f>` | `terminal`, `json`, `md`, `html`, `sarif`, `pdf` |
| `--repo <path>` | Source code path for white-box scanning |
| `--auth <json\|file>` | Authenticated scanning. JSON string or file path; supports `bearer`, `cookie`, `basic`, `header` |
| `--api-spec <path>` | Pre-load endpoints from OpenAPI 3.x / Swagger 2.0 (JSON or YAML) |
| `--export <target>` | Export findings to an issue tracker, e.g. `github:owner/repo` |
| `--race` | Best-of-N strategy racing — run multiple attack strategies in parallel |
| `--egats` | Enable Evidence-Gated Attack Tree Search (beam search over hypotheses) |
| `--cost-ceiling <usd>` | Hard USD ceiling — abort cleanly with partial findings preserved if exceeded |
| `--verbose` | Animated attack replay |
| `--replay` | Re-render the last scan's results from the local DB |

### Authenticated scanning

```bash
0sec scan --target https://app.example.com \
  --auth '{"type":"bearer","token":"eyJhbGciOi..."}'

# Or point at a JSON file
0sec scan --target https://app.example.com --auth ./auth.json
```

Supported auth types: `bearer`, `cookie`, `basic`, `header`.

### API spec import

```bash
0sec scan --target https://api.example.com \
  --api-spec ./openapi.yaml
```

Pre-loads endpoint/parameter knowledge so the agent starts from a rich
surface map instead of discovering everything from scratch.

### Export to GitHub Issues

```bash
0sec scan --target https://example.com \
  --export github:my-org/my-repo
```

### Best-of-N strategy racing

```bash
0sec scan --target https://example.com --race
```

Runs multiple attack strategies in parallel and keeps whichever one produces
a verified finding first.

### EGATS

```bash
0sec scan --target https://example.com --egats
```

Evidence-Gated Attack Tree Search: the agent maintains an explicit hypothesis
tree and only expands branches backed by observed evidence.

## Runtimes

| Runtime | Description |
|---------|-------------|
| `api` | Direct HTTP to an LLM provider, including ChatGPT Codex subscription auth when configured. Default. |
| `claude` | Spawns the Claude Code CLI. |
| `codex` | Source review uses the OpenAI Codex CLI. Live target scans use the direct ChatGPT Codex provider when `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN` is configured. |
| `gemini` | Spawns the Gemini CLI. |
| `auto` | Auto-detect the best runtime per pipeline stage. |

Supported providers: **ChatGPT Codex** subscription auth, **OpenRouter**
(multi-model ensemble), **Anthropic**, **Azure OpenAI**, and **OpenAI**. See
[API Keys](/api-keys/) for priority order.

## Executors and tools

| Feature | Flag / env var | Description |
|---------|----------------|-------------|
| Shell executor | default | Host `bash` with `curl`, `python3`, and standard tooling |
| Kali Docker executor | `0SEC_FEATURE_DOCKER_EXECUTOR=1` | Runs bash inside a Kali container with the full pentesting toolset |
| Cloud sink | `0SEC_CLOUD_SINK` + `0SEC_CLOUD_SCAN_ID` | Streams findings/final report to a remote orchestrator endpoint |
| PTY sessions | `0SEC_FEATURE_PTY_SESSION=1` | Long-lived interactive sessions (reverse shells, DB clients, SSH) |
| Playwright browser | auto in `web` mode | Real-browser verification for XSS, cracked XBEN-011 & XBEN-018 |
| Web search | `0SEC_FEATURE_WEB_SEARCH=1` | Lets the agent look up CVE details and technique references |
| JIT skills | `0SEC_FEATURE_JIT_SKILLS=1` | Tool-callable methodology prompts via `list_skills` and `load_skill` |
| Agent plan | `0SEC_FEATURE_AGENT_PLAN=1` | Typed TODO ledger the agent maintains itself; survives context compaction |
| Drift detection | `0SEC_FEATURE_DRIFT_DETECTION=1` | Flags divergence from the assigned objective (not repetition — see the loop detector) |

## Output formats

| Format | Description |
|--------|-------------|
| `terminal` | Colored terminal report (default) |
| `json` | Machine-readable JSON |
| `md` / `markdown` | Human-readable Markdown |
| `html` | HTML report |
| `sarif` | SARIF 2.1 — drops into GitHub's Security tab |

You can also ask the CLI to emit a final machine-readable `0SEC_RESULT=...`
line with `0SEC_EMIT_RESULT_LINE=1` for wrappers and orchestration layers.

## Triage pipeline

0sec ships a multi-layer triage pipeline that sits between the attack
agent and the verify stage. See [Finding Triage](/triage/) for the
layer-by-layer reference and the [FP Reduction Moat](/research/fp-reduction-moat/)
page for the 2026-04-11 ablation that measured which layers actually
move the needle on XBOW and npm-bench (short version: the effect is
real but mode-dependent — the moat strictly dominates the no-triage
baseline on XBOW black-box, costs 2 flags at limit=50 white-box, and
is a no-op on npm-bench).

- Holding-it-wrong filter
- 45-feature extractor
- Per-class oracles (SQLi, XSS, SSRF, RCE, path traversal, IDOR)
- Reachability gate
- Multi-modal agreement (foxguard × 0sec)
- PoV generation gate
- Structured 4-step verify pipeline
- Self-consistency voting
- Assistant memories (Semgrep-style)
- Adversarial debate (prosecutor vs defender vs judge)
- EGATS (Evidence-Gated Attack Tree Search) — *opt-in only*, see
  [#116](https://github.com/0sec-labs/0sec/issues/116): the single-feature
  ablation on 2026-04-11 showed this layer regresses on hard challenges
  and costs ~10× the next-worst layer per flag, so it's excluded from
  the `moat` profile by default.

## Agent loop enhancements

| Feature | Flag / env var | Description |
|---------|----------------|-------------|
| Early-stop + retry | `0SEC_FEATURE_EARLY_STOP` (on) | Stops at 50% budget with no findings and retries with a different strategy |
| Loop detection | `0SEC_FEATURE_LOOP_DETECTION` (on) | Detects A-A-A / A-B-A-B patterns and injects a warning |
| Context compaction | `0SEC_FEATURE_CONTEXT_COMPACTION` (on) | LLM-based compression of middle messages at 30k tokens |
| Exploit templates | `0SEC_FEATURE_SCRIPT_TEMPLATES` (on) | Blind-SQLi / SSTI / auth-chain exploit scripts in the prompt |
| Dynamic playbooks | `0SEC_FEATURE_DYNAMIC_PLAYBOOKS` | Vuln-class playbooks injected after recon |
| Target-history preseed | `0SEC_FEATURE_TARGET_HISTORY_PRESEED` (on) | Source-review prompts start with prior target CVE/GHSA audit graph leads |
| JIT skills | `0SEC_FEATURE_JIT_SKILLS` | Methodology skills loaded on demand instead of injected upfront |
| External working memory | `0SEC_FEATURE_EXTERNAL_MEMORY` | Agent writes plan/creds to disk; re-injected at reflection checkpoints |
| Progress handoff | `0SEC_FEATURE_PROGRESS_HANDOFF` (on) | LLM-summarized structured progress injected when retrying after early-stop |
| Adversarial debate | `0SEC_FEATURE_DEBATE` | Prosecutor vs defender debate with a skeptical judge |

## Benchmarks

- **Cybench (first scored full 40-challenge run):** **90.0% (36/40)** — single-config
  Azure gpt-5.4, single-shot, 3 retries per challenge. BoxPwnr's published 40/40 = 100%
  is best-of-N across ~10 model+solver configs; 0sec's 36/40 is single-config single-shot.
- **XBOW gpt-5.4 model-specific cohort (load-bearing):** **97.9% (93/95)** —
  the stable, defensible black-box solve rate on the 95 challenges where 0sec has a
  retained gpt-5.4 attempt within the live CI window. Not affected by retention rotation.
- **XBOW retained artifact-backed aggregate:** **99.0% (103/104)** across the
  current recoverable artifact window — only XBEN-030 unsolved in any mode.
- **XBOW retained artifact-backed white-box:** **98.1% (102/104)** (field-leading).
- **XBOW retained-aggregate black-box:** rotation-volatile — currently 81/104
  but oscillates as the 90-day GitHub Actions retention window rotates older "unknown"-model
  proofs out. Use the gpt-5.4 cohort number above as the stable headline.
- **XBOW historical mixed local+CI publication:** **86.5% black-box (90/104)**
  and **91.3% aggregate (95 of 104)**, tracked separately from the retained
  artifact tally on the [Benchmark](/benchmark/) page.
- **gpt-5.4 cost on XBOW:** ~$0.48 / run, $5.20 / flag.
- **AI/LLM regression suite:** 10/10 on the self-authored suite covering
  prompt injection, jailbreaks, system-prompt extraction, PII leakage,
  encoding bypass, multi-turn escalation, MCP SSRF.
- **AutoPenBench, HarmBench, npm audit** harnesses shipped; see
  [Benchmark](/benchmark/).

## Unified SOC story

0sec is one leg of an open-source three-part security stack:

- **[0sec](https://github.com/0sec-labs/0sec)** — AI agent pentester (detect)
- **[foxguard](https://github.com/0sec-labs/foxguard)** — Rust security scanner (prevent)
- **[opensoar](https://github.com/opensoar-hq/opensoar-core)** — Python-native SOAR platform (respond)

With `0SEC_FEATURE_MULTIMODAL=1`, 0sec automatically cross-validates
every finding against foxguard's pattern scanner — the same neural +
symbolic agreement architecture Endor Labs uses in their AI SAST, except
fully open source. For what this actually does in 0sec (rather than
in Endor Labs' closed system on a different domain), see the measured
ablation on the [FP Reduction Moat](/research/fp-reduction-moat/) page.
