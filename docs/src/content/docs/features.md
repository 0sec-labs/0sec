---
title: Features
description: What ships in 0sec and how evidence becomes a finding.
---

## Target coverage

| Target | Command | What 0sec finds |
|--------|---------|-------------------|
| Web apps | `scan --target <url> --mode web` | SQLi, IDOR, SSTI, XSS, auth bypass, SSRF, LFI, RCE, file upload, deserialization, request smuggling |
| AI / LLM apps | `scan --target <url>` | Prompt injection, jailbreaks, system-prompt extraction, PII leakage, MCP tool abuse |
| Package registries | `audit <pkg>` / `audit <pkg> --ecosystem pypi` | Malicious code, known CVEs, supply-chain attacks |
| Source code | `review <path>` | SAST-style vulnerabilities via static analysis + AI review |
| White-box | `scan --target <url> --repo <path>` | Source-aware scanning — reads code before attacking |
| MCP servers | `scan --target mcp://…` | Tool poisoning and schema abuse |
| Compiled binaries (no source) | [`0verse`](https://github.com/0sec-labs/0sec/tree/main/0verse) `triage <binary>` | Memory-safety bugs via a find → prove → patch → verify loop, confirmed with a proof-of-vulnerability |

## CLI flags (scan)

| Flag | Description |
|------|-------------|
| `--target <url>` | Target URL or `mcp://` endpoint (required) |
| `--mode <m>` | `probe`, `deep`, `mcp`, or `web` |
| `--depth <d>` | `quick`, `default`, or `deep` |
| `--runtime <rt>` | `api`, `claude`, `codex`, `gemini`, or `auto` |
| `--format <f>` | `terminal`, `json`, `md`, `html`, `sarif`, `pdf` |
| `--repo <path>` | Source path for white-box scanning |
| `--auth <json\|file>` | Authenticated scanning: `bearer`, `cookie`, `basic`, or `header` |
| `--api-spec <path>` | Pre-load endpoints from OpenAPI 3.x / Swagger 2.0 |
| `--export <target>` | Export findings to an issue tracker, e.g. `github:owner/repo` |
| `--race` | Run multiple attack strategies in parallel, keep the first verified finding |
| `--egats` | Evidence-Gated Attack Tree Search (beam search over hypotheses) |
| `--cost-ceiling <usd>` | Hard USD ceiling; aborts cleanly with partial findings preserved |
| `--verbose` | Animated attack replay |
| `--replay` | Re-render the last scan's results from the local DB |

### Authenticated scanning

```bash
0sec scan --target https://app.example.com \
  --auth '{"type":"bearer","token":"eyJhbGciOi..."}'

# Or point at a JSON file
0sec scan --target https://app.example.com --auth ./auth.json
```

### API spec import

```bash
0sec scan --target https://api.example.com --api-spec ./openapi.yaml
```

Gives the agent a surface map up front instead of making it discover every
endpoint from scratch.

### Export to GitHub Issues

```bash
0sec scan --target https://example.com --export github:my-org/my-repo
```

## Runtimes

| Runtime | Description |
|---------|-------------|
| `api` | Direct HTTP to an LLM provider (default); supports ChatGPT Codex subscription auth |
| `claude` | Spawns the Claude Code CLI |
| `codex` | OpenAI Codex CLI for source review; direct ChatGPT Codex provider for live scans when `0SEC_CHATGPT_OAUTH_REFRESH_TOKEN` is set |
| `gemini` | Spawns the Gemini CLI |
| `auto` | Auto-detects the best runtime per pipeline stage |

Providers: ChatGPT Codex, OpenRouter, Anthropic, Azure OpenAI, and OpenAI.
See [API Keys](/api-keys/) for priority order.

## Executors and tools

No per-scan sandbox in OSS — the shell executor runs on the host.

| Feature | Flag / env var | Description |
|---------|----------------|-------------|
| Shell executor | default | Host `bash` with `curl`, `python3`, and standard tooling |
| Kali Docker executor | `0SEC_FEATURE_DOCKER_EXECUTOR=1` | Runs bash in a Kali container with the full pentest toolset |
| Cloud sink | `0SEC_CLOUD_SINK` + `0SEC_CLOUD_SCAN_ID` | Streams findings/report to a remote orchestrator |
| PTY sessions | `0SEC_FEATURE_PTY_SESSION=1` | Long-lived interactive sessions (reverse shells, DB clients, SSH) |
| Playwright browser | auto in `web` mode | Real-browser verification for XSS |
| Web search | `0SEC_FEATURE_WEB_SEARCH=1` | Looks up CVE details and technique references |
| JIT skills | `0SEC_FEATURE_JIT_SKILLS=1` | Tool-callable methodology prompts via `list_skills` / `load_skill` |
| Agent plan | `0SEC_FEATURE_AGENT_PLAN=1` | Typed TODO ledger the agent maintains; survives compaction |
| Drift detection | `0SEC_FEATURE_DRIFT_DETECTION=1` | Flags divergence from the assigned objective |

## Output formats

`terminal` (default), `json`, `md`/`markdown`, `html`, and `sarif` (2.1, drops
into GitHub's Security tab). Set `0SEC_EMIT_RESULT_LINE=1` to emit a final
machine-readable `0SEC_RESULT=...` line for wrappers.

## Triage pipeline

A multi-layer triage pipeline sits between the attack agent and verification.
See [Finding Triage](/triage/) for the layer reference and the
[FP Reduction Moat](/research/fp-reduction-moat/) page for the measured
ablation. Layers include:

- Holding-it-wrong filter and a 45-feature extractor
- Per-class oracles (SQLi, XSS, SSRF, RCE, path traversal, IDOR)
- Reachability gate
- Multi-modal agreement (foxguard × 0sec)
- PoV generation gate, structured 4-step verify, self-consistency voting
- Assistant memories (Semgrep-style)
- Adversarial debate (prosecutor/defender/judge) — *planned, not implemented*
- EGATS — *opt-in only* ([#116](https://github.com/0sec-labs/0sec/issues/116));
  excluded from the default `moat` profile

## Agent loop enhancements

| Feature | Flag / env var | Description |
|---------|----------------|-------------|
| Early-stop + retry | `0SEC_FEATURE_EARLY_STOP` (on) | Stops at 50% budget with no findings and retries with a different strategy |
| Loop detection | `0SEC_FEATURE_LOOP_DETECTION` (on) | Detects A-A-A / A-B-A-B patterns and injects a warning |
| Context compaction | `0SEC_FEATURE_CONTEXT_COMPACTION` (on) | LLM compression of middle messages at 30k tokens |
| Exploit templates | `0SEC_FEATURE_SCRIPT_TEMPLATES` (on) | Blind-SQLi / SSTI / auth-chain scripts in the prompt |
| Dynamic playbooks | `0SEC_FEATURE_DYNAMIC_PLAYBOOKS` | Vuln-class playbooks injected after recon |
| Target-history preseed | `0SEC_FEATURE_TARGET_HISTORY_PRESEED` (on) | Source-review prompts start with prior CVE/GHSA leads |
| JIT skills | `0SEC_FEATURE_JIT_SKILLS` | Methodology skills loaded on demand |
| External working memory | `0SEC_FEATURE_EXTERNAL_MEMORY` | Agent writes plan/creds to disk; re-injected at reflection checkpoints |
| Progress handoff | `0SEC_FEATURE_PROGRESS_HANDOFF` (on) | Structured progress summary injected when retrying after early-stop |
| Adversarial debate | _(planned)_ | **Not implemented.** No `0SEC_FEATURE_DEBATE` flag exists yet. |

## Benchmarks

The [Benchmark](/benchmark/) page owns the current scores; headline numbers:

- **Cybench:** 90.0% (36/40) — single-config Azure gpt-5.4, single-shot, 3 retries.
- **XBOW gpt-5.4 cohort (stable headline):** 97.9% (93/95) black-box.
- **XBOW retained artifact-backed:** 99.0% (103/104) aggregate, 98.1% (102/104) white-box.
- **gpt-5.4 cost on XBOW:** ~$0.48 / run, $5.20 / flag.
- **AI/LLM regression suite:** 10/10.
- AutoPenBench, HarmBench, and npm audit harnesses shipped.

Retained black-box aggregate is rotation-volatile as the 90-day GitHub Actions
retention window rotates older proofs out; use the gpt-5.4 cohort number as the
stable headline.

## Unified SOC story

0sec is one leg of an open-source three-part stack:

- **[0sec](https://github.com/0sec-labs/0sec)** — AI agent pentester (detect)
- **[foxguard](https://github.com/0sec-labs/foxguard)** — Rust security scanner (prevent)
- **[opensoar](https://github.com/opensoar-hq/opensoar-core)** — Python SOAR platform (respond)

With `0SEC_FEATURE_MULTIMODAL=1`, 0sec cross-validates every finding against
foxguard's pattern scanner (neural + symbolic agreement). See the
[FP Reduction Moat](/research/fp-reduction-moat/) page for what this measurably does.
