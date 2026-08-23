<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/0sec-aperture-white.svg">
    <img src="assets/0sec-aperture-ink.svg" alt="0sec" width="176">
  </picture>
</p>

<h1 align="center">0sec</h1>

<p align="center">
  <strong>The open cybersecurity harness.</strong><br/>
  0sec puts a team of AI agents on your target — web apps, AI/LLM endpoints,
  source, and packages. They explore in parallel, chain exploits, and a separate
  agent reproduces every finding before it counts. For compiled binaries with no
  source, the companion engine <a href="0verse/README.md">0verse</a> does the
  same job on its own toolchain.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-3fb950" alt="license" />
  <img src="https://img.shields.io/github/v/release/0sec-labs/0sec?color=2563eb" alt="release" />
  <img src="https://img.shields.io/badge/docs-0.security-6366f1" alt="docs" />
</p>

<p align="center">
  <sub>Created by the <strong>Swiss Applied AI Cybersecurity Research Lab</strong> · <a href="https://0.security">0.security</a></sub>
</p>

<p align="center">
  <img src="assets/0sec-demo.gif" alt="0sec — a team of AI agents finds, proves, and reports vulnerabilities" width="840">
</p>

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/0sec-labs/0sec/main/install.sh | bash
0sec --help          # or the shorthand: 0 --help
```

Downloads the verified GitHub Release binary (SHA-256 checked), installs to
`~/.0sec/bin`, and adds `0` as a shorthand. macOS (Apple Silicon) and Linux
(x64/arm64); on Windows grab `0sec-windows-x64.exe` from the release. Prefer a
container? `ghcr.io/0sec-labs/0sec:latest`. Not on npm — don't install a package
by that name.

## Quick start

```bash
# 1. Define what you're allowed to touch.
echo '{ "in_scope": ["example.com"] }' > scope.json
export ANTHROPIC_API_KEY=...          # or OpenAI, Azure, OpenRouter, Ollama, …

# 2. Scan a live target (out-of-scope requests are refused).
0sec scan --target https://example.com --scope ./scope.json

# 3. Or review code, audit a package, or open the chat console.
0sec review ./my-app                  # source review
0sec audit lodash                     # npm/pypi/cargo/oci package audit
0 console --scope ./scope.json        # interactive operator console; type / for commands
```

Inside the Bun console, `/` opens the local command menu. Start with `/status`,
`/scope`, `/mode yolo`, `/clear`, and `/help`; commands never bypass the
scope-on-demand and approval flow.

Add `--cost-ceiling 5` for a hard spend cap, `--race` for best-of-N strategy
racing, `--format sarif` for the GitHub Security tab. Every command has its own
`--help`.

## What it does

A team of agents explores the target and saves candidate findings — a lead
agent that can fan out into parallel strategies (`--race`) and focused subagents,
plus a separate, blind verification agent that decides which findings survive. A
finding it can't reproduce is dropped — not shipped as "low confidence." Each run
keeps its own evidence under
`~/.0sec/runs/<id>/` (isolated SQLite state, an append-only journal, artifacts)
so you can `resume`, `replay`, or `disclose` it later.

| You want to… | Command |
| --- | --- |
| Pentest a web app, AI/LLM endpoint, or MCP server | `scan`, `eval`, `agent-assure` |
| Review source, packages, C/C++, or a kernel tree | `review`, `file-review`, `deep-review`, `audit` |
| Recon an attack surface | `recon`, `js-recon`, `npm-discovery`, `intel` |
| Hunt a bug class / kernel variants | `hunt`, `kernel`, `cve` |
| Work with evidence | `findings`, `history`, `resume`, `replay`, `verify`, `timeline`, `disclose` |
| Generate & re-test a source fix | `fix` |
| Assess identity / AD posture (read-only, offline) | `identity`, `adgraph`, `entragraph` |
| Analyze a compiled binary (no source) | [`0verse`](0verse/README.md) |
| Integrate | `mcp-server`, `console`, `tui`, `dashboard` |

That's a slice of the **48-command CLI** — run `0sec --help` for the rest.
Full reference: **[0.security](https://0.security)**.

## How it works

- **Free-form agents inside deterministic guardrails.** No hard-coded exploit
  playbook — the models decide what to probe and how to chain it, and a lead
  agent can spawn parallel strategy racers and focused subagents. Turn budgets,
  reflection checkpoints, loop detection, and context compaction keep them on
  track; scope is enforced on every tool call.
- **Reproduce before trust.** A blind verify agent re-exploits each finding
  seeing only the PoC (never the finder's reasoning); a deterministic
  `verificationSpec` re-checks source with no LLM; a replay runner re-runs the
  real target and asserts on the result. Unreproduced findings are dropped.
- **Triage before verify.** Class oracles, an open-source reachability gate, and
  a second scanner (foxguard) cross-validate to cut noise. The heavier
  false-positive layers are opt-in and slice-dependent.
- **Bring your own model.** Anthropic, OpenAI, Azure (EU regions), OpenRouter,
  DeepSeek, Z.ai GLM, Moonshot Kimi, Qwen, a ChatGPT-Codex subscription, or local
  Ollama — plus per-stage `auto` routing and a cross-session cost ledger.

## Found in the wild

We care more about real vulnerabilities than benchmark leaderboards. 0sec's
research loop has disclosed real bugs in the **Linux kernel** — with maintainer
review from Intel, NVIDIA, Red Hat, Google, Meta, Qualcomm, and Arm — and in
widely-used open source. The running, verified track record (kernel.org threads,
CVEs, and advisories) lives on the site:

**→ [0.security](https://0.security)**

We also run the public CTF benchmarks and score near the top, but treat those as
secondary, condition-specific evidence — caveats in the
[benchmark docs](docs/src/content/docs/benchmark.md).

## Binary analysis (no source)

When there's no source — just a compiled binary — the harness switches to its
binary-native engine, [**0verse**](0verse/README.md). Same principle, harder
setting (no symbols, no sanitizers): it runs a find → prove → patch → verify loop
and confirms a bug only with a reproducing proof-of-vulnerability. It's a
separate engine under the hood (Python + Ghidra/angr/AFL++, so it installs on its
own toolchain), and 0sec trusts its findings only through a verified receipt.

```bash
cd 0verse && uv sync --frozen && uv run --frozen 0verse triage ./target-binary
```

See the [0verse README](0verse/README.md) for the full binary pipeline, backends,
and honest limits.

## Honest limitations

We publish the misses next to the wins.

- **Kernel/IOKit findings stay hypotheses** until a real oracle reproduces them;
  the `linux-kernel` review profile is static and doesn't compile or boot.
- **Verification depth varies.** `verificationSpec` covers file/diff predicates
  today (`ast-shape` and behavioural specs are stubs); the replay runner ships
  local-shell only (Docker/QEMU are stubs).
- **The FP-moat layers are off by default and slice-dependent** — a strict win on
  some slices, a small cost on others, a no-op on the npm suite. EGATS tree
  search regressed and was cut from defaults.
- **Benchmarks are single-model, single-config, single-trial** (`gpt-5.4`);
  cross-model cost isn't published, and CTF challenges are far smaller than real
  repos. AutoPenBench/HarmBench aren't scored yet; the 10/10 AI-suite is
  self-authored, not an independent benchmark.
- **Scaffolds, not live:** the specialist journal-orchestrator router, `0sec
  auth` (token-paste only), and the feature-gated `0sec cloud` surface.
- **`fix` is intentionally narrow:** source-only, single-file, ≤3 attempts, and
  it refuses a hypothesis or a dirty worktree.
- **By design, never:** network sweeps, credential spraying, persistence/C2, or
  stealth. Identity/AD tooling is read-only and offline.

## Build from source

```bash
git clone https://github.com/0sec-labs/0sec.git && cd 0sec
corepack enable && pnpm install --frozen-lockfile && pnpm build
node dist/0sec.js --help
```

`pnpm lint && pnpm build && pnpm test` before a PR. The bundle embeds its build
commit and rejects a stale run against a different checkout.

## Contributing & security

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md); use only
synthetic or authorized test material. Report vulnerabilities privately via
[SECURITY.md](SECURITY.md) (security@0sec.ai), not public issues.

## Supported by

0sec Labs is supported by these startup and research programs:

- [AWS Startups](https://aws.amazon.com/startups/)
- [Microsoft for Startups](https://www.microsoft.com/en-us/startups)
- [E2B for Startups](https://e2b.dev/startups)
- [Hack Nation](https://hack-nation.ai/)
- [NVIDIA Inception Program](https://www.nvidia.com/en-us/startups/)

## License

Dual-licensed **MIT OR Apache-2.0**, at your option — see [LICENSE](LICENSE)
(Apache-2.0) and [LICENSE-MIT](LICENSE-MIT) (MIT). Copyright 2026 0sec Labs.
