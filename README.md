<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/0sec-aperture-white.svg">
    <img src="assets/0sec-aperture-ink.svg" alt="0sec" width="176">
  </picture>
</p>

<h1 align="center">0sec</h1>

<p align="center">
  <strong>The open cybersecurity harness.</strong><br/>
  Point a team of AI agents at a target — a web app, an AI/LLM endpoint, source
  code, or a package. They work in parallel to find and exploit bugs, and a
  separate agent reproduces every finding before it counts. No source, just a
  binary? The companion engine <a href="0verse/README.md">0verse</a> does the
  same on its own toolchain.
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
0sec --help          # or just: 0 --help
```

This downloads the verified release binary (checked against its SHA-256),
installs it to `~/.0sec/bin`, and adds `0` as a short alias. It runs on macOS
(Apple Silicon) and Linux (x64/arm64). On Windows, download
`0sec-windows-x64.exe` from the release. Prefer Docker? Use
`ghcr.io/0sec-labs/0sec:latest`. 0sec is **not on npm** — don't install a package
by that name.

## Quick start

```bash
# 1. Say what you're allowed to touch.
echo '{ "in_scope": ["example.com"] }' > scope.json
export ANTHROPIC_API_KEY=...          # or OpenAI, Azure, OpenRouter, Ollama, …

# 2. Scan a live target (anything out of scope is refused).
0sec scan --target https://example.com --scope ./scope.json

# 3. Or review code, audit a package, or open the console.
0sec review ./my-app                  # source review
0sec audit lodash                     # npm / pypi / cargo / oci package audit
0 console --scope ./scope.json        # interactive console; type / for commands
```

In the console, `/` opens the command menu (`/status`, `/scope`, `/mode`,
`/help`). Commands never skip scope or approval.

Useful flags: `--cost-ceiling 5` sets a hard spend cap, `--race` runs several
strategies and keeps the best, `--format sarif` writes output for the GitHub
Security tab. Every command has its own `--help`.

## How it works

0sec runs a team of agents against your target. A lead agent explores and can
fan out into parallel strategies (`--race`) and focused subagents. Everything
they find is only a *candidate* until it is proven.

- **The agents decide; the guardrails contain them.** No hard-coded exploit
  script — the models choose what to probe. Turn budgets, loop detection, and
  compaction keep them on track, and scope is checked on every tool call.
- **Nothing counts until it's reproduced.** A blind agent re-exploits each
  finding from the proof-of-concept alone. Anything it can't reproduce is
  dropped — never shipped as "low confidence."
- **Triage cuts the noise first.** Class oracles, a reachability gate, and a
  second scanner (foxguard) cross-check findings before verification; the
  heavier false-positive filters are off by default.
- **Bring your own model.** Anthropic, OpenAI, Azure (EU), OpenRouter, DeepSeek,
  Z.ai GLM, Moonshot Kimi, Qwen, a ChatGPT-Codex subscription, or local Ollama —
  with per-stage `auto` routing and a cross-session cost ledger.

Every run keeps its own evidence in `~/.0sec/runs/<id>/` — its own database, an
append-only journal, and artifacts — so you can `resume`, `replay`, or
`disclose` it later.

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

That's part of a **broad CLI** — run `0sec --help` for the full list. Full docs:
**[0.security](https://0.security)**.

## Found in the wild

0sec's research loop has found real bugs in the **Linux kernel** — reviewed by
maintainers from Intel, NVIDIA, Red Hat, Google, Meta, Qualcomm, and Arm — and
in widely-used open source. The verified track record (kernel.org threads, CVEs,
and advisories) lives on the site:

**→ [0.security](https://0.security)**

We run the public CTF benchmarks too, but treat them as secondary evidence —
caveats in the [benchmark docs](docs/src/content/docs/benchmark.md).

## Binary analysis (no source)

For compiled binaries, 0sec hands off to **[0verse](0verse/README.md)** — a
separate Python engine (Ghidra/angr/AFL++) that runs a find → prove → patch →
verify loop and only confirms a bug with a working proof-of-vulnerability:

```bash
cd 0verse && uv sync --frozen && uv run --frozen 0verse triage ./target-binary
```

## Public engine vs. managed service

This repo is the **public engine and CLI** — run it yourself, locally or in CI,
with any model and runtime. A separate **managed service** handles authorized
external testing on isolated workers (scheduling, evidence, delivery). It builds
on this CLI, isn't in this repo, and nothing here depends on it.

## Honest limitations

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

Run `pnpm lint && pnpm build && pnpm test` before a PR. The bundle embeds its
build commit and refuses to run against a different checkout.

## Contributing & security

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md); use only
synthetic or authorized test material. Report vulnerabilities privately via
[SECURITY.md](SECURITY.md) (security@0sec.ai), not public issues.

## Supported by

With special thanks to the startup and research programs supporting our work:

<p align="center">
  <a href="https://aws.amazon.com/startups/" title="AWS Startups">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/assets/supported-by/aws-startups-dark.png">
      <img alt="AWS Startups" height="30" src="docs/assets/supported-by/aws-startups-light.png">
    </picture>
  </a>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <a href="https://www.microsoft.com/en-us/startups" title="Microsoft for Startups">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/assets/supported-by/microsoft-for-startups-dark.png">
      <img alt="Microsoft for Startups" height="30" src="docs/assets/supported-by/microsoft-for-startups-light.png">
    </picture>
  </a>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <a href="https://e2b.dev/startups" title="E2B for Startups">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/assets/supported-by/e2b-dark.svg">
      <img alt="E2B for Startups" height="30" src="docs/assets/supported-by/e2b-light.svg">
    </picture>
  </a>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <a href="https://hack-nation.ai/" title="Hack Nation">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/assets/supported-by/hacknation-dark.png">
      <img alt="Hack Nation" height="30" src="docs/assets/supported-by/hacknation-light.png">
    </picture>
  </a>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <a href="https://www.nvidia.com/en-us/startups/" title="NVIDIA Inception Program">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/assets/supported-by/nvidia-inception-dark.svg">
      <img alt="NVIDIA Inception Program" height="56" src="docs/assets/supported-by/nvidia-inception-light.svg">
    </picture>
  </a>
  
</p>

## License

Dual-licensed **MIT OR Apache-2.0**, at your option — see [LICENSE](LICENSE)
(Apache-2.0) and [LICENSE-MIT](LICENSE-MIT) (MIT). Copyright 2026 0sec Labs.
