<p align="center">
 <img src="assets/pwnkit-icon.gif" alt="pwnkit" width="80" />
</p>

<h1 align="center">pwnkit</h1>

> **This is proprietary software of 0sec Labs. Do not distribute.**

<p align="center">
 <strong>Let autonomous AI agents hack you before attackers do.</strong><br/>
 <em>Fully autonomous agentic pentesting for web apps, AI/LLM apps, package ecosystems, and source code.</em>
</p>

<p align="center">
 <a href="https://docs.0sec.ai/benchmark"><img src="https://img.shields.io/badge/XBOW%20aggregate-99.0%25%20(103%2F104)-e63946?style=flat-square&labelColor=2b2d42" alt="XBOW retained artifact-backed aggregate" /></a>
 <a href="https://docs.0sec.ai/benchmark"><img src="https://img.shields.io/badge/XBOW%20gpt--5.4%20cohort-97.9%25%20(93%2F95)-e63946?style=flat-square&labelColor=2b2d42" alt="XBOW gpt-5.4 model-specific cohort" /></a>
 <a href="https://docs.0sec.ai/benchmark"><img src="https://img.shields.io/badge/Cybench-90.0%25%20(36%2F40)-e63946?style=flat-square&labelColor=2b2d42" alt="Cybench full 40-challenge score" /></a>
</p>

<p align="center">
 <img src="assets/demo.gif" alt="pwnkit Demo" width="700" />
</p>

<p align="center">
 <a href="https://docs.0sec.ai">Docs</a> &middot;
 <a href="https://0sec.ai">Website</a> &middot;
 <a href="https://0sec.ai/blog">Blog</a> &middot;
 <a href="https://docs.0sec.ai/benchmark">Benchmark</a> &middot;
 <a href="https://docs.0sec.ai/triage">Triage</a>
</p>

---

## Install

pwnkit is closed-source software. Public npm and binary distribution have been retired.

```bash
# Docker (Playwright + sqlmap/wpscan/nmap/nikto/gobuster/ffuf/hydra/john preinstalled)
docker run --rm -e OPENROUTER_API_KEY=$KEY \
  ghcr.io/0sec-labs/pwnkit:latest scan --target https://example.com
```

For access, contact **security@0sec.ai**.

## Use

```bash
# AI / LLM endpoint
pwnkit scan --target https://example.com/api/chat

# Web app (optionally with source for white-box)
pwnkit scan --target https://example.com --mode web
pwnkit scan --target https://example.com --repo ./source

# Audit a package, review source, ingest kernel crashes
pwnkit audit lodash
pwnkit review ./my-app
pwnkit ingest ./kernel-crashes --verify --output json
pwnkit ingest --reproducer ./poc.c --kernel-tree ./linux --config kasan --output json
pwnkit ingest ./kernel-crashes --review-subsystem --tree ./linux --output json

# Kernel-advisory variant hunting with foxguard rules
pwnkit kernel variant-hunt --tree ./linux --rules ./foxguard/rules/kernel/dirty-frag-class

# Auto-detect
pwnkit https://example.com
```

`scan`, `audit`, `review`, `ingest`, `kernel`, and `h1` cover detection. `dashboard`, `history`, `findings`, and `triage` cover review. Full reference: [docs.0sec.ai/commands](https://docs.0sec.ai/commands).

## Why It's Different

- **Shell-first web pentesting.** The agent uses `bash`, writes scripts, and chains tools like a human pentester instead of being trapped in a small HTTP-tool DSL.
- **Blind verification.** Findings are independently re-exploited before they are reported.
- **Benchmark transparency.** Raw artifacts and per-challenge breakdowns under `packages/benchmark/results`.

## One research loop, specialized engines

pwnkit's target-specific engines keep their native harnesses and oracles, but
can now run through one evidence lifecycle:

```text
Discover → Reachability? → Harness? → Execute? → Verify → Novelty? → Impact?
```

`Verify` is mandatory before promotion. Optional stages that cannot run are
recorded as skipped or inconclusive rather than silently passing. Proof strength
is monotone (`candidate → reachable → observed → reproduced → impact-proven`),
while novelty is tracked separately and fails closed when no sources were
actually checked. Attacker privilege is a third, orthogonal dimension. Current
native Linux VM replay runs as guest root and is recorded as privileged; a
reproduced crash is therefore not zero-cap proof. Zero-cap promotion requires
runtime-attested non-root real and effective UIDs, an empty effective capability
set, `no_new_privs`, and a digest-bound attestation artifact.
Schema-v2 receipts also bind a private staged host kernel-image digest and its
associated build-config digest to the guest-observed kernel release and a fresh
boot UUID. N-of-K promotion rejects
mixed kernel identities, repeated boot IDs, or missing per-boot dmesg hashes.
This is trusted host/VM orchestration evidence, not hardware remote attestation;
the config association is not a runtime-config measurement.

Connected adapters cover deterministic HTTP protocol conformance, userspace
sanitizer/fuzzing campaigns, the agentic best-of-N hunt, repeated-boot Linux
verification, mobile intake/handoff, XNU selector generation, and the existing
web/AI/source/package/on-chain pipeline. XNU panic promotion intentionally
remains disabled until repeated attributed proof exists. Native engine evidence
is preserved losslessly behind the shared adapter boundary.

Target-specific kernel rigs can import a versioned vulnerable-vs-patched boot
manifest with `pwnkit research linux-matrix`. pwnkit validates distinct boot
markers and thresholds, requires clean completed controls, snapshots and hashes
all logs, and records that execution occurred externally.

For pwnkit-executed boots, `pwnkit research linux` requires an explicit
`--expected-signature`. Only boots containing that literal oracle count toward
the M-of-K threshold; unrelated sanitizer faults fail closed. Every attempted
boot retains and hashes its own dmesg artifact, and an inconclusive command
returns nonzero.

`pwnkit kernel syzbot-mine` mines abandoned syzbot reports with a bounded
adversarial second pass. It reads the top detail pages and exact syz options,
records sandbox and harness dependencies, and demotes privileged, one-shot,
stale, or incompletely enriched leads. This is triage—not an LPE or novelty
claim. Promotion still requires fresh sanitizer proof, COS reachability,
patched differential controls, and novelty receipts.

Kernel campaigns should keep privileged discovery and setuid-isolated discovery
as separate lanes. `sandbox=setuid` is configuration evidence and may support a
zero-cap-plausible label, but it is not runtime proof by itself.

See [Research architecture](docs/src/content/docs/architecture.md#shared-research-plane).

## Docs

[Getting Started](https://docs.0sec.ai/getting-started) · [Commands](https://docs.0sec.ai/commands) · [Configuration](https://docs.0sec.ai/configuration) · [Recipes](https://docs.0sec.ai/recipes) · [Architecture](https://docs.0sec.ai/architecture) · [Triage](https://docs.0sec.ai/triage) · [Benchmark](https://docs.0sec.ai/benchmark) · [Adversarial evals](https://docs.0sec.ai/adversarial-evals) · [Enterprise](https://docs.0sec.ai/enterprise)

## Development

```bash
# Internal — this repo is private and closed-source.
pnpm install && pnpm lint && pnpm test
```

When running from a source checkout, rebuild after every pull before invoking the ignored bundle:

```bash
pnpm run build
node dist/pwnkit.js --help
```

`dist/pwnkit.js` embeds the git commit it was built from and exits if it no longer matches the checkout `HEAD`; this prevents clean-looking source trees from running stale ignored code.

## Part of 0sec Labs

Adversarial security for the agentic AI era:

- **pwnkit** — AI agent pentester (detect)
- **[foxguard](https://github.com/0sec-labs/foxguard)** — Rust security scanner (prevent)

## License

Proprietary. See [LICENSE](LICENSE).
