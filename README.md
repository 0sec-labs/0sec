<p align="center">
  <a href="https://0.security/harness/">
    <img src="https://raw.githubusercontent.com/0sec-labs/0sec/main/assets/readme-cover.png" alt="Your self-improving cybersecurity team. An ivory paper sculpture with a crimson edge." width="100%">
  </a>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/0sec-labs/0sec/main/assets/0sec-aperture-white.svg">
    <img src="https://raw.githubusercontent.com/0sec-labs/0sec/main/assets/0sec-aperture-ink.svg" alt="0sec" width="176">
  </picture>
</p>

<p align="center">
  <strong>Hack any software before attackers do.</strong><br/>
  An open-source, multi-model cybersecurity harness for authorized security research.
</p>

<p align="center">
  <sub>The Swiss Applied AI &amp; Cybersecurity Research Lab · <a href="https://0.security">0.security</a></sub>
</p>

<p align="center">
  <a href="https://0.security"><img src="https://img.shields.io/badge/site-0.security-DC2626?style=flat-square&amp;labelColor=1A1815" alt="0.security"></a>
  <a href="https://docs.0.security/"><img src="https://img.shields.io/badge/docs-0.security-1A1815?style=flat-square&amp;labelColor=1A1815" alt="Documentation"></a>
  <a href="https://github.com/0sec-labs/foxguard"><img src="https://img.shields.io/badge/scanner-Foxguard-1A1815?style=flat-square&amp;labelColor=1A1815" alt="Foxguard scanner"></a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-1A1815?style=flat-square&amp;labelColor=1A1815" alt="License: MIT OR Apache-2.0"></a>
  <a href="https://github.com/0sec-labs/0sec/releases/latest"><img src="https://img.shields.io/github/v/release/0sec-labs/0sec?style=flat-square&amp;labelColor=1A1815&amp;color=1A1815" alt="Latest release"></a>
  <a href="#research-preview"><img src="https://img.shields.io/badge/status-research%20preview-DC2626?style=flat-square&amp;labelColor=1A1815" alt="Status: research preview"></a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/0sec-labs/0sec/main/assets/demo-intro.gif" alt="0sec interactive CLI demonstration" width="840">
</p>

## What you can do

- <img height="14" src="https://raw.githubusercontent.com/0sec-labs/.github/main/profile/assets/icons/zap.png" alt="">&nbsp; **Investigate in chat.** Work through an assessment with persistent conversations, tool output and model selection in the [terminal console](https://docs.0.security/console/).
- <img height="14" src="https://raw.githubusercontent.com/0sec-labs/.github/main/profile/assets/icons/code.png" alt="">&nbsp; **Review code and packages.** Run repository reviews and package audits with [source and scan workflows](https://docs.0.security/scan-workflows/).
- <img height="14" src="https://raw.githubusercontent.com/0sec-labs/.github/main/profile/assets/icons/shield-check.png" alt="">&nbsp; **Start with static analysis.** The installer includes [Foxguard](https://github.com/0sec-labs/foxguard), the separate scanner used by default for static analysis.
- <img height="14" src="https://raw.githubusercontent.com/0sec-labs/.github/main/profile/assets/icons/verified.png" alt="">&nbsp; **Inspect the evidence.** Review reproduction results, verification failures and coverage limits before accepting a finding. See [verification](https://docs.0.security/blind-verification/).
- <img height="14" src="https://raw.githubusercontent.com/0sec-labs/.github/main/profile/assets/icons/beaker.png" alt="">&nbsp; **Extend and evolve the agent.** Explore codebase learning, source evolution and versioned executable plugins in the [improvement plane](https://docs.0.security/improvement-plane/). These workflows are a Research Preview.

## Get started

```bash
curl -fsSL https://raw.githubusercontent.com/0sec-labs/0sec/main/install.sh | bash
export PATH="$HOME/.0sec/bin:$PATH"
0 --help
```

Add the `export` line to your shell profile. Choose a model connection below,
then follow the [console guide](https://docs.0.security/console/) for interactive
work or [scan workflows](https://docs.0.security/scan-workflows/) for command-line runs.
Only test systems you own or have permission to assess.

See [Getting started](https://docs.0.security/getting-started/) for Docker,
source builds, and your first scan.

### Hosted models

**0sec Cloud** is the optional account and hosted-model surface. Hosted inference
is still deployment-gated; production inference has not been qualified.
These commands require a compatible CLI and an approved hosted deployment:

```bash
0sec login
0sec models
0sec balance
```

Login uses browser approval and organization selection. It does not add funds
or grant model access. Funding, purchasing and available aliases depend on the
deployment. Provider keys stay on the service while CLI tools run locally.

Configured BYOK providers retain precedence over automatic hosted selection.
An explicitly selected hosted model must appear in the service catalog; the CLI
does not silently substitute another model. Managed **0cloud** testing and
**0review** CI review retain separate access and billing.

### Use my own API key

Local models, BYOK and supported provider-subscription connections require no
0sec Cloud account. Your provider handles its own authentication and billing.
Follow [provider setup](https://docs.0.security/api-keys/) for API keys, local
endpoints or ChatGPT Codex sign-in. Provider sign-in is separate from a
0sec Cloud login.

## Documentation

[docs.0.security](https://docs.0.security/) is the public documentation
home for the CLI:

- [CLI quickstart](https://docs.0.security/getting-started/) and [scan workflows](https://docs.0.security/scan-workflows/).
- [Console](https://docs.0.security/console/): interactive investigations and saved conversations.
- [Commands](https://docs.0.security/commands/), [configuration](https://docs.0.security/configuration/), and [API keys](https://docs.0.security/api-keys/).
- [Integrations and CI](https://docs.0.security/integrations/), [research workflows](https://docs.0.security/research-workflows/), and [troubleshooting](https://docs.0.security/troubleshooting/).
- [Verification](https://docs.0.security/blind-verification/): how findings are checked and where verification can stop.
- [Research](https://0.security/research/): published investigations and upstream fixes.

Docs follow the source checkout; use `0sec --version` and command-specific
`--help` when comparing an installed release with newly documented features.

**Desktop remains an unpublished development build.** Hosted inference is
deployment-gated; existing managed testing and PR review are separate services.
See the [roadmap](https://docs.0.security/roadmap/).

## Research preview

0sec is in active development. Coverage and verification depth vary by workflow;
review the evidence before treating a reported issue as confirmed. Generated fixes
need review and testing. See the [verification guide](https://docs.0.security/blind-verification/) for prerequisites and limits.

Agents can retain revision-aware codebase notes, propose source changes and
author versioned executable tools. Evaluation and version selection determine
which changes subsequent work uses. Workspace-trusted plugins require a
separate grant from ordinary self-extension.

Live harness replacement and long-running recovery have distinct implementation
and qualification limits. The [improvement-plane guide](https://docs.0.security/improvement-plane/)
records those boundaries; no universal performance gain or unattended recovery
guarantee is implied.

## Contributing

Build instructions and contribution guidelines are in [CONTRIBUTING.md](CONTRIBUTING.md).
Report security issues through [SECURITY.md](SECURITY.md).

To refresh the command reference after changing CLI registrations:

```bash
pnpm --filter '0sec-cli...' build
pnpm docs:sync
pnpm docs:check
```

The synchronizer updates usage, arguments, aliases, subcommands, and option
tables without replacing workflow or safety notes. New or removed commands
require a reviewed documentation section; CI rejects missing sections and
stale reference data. Public fork code is not executed by the PR workflow.
Changes on `main` publish automatically after the docs freshness check and build.

Keep unreleased product guides marked `draft: true`. They are available to
contributors through the docs development server but excluded from production
pages, search, and the sitemap. Remove draft status only when the product is
released and its onboarding instructions have been verified.

## License

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE).
