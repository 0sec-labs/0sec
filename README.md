<p align="center">
  <a href="https://0.security/harness/">
    <img src="assets/readme-cover.png" alt="Your self-improving cybersecurity team. An ivory paper sculpture with a crimson edge." width="100%">
  </a>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/0sec-aperture-white.svg">
    <img src="assets/0sec-aperture-ink.svg" alt="0sec" width="176">
  </picture>
</p>

<p align="center">
  The extensible, multi-model, unified cybersecurity harness.
</p>

<p align="center">
  <sub>🇨🇭 Maintained by the Swiss Applied AI & Cybersecurity Research Lab · <a href="https://0.security">0.security</a></sub>
</p>

<p align="center">
  <a href="https://docs.0.security/"><img src="https://img.shields.io/badge/Documentation-DC2626?style=for-the-badge&amp;logo=gitbook&amp;logoColor=white" alt="Documentation" height="28"></a>
  <a href="https://0.security/harness/"><img src="https://img.shields.io/badge/Website-1A1815?style=for-the-badge" alt="Website" height="28"></a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-1A1815?style=flat-square&amp;labelColor=1A1815" alt="License: MIT OR Apache-2.0"></a>
  <a href="https://github.com/0sec-labs/0sec/releases/latest"><img src="https://img.shields.io/github/v/release/0sec-labs/0sec?style=flat-square&amp;labelColor=1A1815&amp;color=1A1815" alt="Latest release"></a>
  <a href="#research-preview"><img src="https://img.shields.io/badge/status-research%20preview-DC2626?style=flat-square&amp;labelColor=1A1815" alt="Status: research preview"></a>
</p>

<p align="center">
  <img src="assets/demo-intro.gif" alt="0sec interactive CLI demonstration" width="840">
</p>

## Get started

```bash
curl -fsSL https://raw.githubusercontent.com/0sec-labs/0sec/main/install.sh | bash
export PATH="$HOME/.0sec/bin:$PATH"
0 --help
```

Add the `export` line to your shell profile. Configure a [model provider](https://docs.0.security/api-keys/),
then run `0` to open the interactive console. Use `/run` to set up an engagement.
Only test systems you own or have permission to assess.

See [Getting started](https://docs.0.security/getting-started/) for Docker,
source builds, and your first scan.

### Hosted models

This source checkout adds optional hosted inference through a 0sec account.
It requires a deployment with hosted models enabled; it does not indicate
that production access or a compatible CLI release is available.

```bash
0sec login
0sec models
0sec balance
```

Login uses the existing browser approval flow. An organization owner or admin
funds model credits in the console. Provider keys stay on the service, while
CLI tools run locally. Configured BYOK providers retain precedence over
automatic hosted selection. An explicitly selected hosted model must appear
in the service catalogue; the CLI does not silently substitute another model.
Review subscriptions and managed testing are billed separately.

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

**0cloud and Desktop are not released.** Both are in development; their draft
guides are not published as user documentation. See the [roadmap](https://docs.0.security/roadmap/).

## Research preview

0sec is in active development. Coverage and verification depth vary by workflow;
review the evidence before treating a reported issue as confirmed. Generated fixes
need review and testing. See the [verification guide](https://docs.0.security/blind-verification/) for prerequisites and limits.

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
