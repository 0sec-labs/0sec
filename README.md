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

## Get started

```bash
curl -fsSL https://raw.githubusercontent.com/0sec-labs/0sec/main/install.sh | bash
export PATH="$HOME/.0sec/bin:$PATH"
0
```

Add the `export` line to your shell profile. Run `0` to open the interactive
console, or `0 --help` for commands. Only test systems you own or have permission to assess.

### Choose a model connection

- **0sec Cloud:** optional hosted models, still deployment-gated and not production-qualified.
  Login alone does not fund an account or grant model access.
  Managed testing and CI review have separate access and billing.
- **Your own provider:** use an API key, local model or supported provider subscription.
  No 0sec Cloud account is required; your provider handles authentication and billing.
  See [provider setup](https://docs.0.security/api-keys/).

## Documentation

- [Getting started](https://docs.0.security/getting-started/): installation, source builds and your first scan.
- [Console](https://docs.0.security/console/) and [scan workflows](https://docs.0.security/scan-workflows/): interactive and command-line use.
- [Commands](https://docs.0.security/commands/) and [configuration](https://docs.0.security/configuration/): reference.
- [Integrations and CI](https://docs.0.security/integrations/) · [Troubleshooting](https://docs.0.security/troubleshooting/).

Docs follow the source checkout; use `0sec --version` and command-specific
`--help` when comparing an installed release with newly documented features.

## Research preview

Coverage and verification depth vary by workflow. Review the evidence before
treating an issue as confirmed; generated fixes need review and testing.
See [verification](https://docs.0.security/blind-verification/) for limits and prerequisites.

Agent learning, source evolution and executable plugins are also research-preview
workflows. See the [improvement-plane guide](https://docs.0.security/improvement-plane/).

## Contributing

Build instructions and contribution guidelines are in [CONTRIBUTING.md](CONTRIBUTING.md).
Report security issues through [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE).
