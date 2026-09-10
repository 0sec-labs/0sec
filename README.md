<p align="center">
  <a href="https://0.security/harness/">
    <img src="assets/readme-cover.png" alt="The open-source cybersecurity team. An ivory paper sculpture with a crimson edge." width="100%">
  </a>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/0sec-aperture-white.svg">
    <img src="assets/0sec-aperture-ink.svg" alt="0sec" width="176">
  </picture>
</p>

<p align="center">
  0sec is an open-source CLI for AI-assisted security testing and vulnerability research.<br/>
  Use it to investigate web applications, review source code, and test suspected bugs.
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

## Documentation

- [Commands](https://docs.0.security/commands/): CLI reference.
- [Configuration](https://docs.0.security/configuration/): providers, scope, and runtime settings.
- [Verification](https://docs.0.security/blind-verification/): how findings are checked and where verification can stop.
- [Research](https://0.security/research/): published investigations and upstream fixes.

## Research preview

0sec is in active development. Coverage and verification depth vary by workflow;
review the evidence before treating a reported issue as confirmed. Generated fixes
need review and testing. See the [verification guide](https://docs.0.security/blind-verification/) for prerequisites and limits.

## Contributing

Build instructions and contribution guidelines are in [CONTRIBUTING.md](CONTRIBUTING.md).
Report security issues through [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE).
