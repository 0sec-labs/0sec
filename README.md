<p align="center">
  <img src="assets/pwnkit-icon.gif" alt="pwnkit" width="80" />
</p>

<h1 align="center">pwnkit</h1>

<p align="center">
  Open-source security research harness for authorized targets.
</p>

pwnkit turns frontier AI models into autonomous security researchers. Give it an
authorized codebase or target, and it investigates and validates vulnerabilities
with reproducible evidence.

## What it does

- Scans web applications, AI endpoints, source trees, and package ecosystems.
- Runs agent-driven investigation with scoped tools and model providers.
- Records verifier output so a finding can be distinguished from an unproven
  lead.
- Supports local research workflows for source review, package audit, kernel
  intake, and benchmark evaluation.

Use pwnkit only on systems and code you own or are explicitly authorized to
test. It is not a substitute for a written testing scope.

## Install from source

```bash
git clone https://github.com/0sec-labs/pwnkit.git
cd pwnkit
corepack enable
pnpm install --frozen-lockfile
pnpm build
node dist/pwnkit.js --help
```

Set one supported provider credential before a connected scan. For example:

```bash
export OPENAI_API_KEY=...
node dist/pwnkit.js scan --target https://example.com
```

## Common commands

```bash
# Scan an authorized web target
node dist/pwnkit.js scan --target https://example.com --mode web

# Review a local codebase
node dist/pwnkit.js review ./my-app

# Audit a package
node dist/pwnkit.js audit lodash

# Inspect available commands and configuration
node dist/pwnkit.js --help
```

Some commands require additional local tooling or an explicit scope file. Run
`doctor` before a new environment and read each command's help before a
connected scan.

## Development

```bash
pnpm install --frozen-lockfile
pnpm lint
pnpm build
pnpm test
```

The CLI bundle embeds its build commit and rejects a stale bundle run against a
different checkout. Rebuild after changing source.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions must use synthetic or
authorized test material. Do not submit customer data, credentials, embargoed
findings, or undisclosed exploit material.

## Security

Report vulnerabilities in pwnkit through
[SECURITY.md](SECURITY.md), not through public issues.

## License

[Apache-2.0](LICENSE). Copyright 2026 0sec Labs.
