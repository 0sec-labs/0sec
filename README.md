<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/0sec-aperture-white.svg">
    <img src="assets/0sec-aperture-ink.svg" alt="0sec" width="208">
  </picture>
</p>

<p align="center">
  Open-source security research harness for authorized software.<br />
  The technical project and CLI are currently named <code>pwnkit</code>.
</p>

0sec gives researchers and engineering teams a local harness for investigating
authorized codebases and targets. It records verifier output so a finding can
be distinguished from an unproven lead.

## What it does

- Scans web applications, AI endpoints, source trees, and package ecosystems.
- Runs agent-driven investigation with scoped tools and model providers.
- Records verifier output so a finding can be distinguished from an unproven
  lead.
- Supports local research workflows for source review, package audit, kernel
  intake, and benchmark evaluation.

## Multi-model execution

pwnkit supports API, local, and CLI runtime paths. Its OpenRouter ensemble runs
selected models concurrently and selects a response with an explicit
completion, tool-use, and content heuristic. The craft workflow can run
`PWNKIT_ENSEMBLE_MODELS` trajectories in parallel and judge candidates before
continuing.

Use pwnkit only on systems and code you own or are explicitly authorized to
test. It is not a substitute for a written testing scope.

## Install from source

### Source

`pwnkit` is not published to npm yet. Do not run `npx pwnkit` or install an
unverified package with that name.

```bash
git clone https://github.com/0sec-labs/0sec.git
cd 0sec
corepack enable
pnpm install --frozen-lockfile
pnpm build
node dist/pwnkit.js --help
```

Set one supported provider credential and create an engagement scope before a
connected scan:

```bash
export OPENAI_API_KEY=...
cat > scope.json <<'EOF'
{ "in_scope": ["example.com"] }
EOF
node dist/pwnkit.js scan --target https://example.com --scope ./scope.json
```

## Common commands

```bash
# Scan an authorized web target with an engagement scope
node dist/pwnkit.js scan --target https://example.com --mode web --scope ./scope.json

# Review a local codebase
node dist/pwnkit.js review ./my-app

# Audit a package
node dist/pwnkit.js audit lodash

# Inspect available commands and configuration
node dist/pwnkit.js --help
```

Live network targets require `--scope <file>`. Run `doctor` before a new
environment and read each command's help before a connected scan.

## MCP integration

After building from source, run the bundled MCP server over stdio:

```bash
node dist/pwnkit.js mcp-server
```

Use that command from an MCP-capable agent or editor.

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

pwnkit is dual-licensed under MIT OR Apache-2.0, at your option. See
[LICENSE](LICENSE) for the Apache-2.0 terms and [LICENSE-MIT](LICENSE-MIT) for
the MIT terms. Copyright 2026 0sec Labs.
