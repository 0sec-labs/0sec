<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/0sec-aperture-white.svg">
    <img src="assets/0sec-aperture-ink.svg" alt="0sec" width="208">
  </picture>
</p>

<h1 align="center">0sec</h1>

<p align="center">
  <strong>Open-source, evidence-first security research for authorized software.</strong>
</p>

> **One harness. Two evidence engines.** `0sec` investigates source and live
> targets; [`0verse/`](0verse/README.md) handles compiled programs without
> source. Models propose and explore. Reproducing evidence decides what is real.

0sec is built for researchers and engineering teams that need more than a model
naming a plausible bug. It combines a 48-command CLI, an agent-driven research
loop, a reproducible container toolchain, per-run evidence storage, MCP
integration, and the public 0verse binary-analysis engine.

## What ships

| Surface | Start here | Evidence boundary |
| --- | --- | --- |
| **Applications, APIs, source, and packages** | `0sec scan`, `review`, `audit`, `file-review` | Live targets require an explicit scope file; findings retain verifier output. |
| **Recon and research** | `recon`, `js-recon`, `npm-discovery`, `intel`, `hunt`, `cve`, `kernel` | Use the command-specific help and preserve the run record. |
| **Evidence and replay** | `findings`, `history`, `resume`, `replay`, `verify`, `disclose` | A report can distinguish a hypothesis from reproduced evidence. |
| **Benchmarks and evaluation** | `bench`, `eval`, `ingest`, `triage` | Measurements are tied to their configured target, model, budget, and run. |
| **Compiled programs without source** | [`0verse`](0verse/README.md): `triage`, `run`, `scan`, `fleet` | A binary finding is confirmed only by a reproducing proof of vulnerability. |
| **Agents and integrations** | `mcp-server`, `console`, `tui`, `dashboard`, `doctor` | MCP uses stdio; diagnostics expose local setup before a scan starts. |

The CLI exposes 48 commands across scanning, review, reconnaissance, research,
benchmarking, evidence handling, identity analysis, and integrations. Run
`0sec --help` for the complete current surface; each command owns its own help
and safety constraints.

## The workflow

```text
source / API / package / binary
            │
            ▼
      0sec or 0verse
            │
            ▼
hypothesis → scoped investigation → reproducing evidence → report / replay
```

- **0sec** handles source-aware and target-aware research: web applications,
  AI endpoints, codebases, packages, reconnaissance, reviews, and benchmarks.
- **0verse** is the public binary-native research engine for ELF, Mach-O, PE,
  Linux modules, and supported firmware inputs. Its loop is find → prove →
  patch → verify; its rule is **PoV-is-truth**.
- **The container image** bundles the CLI with a curated web, package, network,
  and identity-research toolchain. Run the same public engine locally, from a
  release binary, or as `ghcr.io/0sec-labs/0sec:latest`.
- **MCP and local run storage** make a run inspectable after the model stops:
  tools can integrate over stdio and each run keeps its own SQLite state,
  journal, artifacts, and final report under `~/.0sec/runs/`.

## Quick starts

### Install a verified release binary

```bash
curl -fsSL https://raw.githubusercontent.com/0sec-labs/0sec/main/install.sh | bash
0sec --help
```

The installer downloads the matching GitHub Release binary, verifies its
SHA-256 against the release manifest, and installs it to `~/.0sec/bin/0sec`.
It supports Apple Silicon macOS plus Linux x64 and arm64. Download
`0sec-windows-x64.exe` directly from the GitHub Release on Windows.

### Scan an authorized target

```bash
cat > scope.json <<'EOF'
{ "in_scope": ["example.com"] }
EOF

export OPENAI_API_KEY=...
0sec scan --target https://example.com --mode web --scope ./scope.json
```

Use a supported local, API, or CLI model route. The model can drive the
investigation, but the run's scope and evidence gates remain explicit.

### Review source or a package

```bash
0sec review ./my-app
0sec audit lodash
0sec file-review ./my-app
```

### Triage a compiled artifact with 0verse

```bash
git clone https://github.com/0sec-labs/0sec.git
cd 0sec/0verse
uv sync --frozen
uv run --frozen 0verse triage ./target-binary
```

For the complete binary pipeline, backend choices, supported formats, and
honest capability limits, read the [0verse README](0verse/README.md). Kernel
modules, IOKit, and several dynamic-execution lanes remain hypothesis-only or
parked where no reproducing oracle is available.

### Run the public container image

```bash
docker run --rm ghcr.io/0sec-labs/0sec:latest --help

docker run --rm -v "$PWD:/work" \
  ghcr.io/0sec-labs/0sec:latest \
  scan --target https://example.com --scope /work/scope.json
```

The image is the public CLI runtime. Managed control-plane services are a
separate product and are not bundled into this repository.

### Connect an MCP-capable editor or agent

```bash
0sec mcp-server
# or, after a source build:
node dist/0sec.js mcp-server
```

The server uses stdio and exposes the public 0sec boundary to an MCP-capable
client.

## Source build and development

`0sec` and `0sec-cli` are not published to npm. Do not install an unverified
package with either name.

```bash
git clone https://github.com/0sec-labs/0sec.git
cd 0sec
corepack enable
pnpm install --frozen-lockfile
pnpm build
node dist/0sec.js --help
```

For development:

```bash

pnpm lint
pnpm build
pnpm test
```

The CLI bundle embeds its build commit and rejects a stale bundle run against a
different checkout. Rebuild after changing source.

## Public boundaries

0sec publishes the source, CLI, image, tests, and reviewed 0verse export. It
does not publish managed-service infrastructure, customer data, private research
campaigns, embargoed findings, restricted third-party binaries, internal lab
topology, or unreviewed historical Git objects.

The public 0verse export is deliberately clean-history: future additions must
be individually allowlisted, scanned, and reviewed rather than copied from the
private research repository wholesale.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions must use synthetic or
authorized test material. Do not submit customer data, credentials, embargoed
findings, undisclosed exploit material, or unreviewed third-party binaries.

## Security

Report vulnerabilities in 0sec through [SECURITY.md](SECURITY.md), not through
public issues.

## License

0sec is dual-licensed under MIT OR Apache-2.0, at your option. See
[LICENSE](LICENSE) for the Apache-2.0 terms and [LICENSE-MIT](LICENSE-MIT) for
the Apache terms. Copyright 2026 0sec Labs.
