#!/usr/bin/env node
/**
 * Build the npm-launcher package — replaces the previous full-bundle
 * `pwnkit-cli` that npm-published from `dist/` (and the v0.9.0 dead-end
 * shim before it).
 *
 * From v0.10.0 onwards, the npm package is a smart launcher: on first
 * run it downloads the standalone binary from the matching GitHub
 * Release for the host platform, caches it under `~/.pwnkit/cache/`,
 * and re-execs the user's args against it. Subsequent runs are an
 * instant exec from cache.
 *
 *   npx pwnkit-cli scan --target https://example.com
 *   ↓
 *   downloads pwnkit-darwin-arm64 (one-time, ~75 MB), caches, re-execs
 *   ↓
 *   full OpenTUI experience as if installed via curl install.sh | bash
 *
 * Pattern is the same one esbuild / swc / bun-itself use for shipping
 * platform-specific binaries via npm.
 *
 * Output: dist-npm/  — ready to `npm publish` from.
 */

import { mkdirSync, writeFileSync, rmSync, copyFileSync, existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const OUT = join(ROOT, "dist-npm");

// Read version from root package.json so a single bump propagates.
const rootPkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const VERSION = rootPkg.version;

// ── Clean output ────────────────────────────────────────────────────────────
if (existsSync(OUT)) rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });
mkdirSync(join(OUT, "bin"), { recursive: true });

// ── Launcher binary ─────────────────────────────────────────────────────────
//
// Read the launcher template and substitute the version constant. The
// template is a real .cjs file (not a string literal) so it can be
// linted, type-checked manually, and edited with full editor tooling.
const LAUNCHER_TEMPLATE = readFileSync(
  join(__dirname, "npm-launcher", "launcher.cjs"),
  "utf8",
);
const LAUNCHER = LAUNCHER_TEMPLATE.replace(/__PWNKIT_VERSION__/g, VERSION);
writeFileSync(join(OUT, "bin", "pwnkit-cli.cjs"), LAUNCHER, { mode: 0o755 });

// ── package.json ────────────────────────────────────────────────────────────
const pkg = {
  name: "pwnkit-cli",
  version: VERSION,
  description: "pwnkit-cli npm launcher — downloads and runs the standalone binary on first invocation.",
  bin: { "pwnkit-cli": "bin/pwnkit-cli.cjs" },
  files: ["bin", "README.md", "LICENSE"],
  homepage: "https://github.com/0sec-labs/0sec",
  repository: { type: "git", url: "git+https://github.com/0sec-labs/0sec.git" },
  bugs: { url: "https://github.com/0sec-labs/0sec/issues" },
  license: rootPkg.license ?? "Apache-2.0",
  keywords: rootPkg.keywords ?? [],
  author: rootPkg.author,
  engines: { node: ">=18" },
};
writeFileSync(join(OUT, "package.json"), JSON.stringify(pkg, null, 2) + "\n");

// ── README ──────────────────────────────────────────────────────────────────
const README = `# pwnkit-cli (npm launcher)

This package is a thin launcher for **pwnkit**, an autonomous AI pentesting
framework. From v0.10.0 onwards \`pwnkit-cli\` ships as a tiny launcher
that downloads the standalone binary on first run, caches it under
\`~/.pwnkit/cache/v<version>/\`, and re-execs the user's arguments against
it. Subsequent runs are an instant exec from the cache.

\`\`\`
$ npx pwnkit-cli scan --target https://example.com
[pwnkit] first-run setup — downloading pwnkit-darwin-arm64 (~75 MB)…
[pwnkit] cached at /Users/you/.pwnkit/cache/v0.10.0/pwnkit-darwin-arm64

  pwnkit v0.10.0
    scanning target https://example.com
…
\`\`\`

The binary has the Bun runtime baked in, so the full OpenTUI mission
control + live scan view works even when invoked under Node via npx.

## Install paths

The launcher works through any of these:

\`\`\`bash
npx pwnkit-cli scan --target https://example.com    # one-shot, no install
bunx pwnkit-cli scan --target https://example.com   # same, faster cold start

npm i -g pwnkit-cli   &&  pwnkit-cli scan ...       # global install
bun add -g pwnkit-cli &&  pwnkit-cli scan ...       # global install via bun
\`\`\`

If you'd rather skip the launcher entirely and install the binary
directly (zero Node, zero Bun, zero \`node_modules\`), run:

\`\`\`bash
curl -fsSL https://raw.githubusercontent.com/0sec-labs/0sec/main/install.sh | bash
\`\`\`

That drops a single binary into \`~/.pwnkit/bin/\`.

## Supported platforms

The launcher picks the right binary at runtime from the v\`<version>\`
GitHub Release:

- \`pwnkit-darwin-arm64\` — Apple Silicon
- \`pwnkit-linux-x64\`
- \`pwnkit-linux-arm64\`
- \`pwnkit-windows-x64.exe\`

Intel Mac (\`darwin-x64\`) is intentionally not shipped — Apple stopped
selling them in 2022 and our self-hosted macos-13 pool is unreliable.
Install Bun and compile from source (\`scripts/bun-compile.sh\`) on those.

## Env knobs

- \`PWNKIT_BINARY\` — explicit path to a binary; bypasses cache + download
- \`PWNKIT_NO_DOWNLOAD=1\` — never download; print install.sh URL and exit 1
- \`PWNKIT_DOWNLOAD_TIMEOUT_MS\` — per-attempt download timeout (default 120000)

## Source

<https://github.com/0sec-labs/0sec>
`;
writeFileSync(join(OUT, "README.md"), README);

// ── LICENSE ─────────────────────────────────────────────────────────────────
const licenseSrc = join(ROOT, "LICENSE");
if (existsSync(licenseSrc)) {
  copyFileSync(licenseSrc, join(OUT, "LICENSE"));
}

console.log(`Built npm launcher v${VERSION} → dist-npm/`);
