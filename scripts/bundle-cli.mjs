import { build } from "esbuild";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync, copyFileSync } from "node:fs";

const outdir = "dist";

rmSync(outdir, { force: true, recursive: true });
mkdirSync(outdir, { recursive: true });

// Read the version from the root package.json once. This is the single
// source of truth for the published CLI's --version output. The version
// gets injected into the bundle via esbuild's `define` so the runtime
// constants.ts can pick it up without a runtime fs read. See
// packages/shared/src/constants.ts for the matching loader.
const rootPkg = JSON.parse(readFileSync("package.json", "utf8"));
const cliPkg = JSON.parse(readFileSync("packages/cli/package.json", "utf8"));
const PKG_VERSION = rootPkg.version;

function readBuildCommit() {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return process.env.GITHUB_SHA?.trim() ?? "";
  }
}

const BUILD_COMMIT = readBuildCommit();

// Stub out optional dev-only dependencies that Ink tries to import
const stubPlugin = {
  name: "stub-optional",
  setup(build) {
    const stubModules = ["react-devtools-core", "yoga-wasm-web"];
    const filter = new RegExp(`^(${stubModules.join("|")})$`);
    build.onResolve({ filter }, (args) => ({
      path: args.path,
      namespace: "stub",
    }));
    build.onLoad({ filter: /.*/, namespace: "stub" }, () => ({
      contents: "export default {}; export const activate = () => {};",
      loader: "js",
    }));
  },
};

await build({
  entryPoints: ["packages/cli/src/index.ts"],
  outdir,
  outExtension: { ".js": ".js" },
  entryNames: "pwnkit",
  chunkNames: "chunks/[name]-[hash]",
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node18",
  // Split dynamic imports (await import(...)) into separate chunks so
  // the opentui-based TUI loader stays unloaded on Node runtimes that
  // never call it.
  splitting: true,
  banner: {
    js: '#!/usr/bin/env node\nimport { createRequire as __pwnkitCreateRequire } from "node:module";\nconst require = __pwnkitCreateRequire(import.meta.url);',
  },
  external: [
    // node-sqlite3-wasm ships a .wasm sidecar that is resolved relative to
    // its own package dir at runtime; marking it external keeps that sidecar
    // addressable via the installed node_modules tree instead of trying to
    // inline it.
    "node-sqlite3-wasm",
    "drizzle-orm",
    "drizzle-orm/*",
    "cfonts",
    "playwright",
    "playwright-core",
    // tree-sitter and its C grammar load native .node bindings relative to
    // their installed package directories. Bundling their CommonJS loaders
    // into an ESM chunk removes __dirname and breaks even `pwnkit --help`.
    // Keep both packages intact and declare them in the published tarball.
    "tree-sitter",
    "tree-sitter-c",
    // OpenTUI's reconciler and the TUI chunks must resolve the same React
    // instance. Bundling React here while OpenTUI loads it from node_modules
    // produces the invalid-hook-call crash in the distributed Bun TUI.
    "react",
    "react/*",
    // opentui ships .wasm / tree-sitter query asset imports using the
    // `with { type: "file" }` attribute and conditionally imports `bun:ffi`.
    // esbuild can't inline either, so keep them external and ship them as
    // real runtime dependencies of the published tarball.
    "@opentui/core",
    "@opentui/react",
    "bun:ffi",
  ],
  define: {
    // Inject the root package.json version as a string literal so the
    // bundled constants.ts picks it up without a runtime fs read. The
    // unbundled source/test path falls back to a one-time fs read of
    // the same root package.json.
    __PWNKIT_VERSION__: JSON.stringify(PKG_VERSION),
    __PWNKIT_BUILD_COMMIT__: JSON.stringify(BUILD_COMMIT),
  },
  plugins: [stubPlugin],
});

cpSync("packages/templates/attacks", `${outdir}/attacks`, { recursive: true });
cpSync("packages/dashboard/dist", `${outdir}/dashboard`, { recursive: true });

// Bench corpora: packages/core/src/bench/paths.ts resolves these via
// `new URL("./<file>", import.meta.url)`. The package build co-locates them
// (`cp src/bench/*.json dist/bench/`), but esbuild splits that module into
// `dist/chunks/`, so the JSON must sit next to the chunk too — otherwise
// `pwnkit bench run` (the nightly regression gate) fails with
// `ENOENT dist/chunks/corpus-v1.json`. Keep in sync with the files paths.ts reads.
for (const benchFile of ["corpus-v1.json", "example-manifest.json"]) {
  const source = `packages/core/src/bench/${benchFile}`;
  if (existsSync(source)) {
    copyFileSync(source, `${outdir}/chunks/${benchFile}`);
  }
}

// Archetype/lens registries: packages/core/src/stages/appsec-catalog.ts (and the
// kernel/freebsd/chromium archetype-catalog loaders) resolve their bundled JSON
// via `new URL("./data/<file>.json", import.meta.url)`. The core package build
// co-locates them (`cp src/stages/data/*.json dist/stages/data/`), but esbuild
// splits those modules into `dist/chunks/`, so `import.meta.url` points at the
// chunk and the loader reads `dist/chunks/data/<file>.json`. The appsec loader
// runs at MODULE-EVAL (deep-review's `defaultFinderLenses` const → every command
// incl. `pwnkit --help`), so a missing copy is a hard boot crash, not a lazy
// failure — mirror the bench-corpus copy above into the chunk-relative `data/`
// dir. Keep in sync with the files those loaders read (whole *.json glob, same
// as the core build's copy step).
const stagesDataSrc = "packages/core/src/stages/data";
mkdirSync(`${outdir}/chunks/data`, { recursive: true });
for (const dataFile of readdirSync(stagesDataSrc).filter((f) => f.endsWith(".json"))) {
  copyFileSync(`${stagesDataSrc}/${dataFile}`, `${outdir}/chunks/data/${dataFile}`);
}

// Fix double shebang
const bundlePath = `${outdir}/pwnkit.js`;
const bundle = readFileSync(bundlePath, "utf8").replace(
  "#!/usr/bin/env node\n#!/usr/bin/env node\n",
  "#!/usr/bin/env node\n"
);
writeFileSync(bundlePath, bundle);

// Write a clean package.json for publishing (no workspace: deps).
const publishPkg = {
  name: rootPkg.name,
  version: rootPkg.version,
  type: "module",
  description: rootPkg.description,
  bin: { pwnkit: "./pwnkit.js" },
  files: ["pwnkit.js", "chunks", "attacks", "dashboard"],
  keywords: rootPkg.keywords,
  author: rootPkg.author,
  homepage: rootPkg.homepage,
  bugs: rootPkg.bugs,
  repository: rootPkg.repository,
  license: rootPkg.license,
  // Track the root engines so the published tarball never drifts from the
  // runtime we actually support (root is the source of truth: >=24.0.0).
  engines: rootPkg.engines,
  dependencies: {
    "cfonts": "^3.3.1",
    "drizzle-orm": rootPkg.dependencies["drizzle-orm"],
    "node-sqlite3-wasm": rootPkg.dependencies["node-sqlite3-wasm"],
    "tree-sitter": rootPkg.dependencies["tree-sitter"],
    "tree-sitter-c": rootPkg.dependencies["tree-sitter-c"],
    "@opentui/core": cliPkg.dependencies["@opentui/core"],
    "@opentui/react": cliPkg.dependencies["@opentui/react"],
    "react": cliPkg.dependencies.react,
  },
};
writeFileSync(`${outdir}/package.json`, JSON.stringify(publishPkg, null, 2) + "\n");
copyFileSync("scripts/dist-package-lock.json", `${outdir}/package-lock.json`);
copyFileSync("LICENSE", `${outdir}/LICENSE`);
copyFileSync("README.md", `${outdir}/README.md`);

console.log(`Bundled pwnkit v${rootPkg.version} → ${outdir}/`);
