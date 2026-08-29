import { build } from "esbuild";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync, copyFileSync } from "node:fs";
import { join, dirname } from "node:path";

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
  entryNames: "0sec",
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
    js: '#!/usr/bin/env node\nimport { createRequire as __0secCreateRequire } from "node:module";\nconst require = __0secCreateRequire(import.meta.url);',
  },
  external: [
    // node-sqlite3-wasm ships a .wasm sidecar that is resolved relative to
    // its own package dir at runtime; marking it external keeps that sidecar
    // addressable via the installed node_modules tree instead of trying to
    // inline it.
    "node-sqlite3-wasm",
    "drizzle-orm",
    "drizzle-orm/*",
    "playwright",
    "playwright-core",
    // tree-sitter and its C grammar load native .node bindings relative to
    // their installed package directories. Bundling their CommonJS loaders
    // into an ESM chunk removes __dirname and breaks even `0sec --help`.
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
    // Direct native-addon requires exist only for Bun's standalone compiler.
    // The JavaScript bundle defines that path off and leaves all `.node` imports
    // external so esbuild never expects staged release-only assets.
    "*.node",
  ],
  define: {
    // Inject the root package.json version as a string literal so the
    // bundled constants.ts picks it up without a runtime fs read. The
    // unbundled source/test path falls back to a one-time fs read of
    // the same root package.json.
    __0SEC_VERSION__: JSON.stringify(PKG_VERSION),
    // The JavaScript bundle ships tree-sitter as an external runtime dependency.
    // Only `bun --compile` stages and embeds its native addons.
    __0SEC_COMPILED_TARGET__: "undefined",
    __0SEC_BUILD_COMMIT__: JSON.stringify(BUILD_COMMIT),
  },
  plugins: [stubPlugin],
});

cpSync("packages/templates/attacks", `${outdir}/attacks`, { recursive: true });
cpSync("packages/dashboard/dist", `${outdir}/dashboard`, { recursive: true });

// Bench corpora: packages/core/src/bench/paths.ts resolves these via
// `new URL("./<file>", import.meta.url)`. The package build co-locates them
// (`cp src/bench/*.json dist/bench/`), but esbuild splits that module into
// `dist/chunks/`, so the JSON must sit next to the chunk too — otherwise
// `0sec bench run` (the nightly regression gate) fails with
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
// incl. `0sec --help`), so a missing copy is a hard boot crash, not a lazy
// failure — mirror the bench-corpus copy above into the chunk-relative `data/`
// dir. Keep in sync with the files those loaders read (whole *.json glob, same
// as the core build's copy step).
const stagesDataSrc = "packages/core/src/stages/data";
mkdirSync(`${outdir}/chunks/data`, { recursive: true });
for (const dataFile of readdirSync(stagesDataSrc).filter((f) => f.endsWith(".json"))) {
  copyFileSync(`${stagesDataSrc}/${dataFile}`, `${outdir}/chunks/data/${dataFile}`);
}

// JIT methodology skills: packages/core/src/agent/skills/index.ts walks its own
// module directory (`new URL(".", import.meta.url)`) for *.yaml and validates
// each as a skill. esbuild lands that loader in `dist/chunks/`, so the walk
// targets `dist/chunks/` — mirror the skills tree to `dist/chunks/agent/skills/`
// so `list_skills`/`load_skill` (0SEC_FEATURE_JIT_SKILLS) find every pack in the
// packaged binary, exactly as they do from source. Copy ONLY *.yaml: the loader
// validates every yaml it walks as a skill, so a stray non-skill yaml under
// chunks would hard-fail loading. There are no other yaml under dist/chunks/.
const skillsSrc = "packages/core/src/agent/skills";
let skillYamlCopied = 0;
const copySkillYaml = (relDir) => {
  const absDir = join(skillsSrc, relDir);
  for (const entry of readdirSync(absDir, { withFileTypes: true })) {
    const rel = relDir ? `${relDir}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      copySkillYaml(rel);
    } else if (entry.name.endsWith(".yaml") || entry.name.endsWith(".yml")) {
      const dest = `${outdir}/chunks/agent/skills/${rel}`;
      mkdirSync(dirname(dest), { recursive: true });
      copyFileSync(join(skillsSrc, rel), dest);
      skillYamlCopied++;
    }
  }
};
copySkillYaml("");
console.log(`Copied ${skillYamlCopied} skill YAML files → chunks/agent/skills/`);

// Fix double shebang
const bundlePath = `${outdir}/0sec.js`;
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
  bin: { "0sec": "./0sec.js", "0": "./0sec.js" },
  files: ["0sec.js", "chunks", "attacks", "dashboard"],
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

console.log(`Bundled 0sec v${rootPkg.version} → ${outdir}/`);
