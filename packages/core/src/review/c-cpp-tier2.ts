/**
 * 0sec Tier-2 multi-component C/C++ harness builder.
 *
 * Tier-1 (see `c-cpp-profile.ts`) wraps a single suspect function in a
 * standalone libFuzzer harness. That confirms a primitive is reachable
 * from *inside* the function. Tier-2 confirms the primitive is reachable
 * from a *real* call chain by linking the harness against the
 * transitive object subset of the host library and (optionally) feeding
 * it with corpus-derived seeds.
 *
 * This module emits the harness, the linker fragment, and the
 * compile/run commands. It deliberately does NOT compile or execute
 * anything — that is the caller's job (the agent's, the CLI's, or
 * Tier-3 QEMU validation downstream). Keeping it side-effect-free makes
 * it cheap to test, cheap to dry-run, and safe to call against an
 * untrusted source tree.
 *
 * ── Tier-3 hand-off ───────────────────────────────────────────────
 * Tier-3 (QEMU + sanitizer-instrumented full target binary) is out of
 * scope here. The hand-off contract is: Tier-3 consumes a
 * `Tier2HarnessArtifact`, runs `compile_command` inside a QEMU rootfs
 * with the requested sanitizers, executes `run_command` against the
 * extracted corpus, and reuses the kernel-crash QEMU plumbing in
 * `packages/core/src/ingest/kernel-crash.ts` for crash capture. The
 * `linked_objects` list lets Tier-3 stage only the required slice of
 * the source tree into the VM image instead of the full repository.
 */

import { readFile, readdir, stat, mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, extname, isAbsolute, join, resolve } from "node:path";
import { buildTier1Harness, type FunctionSignature } from "./c-cpp-profile.js";

export type BuildSystem = "autotools" | "cmake" | "meson" | "auto";
export type Sanitizer = "asan" | "ubsan" | "msan";

export interface Tier2HarnessOptions {
  /** Suspect function the Tier-2 harness will drive. */
  suspectFunction: FunctionSignature;
  /** Root of the C/C++ source tree under review. */
  sourceRoot: string;
  /**
   * Build system to interrogate for object subset discovery. "auto"
   * picks the first one detected in `sourceRoot` (autotools → cmake →
   * meson order).
   */
  buildSystem: BuildSystem;
  /** Sanitizers to compile with. Defaults to `["asan", "ubsan"]`. */
  sanitizers?: Sanitizer[];
  /**
   * Optional pre-extracted corpus seed file paths (typically the output
   * of `extractCorpus`). Used to populate the libFuzzer seed-corpus
   * argument. Tier-2 does not auto-generate seeds.
   */
  corpusSeeds?: string[];
  /** Where to write `harness.c`, the linker fragment, etc. */
  outputDir: string;
  /**
   * Optional explicit source file holding the suspect function. When
   * omitted, the discovery heuristic searches `sourceRoot` for a C/C++
   * source file that defines `suspectFunction.functionName`.
   */
  suspectSourceFile?: string;
}

export interface Tier2HarnessArtifact {
  /** Absolute path to the emitted harness source file. */
  harness_path: string;
  /**
   * Object/source files that should be linked into the harness. These
   * are absolute paths inside `sourceRoot`. Compilation downstream may
   * either build the `.c` files directly or substitute the matching
   * `.o` if a prior build already produced them.
   */
  linked_objects: string[];
  /** Shell command that compiles the harness. */
  compile_command: string;
  /** Shell command that runs the compiled harness. */
  run_command: string;
  /** Sanitizers actually enabled (mirror of input + defaults). */
  sanitizers_enabled: Sanitizer[];
  /** Detected build system (resolved from "auto" if applicable). */
  detected_build_system: Exclude<BuildSystem, "auto">;
  /** Absolute path to the linker-helper script. */
  linker_script_path: string;
  /** Absolute path to the Makefile fragment. */
  makefile_fragment_path: string;
}

const SOURCE_EXTENSIONS = new Set([".c", ".cc", ".cpp", ".cxx", ".cu"]);
const HEADER_EXTENSIONS = new Set([".h", ".hh", ".hpp", ".hxx"]);

/**
 * Build a Tier-2 multi-component harness for the supplied suspect
 * function.
 *
 * The function is async because object-subset discovery walks the tree
 * and grep-parses build-system files. It does not spawn any external
 * processes.
 */
export async function buildTier2Harness(
  opts: Tier2HarnessOptions,
): Promise<Tier2HarnessArtifact> {
  const sourceRoot = resolve(opts.sourceRoot);
  if (!existsSync(sourceRoot)) {
    throw new Error(`Tier-2: source root '${sourceRoot}' does not exist`);
  }
  const outputDir = resolve(opts.outputDir);
  await mkdir(outputDir, { recursive: true });

  const sanitizers = dedupeSanitizers(opts.sanitizers ?? ["asan", "ubsan"]);
  const detectedBuildSystem = await detectBuildSystem(sourceRoot, opts.buildSystem);

  const suspectSourceFile = opts.suspectSourceFile
    ? resolve(sourceRoot, opts.suspectSourceFile)
    : await locateSuspectSource(sourceRoot, opts.suspectFunction.functionName);

  const linkedObjects = await discoverObjectSubset({
    sourceRoot,
    suspectSourceFile,
    buildSystem: detectedBuildSystem,
  });

  // Emit harness source — we deliberately reuse the Tier-1 emitter so
  // the call-site shape is identical. Tier-2's value-add is the
  // *linking*, not the harness body.
  const harnessSource = decorateHarnessForTier2(
    buildTier1Harness(opts.suspectFunction),
    {
      buildSystem: detectedBuildSystem,
      linkedObjects,
      sanitizers,
    },
  );
  const harnessPath = join(outputDir, "harness.c");
  await writeFile(harnessPath, harnessSource, "utf8");

  const harnessBinary = join(outputDir, "harness");
  const sanitizerFlag = renderSanitizerFlag(sanitizers);
  const includeDirs = await collectIncludeDirs(sourceRoot, suspectSourceFile);

  const compileCommand = [
    "clang",
    "-O1",
    "-g",
    sanitizerFlag,
    "-fno-omit-frame-pointer",
    ...includeDirs.map((dir) => `-I${shellQuote(dir)}`),
    shellQuote(harnessPath),
    ...linkedObjects.map(shellQuote),
    "-o",
    shellQuote(harnessBinary),
  ].join(" ");

  const corpusArgs = (opts.corpusSeeds ?? []).map(shellQuote);
  const runCommand = [
    shellQuote(harnessBinary),
    "-runs=200000",
    "-max_total_time=300",
    "-timeout=15",
    ...corpusArgs,
  ].join(" ");

  // Emit a shell linker helper *and* a make fragment so the caller can
  // pick whichever fits their environment. Both encode the same
  // information; we just produce both because the cost is trivial.
  const linkerScriptPath = join(outputDir, "link-harness.sh");
  await writeFile(
    linkerScriptPath,
    renderLinkerShellScript({
      compileCommand,
      runCommand,
      harnessBinary,
      linkedObjects,
      sanitizers,
    }),
    { encoding: "utf8", mode: 0o755 },
  );

  const makefileFragmentPath = join(outputDir, "harness.mk");
  await writeFile(
    makefileFragmentPath,
    renderMakefileFragment({
      compileCommand,
      runCommand,
      harnessPath,
      harnessBinary,
      linkedObjects,
      sanitizers,
    }),
    "utf8",
  );

  return {
    harness_path: harnessPath,
    linked_objects: linkedObjects,
    compile_command: compileCommand,
    run_command: runCommand,
    sanitizers_enabled: sanitizers,
    detected_build_system: detectedBuildSystem,
    linker_script_path: linkerScriptPath,
    makefile_fragment_path: makefileFragmentPath,
  };
}

/**
 * Resolve the requested build system. "auto" probes the tree.
 *
 * Known gap: this only checks the top of `sourceRoot`. Nested
 * sub-projects (a top-level autotools project that vendors a CMake
 * sub-directory) will pick the *outer* system.
 */
export async function detectBuildSystem(
  sourceRoot: string,
  requested: BuildSystem,
): Promise<Exclude<BuildSystem, "auto">> {
  if (requested !== "auto") return requested;
  const candidates: Array<[Exclude<BuildSystem, "auto">, string[]]> = [
    ["autotools", ["configure.ac", "configure.in", "Makefile.am"]],
    ["cmake", ["CMakeLists.txt"]],
    ["meson", ["meson.build"]],
  ];
  for (const [name, files] of candidates) {
    for (const file of files) {
      if (existsSync(join(sourceRoot, file))) return name;
    }
  }
  // Fall back to autotools — its `.o`-in-same-dir convention is the
  // most common one for hand-written Makefiles too, so this is the
  // least surprising default for unknown trees.
  return "autotools";
}

/**
 * Heuristic object-subset discovery.
 *
 * The full call-graph problem is out of scope (would need clang AST or
 * libtooling). For v0 we approximate:
 *
 *  1. Every C/C++ source file in the same directory as the suspect
 *     source file — same-directory siblings are usually the same
 *     compilation unit family.
 *  2. Source files corresponding to any `#include "..."` directive in
 *     the suspect source file, when we can locate that header's `.c`
 *     counterpart inside `sourceRoot`.
 *  3. Build-system-specific augmentation: if `Makefile.am`,
 *     `CMakeLists.txt`, or `meson.build` mentions the suspect source
 *     file alongside other sources in the same target/library
 *     declaration, those sibling sources are pulled in too.
 *
 * Known gaps (documented for the agent that calls us):
 *  - Conditional compilation (`#ifdef FOO`) is not interpreted. We
 *    pull in everything mentioned in the build file regardless of
 *    feature flags.
 *  - System headers (`<...>`) are ignored — we only follow quoted
 *    includes.
 *  - Generated sources (e.g. lex/yacc output) declared by a generator
 *    rule but not present on disk are skipped silently.
 *  - Multi-binary trees with the same source compiled into two
 *    different libraries are over-approximated: we union sources from
 *    every target the suspect source appears in.
 */
export async function discoverObjectSubset(args: {
  sourceRoot: string;
  suspectSourceFile: string;
  buildSystem: Exclude<BuildSystem, "auto">;
}): Promise<string[]> {
  const { sourceRoot, suspectSourceFile, buildSystem } = args;
  const collected = new Set<string>();
  collected.add(resolve(suspectSourceFile));

  // 1. Same-directory siblings.
  const suspectDir = dirname(suspectSourceFile);
  try {
    for (const entry of await readdir(suspectDir, { withFileTypes: true })) {
      if (!entry.isFile()) continue;
      if (!SOURCE_EXTENSIONS.has(extname(entry.name).toLowerCase())) continue;
      collected.add(resolve(join(suspectDir, entry.name)));
    }
  } catch {
    // Suspect dir vanished mid-call — fall through with what we have.
  }

  // 2. #include "..." resolution.
  try {
    const src = await readFile(suspectSourceFile, "utf8");
    const includeRe = /^\s*#\s*include\s+"([^"]+)"/gm;
    let match: RegExpExecArray | null;
    while ((match = includeRe.exec(src)) !== null) {
      const headerRel = match[1];
      const candidate = await findSiblingSource(sourceRoot, suspectDir, headerRel);
      if (candidate) collected.add(candidate);
    }
  } catch {
    // Unreadable source file — let later stages surface the error.
  }

  // 3. Build-system augmentation.
  const buildAugment = await augmentFromBuildSystem({
    sourceRoot,
    suspectSourceFile,
    buildSystem,
  });
  for (const file of buildAugment) collected.add(file);

  return Array.from(collected).sort();
}

async function augmentFromBuildSystem(args: {
  sourceRoot: string;
  suspectSourceFile: string;
  buildSystem: Exclude<BuildSystem, "auto">;
}): Promise<string[]> {
  const { sourceRoot, suspectSourceFile, buildSystem } = args;
  const fileNames = buildSystemFileNames(buildSystem);
  const candidates: string[] = [];

  // Walk up from the suspect source file looking for build files; in
  // practice the relevant Makefile.am/CMakeLists.txt sits in or near
  // the same directory.
  const visited = new Set<string>();
  let cursor = dirname(suspectSourceFile);
  while (cursor.startsWith(sourceRoot) && !visited.has(cursor)) {
    visited.add(cursor);
    for (const name of fileNames) {
      const candidate = join(cursor, name);
      if (existsSync(candidate)) candidates.push(candidate);
    }
    const parent = dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }

  const suspectBasename = suspectSourceFile.split("/").pop() ?? "";
  const collected = new Set<string>();
  for (const buildFile of candidates) {
    const text = await readFileSafe(buildFile);
    if (!text) continue;
    if (!text.includes(suspectBasename)) continue;
    // Grep-parse: pull every token that looks like a C/C++ source
    // filename. This is intentionally crude — see the "known gaps"
    // comment on `discoverObjectSubset`.
    const sourceTokenRe = /[A-Za-z0-9_./+-]+\.(?:c|cc|cpp|cxx|cu)\b/g;
    const tokens = text.match(sourceTokenRe) ?? [];
    const buildDir = dirname(buildFile);
    for (const token of tokens) {
      const absolute = isAbsolute(token) ? token : resolve(buildDir, token);
      if (existsSync(absolute)) collected.add(absolute);
    }
  }
  return Array.from(collected);
}

function buildSystemFileNames(buildSystem: Exclude<BuildSystem, "auto">): string[] {
  switch (buildSystem) {
    case "autotools":
      return ["Makefile.am", "Makefile.in", "Makefile"];
    case "cmake":
      return ["CMakeLists.txt"];
    case "meson":
      return ["meson.build"];
  }
}

async function findSiblingSource(
  sourceRoot: string,
  suspectDir: string,
  headerRel: string,
): Promise<string | null> {
  const headerExt = extname(headerRel).toLowerCase();
  if (!HEADER_EXTENSIONS.has(headerExt)) return null;
  const stem = headerRel.slice(0, -headerExt.length);

  // Try the literal sibling first.
  for (const ext of SOURCE_EXTENSIONS) {
    const candidate = resolve(suspectDir, `${stem}${ext}`);
    if (existsSync(candidate) && candidate.startsWith(sourceRoot)) return candidate;
  }

  // Then look anywhere under sourceRoot for a matching basename.
  const basenameStem = stem.split("/").pop() ?? stem;
  const hit = await findFirstByBasename(sourceRoot, basenameStem);
  return hit;
}

async function findFirstByBasename(root: string, stem: string): Promise<string | null> {
  // Bounded BFS to avoid pathological deep trees.
  const queue: string[] = [root];
  let scanned = 0;
  while (queue.length > 0 && scanned < 2000) {
    const dir = queue.shift()!;
    scanned += 1;
    let entries: import("node:fs").Dirent[];
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.name === ".git" || entry.name === "node_modules") continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        queue.push(full);
      } else if (entry.isFile()) {
        const ext = extname(entry.name).toLowerCase();
        if (!SOURCE_EXTENSIONS.has(ext)) continue;
        const base = entry.name.slice(0, -ext.length);
        if (base === stem) return full;
      }
    }
  }
  return null;
}

async function locateSuspectSource(
  sourceRoot: string,
  functionName: string,
): Promise<string> {
  const definitionRe = new RegExp(
    `\\b${escapeRegex(functionName)}\\s*\\([^;]*\\)\\s*\\{`,
    "m",
  );
  const queue: string[] = [sourceRoot];
  while (queue.length > 0) {
    const dir = queue.shift()!;
    let entries: import("node:fs").Dirent[];
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.name === ".git" || entry.name === "node_modules") continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        queue.push(full);
      } else if (entry.isFile() && SOURCE_EXTENSIONS.has(extname(entry.name).toLowerCase())) {
        const text = await readFileSafe(full);
        if (text && definitionRe.test(text)) return full;
      }
    }
  }
  throw new Error(
    `Tier-2: could not locate a source file defining '${functionName}' under '${sourceRoot}'. Pass 'suspectSourceFile' explicitly.`,
  );
}

async function collectIncludeDirs(
  sourceRoot: string,
  suspectSourceFile: string,
): Promise<string[]> {
  // Heuristic: any directory under sourceRoot named "include" or
  // "inc", plus the directory holding the suspect source file. This is
  // enough for the conventional layouts we target (libfoo/include/...).
  const dirs = new Set<string>();
  dirs.add(dirname(suspectSourceFile));
  const queue: string[] = [sourceRoot];
  let scanned = 0;
  while (queue.length > 0 && scanned < 1000) {
    const dir = queue.shift()!;
    scanned += 1;
    let entries: import("node:fs").Dirent[];
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name === ".git" || entry.name === "node_modules") continue;
      const full = join(dir, entry.name);
      if (entry.name === "include" || entry.name === "inc") dirs.add(full);
      queue.push(full);
    }
  }
  return Array.from(dirs).sort();
}

function decorateHarnessForTier2(
  tier1Harness: string,
  context: {
    buildSystem: Exclude<BuildSystem, "auto">;
    linkedObjects: string[];
    sanitizers: Sanitizer[];
  },
): string {
  const banner = [
    "// 0sec Tier-2 multi-component harness — generated, do not edit.",
    "//",
    `// Build system detected: ${context.buildSystem}`,
    `// Sanitizers: ${context.sanitizers.join(", ")}`,
    "// Linked objects:",
    ...context.linkedObjects.map((p) => `//   - ${p}`),
    "//",
    "// Tier-2 confirms the suspect primitive is reachable from a real",
    "// call chain. Drive with the corpus seeds collected by",
    "// `extractCorpus` for best coverage.",
    "",
  ].join("\n");
  return banner + tier1Harness;
}

function renderSanitizerFlag(sanitizers: Sanitizer[]): string {
  const mapped: string[] = sanitizers.map((s) => {
    if (s === "asan") return "address";
    if (s === "ubsan") return "undefined";
    return "memory";
  });
  // libFuzzer is always added — Tier-2 is libFuzzer-driven.
  mapped.push("fuzzer");
  return `-fsanitize=${dedupe(mapped).join(",")}`;
}

function renderLinkerShellScript(args: {
  compileCommand: string;
  runCommand: string;
  harnessBinary: string;
  linkedObjects: string[];
  sanitizers: Sanitizer[];
}): string {
  return `#!/usr/bin/env bash
# 0sec Tier-2 linker helper — generated.
#
# Sanitizers: ${args.sanitizers.join(", ")}
# Output binary: ${args.harnessBinary}
#
# This script just runs the canonical compile command. Use it as a
# starting point; production builds may want to integrate the linker
# step into the host project's own build system instead.
set -euo pipefail

${args.compileCommand}

echo "[0sec tier-2] harness built: ${args.harnessBinary}"
echo "[0sec tier-2] to run:  ${args.runCommand}"
`;
}

function renderMakefileFragment(args: {
  compileCommand: string;
  runCommand: string;
  harnessPath: string;
  harnessBinary: string;
  linkedObjects: string[];
  sanitizers: Sanitizer[];
}): string {
  // We emit a single explicit recipe rather than trying to mimic the
  // host project's own rules. This is intentional — see the module
  // doc comment.
  const deps = [args.harnessPath, ...args.linkedObjects]
    .map((p) => p.replace(/ /g, "\\ "))
    .join(" \\\n  ");
  return `# 0sec Tier-2 harness Makefile fragment — generated.
# Sanitizers: ${args.sanitizers.join(", ")}

OSEC_TIER2_HARNESS := ${args.harnessBinary}
0SEC_TIER2_DEPS := \\
  ${deps}

$(OSEC_TIER2_HARNESS): $(0SEC_TIER2_DEPS)
\t${args.compileCommand}

.PHONY: 0sec-tier2-run
0sec-tier2-run: $(OSEC_TIER2_HARNESS)
\t${args.runCommand}
`;
}

async function readFileSafe(path: string): Promise<string | null> {
  try {
    const st = await stat(path);
    if (!st.isFile()) return null;
    return await readFile(path, "utf8");
  } catch {
    return null;
  }
}

function dedupe<T>(values: T[]): T[] {
  return Array.from(new Set(values));
}

function dedupeSanitizers(values: Sanitizer[]): Sanitizer[] {
  // msan and asan are mutually exclusive in libFuzzer toolchains. If
  // both are requested, drop msan with a deterministic preference.
  const seen = new Set<Sanitizer>();
  const out: Sanitizer[] = [];
  for (const v of values) {
    if (seen.has(v)) continue;
    if (v === "msan" && seen.has("asan")) continue;
    if (v === "asan" && seen.has("msan")) {
      // Replace msan with asan.
      const idx = out.indexOf("msan");
      if (idx >= 0) out.splice(idx, 1);
      seen.delete("msan");
    }
    seen.add(v);
    out.push(v);
  }
  if (out.length === 0) out.push("asan", "ubsan");
  return out;
}

function shellQuote(value: string): string {
  if (/^[A-Za-z0-9_./:=+-]+$/.test(value)) return value;
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
