/**
 * Deterministic investigation brief for a crafted-PoC task.
 *
 * The craft model must not begin with an unbounded "read the repository" loop.
 * This module records the facts that can be established without a model: named
 * description anchors, available fuzz entrypoints, and an optional CPG slice
 * from the exact pre-patch tree. It intentionally makes no reachability or
 * exploitability verdict.
 */

import { execFileSync } from "node:child_process";
import { relative, resolve } from "node:path";
import {
  buildCraftCpgContext,
  extractCraftCpgTargets,
  type CraftCpgContext,
  type CraftCpgLocalization,
} from "./craft-cpg-context.js";

const MAX_FUZZER_ENTRYPOINTS = 12;
const FUZZER_ENTRY_PATTERN = "\\bLLVMFuzzerTestOneInput\\s*\\(";
const SOURCE_INCLUDES = [
  "--include=*.c",
  "--include=*.cc",
  "--include=*.cpp",
  "--include=*.cxx",
  "--include=*.h",
  "--include=*.hpp",
];

export interface CraftFuzzerEntrypoint {
  path: string;
  line: number;
  symbol: "LLVMFuzzerTestOneInput";
}

export interface CraftTargetSpecInput {
  sourceRoot: string;
  description: string;
  taskId?: string;
  cpg?: CraftCpgLocalization;
}

/**
 * Facts available before the first model call. A missing fact is named in
 * `unresolved`, rather than silently replaced with an invented interpretation.
 */
export interface CraftTargetSpec {
  taskId?: string;
  sourceRoot: string;
  descriptionAnchors: string[];
  fuzzerEntrypoints: CraftFuzzerEntrypoint[];
  cpg?: CraftCpgContext;
  unresolved: string[];
}

function toRepoRelative(sourceRoot: string, path: string): string | undefined {
  const rel = relative(sourceRoot, path);
  if (rel === "" || rel === ".." || rel.startsWith(`..${"/"}`)) return undefined;
  return rel;
}

/** Locate concrete libFuzzer entrypoints without asking a model to rediscover them. */
export function findCraftFuzzerEntrypoints(sourceRoot: string): CraftFuzzerEntrypoint[] {
  try {
    const output = execFileSync(
      "grep",
      ["-rnE", ...SOURCE_INCLUDES, FUZZER_ENTRY_PATTERN, sourceRoot],
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], maxBuffer: 1024 * 1024 },
    );
    const seen = new Set<string>();
    const entries: CraftFuzzerEntrypoint[] = [];
    for (const row of output.split("\n")) {
      const match = /^(.*):(\d+):/.exec(row);
      if (!match) continue;
      const path = toRepoRelative(sourceRoot, match[1]);
      const line = Number.parseInt(match[2], 10);
      const key = `${path}:${line}`;
      if (!path || !Number.isFinite(line) || seen.has(key)) continue;
      seen.add(key);
      entries.push({ path, line, symbol: "LLVMFuzzerTestOneInput" });
      if (entries.length >= MAX_FUZZER_ENTRYPOINTS) break;
    }
    return entries;
  } catch {
    // grep exits 1 for no matches. Absence remains explicit on the spec.
    return [];
  }
}

/** Build a model-independent target brief from the exact task tree. */
export function buildCraftTargetSpec(
  input: CraftTargetSpecInput,
  log: (message: string) => void = () => {},
): CraftTargetSpec {
  const sourceRoot = resolve(input.sourceRoot);
  const descriptionAnchors = extractCraftCpgTargets(input.description);
  const fuzzerEntrypoints = findCraftFuzzerEntrypoints(sourceRoot);
  const cpg = input.cpg
    ? buildCraftCpgContext(input.description, input.cpg, log)
    : undefined;
  const unresolved: string[] = [];
  if (descriptionAnchors.length === 0) {
    unresolved.push("description names no callable function anchor");
  }
  if (fuzzerEntrypoints.length === 0) {
    unresolved.push("no LLVMFuzzerTestOneInput entrypoint found in the source tree");
  }
  if (input.cpg && !cpg) {
    unresolved.push("configured CPG did not resolve a description anchor");
  }
  return {
    ...(input.taskId ? { taskId: input.taskId } : {}),
    sourceRoot,
    descriptionAnchors,
    fuzzerEntrypoints,
    ...(cpg ? { cpg } : {}),
    unresolved,
  };
}

/** Render only observed facts. The target spec is evidence, not an oracle verdict. */
export function renderCraftTargetSpec(spec: CraftTargetSpec): string {
  const lines = ["## Target specification (deterministic evidence, not a verdict)"];
  lines.push(
    spec.descriptionAnchors.length > 0
      ? `- Description function anchors: ${spec.descriptionAnchors.join(", ")}`
      : "- Description function anchors: none resolved",
  );
  lines.push(
    spec.fuzzerEntrypoints.length > 0
      ? `- Fuzzer entrypoints: ${spec.fuzzerEntrypoints.map((entry) => `${entry.symbol} (${entry.path}:${entry.line})`).join(", ")}`
      : "- Fuzzer entrypoints: none found",
  );
  if (spec.unresolved.length > 0) {
    lines.push(`- Unresolved: ${spec.unresolved.join("; ")}`);
  }
  if (spec.cpg) lines.push(`\n${spec.cpg.promptBlock}`);
  return lines.join("\n");
}
