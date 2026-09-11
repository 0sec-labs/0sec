import { existsSync, readFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, resolve, sep } from "node:path";
import { z } from "zod";
import { DEFAULT_IMPROVEMENT_PROMOTION_POLICY } from "../bench/improvement-promotion.js";
import type { EvolutionConfig } from "./types.js";

const relativePath = z.string().min(1).max(512).refine(
  (value) => !isAbsolute(value) && !value.includes("\\") && !value.includes("\0")
    && value !== "." && value.split("/").every((part) => part !== ".." && part !== "" && part !== "."),
  "must be a normalized relative file or directory path (not the entire workspace)",
);
const argv = z.array(z.string().max(8192).refine((value) => !value.includes("\0"))).min(1).max(128)
  .refine((value) => value[0]!.length > 0, "executable must not be empty");
const finitePositive = z.number().finite().positive();
const schema = z.object({
  schemaVersion: z.literal(1),
  sourceRoot: z.string().min(1),
  storePath: z.string().min(1),
  image: z.string().min(1).max(512).regex(/^[a-zA-Z0-9][a-zA-Z0-9_./:@-]*$/),
  backend: z.enum(["docker", "smolvm"]).optional(),
  imageArchive: z.string().min(1).max(4096).refine((value) => !value.includes("\0")).optional(),
  sourcePaths: z.array(relativePath).min(1).max(256),
  editablePaths: z.array(relativePath).min(1).max(256),
  kind: z.enum(["source", "skill", "router", "lens"]).default("source"),
  command: argv,
  buildCommand: argv.optional(),
  cases: z.array(z.object({
    id: z.string().min(1).max(128),
    lane: z.enum(["development", "held-out", "negative-control"]),
    input: z.unknown(),
    expected: z.unknown(),
  }).strict()).min(3).max(1000),
  repeats: z.number().int().min(2).max(20).default(3),
  maxIterations: z.number().int().min(1).max(100).default(3),
  maxModelTurns: z.number().int().min(1).max(64).default(12),
  maxModelCostUsd: finitePositive.max(1000).default(5),
  maxEvaluationCostUsd: finitePositive.max(1000).default(5),
  computeUsdPerSecond: finitePositive.max(10),
  timeoutMs: z.number().int().min(100).max(600_000).default(60_000),
  memoryMb: z.number().int().min(32).max(16384).default(1024),
  cpus: finitePositive.max(16).default(1),
  maxOutputBytes: z.number().int().min(256).max(16 * 1024 * 1024).default(64 * 1024),
  maxSourceBytes: z.number().int().min(1024).max(512 * 1024 * 1024).default(64 * 1024 * 1024),
  maxChangedBytes: z.number().int().min(128).max(4 * 1024 * 1024).default(256 * 1024),
  model: z.string().min(1).optional(),
  objective: z.string().min(1).max(16000),
  allowModelSourceAccess: z.boolean().default(false),
  autoPromote: z.boolean().default(false),
  canaryTrials: z.number().int().min(1).max(20).default(2),
  promotionPolicy: z.object({
    minimumCases: z.number().int().min(3).max(1000).default(DEFAULT_IMPROVEMENT_PROMOTION_POLICY.minimumCases),
    minimumDevelopmentLift: finitePositive.max(1).default(DEFAULT_IMPROVEMENT_PROMOTION_POLICY.minimumDevelopmentLift),
    minimumHeldOutLift: finitePositive.max(1).default(DEFAULT_IMPROVEMENT_PROMOTION_POLICY.minimumHeldOutLift),
    maximumNegativeControlFpDelta: z.literal(0).default(0),
    maximumCostMultiplier: finitePositive.max(10).default(DEFAULT_IMPROVEMENT_PROMOTION_POLICY.maximumCostMultiplier),
  }).strict().default({}),
  maxAlternativeParents: z.number().int().min(0).max(10).optional(),
}).strict();

/** Stable JSON comparison also refuses non-JSON input at programmatic call sites. */
export function canonicalEvolutionJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${Array.from(value, canonicalEvolutionJson).join(",")}]`;
  if (typeof value === "object" && value !== null && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalEvolutionJson((value as Record<string, unknown>)[key])}`).join(",")}}`;
  }
  throw new Error("evolution cases must contain finite JSON values only");
}

export function parseEvolutionConfig(raw: unknown, baseDir = process.cwd()): EvolutionConfig {
  const parsed = schema.parse(raw);
  if (parsed.backend === "smolvm") {
    if (!parsed.imageArchive) throw new Error("smolvm requires a local imageArchive");
    if (!Number.isInteger(parsed.cpus)) throw new Error("smolvm cpus must be an integer");
    parsed.imageArchive = resolve(baseDir, parsed.imageArchive);
  } else if (parsed.imageArchive !== undefined) {
    throw new Error("imageArchive is only valid with backend smolvm");
  }
  if (parsed.cases.length * parsed.repeats * 4 * parsed.maxOutputBytes > 64 * 1024 * 1024) {
    throw new Error("evaluation stream retention exceeds 64 MiB; reduce cases, repeats or maxOutputBytes");
  }
  const seenIds = new Set<string>();
  const inputs = new Map<string, string>();
  for (const entry of parsed.cases) {
    if (seenIds.has(entry.id)) throw new Error(`duplicate evolution case id: ${entry.id}`);
    seenIds.add(entry.id);
    const input = canonicalEvolutionJson(entry.input);
    canonicalEvolutionJson(entry.expected);
    if (inputs.has(input)) throw new Error(`duplicate evaluation input: ${entry.id}; cases and lanes must be independent`);
    inputs.set(input, entry.lane);
  }
  for (const lane of ["development", "held-out", "negative-control"] as const) {
    if (parsed.cases.filter((entry) => entry.lane === lane).length < parsed.promotionPolicy.minimumCases) {
      throw new Error(`${lane} requires at least ${parsed.promotionPolicy.minimumCases} distinct cases`);
    }
  }
  for (const edit of parsed.editablePaths) {
    if (!parsed.sourcePaths.some((source) => edit === source || edit.startsWith(`${source}/`))) {
      throw new Error(`editable path ${edit} is not inside a selected source path`);
    }
  }
  const sourceRoot = resolve(baseDir, parsed.sourceRoot === "~" ? homedir() : parsed.sourceRoot.startsWith("~/") ? resolve(homedir(), parsed.sourceRoot.slice(2)) : parsed.sourceRoot);
  const storePath = resolve(baseDir, parsed.storePath === "~" ? homedir() : parsed.storePath.startsWith("~/") ? resolve(homedir(), parsed.storePath.slice(2)) : parsed.storePath);
  if (sourceRoot === storePath) throw new Error("evolution store cannot be the source workspace");
  for (const selected of parsed.sourcePaths) {
    const source = resolve(sourceRoot, selected);
    if (storePath === source || storePath.startsWith(`${source}/`) || source.startsWith(`${storePath}/`)) {
      throw new Error("evolution store and selected source paths must not overlap");
    }
  }
  // Own the nested JSON and omit absent optional configuration keys.
  return JSON.parse(JSON.stringify({ ...parsed, sourceRoot, storePath })) as EvolutionConfig;
}

/** Load and validate an evolution configuration file, rejecting files inside source paths. */
export function loadEvolutionConfigFile(path: string): EvolutionConfig {
  const absPath = resolve(path);
  if (!existsSync(absPath)) throw new Error(`config file not found: ${absPath}`);
  const configFile = realpathSync(absPath);
  const raw = JSON.parse(readFileSync(absPath, "utf8"));
  const config = parseEvolutionConfig(raw, resolve(path, ".."));
  for (const source of config.sourcePaths) {
    const sourcePath = resolve(config.sourceRoot, source);
    const selected = existsSync(sourcePath) ? realpathSync(sourcePath) : sourcePath;
    if (configFile === selected || configFile.startsWith(`${selected}${sep}`)) {
      throw new Error("evolution config contains private answers and must be outside selected source paths");
    }
  }
  return config;
}
