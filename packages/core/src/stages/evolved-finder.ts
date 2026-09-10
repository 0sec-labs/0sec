import { randomUUID } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readSync, realpathSync } from "node:fs";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import type { Finding } from "@0sec/shared";
import { hasKnownMarkerText } from "../disclose/known-marker.js";
import { readEvolutionArtifact } from "../improvement/artifacts.js";
import { parseEvolutionConfig } from "../improvement/config.js";
import { executeEvolutionVersion } from "../improvement/loop.js";
import { configsDir, evolutionDigest, pinEvolutionVersion } from "../improvement/registry.js";
import type { EvolutionConfig } from "../improvement/types.js";
import type { HuntFinder } from "./hunt-scan.js";

const INPUT_SCHEMA = "0sec.finder.input/v1";
const OUTPUT_SCHEMA = "0sec.finder.output/v1";
const MAX_FILE_BYTES = 1024 * 1024;
const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

interface FinderLead {
  title: string;
  severity: Finding["severity"];
  line: number;
  analysis: string;
}

function objectWithKeys(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid evolved finder object");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== keys.length || keys.some((key) => !Object.hasOwn(record, key))) {
    throw new Error("unexpected evolved finder fields");
  }
  return record;
}

function parseLeads(output: unknown, lineCount: number): FinderLead[] {
  const result = objectWithKeys(output, ["schemaVersion", "findings"]);
  if (result.schemaVersion !== OUTPUT_SCHEMA || !Array.isArray(result.findings) || result.findings.length > 100) {
    throw new Error("invalid evolved finder output protocol");
  }
  for (const value of result.findings) {
    const lead = objectWithKeys(value, ["title", "severity", "line", "analysis"]);
    if (typeof lead.title !== "string" || !lead.title.trim() || lead.title.length > 512
      || typeof lead.analysis !== "string" || !lead.analysis.trim() || lead.analysis.length > 8192
      || typeof lead.severity !== "string" || !SEVERITIES.has(lead.severity)
      || typeof lead.line !== "number" || !Number.isSafeInteger(lead.line) || lead.line < 1 || lead.line > lineCount) {
      throw new Error("invalid evolved finder lead or source location");
    }
  }
  return result.findings as FinderLead[];
}

function scopedSource(sourceRoot: string, candidatePath: string): { path: string; content: string } {
  const root = realpathSync(sourceRoot);
  const path = realpathSync(resolve(sourceRoot, candidatePath));
  const rel = relative(root, path);
  if (!rel || isAbsolute(rel) || rel === ".." || rel.startsWith(`..${sep}`)) {
    throw new Error("evolved finder candidate escapes the source scope");
  }
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_FILE_BYTES) throw new Error("evolved finder requires an unaliased source file of at most 1 MiB");
    // Recheck the opened descriptor on Linux, where the worker sandbox runs.
    if (process.platform === "linux") {
      const opened = relative(root, realpathSync(`/proc/self/fd/${fd}`));
      if (!opened || isAbsolute(opened) || opened === ".." || opened.startsWith(`..${sep}`)) {
        throw new Error("evolved finder source changed outside the scope");
      }
    }
    const bytes = Buffer.allocUnsafe(stat.size + 1);
    let size = 0;
    while (size < bytes.length) {
      const count = readSync(fd, bytes, size, bytes.length - size, size);
      if (count === 0) break;
      size += count;
    }
    if (size > stat.size) throw new Error("evolved finder source grew during the read");
    const content = bytes.toString("utf8", 0, size);
    if (Buffer.byteLength(content) > MAX_FILE_BYTES) throw new Error("evolved finder source exceeds 1 MiB");
    return { path: rel.split(sep).join("/"), content };
  } finally { closeSync(fd); }
}

/**
 * Opt-in deployment of a versioned source worker. A parent pin freezes the
 * engagement; child pins bind each distinct input to that same version. Only
 * input digests and private worker-output receipts are retained by the controller.
 * Target text goes to the isolated worker, whose output may quote that text.
 */
export async function createEvolvedFinder(requestedConfig: EvolutionConfig, runId: string): Promise<{
  versionId: string;
  readonly computeCostUsd: number;
  find: (sourceRoot: string, input: Parameters<HuntFinder>[0]) => ReturnType<HuntFinder>;
}> {
  const version = await pinEvolutionVersion(requestedConfig.storePath, runId);
  const stored = readEvolutionArtifact(join(configsDir(requestedConfig.storePath), `${version.configDigest.slice(7)}.json`));
  if (evolutionDigest(stored) !== version.configDigest) throw new Error("evolved finder config digest mismatch");
  const config = parseEvolutionConfig(stored);
  if (config.kind !== "source" || config.storePath !== requestedConfig.storePath) {
    throw new Error("evolved finder requires a source-version config in the selected store");
  }
  for (const fixture of config.cases) {
    const input = objectWithKeys(fixture.input, ["schemaVersion", "file", "lensId", "challengeHint"]);
    const file = objectWithKeys(input.file, ["path", "content"]);
    if (input.schemaVersion !== INPUT_SCHEMA || typeof file.path !== "string" || typeof file.content !== "string"
      || typeof input.lensId !== "string" || typeof input.challengeHint !== "string") {
      throw new Error("evolved finder evaluation cases must implement the source-finder v1 protocol");
    }
    parseLeads(fixture.expected, file.content.split("\n").length);
  }
  let spent = 0;
  let reserved = 0;
  return {
    versionId: version.id,
    get computeCostUsd() { return spent; },
    async find(sourceRoot, input) {
      const reserve = config.timeoutMs / 1000 * config.computeUsdPerSecond;
      if (spent + reserved + reserve > config.maxEvaluationCostUsd) throw new Error("evolved finder compute budget exhausted");
      reserved += reserve;
      const started = performance.now();
      try {
        const file = scopedSource(sourceRoot, input.candidate.path);
        const sourceLines = file.content.split(/\r?\n/);
        const payload = { schemaVersion: INPUT_SCHEMA, file, lensId: input.lens.id, challengeHint: input.challengeHint };
        const childId = `finder-${evolutionDigest({ runId, payload, attempt: input.attempt, model: input.model ?? null }).slice(7)}`;
        let leads: FinderLead[] | undefined;
        const execution = await executeEvolutionVersion(config, childId, payload, {
          parentRunId: runId,
          ...(input.signal ? { signal: input.signal } : {}),
          validateExecutionOutput(output) { leads = parseLeads(output, sourceLines.length); },
        });
        if (execution.execution.error || execution.execution.timedOut || execution.execution.exitCode !== 0 || !leads) {
          throw new Error("evolved finder execution failed; inspect its private execution receipt");
        }
        const timestamp = Date.now();
        return { findings: leads.map((lead): Finding => ({
          id: randomUUID(),
          templateId: `evolved-finder:${version.id}`,
          title: lead.title,
          description: lead.analysis,
          severity: lead.severity,
          category: "other",
          status: "discovered",
          evidence: { request: `${file.path}:${lead.line}`, response: "", analysis: lead.analysis },
          reviewAnnotation: {
            path: file.path,
            startLine: lead.line,
            ...(hasKnownMarkerText(sourceLines[lead.line - 1]!) ? { knownMarker: true } : {}),
          },
          timestamp,
        })) };
      } finally {
        reserved -= reserve;
        spent += (performance.now() - started) / 1000 * config.computeUsdPerSecond;
      }
    },
  };
}
