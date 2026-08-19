import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { relative, resolve } from "node:path";
import type { Finding, RuntimeMode } from "@pwnkit/shared";
import type { ScanListener } from "../scanner.js";
import { runAnalysisAgent, type AnalysisAgentResult } from "../agent-runner.js";
import { runSelectedStaticScan } from "../shared-analysis.js";
import { kernelReviewAgentPrompt } from "../review/linux-kernel-profile.js";
import type { KernelCrashArtifact } from "./kernel-crash.js";

export interface KernelSubsystemReviewOptions {
  tree: string;
  runtime?: RuntimeMode;
  apiKey?: string;
  model?: string;
  timeout?: number;
  costCeilingUsd?: number;
  onEvent?: ScanListener;
  reviewRunner?: KernelSubsystemReviewRunner;
  fixtureFindingsPath?: string;
}

export interface KernelSubsystemReviewRunnerInput {
  artifact: KernelCrashArtifact;
  kernelTree: string;
  subsystemPath: string;
  prompt: string;
  runtime?: RuntimeMode;
  apiKey?: string;
  model?: string;
  timeout?: number;
  costCeilingUsd?: number;
  onEvent: ScanListener;
}

export type KernelSubsystemReviewRunner = (
  input: KernelSubsystemReviewRunnerInput,
) => Promise<AnalysisAgentResult | Finding[]>;

export interface KernelSubsystemReviewSkip {
  sourcePath: string;
  findingId: string;
  subsystem: string;
  reason: string;
}

export interface KernelSubsystemReviewResult {
  crashFindings: Finding[];
  reviewFindings: Finding[];
  findings: Finding[];
  skipped: KernelSubsystemReviewSkip[];
}

function truncateCrashReport(raw: string): string {
  const max = 8_000;
  if (raw.length <= max) return raw;
  return `${raw.slice(0, max)}\n... [truncated for review prompt]`;
}

function extractFaultLocation(raw: string): string {
  const match =
    raw.match(/\b(?:at|in)\s+((?:[A-Za-z0-9_.+-]+\/)*[A-Za-z0-9_.+-]+\.[chS]:\d+(?::\d+)?)/) ??
    raw.match(/((?:[A-Za-z0-9_.+-]+\/)*[A-Za-z0-9_.+-]+\.[chS]:\d+(?::\d+)?)/);
  return match?.[1] ?? "unknown";
}

function resolveSubsystemPath(kernelTree: string, subsystem: string): string | undefined {
  if (subsystem === "unknown" || subsystem.trim() === "") return undefined;

  const treeReal = realpathSync(kernelTree);
  const candidate = resolve(treeReal, subsystem);
  if (!existsSync(candidate)) return undefined;
  const candidateReal = realpathSync(candidate);
  if (candidateReal !== treeReal && !candidateReal.startsWith(`${treeReal}/`)) {
    return undefined;
  }
  try {
    if (!statSync(candidateReal).isDirectory()) return undefined;
  } catch {
    return undefined;
  }
  return candidateReal;
}

function buildCrashDirectedPrompt(
  artifact: KernelCrashArtifact,
  kernelTree: string,
  subsystemPath: string,
): string {
  const subsystemRel = relative(kernelTree, subsystemPath) || artifact.report.subsystem;
  const faultLocation = extractFaultLocation(artifact.report.rawText);
  return `A KASAN/UBSAN/oops crash just fired in this Linux kernel subsystem.

Kernel tree: ${kernelTree}
Subsystem scope: ${subsystemRel}
Crash source: ${artifact.sourcePath}
Crash finding id: ${artifact.finding.id}
Crash type: ${artifact.report.crashType}
Subsystem: ${artifact.report.subsystem}
Faulting function: ${artifact.report.faultingFunction}
Faulting location: ${faultLocation}

Here is the report:

\`\`\`
${truncateCrashReport(artifact.report.rawText)}
\`\`\`

Read the surrounding 200 lines around the faulting function/location when possible, then hunt for sibling bugs of the same shape in ${subsystemRel}. Stay inside that subsystem unless a direct caller/callee path requires brief context elsewhere in the same kernel tree.

Every review-derived finding must be a sibling bug, not a restatement of the triggering crash. Use the linux-kernel finding block format, cite file:line, and tag the same subsystem taxonomy.`;
}

function normalizeReviewFindings(
  findings: Finding[],
  artifact: KernelCrashArtifact,
  subsystem: string,
): Finding[] {
  return findings.map((finding) => ({
    ...finding,
    relatedFindingId: artifact.finding.id,
    evidence: {
      ...finding.evidence,
      analysis: [
        finding.evidence.analysis,
        `Related crash finding: ${artifact.finding.id}`,
        `Crash source: ${artifact.sourcePath}`,
        `Crash subsystem: ${subsystem}`,
      ].filter(Boolean).join("\n"),
    },
  }));
}

function loadFixtureFindings(path: string): Finding[] {
  const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
  if (Array.isArray(parsed)) return parsed as Finding[];
  if (
    parsed &&
    typeof parsed === "object" &&
    Array.isArray((parsed as { findings?: unknown }).findings)
  ) {
    return (parsed as { findings: Finding[] }).findings;
  }
  throw new Error(`Review fixture must be a Finding[] or { findings: Finding[] }: ${path}`);
}

async function defaultReviewRunner(input: KernelSubsystemReviewRunnerInput): Promise<AnalysisAgentResult> {
  const semgrepFindings = runSelectedStaticScan(input.subsystemPath, input.onEvent);
  const subsystemRel = relative(input.kernelTree, input.subsystemPath) || input.artifact.report.subsystem;
  const prompt = [
    input.prompt,
    "",
    kernelReviewAgentPrompt(input.kernelTree, semgrepFindings),
  ].join("\n\n");

  return runAnalysisAgent({
    role: "review",
    scopePath: input.kernelTree,
    target: `repo:${input.kernelTree}#${subsystemRel}`,
    scanId: `ingest-review-${input.artifact.finding.id}`,
    config: {
      runtime: input.runtime ?? "auto",
      timeout: input.timeout,
      depth: "default",
      apiKey: input.apiKey,
      model: input.model,
      costCeilingUsd: input.costCeilingUsd,
    },
    db: null,
    emit: input.onEvent,
    cliPrompt: prompt,
    agentSystemPrompt: prompt,
    cliSystemPrompt:
      "You are performing an authorized Linux kernel crash-directed source review. Only output structured ---FINDING--- blocks for sibling bugs grounded at file:line.",
  });
}

export async function reviewKernelCrashSubsystems(
  artifacts: KernelCrashArtifact[],
  opts: KernelSubsystemReviewOptions,
): Promise<KernelSubsystemReviewResult> {
  const emit = opts.onEvent ?? (() => {});
  const kernelTree = realpathSync(resolve(opts.tree));
  const crashFindings = artifacts.map((artifact) => artifact.finding);
  const reviewFindings: Finding[] = [];
  const skipped: KernelSubsystemReviewSkip[] = [];
  const runner = opts.reviewRunner ?? defaultReviewRunner;

  for (const artifact of artifacts) {
    const subsystem = artifact.report.subsystem;
    const subsystemPath = resolveSubsystemPath(kernelTree, subsystem);
    if (!subsystemPath) {
      skipped.push({
        sourcePath: artifact.sourcePath,
        findingId: artifact.finding.id,
        subsystem,
        reason: subsystem === "unknown"
          ? "crash subsystem is unknown"
          : `subsystem path not found under kernel tree: ${subsystem}`,
      });
      continue;
    }

    emit({
      type: "stage:start",
      stage: "review",
      message: `Reviewing ${subsystem} for sibling bugs from crash ${artifact.finding.id.slice(0, 8)}`,
    });

    const prompt = buildCrashDirectedPrompt(artifact, kernelTree, subsystemPath);
    const rawResult = opts.fixtureFindingsPath
      ? loadFixtureFindings(opts.fixtureFindingsPath)
      : await runner({
          artifact,
          kernelTree,
          subsystemPath,
          prompt,
          runtime: opts.runtime,
          apiKey: opts.apiKey,
          model: opts.model,
          timeout: opts.timeout,
          costCeilingUsd: opts.costCeilingUsd,
          onEvent: emit,
        });
    const findings = Array.isArray(rawResult) ? rawResult : rawResult.findings;
    reviewFindings.push(...normalizeReviewFindings(findings, artifact, subsystem));

    emit({
      type: "stage:end",
      stage: "review",
      message: `Subsystem review complete: ${findings.length} sibling finding${findings.length === 1 ? "" : "s"}`,
    });
  }

  return {
    crashFindings,
    reviewFindings,
    findings: [...crashFindings, ...reviewFindings],
    skipped,
  };
}
