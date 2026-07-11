import { createHash, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type {
  ResearchCandidate,
  ResearchContext,
  ResearchEvidence,
  ResearchFinding,
  ResearchHandoff,
  ResearchRunResult,
  ResearchStage,
  ResearchStageResult,
  ResearchTarget,
  TargetResearchAdapter,
} from "./target-research-adapter.js";
import type { ResearchEvidenceEnvelope } from "@pwnkit/shared";
import type { Finding } from "@pwnkit/shared";
import { checkResearchNovelty, type ResearchNoveltyProvider } from "./novelty-provider.js";

export interface RunResearchOptions<T = unknown> {
  runId?: string;
  artifactRoot?: string;
  signal?: AbortSignal;
  log?: (message: string) => void;
  /** Persist the compact evidence-envelope array under the run artifact dir. Default true. */
  persistEnvelopes?: boolean;
  /** Optional ecosystem novelty feeds applied after the adapter's native novelty gate. */
  noveltyProviders?: ResearchNoveltyProvider<T>[];
  /** Optional sink invoked only after the run's evidence envelope is attached. */
  emitFinding?: (finding: Finding) => Promise<void>;
}

function skipped(stage: ResearchStage, summary: string): ResearchEvidence {
  return { stage, status: "skipped", summary };
}

function append<T>(result: ResearchStageResult<T>, evidence: ResearchEvidence[], warnings: string[]): T[] {
  evidence.push(...(result.evidence ?? []));
  warnings.push(...(result.warnings ?? []));
  return result.items;
}

function artifactReceipts(item: ResearchFinding) {
  return [...new Set(item.evidence.flatMap((record) => record.artifacts ?? []))]
    .filter((path) => existsSync(path) && statSync(path).isFile())
    .map((path) => {
      const contents = readFileSync(path);
      return {
        kind: "research-artifact",
        path,
        sha256: createHash("sha256").update(contents).digest("hex"),
        bytes: contents.byteLength,
      };
    });
}

/** Execute the common monotone research lifecycle while preserving native adapter payloads. */
export async function runResearch<
  T extends ResearchTarget,
  C extends ResearchCandidate,
  H,
  X,
>(
  adapter: TargetResearchAdapter<T, C, H, X>,
  target: T,
  opts: RunResearchOptions<T> = {},
): Promise<ResearchRunResult<C>> {
  if (adapter.kind !== target.kind) {
    throw new Error(`research adapter kind ${adapter.kind} cannot run target kind ${target.kind}`);
  }
  const runId = opts.runId ?? randomUUID();
  const startedAt = new Date().toISOString();
  const artifactDir = join(opts.artifactRoot ?? ".pwnkit-research", runId);
  mkdirSync(artifactDir, { recursive: true });
  const ctx: ResearchContext = {
    runId,
    artifactDir,
    ...(opts.signal ? { signal: opts.signal } : {}),
    log: opts.log ?? (() => {}),
  };
  const evidence: ResearchEvidence[] = [];
  const warnings: string[] = [];
  let candidates: C[] = [];
  let findings: ResearchFinding[] = [];
  let handoffs: ResearchHandoff[] = [];

  try {
    candidates = append(await adapter.discover(target, ctx), evidence, warnings);
    if (adapter.assessReachability) {
      candidates = append(await adapter.assessReachability(target, candidates, ctx), evidence, warnings);
    } else {
      evidence.push(skipped("reachability", "adapter does not implement reachability assessment"));
    }
    if (adapter.deriveTargets) {
      handoffs = append(await adapter.deriveTargets(target, candidates, ctx), evidence, warnings);
    } else {
      evidence.push(skipped("handoff", "adapter does not derive downstream targets"));
    }

    let harnesses: H[] | undefined;
    if (adapter.buildHarness) {
      harnesses = append(await adapter.buildHarness(target, candidates, ctx), evidence, warnings);
    } else {
      evidence.push(skipped("harness", "adapter does not implement a separate harness stage"));
    }

    let executions: X[] | undefined;
    if (adapter.execute) {
      executions = append(await adapter.execute(target, harnesses ?? [], ctx), evidence, warnings);
    } else {
      evidence.push(skipped("execute", "adapter executes inside verification or has no execution stage"));
    }

    findings = append(
      await adapter.verify(target, { candidates, ...(harnesses ? { harnesses } : {}), ...(executions ? { executions } : {}) }, ctx),
      evidence,
      warnings,
    );

    if (adapter.checkNovelty) {
      findings = append(await adapter.checkNovelty(target, findings, ctx), evidence, warnings);
    } else {
      evidence.push(skipped("novelty", "adapter does not implement novelty checking"));
    }
    if (opts.noveltyProviders && opts.noveltyProviders.length > 0) {
      const checked: ResearchFinding[] = [];
      for (const item of findings) {
        const novelty = await checkResearchNovelty(item.finding, target, opts.noveltyProviders);
        evidence.push({
          stage: "novelty",
          status: novelty.receipt.state === "novel"
            ? "passed"
            : novelty.receipt.state === "duplicate"
              ? "failed"
              : "inconclusive",
          summary: `ecosystem novelty result: ${novelty.receipt.state} (${novelty.receipt.scanned ?? 0} record(s) checked)`,
          data: novelty,
        });
        if (novelty.receipt.state === "duplicate") continue;
        checked.push({ ...item, novelty: novelty.receipt });
      }
      findings = checked;
    }
    if (adapter.assessImpact) {
      findings = append(await adapter.assessImpact(target, findings, ctx), evidence, warnings);
    } else {
      evidence.push(skipped("impact", "adapter does not implement impact assessment"));
    }
    const completedAt = new Date().toISOString();
    for (const item of findings) {
      if (!item.evidence.some((record) => record.stage === "verify" && record.status === "passed")) {
        if (item.grade && item.grade !== "candidate") {
          warnings.push(`finding ${item.finding.id} was downgraded to candidate: no passed verification evidence`);
        }
        item.grade = "candidate";
      }
    }
    const envelopes: ResearchEvidenceEnvelope[] = findings.map((item) => ({
      schemaVersion: 1,
      evidenceId: randomUUID(),
      findingId: item.finding.id,
      target: {
        kind: target.kind,
        locator: target.location,
        ...(target.version ? { version: target.version } : {}),
        ...(target.buildId ? { buildId: target.buildId } : {}),
        ...(target.configDigest ? { configDigest: target.configDigest } : {}),
      },
      provenance: {
        producer: adapter.kind,
        runId,
        startedAt,
        completedAt,
        candidateId: item.candidateId,
      },
      grade: item.grade ?? "observed",
      novelty: item.novelty ?? { state: "unchecked" },
      ...(item.executionContext ? { executionContext: item.executionContext } : {}),
      artifacts: artifactReceipts(item),
      native: { oracleKind: adapter.kind, oraclePayload: item.evidence },
    }));
    for (let i = 0; i < findings.length; i++) {
      const envelope = envelopes[i];
      if (!envelope) continue;
      const finding = findings[i].finding;
      finding.researchEvidence = [...(finding.researchEvidence ?? []), envelope];
    }
    if (opts.emitFinding) {
      for (const item of findings) {
        try {
          await opts.emitFinding(item.finding);
        } catch (error) {
          warnings.push(`finding sink failed: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
    }
    let envelopePath: string | undefined;
    if (opts.persistEnvelopes !== false) {
      envelopePath = join(artifactDir, "evidence-envelopes.json");
      const seen = new WeakSet<object>();
      writeFileSync(envelopePath, JSON.stringify(envelopes, (_key, value: unknown) => {
        if (typeof value === "bigint") return value.toString();
        if (typeof value === "function") return undefined;
        if (value && typeof value === "object") {
          if (seen.has(value as object)) return "[circular]";
          seen.add(value as object);
        }
        return value;
      }, 2) + "\n", "utf8");
    }
    return { runId, target, candidates, findings, handoffs, envelopes, ...(envelopePath ? { envelopePath } : {}), evidence, warnings, completed: true };
  } finally {
    await adapter.dispose?.(ctx);
  }
}
