import { copyFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import type { Finding } from "@pwnkit/shared";
import type { ResearchCandidate, ResearchContext, ResearchEvidence, ResearchFinding, ResearchStageResult, ResearchTarget, TargetResearchAdapter } from "../target-research-adapter.js";

export interface ExternalBootLog { id: string; logPath: string; bootMarker: string }
export interface ExternalKernelSide {
  buildId: string;
  version?: string;
  configDigest?: string;
  boots: ExternalBootLog[];
}
export interface ExternalKernelBootMatrixManifest {
  schemaVersion: 1;
  executedBy: string;
  expectedSignature: string;
  completionMarker: string;
  minVulnerableHits: number;
  minCleanControls: number;
  vulnerable: ExternalKernelSide;
  patched: ExternalKernelSide;
}
export interface LinuxBootMatrixTargetConfig { finding: Finding }
export type LinuxBootMatrixTarget = ResearchTarget<"linux.kernel-boot-matrix-import", LinuxBootMatrixTargetConfig>;
interface MatrixPayload { finding: Finding; manifest: ExternalKernelBootMatrixManifest; manifestPath: string }
export type LinuxBootMatrixCandidate = ResearchCandidate<MatrixPayload>;
export interface BootMatrixObservation {
  side: "vulnerable" | "patched";
  id: string;
  sourcePath: string;
  snapshotPath: string;
  completed: boolean;
  identityMatched: boolean;
  signatureMatched: boolean;
}
export interface BootMatrixVerdict {
  executionOrigin: "external";
  executedBy: string;
  observations: BootMatrixObservation[];
  vulnerableHits: number;
  cleanControls: number;
  passed: boolean;
}

function nonempty(value: unknown): value is string { return typeof value === "string" && value.trim().length > 0; }

function parseManifest(path: string): ExternalKernelBootMatrixManifest {
  const value = JSON.parse(readFileSync(path, "utf8")) as Partial<ExternalKernelBootMatrixManifest>;
  const sides = [value.vulnerable, value.patched];
  if (value.schemaVersion !== 1 || !nonempty(value.executedBy) || !nonempty(value.expectedSignature)
    || !nonempty(value.completionMarker) || !sides.every((side) => side && nonempty(side.buildId) && Array.isArray(side.boots))) {
    throw new Error("invalid boot-matrix manifest header or side identity");
  }
  if (value.expectedSignature === value.completionMarker) throw new Error("signature and completion oracles must be distinct");
  const allBoots = [...value.vulnerable!.boots, ...value.patched!.boots];
  if (allBoots.some((boot) => !nonempty(boot.id) || !nonempty(boot.logPath) || !nonempty(boot.bootMarker))) {
    throw new Error("every boot requires non-empty id, logPath, and bootMarker");
  }
  if (new Set(allBoots.map((boot) => boot.id)).size !== allBoots.length
    || new Set(allBoots.map((boot) => boot.bootMarker)).size !== allBoots.length) {
    throw new Error("boot ids and markers must be globally unique");
  }
  if (allBoots.some((boot) => boot.bootMarker === value.expectedSignature || boot.bootMarker === value.completionMarker)) {
    throw new Error("boot identity markers must be distinct from global oracles");
  }
  if (!Number.isInteger(value.minVulnerableHits) || value.minVulnerableHits! < 1
    || value.minVulnerableHits! > value.vulnerable!.boots.length
    || !Number.isInteger(value.minCleanControls) || value.minCleanControls! < 1
    || value.minCleanControls! > value.patched!.boots.length) {
    throw new Error("boot-matrix thresholds are invalid or unattainable");
  }
  return value as ExternalKernelBootMatrixManifest;
}

export class LinuxBootMatrixImportAdapter implements TargetResearchAdapter<LinuxBootMatrixTarget, LinuxBootMatrixCandidate, never, never> {
  readonly kind = "linux.kernel-boot-matrix-import" as const;

  async discover(target: LinuxBootMatrixTarget): Promise<ResearchStageResult<LinuxBootMatrixCandidate>> {
    try {
      const manifestPath = resolve(target.location);
      if (!existsSync(manifestPath) || !statSync(manifestPath).isFile()) throw new Error("manifest is not a regular file");
      const manifest = parseManifest(manifestPath);
      const base = dirname(manifestPath);
      for (const boot of [...manifest.vulnerable.boots, ...manifest.patched.boots]) {
        const path = resolve(base, boot.logPath);
        if (!existsSync(path) || !statSync(path).isFile()) throw new Error(`boot log is not a regular file: ${boot.logPath}`);
      }
      return {
        items: [{ id: `${target.id}:matrix`, title: target.config.finding.title, hypothesis: "externally declared vulnerable boots reproduce while patched controls remain clean", payload: { finding: target.config.finding, manifest, manifestPath } }],
        evidence: [{ stage: "discover", status: "passed", summary: `validated external matrix manifest with ${manifest.vulnerable.boots.length + manifest.patched.boots.length} distinct boot declaration(s)` }],
      };
    } catch (error) {
      return { items: [], evidence: [{ stage: "discover", status: "failed", summary: `boot-matrix import rejected: ${error instanceof Error ? error.message : String(error)}` }], warnings: ["external boot-matrix manifest failed validation"] };
    }
  }

  async verify(_target: LinuxBootMatrixTarget, input: { candidates: LinuxBootMatrixCandidate[] }, ctx: ResearchContext): Promise<ResearchStageResult<ResearchFinding>> {
    const items: ResearchFinding[] = [];
    const evidence: ResearchEvidence[] = [];
    for (const candidate of input.candidates) {
      const { manifest, manifestPath } = candidate.payload;
      const snapshotRoot = join(ctx.artifactDir, "external-boot-matrix");
      mkdirSync(join(snapshotRoot, "vulnerable"), { recursive: true });
      mkdirSync(join(snapshotRoot, "patched"), { recursive: true });
      const manifestSnapshot = join(snapshotRoot, "manifest.json");
      const observations: BootMatrixObservation[] = [];
      copyFileSync(manifestPath, manifestSnapshot);
      for (const side of ["vulnerable", "patched"] as const) {
        for (const boot of manifest[side].boots) {
          const sourcePath = resolve(dirname(manifestPath), boot.logPath);
          const snapshotPath = join(snapshotRoot, side, `${boot.id}.log`);
          copyFileSync(sourcePath, snapshotPath);
          const text = readFileSync(snapshotPath, "utf8");
          observations.push({ side, id: boot.id, sourcePath, snapshotPath, completed: text.includes(manifest.completionMarker), identityMatched: text.includes(boot.bootMarker), signatureMatched: text.includes(manifest.expectedSignature) });
        }
      }
      const vulnerable = observations.filter((boot) => boot.side === "vulnerable");
      const patched = observations.filter((boot) => boot.side === "patched");
      const vulnerableHits = vulnerable.filter((boot) => boot.signatureMatched).length;
      const cleanControls = patched.filter((boot) => !boot.signatureMatched).length;
      const contradiction = patched.some((boot) => boot.signatureMatched);
      const identitiesValid = observations.every((boot) => boot.identityMatched);
      const controlsComplete = patched.every((boot) => boot.completed);
      // A positive sanitizer signature is a terminal vulnerable-side oracle;
      // it need not reach a graceful harness shutdown. Non-hit boots remain
      // recorded as incomplete but do not defeat an explicit M-of-K threshold.
      const passed = identitiesValid && controlsComplete && !contradiction
        && vulnerableHits >= manifest.minVulnerableHits && cleanControls >= manifest.minCleanControls;
      const verdict: BootMatrixVerdict = { executionOrigin: "external", executedBy: manifest.executedBy, observations, vulnerableHits, cleanControls, passed };
      const verdictPath = join(snapshotRoot, "matrix-verdict.json");
      writeFileSync(verdictPath, JSON.stringify(verdict, null, 2) + "\n");
      const artifacts = [manifestSnapshot, ...observations.map((boot) => boot.snapshotPath), verdictPath];
      evidence.push({ stage: "verify", status: contradiction ? "failed" : passed ? "passed" : "inconclusive", summary: passed ? `imported external differential passed: ${vulnerableHits}/${vulnerable.length} vulnerable hit(s), no target signature in ${cleanControls}/${patched.length} tested patched controls` : "imported external boot matrix did not clear identity, completion, signature, and clean-control gates", data: verdict, artifacts });
      if (passed) items.push({ finding: candidate.payload.finding, candidateId: candidate.id, grade: "reproduced", evidence: [{ stage: "verify", status: "passed", summary: "pwnkit validated and hashed externally executed logs; pwnkit did not execute these boots", data: verdict, artifacts }] });
    }
    return { items, evidence };
  }
}
