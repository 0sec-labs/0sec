import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import type { Finding } from "@pwnkit/shared";
import type {
  ResearchCandidate,
  ResearchContext,
  ResearchEvidence,
  ResearchFinding,
  ResearchStageResult,
  ResearchTarget,
  TargetResearchAdapter,
} from "../target-research-adapter.js";

const EVIDENCE_SCHEMA = "0verse.hyperv-evidence/v1";
const SHA256 = /^[a-f0-9]{64}$/;

export interface ZeroverseHyperVObservation {
  case: "control" | "target";
  trial: number;
  build_lab_ex: string;
  status: "CLEAN" | "CRASH" | "ERROR";
  crash_signature: string;
  dump_sha256: string;
  guest_transcript_sha256: string;
  guest_transcript_path: string;
  dump_analysis_path: string;
  error: string;
}

export interface ZeroverseHyperVEvidence {
  schema_version: typeof EVIDENCE_SCHEMA;
  manifest_sha256: string;
  scope_manifest_sha256: string;
  campaign_id: string;
  scope_program: "hyperv-insider" | "hyperv-server";
  worker: string;
  status: "REPRODUCED" | "NOT_REPRODUCED" | "INCONCLUSIVE";
  crash_signature: string;
  confirmations: number;
  required_confirmations: number;
  observations: ZeroverseHyperVObservation[];
  error: string;
}

export interface WindowsHyperVTargetConfig {
  finding: Finding;
  campaignId: string;
  worker: string;
  campaignManifestSha256: string;
  scopeManifestSha256: string;
}

export type WindowsHyperVTarget = ResearchTarget<
  "windows.hyperv-prover-import",
  WindowsHyperVTargetConfig
>;

interface HyperVCandidatePayload {
  finding: Finding;
  receipt: ZeroverseHyperVEvidence;
  receiptPath: string;
}

interface ValidatedSidecar {
  content: Buffer;
  path: string;
  suffix: ".json" | ".txt";
}

export type WindowsHyperVCandidate = ResearchCandidate<HyperVCandidatePayload>;

export interface WindowsHyperVImportVerdict {
  executionOrigin: "external";
  producer: "0verse";
  schemaVersion: typeof EVIDENCE_SCHEMA;
  campaignId: string;
  buildLabEx: string;
  signature: string;
  confirmations: number;
  requiredConfirmations: number;
  cleanControls: number;
  sidecarsRehashed: number;
  passed: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function nonempty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function integer(value: unknown): value is number {
  return Number.isSafeInteger(value);
}

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function regularFile(path: string, label: string): string {
  const absolute = resolve(path);
  if (!existsSync(absolute) || !statSync(absolute).isFile()) {
    throw new Error(`${label} is not a regular file: ${path}`);
  }
  return absolute;
}

function cdbSignature(text: string): string {
  const bugcheck = /^\s*BugCheck\s+([0-9A-Fa-f]+)(?:,|\s)/m.exec(text);
  const bucket = /^\s*FAILURE_BUCKET_ID:\s*(\S.+?)\s*$/im.exec(text);
  if (!bugcheck?.[1] || !bucket?.[1]) return "";
  return `bugcheck-${bugcheck[1].toLowerCase()}:${bucket[1].trim().replace(/\s+/g, " ").toLowerCase()}`;
}

function parseObservation(value: unknown): ZeroverseHyperVObservation {
  if (!isRecord(value)
    || (value.case !== "control" && value.case !== "target")
    || !integer(value.trial) || value.trial < 1
    || !nonempty(value.build_lab_ex)
    || !["CLEAN", "CRASH", "ERROR"].includes(String(value.status))) {
    throw new Error("invalid Hyper-V observation header");
  }
  const strings = [
    "crash_signature",
    "dump_sha256",
    "guest_transcript_sha256",
    "guest_transcript_path",
    "dump_analysis_path",
    "error",
  ] as const;
  if (strings.some((key) => typeof value[key] !== "string")) {
    throw new Error("invalid Hyper-V observation evidence fields");
  }
  return value as unknown as ZeroverseHyperVObservation;
}

function parseReceipt(path: string): ZeroverseHyperVEvidence {
  const value = JSON.parse(readFileSync(regularFile(path, "Hyper-V receipt"), "utf8")) as unknown;
  if (!isRecord(value)
    || value.schema_version !== EVIDENCE_SCHEMA
    || !SHA256.test(String(value.manifest_sha256))
    || !SHA256.test(String(value.scope_manifest_sha256))
    || !nonempty(value.campaign_id)
    || (value.scope_program !== "hyperv-insider" && value.scope_program !== "hyperv-server")
    || !nonempty(value.worker)
    || !["REPRODUCED", "NOT_REPRODUCED", "INCONCLUSIVE"].includes(String(value.status))
    || !integer(value.confirmations)
    || !integer(value.required_confirmations)
    || !Array.isArray(value.observations)
    || typeof value.crash_signature !== "string"
    || typeof value.error !== "string") {
    throw new Error("invalid or unsupported 0verse Hyper-V evidence receipt");
  }
  return {
    ...value,
    observations: value.observations.map(parseObservation),
  } as unknown as ZeroverseHyperVEvidence;
}

function validateIdentity(receipt: ZeroverseHyperVEvidence, target: WindowsHyperVTarget): void {
  if (!target.buildId || receipt.observations.some((row) => row.build_lab_ex !== target.buildId)) {
    throw new Error("receipt observations do not match the target Windows BuildLabEx");
  }
  if (target.version !== receipt.scope_program
    || target.config.campaignId !== receipt.campaign_id
    || target.config.worker !== receipt.worker
    || target.config.campaignManifestSha256 !== receipt.manifest_sha256
    || target.config.scopeManifestSha256 !== receipt.scope_manifest_sha256) {
    throw new Error("receipt campaign, worker, program, or manifest identity mismatch");
  }
  if (target.configDigest && target.configDigest !== receipt.manifest_sha256) {
    throw new Error("target configDigest does not match the campaign manifest SHA-256");
  }
}

function validateSidecars(receipt: ZeroverseHyperVEvidence): ValidatedSidecar[] {
  const sidecars: ValidatedSidecar[] = [];
  for (const row of receipt.observations) {
    const transcript = regularFile(row.guest_transcript_path, "guest transcript");
    const transcriptContent = readFileSync(transcript);
    if (!SHA256.test(row.guest_transcript_sha256)
      || createHash("sha256").update(transcriptContent).digest("hex") !== row.guest_transcript_sha256) {
      throw new Error(`guest transcript hash mismatch for ${row.case} trial ${row.trial}`);
    }
    sidecars.push({ content: transcriptContent, path: transcript, suffix: ".txt" });
    if (row.status === "CRASH") {
      const analysis = regularFile(row.dump_analysis_path, "cdb analysis");
      const analysisContent = readFileSync(analysis);
      if (!SHA256.test(row.dump_sha256)
        || !nonempty(row.crash_signature)
        || cdbSignature(analysisContent.toString("utf8")) !== row.crash_signature) {
        throw new Error(`crash sidecar mismatch for ${row.case} trial ${row.trial}`);
      }
      sidecars.push({ content: analysisContent, path: analysis, suffix: ".txt" });
    } else if (row.crash_signature || row.dump_sha256 || row.dump_analysis_path) {
      throw new Error(`non-crash observation carries crash authority for ${row.case} trial ${row.trial}`);
    }
  }
  return sidecars;
}

function validateReproduced(receipt: ZeroverseHyperVEvidence): { cleanControls: number; trials: number } {
  const trials = Math.max(0, ...receipt.observations.map((row) => row.trial));
  if (trials < 2 || receipt.required_confirmations < 2
    || receipt.required_confirmations > trials
    || receipt.observations.length !== trials * 2) {
    throw new Error("Hyper-V trial matrix or confirmation threshold is invalid");
  }
  for (let trial = 1; trial <= trials; trial++) {
    const rows = receipt.observations.filter((row) => row.trial === trial);
    if (rows.length !== 2 || rows.filter((row) => row.case === "control").length !== 1
      || rows.filter((row) => row.case === "target").length !== 1) {
      throw new Error(`Hyper-V trial ${trial} is not a complete control/target pair`);
    }
  }
  const controls = receipt.observations.filter((row) => row.case === "control");
  const targets = receipt.observations.filter((row) => row.case === "target");
  const crashes = targets.filter((row) => row.status === "CRASH");
  if (receipt.status !== "REPRODUCED"
    || controls.some((row) => row.status !== "CLEAN")
    || targets.some((row) => row.status === "ERROR")
    || crashes.length !== receipt.confirmations
    || crashes.length < receipt.required_confirmations
    || !nonempty(receipt.crash_signature)
    || new Set(crashes.map((row) => row.crash_signature)).size !== 1
    || crashes.some((row) => row.crash_signature !== receipt.crash_signature)) {
    throw new Error("receipt did not clear repeated target-only Hyper-V reproduction gates");
  }
  return { cleanControls: controls.length, trials };
}

export class WindowsHyperVImportAdapter implements TargetResearchAdapter<
  WindowsHyperVTarget,
  WindowsHyperVCandidate,
  never,
  never
> {
  readonly kind = "windows.hyperv-prover-import" as const;

  async discover(target: WindowsHyperVTarget): Promise<ResearchStageResult<WindowsHyperVCandidate>> {
    try {
      const receiptPath = regularFile(target.location, "Hyper-V receipt");
      const receipt = parseReceipt(receiptPath);
      validateIdentity(receipt, target);
      validateSidecars(receipt);
      return {
        items: [{
          id: `${target.id}:0verse-receipt`,
          title: target.config.finding.title,
          location: receiptPath,
          hypothesis: "externally executed Hyper-V controls remain clean while target trials produce an identical host dump signature",
          payload: { finding: target.config.finding, receipt, receiptPath },
        }],
        evidence: [{
          stage: "discover",
          status: "passed",
          summary: `validated ${receipt.schema_version} identity and ${receipt.observations.length} observation(s)`,
        }],
      };
    } catch (error) {
      return {
        items: [],
        evidence: [{
          stage: "discover",
          status: "failed",
          summary: `0verse Hyper-V import rejected: ${error instanceof Error ? error.message : String(error)}`,
        }],
        warnings: ["0verse Hyper-V receipt failed identity, schema, or sidecar validation"],
      };
    }
  }

  async verify(
    target: WindowsHyperVTarget,
    input: { candidates: WindowsHyperVCandidate[] },
    ctx: ResearchContext,
  ): Promise<ResearchStageResult<ResearchFinding>> {
    const items: ResearchFinding[] = [];
    const evidence: ResearchEvidence[] = [];
    for (const candidate of input.candidates) {
      try {
        const snapshotRoot = join(ctx.artifactDir, "0verse-hyperv");
        mkdirSync(snapshotRoot, { recursive: true });
        const receiptPath = join(snapshotRoot, "receipt.json");
        copyFileSync(candidate.payload.receiptPath, receiptPath);
        const receipt = parseReceipt(receiptPath);
        validateIdentity(receipt, target);
        const sidecars = validateSidecars(receipt);
        const { cleanControls } = validateReproduced(receipt);
        const snapshots: string[] = [receiptPath];
        for (const [index, sidecar] of sidecars.entries()) {
          const destination = join(snapshotRoot, `sidecar-${String(index + 1).padStart(2, "0")}${sidecar.suffix}`);
          writeFileSync(destination, sidecar.content);
          if (createHash("sha256").update(sidecar.content).digest("hex") !== sha256File(destination)) {
            throw new Error("sidecar changed while it was being snapshotted");
          }
          snapshots.push(destination);
        }
        const verdict: WindowsHyperVImportVerdict = {
          executionOrigin: "external",
          producer: "0verse",
          schemaVersion: EVIDENCE_SCHEMA,
          campaignId: receipt.campaign_id,
          buildLabEx: target.buildId!,
          signature: receipt.crash_signature,
          confirmations: receipt.confirmations,
          requiredConfirmations: receipt.required_confirmations,
          cleanControls,
          sidecarsRehashed: sidecars.length,
          passed: true,
        };
        const verdictPath = join(snapshotRoot, "import-verdict.json");
        writeFileSync(verdictPath, `${JSON.stringify(verdict, null, 2)}\n`, "utf8");
        snapshots.push(verdictPath);
        const record: ResearchEvidence = {
          stage: "verify",
          status: "passed",
          summary: `re-hashed ${sidecars.length} 0verse sidecar(s); ${receipt.confirmations}/${receipt.observations.filter((row) => row.case === "target").length} target trial(s) matched and ${cleanControls} control(s) were clean`,
          data: verdict,
          artifacts: snapshots,
        };
        evidence.push(record);
        items.push({
          finding: candidate.payload.finding,
          candidateId: candidate.id,
          grade: "reproduced",
          executionContext: {
            privilege: "unknown",
            basis: "runtime-attested",
            sandbox: "hyperv-child-partition",
            campaignId: receipt.campaign_id,
            configDigest: receipt.manifest_sha256,
          },
          evidence: [record],
        });
      } catch (error) {
        evidence.push({
          stage: "verify",
          status: "inconclusive",
          summary: `0verse Hyper-V receipt was not promoted: ${error instanceof Error ? error.message : String(error)}`,
        });
      }
    }
    return { items, evidence };
  }
}
