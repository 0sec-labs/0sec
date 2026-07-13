import { createHash } from "node:crypto";
import {
  closeSync,
  copyFileSync,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { constants as fsConstants } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
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
const RUN_NONCE = /^[A-Za-z0-9_-]{32,128}$/;

export interface ZeroverseHyperVObservation {
  case: "control" | "target";
  trial: number;
  build_lab_ex: string;
  status: "CLEAN" | "CRASH" | "ERROR";
  crash_signature: string;
  dump_sha256: string;
  dump_identity: string;
  dump_artifact_path: string;
  guest_transcript_sha256: string;
  guest_transcript_path: string;
  dump_analysis_path: string;
  dump_analysis_sha256: string;
  run_nonce: string;
  argv_sha256: string;
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
  claim_eligible: boolean;
  fixture_kind?: string;
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
  field: "guest_transcript_path" | "dump_analysis_path";
  observationIndex: number;
  suffix: ".json" | ".txt";
}

interface ValidatedBundle {
  sidecars: ValidatedSidecar[];
  dumps: Array<{ source: string; sha256: string; observationIndex: number }>;
}

export type WindowsHyperVCandidate = ResearchCandidate<HyperVCandidatePayload>;

export interface WindowsHyperVImportVerdict {
  verdictSchema: "pwnkit.windows-hyperv-import-verdict/v1";
  executionOrigin: "external";
  producer: "0verse";
  schemaVersion: typeof EVIDENCE_SCHEMA;
  campaignId: string;
  buildLabEx: string;
  signature: string;
  confirmations: number;
  requiredConfirmations: number;
  cleanControls: number;
  distinctDumpArtifacts: number;
  dumpHashBasis: "retained-bundle-bytes";
  receiptSha256: string;
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

function hashOpenedFile(path: string, maximumBytes = 8 * 1024 * 1024 * 1024): { sha256: string; bytes: number } {
  const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.size > maximumBytes) throw new Error(`evidence file has invalid size: ${path}`);
    const hash = createHash("sha256");
    const chunk = Buffer.allocUnsafe(1024 * 1024);
    let bytes = 0;
    for (;;) {
      const count = readSync(descriptor, chunk, 0, chunk.length, null);
      if (count === 0) break;
      bytes += count;
      hash.update(chunk.subarray(0, count));
    }
    return { sha256: hash.digest("hex"), bytes };
  } finally {
    closeSync(descriptor);
  }
}

function readOpenedFile(path: string, maximumBytes = 16 * 1024 * 1024): Buffer {
  const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.size > maximumBytes) throw new Error(`evidence sidecar has invalid size: ${path}`);
    return readFileSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function hasWindowsCrashDumpHeader(path: string): boolean {
  const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const header = Buffer.alloc(8);
    return readSync(descriptor, header, 0, header.length, 0) === header.length
      && (header.equals(Buffer.from("PAGEDUMP")) || header.equals(Buffer.from("PAGEDU64")));
  } finally {
    closeSync(descriptor);
  }
}

function regularFile(path: string, label: string, base?: string): string {
  if (base && isAbsolute(path)) {
    throw new Error(`${label} must use a receipt-relative bundle path`);
  }
  const absolute = base ? resolve(base, path) : resolve(path);
  if (base) {
    const escaped = relative(resolve(base), absolute);
    if (escaped === ".." || escaped.startsWith(`..${sep}`) || isAbsolute(escaped)) {
      throw new Error(`${label} escapes the Hyper-V evidence bundle: ${path}`);
    }
  }
  if (!existsSync(absolute) || !lstatSync(absolute).isFile() || !statSync(absolute).isFile()) {
    throw new Error(`${label} is not a regular file: ${path}`);
  }
  const real = realpathSync(absolute);
  if (base) {
    const escaped = relative(realpathSync(base), real);
    if (escaped === ".." || escaped.startsWith(`..${sep}`) || isAbsolute(escaped)) {
      throw new Error(`${label} resolves outside the Hyper-V evidence bundle: ${path}`);
    }
  }
  return real;
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
    "dump_identity",
    "dump_artifact_path",
    "guest_transcript_sha256",
    "guest_transcript_path",
    "dump_analysis_path",
    "dump_analysis_sha256",
    "run_nonce",
    "argv_sha256",
    "error",
  ] as const;
  if (strings.some((key) => typeof value[key] !== "string")) {
    throw new Error("invalid Hyper-V observation evidence fields");
  }
  return value as unknown as ZeroverseHyperVObservation;
}

function parseReceipt(path: string): ZeroverseHyperVEvidence {
  const value = JSON.parse(readOpenedFile(regularFile(path, "Hyper-V receipt"), 4 * 1024 * 1024).toString("utf8")) as unknown;
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
    || typeof value.error !== "string"
    || typeof value.claim_eligible !== "boolean"
    || (value.fixture_kind !== undefined && typeof value.fixture_kind !== "string")) {
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

function validateSidecars(
  receipt: ZeroverseHyperVEvidence,
  receiptPath: string,
): ValidatedBundle {
  const sidecars: ValidatedSidecar[] = [];
  const bundleRoot = dirname(receiptPath);
  const nonces = new Set<string>();
  const dumps: ValidatedBundle["dumps"] = [];
  for (const [observationIndex, row] of receipt.observations.entries()) {
    if (!RUN_NONCE.test(row.run_nonce) || nonces.has(row.run_nonce)) {
      throw new Error(`invalid or reused run nonce for ${row.case} trial ${row.trial}`);
    }
    nonces.add(row.run_nonce);
    if (!SHA256.test(row.argv_sha256)) {
      throw new Error(`invalid argv hash for ${row.case} trial ${row.trial}`);
    }
    const transcript = regularFile(row.guest_transcript_path, "guest transcript", bundleRoot);
    const transcriptContent = readOpenedFile(transcript);
    if (!SHA256.test(row.guest_transcript_sha256)
      || createHash("sha256").update(transcriptContent).digest("hex") !== row.guest_transcript_sha256) {
      throw new Error(`guest transcript hash mismatch for ${row.case} trial ${row.trial}`);
    }
    sidecars.push({
      content: transcriptContent,
      field: "guest_transcript_path",
      observationIndex,
      suffix: ".json",
    });
    if (row.status === "CRASH") {
      const analysis = regularFile(row.dump_analysis_path, "cdb analysis", bundleRoot);
      const analysisContent = readOpenedFile(analysis);
      const dump = regularFile(row.dump_artifact_path, "retained dump", bundleRoot);
      const dumpHash = hashOpenedFile(dump).sha256;
      if (!SHA256.test(row.dump_sha256)
        || dumpHash !== row.dump_sha256
        || (receipt.claim_eligible && !hasWindowsCrashDumpHeader(dump))
        || !SHA256.test(row.dump_analysis_sha256)
        || createHash("sha256").update(analysisContent).digest("hex") !== row.dump_analysis_sha256
        || !nonempty(row.crash_signature)
        || !nonempty(row.dump_identity)
        || !nonempty(row.dump_artifact_path)
        || cdbSignature(analysisContent.toString("utf8")) !== row.crash_signature) {
        throw new Error(`crash sidecar mismatch for ${row.case} trial ${row.trial}`);
      }
      sidecars.push({
        content: analysisContent,
        field: "dump_analysis_path",
        observationIndex,
        suffix: ".txt",
      });
      dumps.push({ source: dump, sha256: dumpHash, observationIndex });
    } else if (row.crash_signature || row.dump_sha256 || row.dump_identity
      || row.dump_artifact_path || row.dump_analysis_path || row.dump_analysis_sha256) {
      throw new Error(`non-crash observation carries crash authority for ${row.case} trial ${row.trial}`);
    }
  }
  return { sidecars, dumps };
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
    || new Set(crashes.map((row) => row.dump_sha256)).size !== crashes.length
    || new Set(crashes.map((row) => row.dump_identity)).size !== crashes.length
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
      validateSidecars(receipt, receiptPath);
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
        const receipt = parseReceipt(candidate.payload.receiptPath);
        validateIdentity(receipt, target);
        const { sidecars, dumps } = validateSidecars(receipt, candidate.payload.receiptPath);
        const { cleanControls } = validateReproduced(receipt);
        if (!receipt.claim_eligible || receipt.fixture_kind) {
          evidence.push({
            stage: "verify",
            status: "passed",
            summary: "validated a non-claim Hyper-V contract fixture; no finding was promoted",
          });
          continue;
        }
        const portableReceipt = structuredClone(receipt);
        const snapshots: string[] = [];
        for (const [index, sidecar] of sidecars.entries()) {
          const destination = join(snapshotRoot, `sidecar-${String(index + 1).padStart(2, "0")}${sidecar.suffix}`);
          writeFileSync(destination, sidecar.content, { flag: "wx" });
          if (createHash("sha256").update(sidecar.content).digest("hex") !== hashOpenedFile(destination).sha256) {
            throw new Error("sidecar changed while it was being snapshotted");
          }
          portableReceipt.observations[sidecar.observationIndex]![sidecar.field] = basename(destination);
          snapshots.push(destination);
        }
        for (const [index, dump] of dumps.entries()) {
          const destination = join(snapshotRoot, `dump-${String(index + 1).padStart(2, "0")}.dmp`);
          copyFileSync(dump.source, destination, fsConstants.COPYFILE_EXCL);
          if (hashOpenedFile(destination).sha256 !== dump.sha256) {
            throw new Error("dump changed while it was being snapshotted");
          }
          portableReceipt.observations[dump.observationIndex]!.dump_artifact_path = basename(destination);
          snapshots.push(destination);
        }
        const receiptPath = join(snapshotRoot, "receipt.json");
        writeFileSync(receiptPath, `${JSON.stringify(portableReceipt, null, 2)}\n`, {
          encoding: "utf8",
          flag: "wx",
        });
        snapshots.unshift(receiptPath);
        const verdict: WindowsHyperVImportVerdict = {
          verdictSchema: "pwnkit.windows-hyperv-import-verdict/v1",
          executionOrigin: "external",
          producer: "0verse",
          schemaVersion: EVIDENCE_SCHEMA,
          campaignId: receipt.campaign_id,
          buildLabEx: target.buildId!,
          signature: receipt.crash_signature,
          confirmations: receipt.confirmations,
          requiredConfirmations: receipt.required_confirmations,
          cleanControls,
          distinctDumpArtifacts: new Set(dumps.map((dump) => dump.sha256)).size,
          dumpHashBasis: "retained-bundle-bytes",
          receiptSha256: hashOpenedFile(receiptPath, 4 * 1024 * 1024).sha256,
          sidecarsRehashed: sidecars.length,
          passed: true,
        };
        const verdictPath = join(snapshotRoot, "import-verdict.json");
        writeFileSync(verdictPath, `${JSON.stringify(verdict, null, 2)}\n`, {
          encoding: "utf8",
          flag: "wx",
        });
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
