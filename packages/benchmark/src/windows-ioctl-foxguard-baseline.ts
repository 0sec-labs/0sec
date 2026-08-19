import { createHash } from "node:crypto";

import { assertNoDuplicateWindowsLpeJsonKeys } from "./windows-lpe-paired-corpus.js";
import { wilsonIntervalTuple } from "./wilson.js";

export const WINDOWS_IOCTL_FOXGUARD_BASELINE_SCHEMA =
  "pwnkit.windows-ioctl-foxguard-baseline/v1" as const;
export const WINDOWS_IOCTL_LOCATION_PROJECTION_VERDICT_SCHEMA =
  "pwnkit.verified-0verse-windows-ioctl-location-projection/v1" as const;
export const WINDOWS_IOCTL_FOXGUARD_VERSION = "0.12.0" as const;
export const WINDOWS_IOCTL_FOXGUARD_BASELINE_PROOF_LIMIT =
  "Evaluator-private import of one upstream-verified signed 0verse Windows IOCTL location projection and one exact Foxguard v0.12 native finding-v1 report. Exact source-region overlap produces a label-blind static baseline only. It does not execute a target, invoke Foxguard, create a Research Finding, establish reachability, vulnerability, impact, novelty, claim or bounty eligibility, authorize disclosure, or provide weaponization evidence." as const;

const SHA256 = /^[0-9a-f]{64}$/;
const MAX_SITES = 8_192;
const MAX_FINDINGS = 8_192;
const MAX_REPORT_BYTES = 8 * 1024 * 1024;
const MAX_TEXT = 8_192;
const MAX_PATH = 1_024;
const MAX_DURATION_MS = 7 * 24 * 60 * 60 * 1_000;
const RATE_SCALE_PPM = 1_000_000;

type JsonRecord = Record<string, unknown>;
export type FoxguardSeverity = "low" | "medium" | "high" | "critical";
export type WindowsIoctlEvaluatorSiteRole = "expected" | "control" | "abstention";

export interface WindowsIoctlLocationRegion {
  siteId: string;
  file: string;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
}

/**
 * Construct this value only after the 0verse verifier has authenticated the
 * detached location-projection signature and its complete site-universe binding.
 * It is trusted caller context and is never accepted from the baseline document.
 */
export interface VerifiedWindowsIoctlLocationProjection {
  schemaVersion: typeof WINDOWS_IOCTL_LOCATION_PROJECTION_VERDICT_SCHEMA;
  signatureVerified: true;
  driverSha256: string;
  analysisSha256: string;
  analysisReceiptSha256: string;
  siteUniverseManifestSha256: string;
  siteUniverseSha256: string;
  siteCount: number;
  locationProjectionManifestSha256: string;
  locationProjectionSignatureSha256: string;
  sites: WindowsIoctlLocationRegion[];
}

export interface WindowsIoctlFoxguardEvidenceCommitments {
  executableSha256: string;
  rulesSha256: string;
  configSha256: string;
  argvSha256: string;
  inputSha256: string;
  reportSha256: string;
  stdoutSha256: string;
}

export interface WindowsIoctlFoxguardBaselineObservation {
  schemaVersion: typeof WINDOWS_IOCTL_FOXGUARD_BASELINE_SCHEMA;
  upstream: Omit<VerifiedWindowsIoctlLocationProjection, "schemaVersion" | "signatureVerified" | "sites">;
  foxguard: WindowsIoctlFoxguardEvidenceCommitments & {
    version: typeof WINDOWS_IOCTL_FOXGUARD_VERSION;
    findingSchemaVersion: "1.0.0";
    findingCount: number;
  };
  timing: {
    startedAt: string;
    completedAt: string;
    durationMs: number;
  };
  cost: {
    modelCalls: 0;
    inputTokens: 0;
    outputTokens: 0;
    estimatedUsd: number;
  };
  safety: {
    evaluatorPrivate: true;
    agentVisible: false;
    benchmarkOnly: true;
    staticOnly: true;
    executionPerformed: false;
    executionAuthorized: false;
    runtimeConsumable: false;
    deviceIoctlAttempts: 0;
    researchFindingCreated: false;
    capabilityMeasure: false;
    reachabilityEstablished: false;
    vulnerabilityEstablished: false;
    impactEstablished: false;
    noveltyEstablished: false;
    claimEligible: false;
    bountyEligible: false;
    weaponization: false;
    automaticDisclosure: false;
    humanPromotionGate: true;
    humanReportGate: true;
  };
  proofLimit: typeof WINDOWS_IOCTL_FOXGUARD_BASELINE_PROOF_LIMIT;
}

export interface WindowsIoctlFoxguardBaselineContext {
  verifiedProjection: VerifiedWindowsIoctlLocationProjection;
  expectedFoxguard: WindowsIoctlFoxguardEvidenceCommitments;
  /** Exact retained bytes. Foxguard native JSON is emitted on stdout. */
  reportBytes: Uint8Array;
  stdoutBytes: Uint8Array;
  evaluatorPolicy: {
    rankCutoff: number;
    siteRoles: Array<{ siteId: string; role: WindowsIoctlEvaluatorSiteRole }>;
  };
}

export interface WindowsIoctlFoxguardRankRow {
  siteId: string;
  severity: FoxguardSeverity;
  confidence: number;
  findingCount: number;
  rank: number;
}

export interface ValidatedWindowsIoctlFoxguardBaseline {
  observation: WindowsIoctlFoxguardBaselineObservation;
  accounting: {
    siteUniverseCount: number;
    findingCount: number;
    mappedFindingCount: number;
    unmappedFindingCount: number;
    ambiguousFindingCount: number;
    mappedSiteCount: number;
    emittedSiteCount: number;
  };
  rankRows: WindowsIoctlFoxguardRankRow[];
  evaluatorAggregate: {
    rankCutoff: number;
    firstExpectedRank: number | null;
    expectedCount: number;
    expectedFoundAtCutoff: number;
    controlCount: number;
    controlsEmitted: number;
    abstentionCount: number;
    emittedAbstentionCount: number;
  };
  metrics: {
    recallAtCutoff: number;
    recallAtCutoffCi95: [number, number];
    mrrContributionPpm: number;
    controlSuppression: number;
    controlSuppressionCi95: [number, number];
  };
  timing: WindowsIoctlFoxguardBaselineObservation["timing"];
  cost: WindowsIoctlFoxguardBaselineObservation["cost"];
}

interface ParsedFoxguardFinding {
  ruleId: string;
  snippet: string;
  severity: FoxguardSeverity;
  confidence: number;
  file: string;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function record(value: unknown, name: string): JsonRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value as JsonRecord;
}

function exact(value: unknown, name: string, fields: readonly string[]): JsonRecord {
  const object = record(value, name);
  const actual = Object.keys(object).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    throw new Error(`${name} has unknown or missing fields`);
  }
  return object;
}

function digest(value: unknown, name: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${name} must be a lowercase SHA-256`);
  }
  return value;
}

function integer(value: unknown, name: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) {
    throw new Error(`${name} must be an integer in [${minimum}, ${maximum}]`);
  }
  return Number(value);
}

function text(value: unknown, name: string, maximum = MAX_TEXT): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || value.includes("\0")) {
    throw new Error(`${name} must be bounded nonempty text`);
  }
  return value;
}

function finite(value: unknown, name: string, minimum: number, maximum: number): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be a finite number in [${minimum}, ${maximum}]`);
  }
  return value;
}

function normalizedPath(value: unknown, name: string): string {
  const path = text(value, name, MAX_PATH);
  if (path.startsWith("/") || path.includes("\\") || path.includes(":") || path !== path.normalize("NFC")) {
    throw new Error(`${name} must be a normalized portable relative path`);
  }
  const parts = path.split("/");
  if (parts.some((part) => part.length === 0 || part === "." || part === "..")) {
    throw new Error(`${name} must be a normalized portable relative path`);
  }
  return path;
}

function region(value: unknown, name: string): WindowsIoctlLocationRegion {
  const row = exact(value, name, [
    "siteId", "file", "startLine", "startColumn", "endLine", "endColumn",
  ]);
  const parsed: WindowsIoctlLocationRegion = {
    siteId: digest(row.siteId, `${name}.siteId`),
    file: normalizedPath(row.file, `${name}.file`),
    startLine: integer(row.startLine, `${name}.startLine`, 1, Number.MAX_SAFE_INTEGER),
    startColumn: integer(row.startColumn, `${name}.startColumn`, 1, Number.MAX_SAFE_INTEGER),
    endLine: integer(row.endLine, `${name}.endLine`, 1, Number.MAX_SAFE_INTEGER),
    endColumn: integer(row.endColumn, `${name}.endColumn`, 1, Number.MAX_SAFE_INTEGER),
  };
  if (comparePosition(parsed.endLine, parsed.endColumn, parsed.startLine, parsed.startColumn) < 0) {
    throw new Error(`${name} end must not precede start`);
  }
  return parsed;
}

function parseVerifiedProjection(value: unknown): VerifiedWindowsIoctlLocationProjection {
  const row = exact(value, "verifiedProjection", [
    "schemaVersion", "signatureVerified", "driverSha256", "analysisSha256",
    "analysisReceiptSha256", "siteUniverseManifestSha256", "siteUniverseSha256",
    "siteCount", "locationProjectionManifestSha256", "locationProjectionSignatureSha256",
    "sites",
  ]);
  if (row.schemaVersion !== WINDOWS_IOCTL_LOCATION_PROJECTION_VERDICT_SCHEMA || row.signatureVerified !== true) {
    throw new Error("location projection must be an upstream-verified signed verdict");
  }
  const digestFields = [
    "driverSha256", "analysisSha256", "analysisReceiptSha256", "siteUniverseManifestSha256",
    "siteUniverseSha256", "locationProjectionManifestSha256", "locationProjectionSignatureSha256",
  ] as const;
  const digests = Object.fromEntries(digestFields.map((field) => [
    field, digest(row[field], `verifiedProjection.${field}`),
  ])) as unknown as Pick<VerifiedWindowsIoctlLocationProjection, typeof digestFields[number]>;
  if (new Set(Object.values(digests)).size !== digestFields.length) {
    throw new Error("location projection digest roles must not alias");
  }
  const siteCount = integer(row.siteCount, "verifiedProjection.siteCount", 1, MAX_SITES);
  if (!Array.isArray(row.sites) || row.sites.length !== siteCount) {
    throw new Error("verifiedProjection.sites must exactly cover siteCount");
  }
  const sites = row.sites.map((item, index) => region(item, `verifiedProjection.sites[${index}]`));
  if (new Set(sites.map((site) => site.siteId)).size !== sites.length) {
    throw new Error("verifiedProjection contains duplicate siteId");
  }
  const sorted = [...sites].sort((left, right) => compareText(left.siteId, right.siteId));
  if (sites.some((site, index) => site.siteId !== sorted[index]!.siteId)) {
    throw new Error("verifiedProjection.sites must be sorted by siteId");
  }
  return {
    schemaVersion: WINDOWS_IOCTL_LOCATION_PROJECTION_VERDICT_SCHEMA,
    signatureVerified: true,
    ...digests,
    siteCount,
    sites,
  };
}

function parseEvidenceCommitments(value: unknown, name: string): WindowsIoctlFoxguardEvidenceCommitments {
  const fields = [
    "executableSha256", "rulesSha256", "configSha256", "argvSha256",
    "inputSha256", "reportSha256", "stdoutSha256",
  ] as const;
  const row = exact(value, name, fields);
  const parsed = Object.fromEntries(
    fields.map((field) => [field, digest(row[field], `${name}.${field}`)]),
  ) as unknown as WindowsIoctlFoxguardEvidenceCommitments;
  if (parsed.reportSha256 !== parsed.stdoutSha256) {
    throw new Error(`${name} report and stdout digests must be identical`);
  }
  const independentRoles = [
    parsed.executableSha256, parsed.rulesSha256, parsed.configSha256,
    parsed.argvSha256, parsed.inputSha256, parsed.reportSha256,
  ];
  if (new Set(independentRoles).size !== independentRoles.length) {
    throw new Error(`${name} digest roles must not alias`);
  }
  return parsed;
}

function sameEvidence(
  left: WindowsIoctlFoxguardEvidenceCommitments,
  right: WindowsIoctlFoxguardEvidenceCommitments,
): boolean {
  return (Object.keys(left) as Array<keyof WindowsIoctlFoxguardEvidenceCommitments>)
    .every((field) => left[field] === right[field]);
}

function parseUtc(value: unknown, name: string): { text: string; milliseconds: number } {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    throw new Error(`${name} must be canonical UTC RFC3339 with milliseconds`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new Error(`${name} must be a valid canonical timestamp`);
  }
  return { text: value, milliseconds };
}

function parseSafety(value: unknown): WindowsIoctlFoxguardBaselineObservation["safety"] {
  const expected: WindowsIoctlFoxguardBaselineObservation["safety"] = {
    evaluatorPrivate: true,
    agentVisible: false,
    benchmarkOnly: true,
    staticOnly: true,
    executionPerformed: false,
    executionAuthorized: false,
    runtimeConsumable: false,
    deviceIoctlAttempts: 0,
    researchFindingCreated: false,
    capabilityMeasure: false,
    reachabilityEstablished: false,
    vulnerabilityEstablished: false,
    impactEstablished: false,
    noveltyEstablished: false,
    claimEligible: false,
    bountyEligible: false,
    weaponization: false,
    automaticDisclosure: false,
    humanPromotionGate: true,
    humanReportGate: true,
  };
  const row = exact(value, "safety", Object.keys(expected));
  for (const [field, expectedValue] of Object.entries(expected)) {
    if (row[field] !== expectedValue) throw new Error(`safety.${field} must remain fail-closed`);
  }
  return expected;
}

function decodeReport(bytes: Uint8Array): string {
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_REPORT_BYTES) {
    throw new Error("Foxguard report bytes must be nonempty and bounded");
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new Error("Foxguard report must be valid UTF-8", { cause: error });
  }
}

function parseFoxguardReport(textValue: string): ParsedFoxguardFinding[] {
  assertNoDuplicateWindowsLpeJsonKeys(textValue);
  const top = record(JSON.parse(textValue) as unknown, "Foxguard report");
  if (top.schema_version !== "1.0.0" || top.finding_schema_version !== "1.0.0") {
    throw new Error("Foxguard report must use native finding schema v1");
  }
  const scanner = record(top.scanner, "Foxguard report.scanner");
  if (scanner.name !== "foxguard" || scanner.version !== WINDOWS_IOCTL_FOXGUARD_VERSION || scanner.command !== "scan") {
    throw new Error("Foxguard report must be an exact v0.12 scan report");
  }
  const config = record(top.config, "Foxguard report.config");
  text(config.source, "Foxguard report.config.source");
  const target = record(top.target, "Foxguard report.target");
  text(target.path, "Foxguard report.target.path");
  text(target.kind, "Foxguard report.target.kind");
  integer(target.files_scanned, "Foxguard report.target.files_scanned", 1, Number.MAX_SAFE_INTEGER);
  if (target.changed_only !== false) throw new Error("Foxguard baseline cannot use a changed-only scan");
  const timing = record(top.timing, "Foxguard report.timing");
  integer(timing.duration_ms, "Foxguard report.timing.duration_ms", 0, MAX_DURATION_MS);
  if (!Array.isArray(top.findings) || top.findings.length > MAX_FINDINGS) {
    throw new Error("Foxguard findings must be a bounded array");
  }
  const findings = top.findings.map((item, index): ParsedFoxguardFinding => {
    const name = `Foxguard report.findings[${index}]`;
    const finding = record(item, name);
    const severity = finding.severity;
    if (severity !== "low" && severity !== "medium" && severity !== "high" && severity !== "critical") {
      throw new Error(`${name}.severity is invalid`);
    }
    const ruleId = text(finding.rule_id, `${name}.rule_id`);
    if (finding.cwe !== null) text(finding.cwe, `${name}.cwe`);
    text(finding.description, `${name}.description`);
    const snippet = text(finding.snippet, `${name}.snippet`);
    const parsed: ParsedFoxguardFinding = {
      ruleId,
      snippet,
      severity,
      confidence: finite(finding.confidence, `${name}.confidence`, 0, 1),
      file: normalizedPath(finding.file, `${name}.file`),
      startLine: integer(finding.line, `${name}.line`, 1, Number.MAX_SAFE_INTEGER),
      startColumn: integer(finding.column, `${name}.column`, 1, Number.MAX_SAFE_INTEGER),
      endLine: integer(finding.end_line, `${name}.end_line`, 1, Number.MAX_SAFE_INTEGER),
      endColumn: integer(finding.end_column, `${name}.end_column`, 1, Number.MAX_SAFE_INTEGER),
    };
    if (comparePosition(parsed.endLine, parsed.endColumn, parsed.startLine, parsed.startColumn) < 0) {
      throw new Error(`${name} end must not precede start`);
    }
    return parsed;
  });
  const identities = findings.map((finding) => JSON.stringify([
    finding.ruleId,
    finding.file,
    finding.startLine,
    finding.startColumn,
    finding.endLine,
    finding.endColumn,
    finding.snippet,
  ]));
  if (new Set(identities).size !== identities.length) throw new Error("Foxguard report contains duplicate findings");

  const counts = exact(top.finding_counts, "Foxguard report.finding_counts", ["total", "by_severity"]);
  if (integer(counts.total, "Foxguard report.finding_counts.total", 0, MAX_FINDINGS) !== findings.length) {
    throw new Error("Foxguard finding total does not match findings");
  }
  const bySeverity = exact(counts.by_severity, "Foxguard report.finding_counts.by_severity", [
    "low", "medium", "high", "critical",
  ]);
  for (const severity of ["low", "medium", "high", "critical"] as const) {
    if (integer(bySeverity[severity], `Foxguard report.finding_counts.by_severity.${severity}`, 0, MAX_FINDINGS)
      !== findings.filter((finding) => finding.severity === severity).length) {
      throw new Error("Foxguard severity counts do not match findings");
    }
  }
  return findings;
}

function comparePosition(leftLine: number, leftColumn: number, rightLine: number, rightColumn: number): number {
  return leftLine === rightLine ? leftColumn - rightColumn : leftLine - rightLine;
}

function overlaps(finding: ParsedFoxguardFinding, site: WindowsIoctlLocationRegion): boolean {
  if (finding.file !== site.file) return false;
  return comparePosition(finding.startLine, finding.startColumn, site.endLine, site.endColumn) <= 0
    && comparePosition(site.startLine, site.startColumn, finding.endLine, finding.endColumn) <= 0;
}

function parseObservation(value: unknown): WindowsIoctlFoxguardBaselineObservation {
  const top = exact(value, "observation", [
    "schemaVersion", "upstream", "foxguard", "timing", "cost", "safety", "proofLimit",
  ]);
  if (top.schemaVersion !== WINDOWS_IOCTL_FOXGUARD_BASELINE_SCHEMA) {
    throw new Error("unsupported Foxguard baseline schema");
  }
  if (top.proofLimit !== WINDOWS_IOCTL_FOXGUARD_BASELINE_PROOF_LIMIT) {
    throw new Error("Foxguard baseline proof limit mismatch");
  }
  const upstream = exact(top.upstream, "observation.upstream", [
    "driverSha256", "analysisSha256", "analysisReceiptSha256", "siteUniverseManifestSha256",
    "siteUniverseSha256", "siteCount", "locationProjectionManifestSha256",
    "locationProjectionSignatureSha256",
  ]);
  const foxguard = exact(top.foxguard, "observation.foxguard", [
    "version", "findingSchemaVersion", "findingCount", "executableSha256", "rulesSha256",
    "configSha256", "argvSha256", "inputSha256", "reportSha256", "stdoutSha256",
  ]);
  if (foxguard.version !== WINDOWS_IOCTL_FOXGUARD_VERSION || foxguard.findingSchemaVersion !== "1.0.0") {
    throw new Error("Foxguard baseline requires v0.12 native finding-v1 evidence");
  }
  const evidence = parseEvidenceCommitments(
    Object.fromEntries(Object.entries(foxguard).filter(([field]) => !["version", "findingSchemaVersion", "findingCount"].includes(field))),
    "observation.foxguard evidence",
  );
  const timingRaw = exact(top.timing, "observation.timing", ["startedAt", "completedAt", "durationMs"]);
  const started = parseUtc(timingRaw.startedAt, "observation.timing.startedAt");
  const completed = parseUtc(timingRaw.completedAt, "observation.timing.completedAt");
  const durationMs = integer(timingRaw.durationMs, "observation.timing.durationMs", 0, MAX_DURATION_MS);
  if (completed.milliseconds - started.milliseconds !== durationMs) {
    throw new Error("Foxguard baseline duration must exactly bind its timestamps");
  }
  const costRaw = exact(top.cost, "observation.cost", ["modelCalls", "inputTokens", "outputTokens", "estimatedUsd"]);
  if (costRaw.modelCalls !== 0 || costRaw.inputTokens !== 0 || costRaw.outputTokens !== 0) {
    throw new Error("Foxguard static baseline cannot declare model calls or tokens");
  }
  return {
    schemaVersion: WINDOWS_IOCTL_FOXGUARD_BASELINE_SCHEMA,
    upstream: {
      driverSha256: digest(upstream.driverSha256, "observation.upstream.driverSha256"),
      analysisSha256: digest(upstream.analysisSha256, "observation.upstream.analysisSha256"),
      analysisReceiptSha256: digest(upstream.analysisReceiptSha256, "observation.upstream.analysisReceiptSha256"),
      siteUniverseManifestSha256: digest(upstream.siteUniverseManifestSha256, "observation.upstream.siteUniverseManifestSha256"),
      siteUniverseSha256: digest(upstream.siteUniverseSha256, "observation.upstream.siteUniverseSha256"),
      siteCount: integer(upstream.siteCount, "observation.upstream.siteCount", 1, MAX_SITES),
      locationProjectionManifestSha256: digest(upstream.locationProjectionManifestSha256, "observation.upstream.locationProjectionManifestSha256"),
      locationProjectionSignatureSha256: digest(upstream.locationProjectionSignatureSha256, "observation.upstream.locationProjectionSignatureSha256"),
    },
    foxguard: {
      version: WINDOWS_IOCTL_FOXGUARD_VERSION,
      findingSchemaVersion: "1.0.0",
      findingCount: integer(foxguard.findingCount, "observation.foxguard.findingCount", 0, MAX_FINDINGS),
      ...evidence,
    },
    timing: { startedAt: started.text, completedAt: completed.text, durationMs },
    cost: {
      modelCalls: 0,
      inputTokens: 0,
      outputTokens: 0,
      estimatedUsd: finite(costRaw.estimatedUsd, "observation.cost.estimatedUsd", 0, 1_000_000),
    },
    safety: parseSafety(top.safety),
    proofLimit: WINDOWS_IOCTL_FOXGUARD_BASELINE_PROOF_LIMIT,
  };
}

function projectionBindings(projection: VerifiedWindowsIoctlLocationProjection) {
  const { schemaVersion: _schemaVersion, signatureVerified: _signatureVerified, sites: _sites, ...bindings } = projection;
  return bindings;
}

function sameProjectionBindings(
  left: WindowsIoctlFoxguardBaselineObservation["upstream"],
  right: ReturnType<typeof projectionBindings>,
): boolean {
  return (Object.keys(left) as Array<keyof typeof left>).every((field) => left[field] === right[field]);
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

const SEVERITY_RANK: Record<FoxguardSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/**
 * Pure evaluator-side adapter. It parses retained bytes and caller-held
 * verified commitments; it has no execution, runner, target, or Finding seam.
 */
export function validateWindowsIoctlFoxguardBaseline(
  value: unknown,
  context: WindowsIoctlFoxguardBaselineContext,
): ValidatedWindowsIoctlFoxguardBaseline {
  const observation = parseObservation(value);
  const projection = parseVerifiedProjection(context.verifiedProjection);
  const expectedFoxguard = parseEvidenceCommitments(context.expectedFoxguard, "expectedFoxguard");
  if (!sameProjectionBindings(observation.upstream, projectionBindings(projection))) {
    throw new Error("baseline does not match the upstream-verified location projection");
  }
  const observedEvidence: WindowsIoctlFoxguardEvidenceCommitments = {
    executableSha256: observation.foxguard.executableSha256,
    rulesSha256: observation.foxguard.rulesSha256,
    configSha256: observation.foxguard.configSha256,
    argvSha256: observation.foxguard.argvSha256,
    inputSha256: observation.foxguard.inputSha256,
    reportSha256: observation.foxguard.reportSha256,
    stdoutSha256: observation.foxguard.stdoutSha256,
  };
  if (!sameEvidence(observedEvidence, expectedFoxguard)) {
    throw new Error("baseline does not match the independently verified Foxguard commitments");
  }
  if (context.reportBytes.byteLength === 0 || context.reportBytes.byteLength > MAX_REPORT_BYTES
    || context.stdoutBytes.byteLength === 0 || context.stdoutBytes.byteLength > MAX_REPORT_BYTES) {
    throw new Error("Foxguard report/stdout bytes must be nonempty and bounded");
  }
  const report = Buffer.from(context.reportBytes);
  const stdout = Buffer.from(context.stdoutBytes);
  if (!report.equals(stdout)) throw new Error("Foxguard native report must be the exact stdout bytes");
  if (sha256(report) !== observation.foxguard.reportSha256
    || sha256(stdout) !== observation.foxguard.stdoutSha256) {
    throw new Error("Foxguard retained report/stdout bytes do not match verified commitments");
  }
  const findings = parseFoxguardReport(decodeReport(report));
  if (findings.length !== observation.foxguard.findingCount) {
    throw new Error("Foxguard finding count does not match the retained report");
  }

  const mapped: Array<{ finding: ParsedFoxguardFinding; siteId: string }> = [];
  let unmappedFindingCount = 0;
  let ambiguousFindingCount = 0;
  for (const finding of findings) {
    const matches = projection.sites.filter((site) => overlaps(finding, site));
    if (matches.length === 0) unmappedFindingCount += 1;
    else if (matches.length > 1) ambiguousFindingCount += 1;
    else mapped.push({ finding, siteId: matches[0]!.siteId });
  }

  const bySite = new Map<string, ParsedFoxguardFinding[]>();
  for (const item of mapped) {
    const current = bySite.get(item.siteId) ?? [];
    current.push(item.finding);
    bySite.set(item.siteId, current);
  }
  const rankRows = [...bySite.entries()].map(([siteId, siteFindings]) => {
    const ordered = [...siteFindings].sort((left, right) =>
      SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity]
      || right.confidence - left.confidence);
    const best = ordered[0]!;
    return {
      siteId,
      severity: best.severity,
      confidence: best.confidence,
      findingCount: siteFindings.length,
      rank: 0,
    };
  }).sort((left, right) =>
    SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity]
    || right.confidence - left.confidence
    || compareText(left.siteId, right.siteId));
  rankRows.forEach((row, index) => { row.rank = index + 1; });

  const policy = exact(context.evaluatorPolicy, "evaluatorPolicy", ["rankCutoff", "siteRoles"]);
  const rankCutoff = integer(policy.rankCutoff, "evaluatorPolicy.rankCutoff", 1, MAX_SITES);
  if (!Array.isArray(policy.siteRoles) || policy.siteRoles.length !== projection.siteCount) {
    throw new Error("evaluator site roles must exactly partition the site universe");
  }
  const roles = new Map<string, WindowsIoctlEvaluatorSiteRole>();
  for (const [index, item] of policy.siteRoles.entries()) {
    const roleRow = exact(item, `evaluatorPolicy.siteRoles[${index}]`, ["siteId", "role"]);
    const siteId = digest(roleRow.siteId, `evaluatorPolicy.siteRoles[${index}].siteId`);
    if (roleRow.role !== "expected" && roleRow.role !== "control" && roleRow.role !== "abstention") {
      throw new Error(`evaluatorPolicy.siteRoles[${index}].role is invalid`);
    }
    if (roles.has(siteId)) throw new Error("evaluator site roles contain duplicate siteId");
    roles.set(siteId, roleRow.role);
  }
  const universeIds = new Set(projection.sites.map((site) => site.siteId));
  if ([...roles.keys()].some((siteId) => !universeIds.has(siteId))
    || [...universeIds].some((siteId) => !roles.has(siteId))) {
    throw new Error("evaluator site roles do not match the verified site universe");
  }
  const counts = { expected: 0, control: 0, abstention: 0 };
  for (const role of roles.values()) counts[role] += 1;
  if (counts.expected === 0 || counts.control === 0) {
    throw new Error("Foxguard baseline evaluation requires expected and control sites");
  }
  const emitted = new Set(rankRows.map((row) => row.siteId));
  const cutoffRows = rankRows.slice(0, Math.min(rankCutoff, rankRows.length));
  const expectedFoundAtCutoff = cutoffRows.filter((row) => roles.get(row.siteId) === "expected").length;
  const firstExpectedRank = rankRows.find((row) => roles.get(row.siteId) === "expected")?.rank ?? null;
  const controlsEmitted = [...emitted].filter((siteId) => roles.get(siteId) === "control").length;
  const emittedAbstentionCount = [...emitted].filter((siteId) => roles.get(siteId) === "abstention").length;
  const suppressedControls = counts.control - controlsEmitted;

  return {
    observation,
    accounting: {
      siteUniverseCount: projection.siteCount,
      findingCount: findings.length,
      mappedFindingCount: mapped.length,
      unmappedFindingCount,
      ambiguousFindingCount,
      mappedSiteCount: bySite.size,
      emittedSiteCount: rankRows.length,
    },
    rankRows,
    evaluatorAggregate: {
      rankCutoff,
      firstExpectedRank,
      expectedCount: counts.expected,
      expectedFoundAtCutoff,
      controlCount: counts.control,
      controlsEmitted,
      abstentionCount: counts.abstention,
      emittedAbstentionCount,
    },
    metrics: {
      recallAtCutoff: expectedFoundAtCutoff / counts.expected,
      recallAtCutoffCi95: wilsonIntervalTuple(expectedFoundAtCutoff, counts.expected),
      mrrContributionPpm: firstExpectedRank === null ? 0 : Math.floor(RATE_SCALE_PPM / firstExpectedRank),
      controlSuppression: suppressedControls / counts.control,
      controlSuppressionCi95: wilsonIntervalTuple(suppressedControls, counts.control),
    },
    timing: observation.timing,
    cost: observation.cost,
  };
}
