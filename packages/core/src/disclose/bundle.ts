/**
 * 0sec#168 — disclosure bundle assembly.
 *
 * Pure helpers that turn a list of {@link Finding}s plus optional
 * canary / behavioural verdicts into the bundle layout the operator's
 * runbooks point at:
 *
 *   <out>/
 *     INDEX.md
 *     <finding-id>.md
 *     <finding-id>.execution.json
 *     images/<finding-id>-step-N.png
 *     _dropped/<finding-id>-<severity>-<reason>.md
 *
 * This module owns the *layout decisions* — filing-state gate, INDEX columns,
 * dropped-reason file shape — and exposes them as composable functions so the
 * CLI is the only place that touches I/O and persistence.
 *
 * Implementation note: writing files is the CLI's job, not this module's.
 * `assembleBundleIndex` returns the rendered INDEX.md string;
 * `formatDroppedReason` returns the rendered _dropped/<file>.md string.
 * The CLI calls fs.writeFileSync. Tests stay deterministic and offline.
 */

import type { Finding } from "@0sec/shared";
import type { PatchStatus, ReverifyResult } from "./canary.js";
import type { PocExecutionReport, PocOverallVerdict } from "./poc-runtime.js";
import { redactSensitiveHeaders } from "./template.js";

/** Whether a finding should land in the bundle, _dropped/, or be flagged. */
export type FilingState = "keep" | "drop" | "needs-review";

export interface BundleEntry {
  finding: Finding;
  /** Advisory filename when filingState=keep. Empty for drops. */
  filename: string;
  primaryCwe: string;
  cvssScore: number;
  patchStatus?: PatchStatus;
  behaviouralVerdict?: PocOverallVerdict;
  filingState: FilingState;
  /** When filingState=drop, the human-readable reason. */
  dropReason?: string;
}

export interface AssembleIndexOptions {
  scanIds: string[];
  generatedAt?: Date;
}

/**
 * Decide a finding's filing state from the canary patch status (#170 canary)
 * and the behavioural reverify verdict (#171). The gate is conservative:
 *
 *   - Empty PoC                                  → drop, reason = unverified-poc
 *   - Code-level fixed (when --drop-fixed is on) → drop, reason = canary
 *   - Behavioural `exploit_broken`               → drop, reason = behavioural
 *   - Behavioural `could_not_run`                → drop (default), or
 *                                                  needs-review when
 *                                                  `keepUnrun` is on
 *   - Otherwise                                  → keep
 *
 * Defaulting `could_not_run` to drop (rather than the previous
 * needs-review) is an advisory-quality hardening: a finding whose own
 * runtime can't reproduce the exploit is the canonical "AI-generated
 * low-quality" advisory trigger and gets auto-closed at any responsible
 * disclosure venue. Operators who want to manually inspect those rows
 * can pass `--keep-unrun`.
 *
 * Returns both the verdict and the reason so the caller can render the
 * dropped-reason file or surface "needs-review" in the INDEX.
 */
export function decideFilingState(
  inputs: {
    patchStatus?: ReverifyResult;
    behaviouralReport?: PocExecutionReport;
    dropFixed: boolean;
    /**
     * When true, route `could_not_run` to needs-review instead of the new
     * default (drop). Mirrors the disclose CLI's `--keep-unrun` flag.
     */
    keepUnrun?: boolean;
    /**
     * When true, the renderer threw `EmptyPocError` because the finding has
     * no PoC content (no pocSteps, no evidence request/response, no
     * screenshots). Such findings are dropped with reason `unverified-poc`.
     */
    emptyPoc?: boolean;
  },
): { filingState: FilingState; dropReason?: string } {
  const { patchStatus, behaviouralReport, dropFixed, keepUnrun, emptyPoc } = inputs;
  if (emptyPoc) {
    return { filingState: "drop", dropReason: "unverified-poc: empty PoC" };
  }
  if (patchStatus && dropFixed && (patchStatus.status === "fixed" || patchStatus.status === "file-removed")) {
    return { filingState: "drop", dropReason: `canary status=${patchStatus.status}` };
  }
  if (behaviouralReport?.overallVerdict === "exploit_broken") {
    return { filingState: "drop", dropReason: "behavioural reverify: exploit_broken" };
  }
  if (behaviouralReport?.overallVerdict === "could_not_run") {
    if (keepUnrun) return { filingState: "needs-review" };
    return { filingState: "drop", dropReason: "unverified-poc: behavioural reverify could_not_run" };
  }
  return { filingState: "keep" };
}

/**
 * The slug used for the _dropped/<id>-<sev>-<slug>.md filename. Combines
 * canary status (preferred) with behavioural verdict, falling back to the
 * literal "dropped" — the slug is a hint, not a key.
 */
export function dropSlug(entry: BundleEntry): string {
  return entry.patchStatus ?? entry.behaviouralVerdict ?? "dropped";
}

/** Filename of the dropped-reason markdown for an entry. */
export function droppedFilename(entry: BundleEntry): string {
  return `${entry.finding.id.slice(0, 8)}-${entry.finding.severity}-${dropSlug(entry)}.md`;
}

/**
 * Render the dropped-reason markdown body. Includes the canary patch status,
 * the behavioural verdict, and a pointer to the `<id>.execution.json` sidecar
 * — that's the audit trail an operator (or the cloud's pre-file gate) walks
 * when answering "why did this finding get dropped?".
 */
export function formatDroppedReason(args: {
  finding: Finding;
  scanId: string;
  patchStatus?: ReverifyResult;
  behaviouralReport?: PocExecutionReport;
  reason: string;
}): string {
  const { finding, scanId, patchStatus, behaviouralReport, reason } = args;
  const lines: string[] = [];
  lines.push(`# Dropped: ${finding.title}`);
  lines.push("");
  lines.push(`- **Reason:** ${reason}`);
  lines.push(`- **Scan:** \`${scanId}\``);
  lines.push(`- **Finding id:** \`${finding.id}\``);
  if (patchStatus) {
    lines.push(`- **Canary status:** ${patchStatus.status}`);
    lines.push(`- **Canary ref:** \`${patchStatus.ref}\``);
  }
  if (behaviouralReport) {
    lines.push(`- **Behavioural verdict:** ${behaviouralReport.overallVerdict}`);
    lines.push(`- **Last-known-good execution:** see \`${finding.id.slice(0, 8)}.execution.json\``);
  }
  lines.push("");
  if (patchStatus) {
    lines.push("## Canary notes", "");
    for (const n of patchStatus.notes) lines.push(`- ${n}`);
    lines.push("", "## Refs checked", "");
    for (const r of patchStatus.refsChecked) {
      lines.push(`- \`${r.file}${r.line ? `:${r.line}` : ""}\``);
    }
    lines.push("");
  }
  if (behaviouralReport) {
    lines.push("## Behavioural step verdicts", "");
    for (const s of behaviouralReport.steps) {
      lines.push(`- \`${s.stepId}\` → ${s.kind}${s.error ? ` (${s.error})` : ""}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

/**
 * Extract SHA-256 hex digests from a finding's already-attached evidence
 * artifacts. Two typed sources are consulted:
 *
 *   1. `finding.verification_result?.evidence_artifacts` — written by the
 *      #193 deterministic replay runner when it persists stdout/stderr/
 *      screenshot captures during PoC reverify.
 *   2. `finding.researchEvidence[].artifacts` — carried by the research
 *      envelope's retained-artifact list from the shared adapter plane.
 *
 * Every hash is validated as a 64-char hex string (case-insensitive) before
 * being included, matching the `EvidenceArtifactSchema` zod regex.
 * Deduplicated and sorted for stable rendering.
 */
function findingProvenanceHashes(finding: Finding): string[] {
  const HEX64 = /^[0-9a-f]{64}$/i;
  const seen = new Set<string>();

  for (const art of finding.verification_result?.evidence_artifacts ?? []) {
    if (art.sha256 && HEX64.test(art.sha256)) seen.add(art.sha256.toLowerCase());
  }

  for (const envelope of finding.researchEvidence ?? []) {
    for (const art of envelope.artifacts ?? []) {
      if (art.sha256 && HEX64.test(art.sha256)) seen.add(art.sha256.toLowerCase());
    }
  }

  return [...seen].sort();
}

/**
 * Render the INDEX.md a disclosure bundle ships at its root. Filing-order
 * columns per the #168 spec:
 *     finding-id | severity | title | gate-status | behavioural | filing-state | provenance
 *
 * `gate-status` is the canary patch status, `behavioural` is the #171 verdict,
 * and `filing-state` is the {@link decideFilingState} verdict.
 *
 * Empty input round-trips to a stub INDEX with no rows so the bundle dir is
 * still self-explanatory if a scan produced 0 findings above the floor.
 */
export function assembleBundleIndex(
  entries: BundleEntry[],
  options: AssembleIndexOptions,
): string {
  const { scanIds } = options;
  const generatedAt = options.generatedAt ?? new Date();
  const drafts = entries.filter((e) => e.filingState !== "drop");
  const dropped = entries.filter((e) => e.filingState === "drop");
  const scanLabel = scanIds.length === 1
    ? `\`${scanIds[0]}\``
    : `\`${scanIds.join("`, `")}\` (${scanIds.length} scans)`;

  const truncateTitle = (t: string, max = 64): string => t.length > max ? t.slice(0, max - 1) + "…" : t;
  const truncateReason = (r: string | undefined, max = 48): string =>
    !r ? "—" : r.length > max ? r.slice(0, max - 1) + "…" : r;
  const escapePipe = (s: string): string => s.replace(/\|/g, "\\|");

  // Render a stable, inspectable digest even when a finding carries multiple
  // artifacts; the suffix reports additional retained hashes without turning
  // the review table into an unbounded artifact dump.
  const formatProvenance = (e: BundleEntry): string => {
    const hashes = findingProvenanceHashes(e.finding);
    if (hashes.length === 0) return "—";
    const first = `\`${hashes[0].slice(0, 12)}…\``;
    return hashes.length === 1 ? first : `${first} +${hashes.length - 1}`;
  };

  // Redact sensitive values in rendered INDEX fields.
  const redactTitle = (e: BundleEntry): string =>
    escapePipe(truncateTitle(redactSensitiveHeaders(e.finding.title)));
  const redactReason = (e: BundleEntry): string =>
    escapePipe(truncateReason(e.dropReason ? redactSensitiveHeaders(e.dropReason) : undefined));

  if (entries.length === 0) {
    return [
      "# Disclosure batch",
      "",
      `- Scan: ${scanLabel}`,
      "- Drafts: 0",
      `- Generated: ${generatedAt.toISOString()}`,
      "",
      "_No findings matched the current filters. Pass `--severity-floor low` or `--scan <id>` to widen the selection._",
      "",
    ].join("\n");
  }

  const lines: string[] = [];
  lines.push("# Disclosure batch", "");
  lines.push(`- Scan: ${scanLabel}`);
  lines.push(`- Drafts: ${drafts.length}`);
  if (dropped.length > 0) lines.push(`- Dropped: ${dropped.length} (see \`_dropped/\`)`);
  lines.push(`- Generated: ${generatedAt.toISOString()}`, "");

  lines.push(
    "## Filing order",
    "",
    "| finding-id | severity | title | gate-status | behavioural | filing-state | provenance |",
    "|---|---|---|---|---|---|---|",
  );
  for (const e of drafts) {
    const id = e.finding.id.slice(0, 8);
    const titleCell = `[${redactTitle(e)}](./${e.filename})`;
    lines.push(`| \`${id}\` | ${e.finding.severity} | ${titleCell} | ${e.patchStatus ?? "—"} | ${e.behaviouralVerdict ?? "—"} | ${e.filingState} | ${formatProvenance(e)} |`);
  }

  if (dropped.length > 0) {
    lines.push(
      "",
      "## Dropped",
      "",
      "| finding-id | severity | title | gate-status | behavioural | reason | provenance |",
      "|---|---|---|---|---|---|---|",
    );
    for (const e of dropped) {
      const id = e.finding.id.slice(0, 8);
      const titleCell = `[${redactTitle(e)}](./_dropped/${droppedFilename(e)})`;
      lines.push(`| \`${id}\` | ${e.finding.severity} | ${titleCell} | ${e.patchStatus ?? "—"} | ${e.behaviouralVerdict ?? "—"} | ${redactReason(e)} | ${formatProvenance(e)} |`);
    }
  }

  lines.push(
    "",
    "## Before filing each advisory",
    "",
    "1. Re-read the draft — the PoC and Patch Status sections are auto-populated from the scan but you should sanity-check against the current upstream HEAD.",
    "2. Verify the CVSS vector suggested by 0sec is still appropriate for your deployment model.",
    "3. Attach or replace screenshots in the PoC section as needed.",
    "4. File at https://github.com/<owner>/<repo>/security/advisories/new",
    "",
  );

  return lines.join("\n");
}
