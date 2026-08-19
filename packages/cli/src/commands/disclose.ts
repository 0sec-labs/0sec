import type { Command } from "commander";
import { writeFileSync, mkdirSync, existsSync, readFileSync } from "node:fs";
import { resolve, join, dirname } from "node:path";
import { homedir } from "node:os";
import chalk from "chalk";
import type { Finding, AttackCategory, Severity, Evidence, FindingStatus, PocStep } from "@0sec/shared";
import { DEFAULT_SEVERITY_FLOOR, meetsSeverityFloor } from "@0sec/shared";
import { z } from "zod";
import { pocStepArraySchema, formatZodError } from "./schemas.js";
import {
  renderAdvisoryMarkdown,
  renderExploitScreenshot,
  isFreezeAvailable,
  verifyAgainstRef,
  detectVersionRange,
  extractSiblingFix,
  executePocSteps,
  EmptyPocError,
  type AdvisoryContext,
  type AdvisoryScreenshot,
  type ReverifyResult,
  type VersionRangeResult,
  type PatchStatus,
  type PocExecutionReport,
  type PocExecutionTarget,
  type PocStepResult,
  decideFilingState,
  assembleBundleIndex,
  formatDroppedReason,
  droppedFilename,
  type BundleEntry,
  assembleEvidencePack,
  renderVendorNotificationMarkdown,
  UnreproducedFindingError,
  createDisclosureRecord,
  transition,
  DISCLOSURE_STATUSES,
  type DisclosureRecord,
  type DisclosureStatus,
  assembleReproducibilityManifest,
  renderReproducibilityManifest,
  UnverifiedFindingError,
  IncompleteEvidenceError,
} from "@0sec/core";

interface DiscloseOptions {
  dbPath?: string;
  scan?: string;
  outputDir?: string;
  severityFloor?: string;
  dryRun?: boolean;
  noScreenshots?: boolean;
  repo?: string;
  ref?: string;
  dropFixed?: boolean;
  reverify?: boolean;
  targetUrl?: string;
  targetEnv?: string[];
  targetTimeoutMs?: string;
  keepUnrun?: boolean;
  reverifyRps?: string;
  scopeAllowlist?: string;
}

const STATUS_COLOUR: Record<PatchStatus, (s: string) => string> = {
  "still-vulnerable": (s) => chalk.green(s),
  "partial-fix": (s) => chalk.yellow(s),
  "fixed": (s) => chalk.gray(s),
  "file-removed": (s) => chalk.gray(s),
  "unknown": (s) => chalk.dim(s),
};

interface FindingRow {
  id: string;
  scanId: string;
  title: string;
  severity: string;
  category: string;
  status: string;
  fingerprint?: string | null;
  triageStatus?: string | null;
  triageNote?: string | null;
  timestamp: number;
  templateId: string;
  description: string;
  evidenceRequest: string;
  evidenceResponse: string;
  evidenceAnalysis?: string | null;
  cvssVector?: string | null;
  cvssScore?: number | null;
  pocSteps?: string | null;
}

function rowToFinding(row: FindingRow): Finding {
  const evidence: Evidence = {
    request: row.evidenceRequest,
    response: row.evidenceResponse,
    analysis: row.evidenceAnalysis ?? undefined,
  };
  const finding: Finding = {
    id: row.id,
    templateId: row.templateId,
    title: row.title,
    description: row.description,
    severity: row.severity as Severity,
    category: row.category as AttackCategory,
    status: row.status as FindingStatus,
    evidence,
    fingerprint: row.fingerprint ?? undefined,
    timestamp: row.timestamp,
  };
  if (row.cvssVector) finding.cvssVector = row.cvssVector;
  if (row.cvssScore !== null && row.cvssScore !== undefined) finding.cvssScore = row.cvssScore;
  if (row.pocSteps) {
    try {
      // Validated parse: zod ensures every element is a well-formed PocStep
      // before downstream code (verify replay, advisory renderer, screenshot
      // renderer) touches `step.action.type` / `step.expect`. DB corruption or
      // a migration mismatch surfaces as a clear warning rather than a deep
      // TypeError later. Falls back silently to evidence-prose on failure,
      // matching the pre-zod behaviour for malformed blobs.
      const raw = JSON.parse(row.pocSteps) as unknown;
      const parsed = pocStepArraySchema.parse(raw) as PocStep[];
      if (parsed.length > 0) finding.pocSteps = parsed;
    } catch (err) {
      if (err instanceof z.ZodError) {
        console.warn(
          chalk.yellow(
            `[disclose] dropping pocSteps for finding ${row.id}: ${formatZodError(err, "pocSteps")}`,
          ),
        );
      } else if (err instanceof SyntaxError) {
        console.warn(
          chalk.yellow(
            `[disclose] dropping pocSteps for finding ${row.id}: invalid JSON (${err.message})`,
          ),
        );
      }
      // Either way: fall back to evidence prose, preserving the original
      // best-effort behaviour.
    }
  }
  return finding;
}

/**
 * Parse `--target-env KEY=VAL --target-env OTHER=VAL` repeated flags into a
 * `Record<string, string>` shaped for `PocExecutionTarget.env`.
 */
function parseTargetEnv(pairs: string[] | undefined): Record<string, string> | undefined {
  if (!pairs || pairs.length === 0) return undefined;
  const out: Record<string, string> = {};
  for (const raw of pairs) {
    const eq = raw.indexOf("=");
    if (eq <= 0) {
      throw new Error(`--target-env expects KEY=VALUE, got: ${raw}`);
    }
    const k = raw.slice(0, eq);
    const v = raw.slice(eq + 1);
    out[k] = v;
  }
  return out;
}

const VERDICT_COLOUR: Record<NonNullable<PocExecutionReport["overallVerdict"]>, (s: string) => string> = {
  exploit_still_works: (s) => chalk.green(s),
  exploit_broken: (s) => chalk.yellow(s),
  could_not_run: (s) => chalk.red(s),
};

function resolveOutputDir(opts: DiscloseOptions, scanId: string): string {
  if (opts.outputDir) return resolve(opts.outputDir);
  return join(homedir(), "0sec", "disclosures", `scan-${scanId.slice(0, 8)}`);
}

async function disclose(findingId: string | undefined, opts: DiscloseOptions): Promise<void> {
  const { osecDB } = await import("@0sec/db");
  const db = new osecDB(opts.dbPath);
  try {
    const rows = db.listFindings({ scanId: opts.scan, limit: 5000 }) as FindingRow[];
    if (rows.length === 0) {
      console.log(chalk.gray("No findings in the database matching your filters."));
      return;
    }

    let selected: FindingRow[];
    if (findingId) {
      const exact = rows.find((r) => r.id === findingId);
      const prefix = rows.filter((r) => r.id.startsWith(findingId));
      if (exact) selected = [exact];
      else if (prefix.length === 1) selected = prefix;
      else if (prefix.length > 1) throw new Error(`Finding prefix '${findingId}' is ambiguous across ${prefix.length} rows.`);
      else throw new Error(`Finding '${findingId}' not found.`);
    } else {
      const floor = opts.severityFloor ?? DEFAULT_SEVERITY_FLOOR;
      // Advisory quality gate: never auto-draft advisories from "discovered"
      // (LLM hypothesised but not agent-confirmed) or "false-positive"
      // (explicitly rejected) findings. Auto-filing an unverified PoC is the
      // canonical "AI-generated low-quality" trigger that gets advisories
      // auto-closed at any responsible disclosure venue. Operators who
      // explicitly want to inspect those rows can pass an exact `--scan` +
      // `findingId` since single-finding mode bypasses this filter.
      selected = rows.filter(
        (r) =>
          meetsSeverityFloor(r.severity, floor) &&
          r.triageStatus !== "suppressed" &&
          r.status !== "discovered" &&
          r.status !== "false-positive",
      );
      if (selected.length === 0) {
        console.log(chalk.gray(`No findings at or above severity '${floor}' after triage filtering.`));
        return;
      }
    }

    const scanIds = Array.from(new Set(selected.map((r) => r.scanId)));
    const scanId = scanIds[0];
    if (scanIds.length > 1 && !opts.outputDir && !opts.scan) {
      throw new Error(
        `Selected ${selected.length} findings span ${scanIds.length} scans. Pass --scan <id> to narrow, or --output-dir <path> to override the default scan-scoped output directory.`,
      );
    }
    const outputDir = resolveOutputDir(opts, scanId);
    const imagesDir = join(outputDir, "images");
    if (!opts.dryRun) mkdirSync(outputDir, { recursive: true });

    const freezeOn = !opts.noScreenshots && !opts.dryRun && isFreezeAvailable();
    const reverifyOn = !!opts.repo;
    const behaviouralOn = !!opts.reverify && !!opts.targetUrl;
    if (opts.reverify && !opts.targetUrl) {
      throw new Error("--reverify requires --target-url <url> to dispatch http actions against.");
    }
    const targetEnv = parseTargetEnv(opts.targetEnv);
    const targetTimeoutMs = opts.targetTimeoutMs ? Number(opts.targetTimeoutMs) : undefined;
    if (targetTimeoutMs !== undefined && (!Number.isFinite(targetTimeoutMs) || targetTimeoutMs <= 0)) {
      throw new Error(`--target-timeout-ms must be a positive integer, got: ${opts.targetTimeoutMs}`);
    }
    const reverifyRps = opts.reverifyRps ? Number(opts.reverifyRps) : undefined;
    if (reverifyRps !== undefined && (!Number.isFinite(reverifyRps) || reverifyRps <= 0)) {
      throw new Error(`--reverify-rps must be a positive number, got: ${opts.reverifyRps}`);
    }
    const scopeAllowlist = opts.scopeAllowlist
      ? opts.scopeAllowlist.split(",").map((s) => s.trim()).filter(Boolean)
      : undefined;
    const droppedDir = join(outputDir, "_dropped");
    console.log(chalk.red.bold("\n  ◆ 0sec") + chalk.gray(` disclose — ${selected.length} finding${selected.length === 1 ? "" : "s"}`));
    console.log(chalk.gray(`  output: ${outputDir}${opts.dryRun ? " (dry-run — nothing written)" : ""}`));
    console.log(chalk.gray(`  screenshots: ${freezeOn ? "on (freeze)" : opts.noScreenshots ? "disabled" : opts.dryRun ? "skipped (dry-run)" : "disabled (freeze not on PATH)"}`));
    if (reverifyOn) {
      console.log(chalk.gray(`  reverify:    ${opts.repo}${opts.ref ? ` @ ${opts.ref}` : " @ HEAD"}${opts.dropFixed ? " (fixed → _dropped/)" : ""}`));
    } else {
      console.log(chalk.gray(`  reverify:    disabled (pass --repo to enable)`));
    }
    if (behaviouralOn) {
      console.log(chalk.gray(`  behavioural: ${opts.targetUrl}${targetTimeoutMs ? ` (timeout=${targetTimeoutMs}ms)` : ""}`));
    } else {
      console.log(chalk.gray(`  behavioural: disabled (pass --reverify --target-url to enable)`));
    }
    console.log("");

    type ResultState = "wrote" | "skipped-exists" | "dropped";
    interface FindingResult extends BundleEntry {
      severity: string;
      title: string;
      shotCount: number;
      state: ResultState;
    }
    const results: FindingResult[] = [];

    /**
     * Route a finding into `_dropped/` with a reason file, log it, and push
     * the entry into `results`. Shared between the canary/behavioural drop
     * branch and the empty-PoC catch — both paths build identical
     * BundleEntry shapes and emit identical console lines, so a single
     * helper avoids the previous bug where the empty-poc branch hand-rolled
     * its filename via `${id}-${sev}-empty-poc.md` and bypassed
     * `droppedFilename()` (which would have used `dropSlug(entry)` derived
     * from the canary/behavioural state).
     */
    function routeDroppedFinding(args: {
      finding: Finding;
      row: FindingRow;
      patchStatus: ReverifyResult | undefined;
      behaviouralReport: PocExecutionReport | undefined;
      dropReason: string | undefined;
      label: string;
    }): void {
      const { finding, row, patchStatus, behaviouralReport, dropReason, label } = args;
      const droppedEntry: BundleEntry = {
        finding,
        filename: "",
        primaryCwe: "",
        cvssScore: 0,
        patchStatus: patchStatus?.status,
        behaviouralVerdict: behaviouralReport?.overallVerdict,
        filingState: "drop",
        dropReason,
      };
      if (!opts.dryRun) {
        mkdirSync(droppedDir, { recursive: true });
        const reasonPath = join(droppedDir, droppedFilename(droppedEntry));
        const body = formatDroppedReason({
          finding,
          scanId,
          patchStatus,
          behaviouralReport,
          reason: dropReason ?? "dropped",
        });
        writeFileSync(reasonPath, body, "utf8");
      }
      console.log(
        `  ${chalk.gray("drop")}  ${chalk.dim((row.title + " …").slice(0, 64).padEnd(64))}  ${chalk.gray(label)}`
      );
      results.push({
        ...droppedEntry,
        severity: row.severity,
        title: row.title,
        shotCount: 0,
        state: "dropped",
      });
    }

    for (const row of selected) {
      const finding = rowToFinding(row);
      let patchStatus: ReverifyResult | undefined;
      let versionRange: VersionRangeResult | undefined;
      let behaviouralReport: PocExecutionReport | undefined;
      if (behaviouralOn && finding.pocSteps && finding.pocSteps.length > 0) {
        const target: PocExecutionTarget = {
          baseUrl: opts.targetUrl,
          env: targetEnv,
          timeoutMs: targetTimeoutMs,
          rpsPerHost: reverifyRps,
          scopeAllowlist,
          allowProcessActions: false,
        };
        try {
          behaviouralReport = await executePocSteps(finding, target);
        } catch (err) {
          console.log(chalk.red(`  behavioural reverify failed on ${row.id.slice(0, 8)}: ${err instanceof Error ? err.message : String(err)}`));
        }
        if (behaviouralReport && !opts.dryRun) {
          const execPath = join(outputDir, `${finding.id.slice(0, 8)}.execution.json`);
          writeFileSync(execPath, JSON.stringify(behaviouralReport, null, 2), "utf8");
          // Round-trip the verdict through the findings table so cloud sinks
          // and re-runs of disclose can read it back without re-executing
          // the step graph against the live target.
          db.saveFindingPocExecution(finding.id, behaviouralReport);
        }
      }
      if (reverifyOn) {
        try {
          patchStatus = verifyAgainstRef(finding, { repoPath: opts.repo!, ref: opts.ref, checkout: !!opts.ref });
        } catch (err) {
          console.log(chalk.red(`  reverify failed on ${row.id.slice(0, 8)}: ${err instanceof Error ? err.message : String(err)}`));
        }
        try {
          versionRange = detectVersionRange(finding, { repoPath: opts.repo! });
        } catch (err) {
          console.log(chalk.red(`  version-range failed on ${row.id.slice(0, 8)}: ${err instanceof Error ? err.message : String(err)}`));
        }
        // Sibling-code correct-pattern extractor (#172). If the finding has no
        // pre-populated code example, scan its prose for "correct pattern at
        // file.ts:N" cues and read the matching snippet from the local repo —
        // the advisory template renders this verbatim under "Suggested fix".
        if (!finding.remediation?.codeExample?.after) {
          try {
            const sibling = extractSiblingFix(finding, { repoPath: opts.repo! });
            if (sibling) {
              const existing = finding.remediation;
              finding.remediation = {
                summary: existing?.summary ?? "",
                steps: existing?.steps ?? [],
                references: existing?.references ?? [],
                codeExample: {
                  before: "",
                  after: sibling.snippet,
                  language: sibling.language,
                },
              };
            }
          } catch (err) {
            console.log(chalk.red(`  sibling-fix failed on ${row.id.slice(0, 8)}: ${err instanceof Error ? err.message : String(err)}`));
          }
        }
      }

      // ── Filing-state gate (#168) ──
      // Combine code-level patch status (canary) and behavioural verdict
      // (#171) into a single keep / drop / needs-review verdict the operator
      // sees in the INDEX. Logic lives in @0sec/core/disclose/bundle so the
      // tests can exercise it without going through the CLI.
      const { filingState, dropReason } = decideFilingState({
        patchStatus,
        behaviouralReport,
        dropFixed: !!opts.dropFixed,
        keepUnrun: !!opts.keepUnrun,
      });

      // Route dropped findings into _dropped/ with a reason file. This catches
      // both code-level drops (canary-fixed) and behavioural drops (exploit
      // no longer fires) — the reason file makes the audit trail explicit.
      if (filingState === "drop") {
        routeDroppedFinding({
          finding,
          row,
          patchStatus,
          behaviouralReport,
          dropReason,
          label: dropReason ?? "dropped",
        });
        continue;
      }

      // ── Multi-frame screenshot rendering (#168 / #170) ──
      // When the finding has a step graph, render one PNG per step and embed
      // each as its own <img>. Falls back to the single-frame composite when
      // the graph is absent so existing scans without pocSteps still get a
      // screenshot the way #169 shipped them.
      const screenshots: AdvisoryScreenshot[] = [];
      let shotCount = 0;
      if (freezeOn) {
        if (finding.pocSteps && finding.pocSteps.length > 0) {
          const stepResults: Record<string, PocStepResult> = {};
          if (behaviouralReport) {
            for (const sr of behaviouralReport.steps) stepResults[sr.stepId] = sr;
          }
          const frames = renderExploitScreenshot(finding, {
            outputDir: imagesDir,
            markdownDir: outputDir,
            pocSteps: finding.pocSteps,
            stepResults,
          });
          for (const f of frames) {
            screenshots.push({ alt: f.alt, relativePath: f.relativePath, caption: f.caption, width: 1200 });
            shotCount++;
          }
        } else {
          const shot = renderExploitScreenshot(finding, { outputDir: imagesDir, markdownDir: outputDir });
          if (shot) {
            screenshots.push({ alt: shot.alt, relativePath: shot.relativePath, caption: shot.caption, width: 1200 });
            shotCount = 1;
          }
        }
      }
      const ctx: AdvisoryContext = { scanId, screenshots, patchStatus, versionRange, pocExecution: behaviouralReport };
      let rendered;
      try {
        rendered = renderAdvisoryMarkdown(finding, ctx);
      } catch (err) {
        // Empty-PoC drop. Re-route the finding through the dropped-reason
        // path with `unverified-poc` as the explicit reason so the audit
        // trail shows why we refused to draft.
        if (err instanceof EmptyPocError) {
          const { dropReason: emptyReason } = decideFilingState({
            patchStatus,
            behaviouralReport,
            dropFixed: !!opts.dropFixed,
            keepUnrun: !!opts.keepUnrun,
            emptyPoc: true,
          });
          routeDroppedFinding({
            finding,
            row,
            patchStatus,
            behaviouralReport,
            dropReason: emptyReason,
            label: "empty-poc",
          });
          continue;
        }
        throw err;
      }
      const path = join(outputDir, rendered.filename);
      let state: ResultState = "wrote";
      if (!opts.dryRun) {
        if (existsSync(path)) {
          state = "skipped-exists";
        } else {
          writeFileSync(path, rendered.markdown, "utf8");
        }
      }
      results.push({
        finding,
        filename: rendered.filename,
        primaryCwe: rendered.primaryCwe,
        cvssScore: rendered.cvssScore,
        severity: row.severity,
        title: row.title,
        shotCount,
        patchStatus: patchStatus?.status,
        behaviouralVerdict: behaviouralReport?.overallVerdict,
        filingState,
        state,
      });
      const shotMark = shotCount > 0 ? chalk.cyan(` +${shotCount}png`) : chalk.gray("       ");
      const patchMark = patchStatus ? " " + STATUS_COLOUR[patchStatus.status](`[${patchStatus.status}]`) : "";
      const behaviouralMark = behaviouralReport
        ? " " + VERDICT_COLOUR[behaviouralReport.overallVerdict](`[${behaviouralReport.overallVerdict}]`)
        : "";
      const reviewMark = filingState === "needs-review" ? " " + chalk.magenta("[needs-review]") : "";
      const verb = state === "skipped-exists"
        ? chalk.yellow("skip ")
        : chalk.green("wrote");
      console.log(
        `  ${verb}  ${chalk.white(rendered.filename.padEnd(70))}  ${chalk.cyan(rendered.primaryCwe.padEnd(10))}  ${chalk.dim(`cvss=${rendered.cvssScore.toFixed(1)}`)}${shotMark}${patchMark}${behaviouralMark}${reviewMark}`
      );
    }

    if (!opts.dryRun) {
      const indexPath = join(outputDir, "INDEX.md");
      // Bundle index assembly is pure and lives in @0sec/core/disclose so
      // the table layout can be tested without touching the CLI / db / fs.
      const indexContent = assembleBundleIndex(results, { scanIds });
      writeFileSync(indexPath, indexContent, "utf8");
      console.log("\n  " + chalk.gray(`wrote ${indexPath}`));
    }
  } finally {
    db.close();
  }
}

interface EvidencePackOptions {
  target?: string;
  affectedRef?: string;
  allowUnreproduced?: boolean;
  out?: string;
}

/**
 * `disclose evidence-pack <finding.json>` — assemble a DRAFT vendor-notification
 * from a single finding JSON and emit the markdown to stdout (or `--out`). The
 * rendered markdown ALWAYS carries the mandatory `DRAFT — NOT SENT` banner;
 * this command never sends or publishes anything (operator-gated by design).
 */
function discloseEvidencePack(findingPath: string, opts: EvidencePackOptions): void {
  let finding: Finding;
  try {
    const raw = readFileSync(resolve(findingPath), "utf8");
    finding = JSON.parse(raw) as Finding;
  } catch (err) {
    console.error(chalk.red(`Failed to read finding JSON '${findingPath}': ${err instanceof Error ? err.message : String(err)}`));
    process.exitCode = 2;
    return;
  }
  if (!finding || typeof finding.id !== "string" || typeof finding.title !== "string") {
    console.error(chalk.red(`'${findingPath}' is not a valid Finding (missing id/title).`));
    process.exitCode = 2;
    return;
  }

  let md: string;
  try {
    const draft = assembleEvidencePack(finding, {
      target: opts.target,
      affectedRef: opts.affectedRef,
      allowUnreproduced: !!opts.allowUnreproduced,
    });
    md = renderVendorNotificationMarkdown(draft);
  } catch (err) {
    if (err instanceof UnreproducedFindingError) {
      console.error(
        chalk.red(
          `${err.message}\nRefusing to draft a vendor notification for an unreproduced finding. Pass --allow-unreproduced to stage an internal draft.`,
        ),
      );
    } else {
      console.error(chalk.red(err instanceof Error ? err.message : String(err)));
    }
    process.exitCode = 2;
    return;
  }

  if (opts.out) {
    writeFileSync(resolve(opts.out), md, "utf8");
    console.log(chalk.gray(`DRAFT vendor-notification written to ${resolve(opts.out)} (not sent).`));
    return;
  }
  console.log(md);
}

interface TrackOptions {
  record?: string;
  to?: string;
  actor?: string;
  message?: string;
  disclosedTo?: string;
  cveId?: string;
  out?: string;
}

interface ReviewOptions {
  timestamp?: string;
  toolVersion?: string;
  modelConfig?: string;
  target?: string;
  out?: string;
}

/**
 * `disclose track <findingId>` — drive the disclosure tracking state machine.
 * With no `--record`, opens a fresh draft record. With `--record <file> --to
 * <status>`, applies one legal transition and re-emits the record. Records
 * intent only — sends nothing (the operator performs the real-world action).
 */
function discloseTrack(findingId: string, opts: TrackOptions): void {
  let record: DisclosureRecord;
  try {
    if (opts.record) {
      const raw = readFileSync(resolve(opts.record), "utf8");
      const loaded = JSON.parse(raw) as DisclosureRecord;
      if (!opts.to) {
        console.error(chalk.red("--record requires --to <status> to apply a transition."));
        process.exitCode = 2;
        return;
      }
      if (!(DISCLOSURE_STATUSES as readonly string[]).includes(opts.to)) {
        console.error(chalk.red(`Invalid --to '${opts.to}'. Valid statuses: ${DISCLOSURE_STATUSES.join(", ")}.`));
        process.exitCode = 2;
        return;
      }
      record = transition(loaded, {
        to: opts.to as DisclosureStatus,
        actor: opts.actor,
        message: opts.message,
        disclosedTo: opts.disclosedTo,
        cveId: opts.cveId,
      });
    } else {
      record = createDisclosureRecord(findingId, { actor: opts.actor, message: opts.message });
    }
  } catch (err) {
    console.error(chalk.red(err instanceof Error ? err.message : String(err)));
    process.exitCode = 2;
    return;
  }

  const json = JSON.stringify(record, null, 2);
  if (opts.out) {
    writeFileSync(resolve(opts.out), json, "utf8");
    console.log(chalk.gray(`Disclosure record (status: ${record.status}) written to ${resolve(opts.out)} — intent only, nothing sent.`));
    return;
  }
  console.log(json);
}

/**
 * `disclose review <finding.json>` — render a local reproducibility manifest
 * for a verified finding. Assembles the manifest from the finding JSON and
 * renders it to stdout (or --out). Refuses non-verified findings and
 * incomplete evidence. Never sends or publishes anything.
 */
function discloseReview(findingPath: string, opts: ReviewOptions): void {
  const jsonPath = resolve(findingPath);
  const raw = readFileSync(jsonPath, "utf8");
  const finding = JSON.parse(raw) as Finding;
  const manifest = assembleReproducibilityManifest(finding, {
    timestamp: opts.timestamp,
    toolVersion: opts.toolVersion,
    modelConfig: opts.modelConfig,
    targetIdentifier: opts.target,
  });
  const rendered = renderReproducibilityManifest(manifest);
  if (opts.out) {
    const outPath = resolve(opts.out);
    const outDir = dirname(outPath);
    if (!existsSync(outDir)) {
      mkdirSync(outDir, { recursive: true });
    }
    writeFileSync(outPath, rendered + "\n", "utf8");
    console.log(`Manifest written to ${outPath}`);
  } else {
    console.log(rendered);
  }
}

export function registerDiscloseCommand(program: Command): void {
  const discloseCmd = program
    .command("disclose")
    .description("Assemble GHSA-ready advisory drafts from persisted findings")
    .argument("[findingId]", "Finding ID (or prefix). Omit to batch every finding at or above --severity-floor.")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--scan <scanId>", "Restrict to findings from this scan")
    .option("--output-dir <path>", "Directory to write advisories into (default ~/0sec/disclosures/scan-<id>)")
    .option("--severity-floor <severity>", "In batch mode, only draft findings at or above this severity", DEFAULT_SEVERITY_FLOOR)
    .option("--no-screenshots", "Skip terminal-screenshot rendering even when freeze is available")
    .option("--repo <path>", "Local git checkout of the target repo to re-verify findings against")
    .option("--ref <tag>", "Git ref (tag/sha/branch) to check out before verifying — defaults to the repo's current HEAD")
    .option("--drop-fixed", "Move findings whose status is 'fixed' or 'file-removed' into _dropped/ with a reason file instead of drafting an advisory for them", false)
    .option("--reverify", "Behaviourally re-verify each finding's PoC step graph against a live target. Requires --target-url.", false)
    .option("--target-url <url>", "Base URL the behavioural re-verify runtime dispatches http actions against (e.g. http://localhost:3108)")
    .option("--target-env <kv...>", "Repeated KEY=VALUE pairs added to the shell-action environment for behavioural re-verify")
    .option("--target-timeout-ms <ms>", "Per-step timeout for behavioural re-verify, in milliseconds (default 30000)")
    .option("--keep-unrun", "Route `could_not_run` behavioural verdicts to needs-review instead of dropping them. Default-off because unverified PoCs should never auto-file.", false)
    .option("--reverify-rps <n>", "Per-host requests-per-second cap for behavioural reverify (default 2). Honours 429 Retry-After.")
    .option("--scope-allowlist <hosts>", "Comma-separated host allowlist for reverify. Supports `*.domain.com` wildcard (matches subdomains, NOT the apex). Out-of-scope http/shell steps fail closed.")
    .option("--dry-run", "Show what would be written without writing files", false)
    .action(async (findingId: string | undefined, opts: DiscloseOptions) => {
      await disclose(findingId, opts);
    });

  discloseCmd
    .command("evidence-pack")
    .description(
      "Assemble a DRAFT vendor-notification (what/where/impact/repro/remediation) from a single finding JSON. Emits the mandatory 'DRAFT — NOT SENT' banner. Never sends. #928",
    )
    .argument("<finding.json>", "Path to a Finding JSON file")
    .option("--target <label>", "Affected target/package label for the 'where' line, e.g. lodash@4.17.21")
    .option("--affected-ref <ref>", "Git ref / version range string for the 'where' line")
    .option(
      "--allow-unreproduced",
      "Stage an internal draft even when the finding's PoC did not reproduce (default off — unreproduced findings are a low-signal disclosure trip-wire)",
      false,
    )
    .option("--out <file>", "Write the DRAFT markdown to a file instead of stdout")
    .action((findingPath: string, opts: EvidencePackOptions) => {
      discloseEvidencePack(findingPath, opts);
    });

  discloseCmd
    .command("track")
    .description(
      "Drive the disclosure tracking state machine. With no --record, opens a fresh draft record; with --record + --to, applies one legal transition. Records intent only — sends nothing.",
    )
    .argument("<findingId>", "Finding ID the disclosure record is for")
    .option("--record <file>", "Existing disclosure-record JSON to transition (omit to open a fresh draft)")
    .option("--to <status>", "Target status for the transition (requires --record)")
    .option("--actor <actor>", "Actor recorded on the timeline event (default 'operator')")
    .option("--message <text>", "Free-text note recorded on the timeline event")
    .option("--disclosed-to <vendor>", "Vendor/contact stamped when transitioning into 'sent'")
    .option("--cve-id <cve>", "CVE id stamped when transitioning into 'cve_assigned'")
    .option("--out <file>", "Write the record JSON to a file instead of stdout")
    .action((findingId: string, opts: TrackOptions) => {
      discloseTrack(findingId, opts);
    });

  discloseCmd
    .command("review")
    .description(
      "Render a local reproducibility manifest for a verified finding. " +
      "The manifest is deterministic, redacted, and safe for human inspection. " +
      "Never sends or publishes anything.",
    )
    .argument("<finding.json>", "Path to a Finding JSON file")
    .option("--timestamp <iso>", "Override generation timestamp for deterministic output")
    .option("--tool-version <ver>", "Override tool version string")
    .option("--model-config <str>", "Provider/model config, e.g. anthropic/claude-sonnet-4")
    .option("--target <id>", "Override the finding target identifier")
    .option("--out <file>", "Write manifest to a file instead of stdout")
    .action((findingPath: string, opts: ReviewOptions) => {
      try {
        discloseReview(findingPath, opts);
      } catch (err) {
        if (err instanceof UnverifiedFindingError || err instanceof IncompleteEvidenceError) {
          console.error(chalk.red(err.message));
          process.exitCode = 2;
        } else if (err instanceof SyntaxError && err.message.includes("JSON")) {
          console.error(chalk.red(`Failed to read finding JSON: ${(err as Error).message}`));
          process.exitCode = 2;
        } else {
          console.error(chalk.red(String(err)));
          process.exitCode = 2;
        }
      }
    });
}
