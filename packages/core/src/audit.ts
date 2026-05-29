import { rmSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { randomUUID } from "node:crypto";
import type {
  AuditConfig,
  AuditReport,
  NpmAuditFinding,
  SemgrepFinding,
  Finding,
  ScanConfig,
  Severity,
} from "@pwnkit/shared";
import type { ScanEvent, ScanListener } from "./scanner.js";
import { auditAgentPrompt } from "./analysis-prompts.js";
import { runAnalysisAgent } from "./agent-runner.js";
import { runSelectedStaticScan, selectedStaticScanner } from "./shared-analysis.js";
import {
  scanForMaliciousPatterns,
  scanTransitiveDependencies,
  checkDependencyConfusion,
  isInternalPackageName,
} from "./malicious-detector.js";
import { postProcessPackageAuditFindings } from "./package-audit-suppressor.js";
import { collectScopeFiles } from "./source-files.js";
import { features as agentFeatures } from "./agent/features.js";
import { researchPromptSingleFile } from "./agent/prompts.js";
import {
  installPackageForEcosystem,
  normalizeSeverity,
  formatFixAvailable,
  runDependencyAuditForEcosystem,
  walkInstalledNpmTree,
  probePublicNpmRegistry,
  type InstalledPackage,
} from "./package-ecosystems.js";

export interface PackageAuditOptions {
  config: AuditConfig;
  onEvent?: ScanListener;
}

interface OsvVulnerability {
  id?: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: Array<{ type?: string; score?: string }>;
  database_specific?: { severity?: string };
  references?: Array<{ type?: string; url?: string }>;
  affected?: Array<{
    ranges?: Array<{
      type?: string;
      events?: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
    }>;
  }>;
}

function parseCvssSeverity(score: string | undefined): Severity | undefined {
  if (!score) return undefined;
  const match = score.match(/CVSS:\d\.\d\/[^/]*\/[^/]*\/[^/]*\/[^/]*\/[^/]*\/[^/]*\/[^/]*\/[^/]*\/([^/]+)/i);
  if (match) {
    const label = match[1]?.toUpperCase();
    if (label === "CRITICAL") return "critical";
    if (label === "HIGH") return "high";
    if (label === "MEDIUM") return "medium";
    if (label === "LOW") return "low";
  }
  return undefined;
}

function extractOsvSeverity(vuln: OsvVulnerability): Severity {
  const dbSeverity = vuln.database_specific?.severity;
  if (typeof dbSeverity === "string" && dbSeverity.length > 0) {
    return normalizeSeverity(dbSeverity);
  }
  for (const sev of vuln.severity ?? []) {
    const parsed = parseCvssSeverity(sev.score);
    if (parsed) return parsed;
  }
  return "medium";
}

function extractOsvRange(vuln: OsvVulnerability): string | undefined {
  const segments: string[] = [];
  for (const affected of vuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      if (range.type !== "SEMVER") continue;
      const parts = (range.events ?? []).flatMap((event) => {
        const items: string[] = [];
        if (event.introduced) items.push(`introduced:${event.introduced}`);
        if (event.fixed) items.push(`fixed:${event.fixed}`);
        if (event.last_affected) items.push(`last_affected:${event.last_affected}`);
        return items;
      });
      if (parts.length > 0) {
        segments.push(parts.join(","));
      }
    }
  }
  return segments.length > 0 ? segments.join(" | ") : undefined;
}

function extractOsvFix(vuln: OsvVulnerability): boolean | string {
  for (const affected of vuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return false;
}

export function parseOsvAdvisories(
  packageName: string,
  raw: unknown,
): NpmAuditFinding[] {
  const vulns = Array.isArray((raw as { vulns?: unknown[] })?.vulns)
    ? ((raw as { vulns?: unknown[] }).vulns as OsvVulnerability[])
    : [];

  return vulns.map((vuln) => {
    const aliases = [...new Set([vuln.id, ...(vuln.aliases ?? [])].filter(Boolean) as string[])];
    const source = aliases[0];
    const url = vuln.references?.find((ref) => typeof ref.url === "string")?.url;
    const title =
      (typeof vuln.summary === "string" && vuln.summary.trim()) ||
      (typeof vuln.details === "string" && vuln.details.trim().slice(0, 120)) ||
      source ||
      "OSV advisory";

    return {
      name: packageName,
      severity: extractOsvSeverity(vuln),
      title,
      range: extractOsvRange(vuln),
      source,
      url,
      via: aliases.length > 0 ? aliases : ["OSV"],
      fixAvailable: extractOsvFix(vuln),
    };
  });
}

export async function queryOsvAdvisories(
  packageName: string,
  version: string,
  ecosystem: "npm" | "pypi" | "cargo" | "oci" = "npm",
  emit?: ScanListener,
): Promise<NpmAuditFinding[]> {
  if (ecosystem === "oci") {
    emit?.({
      type: "stage:end",
      stage: "discovery",
      message: "OSV lookup unavailable for OCI images",
    });
    return [];
  }
  emit?.({
    type: "stage:start",
    stage: "discovery",
    message: `Querying OSV for ${ecosystem}:${packageName}@${version}...`,
  });

  try {
    const res = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        package: {
          ecosystem:
            ecosystem === "pypi"
              ? "PyPI"
              : ecosystem === "cargo"
                ? "crates.io"
                : "npm",
          name: packageName,
        },
        version,
      }),
    });

    if (!res.ok) {
      emit?.({
        type: "stage:end",
        stage: "discovery",
        message: `OSV lookup failed: ${res.status}`,
      });
      return [];
    }

    const json = await res.json();
    const findings = parseOsvAdvisories(packageName, json);
    emit?.({
      type: "stage:end",
      stage: "discovery",
      message: `OSV: ${findings.length} advisories`,
    });
    return findings;
  } catch {
    emit?.({
      type: "stage:end",
      stage: "discovery",
      message: "OSV lookup unavailable",
    });
    return [];
  }
}

function mergeAdvisories(
  primary: NpmAuditFinding[],
  extra: NpmAuditFinding[],
): NpmAuditFinding[] {
  const seen = new Set(
    primary.map((finding) => `${finding.name}|${finding.title}|${finding.source ?? ""}`),
  );
  const merged = [...primary];
  for (const finding of extra) {
    const key = `${finding.name}|${finding.title}|${finding.source ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    merged.push(finding);
  }
  return merged;
}

function severityRank(severity: Severity): number {
  switch (severity) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    case "info":
    default:
      return 1;
  }
}

export function summarizeKnownAdvisoriesFinding(
  pkg: InstalledPackage,
  advisories: NpmAuditFinding[],
): Finding | null {
  if (advisories.length === 0) return null;

  const ordered = [...advisories].sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity),
  );
  const topSeverity = ordered[0]?.severity ?? "medium";
  const lines = ordered.slice(0, 8).map((advisory) => {
    const id = advisory.source ? ` (${advisory.source})` : "";
    const fix =
      typeof advisory.fixAvailable === "string" && advisory.fixAvailable.length > 0
        ? ` — fix: ${advisory.fixAvailable}`
        : "";
    return `- [${advisory.severity.toUpperCase()}] ${advisory.title}${id}${fix}`;
  });

  return {
    id: randomUUID(),
    templateId: "known-package-advisories",
    title: `${pkg.name}@${pkg.version} matches ${advisories.length} known advisory${advisories.length === 1 ? "" : "ies"}`,
    description:
      `Deterministic package-version match against registry advisory data for the audited root package.\n\n` +
      `${lines.join("\n")}` +
      (advisories.length > lines.length
        ? `\n- ... ${advisories.length - lines.length} more advisory matches`
        : ""),
    severity: topSeverity,
    category: "known-vulnerable-package",
    status: "verified",
    evidence: {
      request: `advisory lookup for ${pkg.name}@${pkg.version}`,
      response: ordered
        .slice(0, 8)
        .map((advisory) => `${advisory.title} | ${advisory.source ?? "unknown"} | ${advisory.url ?? "no-url"}`)
        .join("\n"),
      analysis:
        "Deterministic root-package advisory match from registry/dependency advisory sources. This finding does not depend on the LLM reading the source code or rediscovering the issue manually.",
    },
    confidence: 0.95,
    timestamp: Date.now(),
  };
}

function buildCliAuditPrompt(
  pkg: InstalledPackage,
  semgrepFindings: SemgrepFinding[],
  npmAuditFindings: NpmAuditFinding[],
): string {
  const auditLabel =
    pkg.ecosystem === "pypi"
      ? "OSV PyPI advisory lookup"
      : pkg.ecosystem === "cargo"
        ? "OSV crates.io advisory lookup"
        : pkg.ecosystem === "oci"
          ? "OCI image dependency audit"
        : "npm audit";
  const semgrepContext = semgrepFindings.length > 0
    ? semgrepFindings
        .slice(0, 30)
        .map((f, i) => `  ${i + 1}. [${f.severity}] ${f.ruleId} — ${f.path}:${f.startLine}: ${f.message}`)
        .join("\n")
    : "  None.";

  const npmContext = npmAuditFindings.length > 0
    ? npmAuditFindings
        .slice(0, 30)
        .map((f, i) => `  ${i + 1}. [${f.severity}] ${f.name}: ${f.title}`)
        .join("\n")
    : "  None.";

  return `Audit the ${pkg.ecosystem === "pypi" ? "PyPI package" : pkg.ecosystem === "cargo" ? "crates.io crate" : pkg.ecosystem === "oci" ? "OCI image" : "npm package"} at ${pkg.path} (${pkg.name}@${pkg.version}).

Read the source code, look for: prototype pollution, ReDoS, path traversal, injection, unsafe deserialization, missing validation. Map data flow from untrusted input to sensitive operations. Report any security findings with severity and PoC suggestions.

The static scanner already found these leads:
${semgrepContext}

${auditLabel} found these advisories:
${npmContext}

For EACH confirmed vulnerability, output a block in this exact format:

---FINDING---
title: <clear title>
severity: <critical|high|medium|low|info>
category: <prototype-pollution|redos|path-traversal|command-injection|code-injection|unsafe-deserialization|ssrf|information-disclosure|missing-validation|other>
description: <detailed description of the vulnerability, how to exploit it, and suggested PoC>
file: <path/to/file.js:lineNumber>
---END---

Output as many ---FINDING--- blocks as needed. Be precise and honest about severity.`;
}

/**
 * Build a prompt that includes the actual source code for direct API analysis.
 */
function buildDirectApiAuditPrompt(
  pkg: InstalledPackage,
  semgrepFindings: SemgrepFinding[],
  npmAuditFindings: NpmAuditFinding[],
): string {
  const auditLabel =
    pkg.ecosystem === "pypi"
      ? "OSV PyPI advisory lookup"
      : pkg.ecosystem === "cargo"
        ? "OSV crates.io advisory lookup"
        : pkg.ecosystem === "oci"
          ? "OCI image dependency audit"
        : "npm audit";
  const sourceFiles = collectScopeFiles(pkg.path);
  const sourceBlocks: string[] = [];
  let totalChars = 0;
  const MAX_CHARS = 150_000; // stay well within context window

  for (const filePath of sourceFiles) {
    if (totalChars >= MAX_CHARS) break;
    try {
      const content = readFileSync(filePath, "utf-8");
      const rel = relative(pkg.path, filePath);
      const block = `--- FILE: ${rel} ---\n${content}\n--- END FILE ---`;
      totalChars += block.length;
      sourceBlocks.push(block);
    } catch {
      // skip unreadable files
    }
  }

  const semgrepContext = semgrepFindings.length > 0
    ? semgrepFindings
        .slice(0, 30)
        .map((f, i) => `  ${i + 1}. [${f.severity}] ${f.ruleId} — ${f.path}:${f.startLine}: ${f.message}`)
        .join("\n")
    : "  None.";

  const npmContext = npmAuditFindings.length > 0
    ? npmAuditFindings
        .slice(0, 30)
        .map((f, i) => `  ${i + 1}. [${f.severity}] ${f.name}: ${f.title}`)
        .join("\n")
    : "  None.";

  return `You are a security researcher performing an authorized source code audit of the ${pkg.ecosystem === "pypi" ? "PyPI package" : pkg.ecosystem === "cargo" ? "crates.io crate" : pkg.ecosystem === "oci" ? "OCI image" : "npm package"} "${pkg.name}@${pkg.version}".

## Static scanner findings:
${semgrepContext}

## ${auditLabel} advisories:
${npmContext}

## Source code:

${sourceBlocks.join("\n\n")}

## Instructions

Analyze the source code above for security vulnerabilities. Look for:
- Prototype pollution (object merge/extend without hasOwnProperty checks, __proto__ access)
- ReDoS (regex with nested quantifiers, user input in new RegExp())
- Path traversal (user-supplied paths without normalization)
- Command/code injection (exec/eval with user input)
- Unsafe deserialization
- SSRF (HTTP requests with user-controlled URLs)
- Information disclosure (hardcoded credentials, debug modes)
- Missing input validation

For EACH confirmed vulnerability, output a block in this exact format:

---FINDING---
title: <clear title>
severity: <critical|high|medium|low|info>
category: <prototype-pollution|redos|path-traversal|command-injection|code-injection|unsafe-deserialization|ssrf|information-disclosure|missing-validation|other>
description: <detailed description of the vulnerability, how to exploit it, and suggested PoC>
file: <path/to/file.js:lineNumber>
---END---

Output as many ---FINDING--- blocks as needed. If there are no real vulnerabilities, output none.
Be precise and honest about severity — only report real, exploitable issues.`;
}

/**
 * Per-file variant of `buildDirectApiAuditPrompt`: embeds ONE file's source
 * verbatim and asks for findings scoped to that file. Used by the per-file
 * audit loop (#285) so the single-shot fallback path no longer dumps all
 * 50 files into a single prompt the model can't actually walk.
 */
export function buildDirectApiAuditPromptForFile(
  pkg: InstalledPackage,
  filePath: string,
  semgrepFindings: SemgrepFinding[],
  npmAuditFindings: NpmAuditFinding[],
): string {
  const auditLabel =
    pkg.ecosystem === "pypi"
      ? "OSV PyPI advisory lookup"
      : pkg.ecosystem === "cargo"
        ? "OSV crates.io advisory lookup"
        : pkg.ecosystem === "oci"
          ? "OCI image dependency audit"
        : "npm audit";

  const fileRel = relative(pkg.path, filePath);
  let sourceBlock = "";
  try {
    const content = readFileSync(filePath, "utf-8");
    sourceBlock = `--- FILE: ${fileRel} ---\n${content}\n--- END FILE ---`;
  } catch {
    sourceBlock = `--- FILE: ${fileRel} ---\n[unreadable]\n--- END FILE ---`;
  }

  // Filter static scanner hits to this file (mirrors researchPromptSingleFile).
  const relevantSemgrep = semgrepFindings.filter(
    (f) => f.path === fileRel || f.path.endsWith(fileRel) || fileRel.endsWith(f.path),
  );
  const semgrepContext = relevantSemgrep.length > 0
    ? relevantSemgrep
        .slice(0, 30)
        .map((f, i) => `  ${i + 1}. [${f.severity}] ${f.ruleId} — ${f.path}:${f.startLine}: ${f.message}`)
        .join("\n")
    : "  None for this file.";

  const npmContext = npmAuditFindings.length > 0
    ? npmAuditFindings
        .slice(0, 10)
        .map((f, i) => `  ${i + 1}. [${f.severity}] ${f.name}: ${f.title}`)
        .join("\n")
    : "  None.";

  return `You are a security researcher performing an authorized source code audit of the ${pkg.ecosystem === "pypi" ? "PyPI package" : pkg.ecosystem === "cargo" ? "crates.io crate" : pkg.ecosystem === "oci" ? "OCI image" : "npm package"} "${pkg.name}@${pkg.version}".

You are analyzing ONE FILE: ${fileRel}

## Static scanner findings (this file):
${semgrepContext}

## ${auditLabel} advisories (package-level context):
${npmContext}

## Source code:

${sourceBlock}

## Instructions

Analyze ONLY the source above for vulnerabilities. Look for prototype pollution, ReDoS, path traversal, command/code injection, unsafe deserialization, SSRF, information disclosure, missing input validation.

For EACH confirmed vulnerability in THIS file, output a block in this exact format:

---FINDING---
title: <clear title>
severity: <critical|high|medium|low|info>
category: <prototype-pollution|redos|path-traversal|command-injection|code-injection|unsafe-deserialization|ssrf|information-disclosure|missing-validation|other>
description: <detailed description of the vulnerability, how to exploit it, and suggested PoC>
file: <path/to/file.js:lineNumber>
---END---

Output as many ---FINDING--- blocks as needed. If there are no real vulnerabilities, output none.
Be precise and honest about severity — only report real, exploitable issues.`;
}

// ── Per-file audit orchestration (#285) ──

export interface PerFileAuditOptions {
  pkg: InstalledPackage;
  files: string[];
  semgrepFindings: SemgrepFinding[];
  npmAuditFindings: NpmAuditFinding[];
  targetLabel: string;
  advisoryLabel: string;
  /** Per-file agent invoker. Production wires this to runAnalysisAgent;
   *  tests can pass a counting stub to verify the loop shape. */
  invoke: (perFile: {
    fileAbs: string;
    fileRel: string;
    systemPrompt: string;
    cliSystemPrompt: string;
    directApiPrompt: string;
  }) => Promise<{
    findings: Finding[];
    usage?: { inputTokens: number; outputTokens: number };
    estimatedCostUsd?: number;
  }>;
  /** Optional emit hook for per-file lifecycle progress events. */
  onFileStart?: (fileRel: string, index: number, total: number) => void;
  /** Optional handler for per-file errors — does not abort the loop. */
  onFileError?: (fileRel: string, error: Error) => void;
}

/**
 * Runs the per-file audit loop. One agent session per file, findings
 * aggregated and usage / cost summed.
 *
 * Reference pattern: `pov-gate.ts:367 buildPovSystemPrompt` — one finding /
 * file per agent session, deterministic outer loop. Closes #285 Fix 3.
 *
 * Replaces the prior "dump all 50 files into one prompt" behavior of the
 * single-shot fallback at audit.ts:388. With per-file iteration:
 *   - Coverage is deterministic — N files → N invocations
 *   - One file's runtime failure is isolated, the rest still run
 *   - Per-file token budget is independent
 */
export async function runPerFileAudit(
  opts: PerFileAuditOptions,
): Promise<{
  findings: Finding[];
  usage?: { inputTokens: number; outputTokens: number };
  estimatedCostUsd?: number;
}> {
  const aggregated: Finding[] = [];
  let totalInputTokens = 0;
  let totalOutputTokens = 0;
  let totalCost = 0;
  let usageObserved = false;

  for (let i = 0; i < opts.files.length; i++) {
    const fileAbs = opts.files[i];
    const fileRel = relative(opts.pkg.path, fileAbs);
    const filePrompt = researchPromptSingleFile(
      opts.pkg.path,
      fileRel,
      opts.semgrepFindings.map(f => ({ ruleId: f.ruleId, message: f.message, path: f.path, startLine: f.startLine })),
      opts.npmAuditFindings.map(f => ({ name: f.name, severity: f.severity, title: f.title })),
      `${opts.targetLabel} ${opts.pkg.name}@${opts.pkg.version}`,
      opts.advisoryLabel,
    );
    const cliSystemPrompt = `You are a security researcher analyzing the single file ${fileRel} from ${opts.pkg.name}@${opts.pkg.version}. For EACH vulnerability you find in THIS file, output it using the exact ---FINDING--- / ---END--- format. Do NOT analyze other files. If you find no vulnerabilities, say 'No vulnerabilities found.' and nothing else.`;
    const directApiPrompt = buildDirectApiAuditPromptForFile(
      opts.pkg,
      fileAbs,
      opts.semgrepFindings,
      opts.npmAuditFindings,
    );

    opts.onFileStart?.(fileRel, i, opts.files.length);

    try {
      const perFileResult = await opts.invoke({
        fileAbs,
        fileRel,
        systemPrompt: filePrompt,
        cliSystemPrompt,
        directApiPrompt,
      });
      aggregated.push(...perFileResult.findings);
      if (perFileResult.usage) {
        totalInputTokens += perFileResult.usage.inputTokens ?? 0;
        totalOutputTokens += perFileResult.usage.outputTokens ?? 0;
        usageObserved = true;
      }
      if (typeof perFileResult.estimatedCostUsd === "number") {
        totalCost += perFileResult.estimatedCostUsd;
      }
    } catch (err) {
      // One file's runtime failure must not abort the whole audit pass.
      const e = err instanceof Error ? err : new Error(String(err));
      opts.onFileError?.(fileRel, e);
    }
  }

  return {
    findings: aggregated,
    usage: usageObserved ? { inputTokens: totalInputTokens, outputTokens: totalOutputTokens } : undefined,
    estimatedCostUsd: totalCost > 0 ? totalCost : undefined,
  };
}

/**
 * Run an AI agent to analyze static scanner findings and hunt for additional
 * vulnerabilities in the package source code.
 *
 * Delegates to the unified runAnalysisAgent with audit-specific prompts.
 * When `perItemOrchestration` is on (default), walks files via
 * `runPerFileAudit` rather than dumping all of them into a single prompt.
 */
async function runAuditAgent(
  pkg: InstalledPackage,
  semgrepFindings: SemgrepFinding[],
  npmAuditFindings: NpmAuditFinding[],
  db: any,
  scanId: string,
  config: AuditConfig,
  emit: ScanListener,
): Promise<{ findings: Finding[]; usage?: { inputTokens: number; outputTokens: number }; estimatedCostUsd?: number }> {
  const targetLabel = pkg.ecosystem === "pypi" ? "PyPI package" : pkg.ecosystem === "cargo" ? "crates.io crate" : pkg.ecosystem === "oci" ? "OCI image" : "npm package";
  const advisoryLabel = pkg.ecosystem === "pypi" ? "OSV PyPI advisory lookup" : pkg.ecosystem === "cargo" ? "OSV crates.io advisory lookup" : pkg.ecosystem === "oci" ? "OCI image dependency audit" : "npm audit";
  const sharedCliSystemPrompt = `You are a security researcher performing an authorized ${pkg.ecosystem === "pypi" ? "PyPI" : pkg.ecosystem === "cargo" ? "crates.io" : pkg.ecosystem === "oci" ? "OCI image" : "npm"} package audit. Be thorough and precise. Only report real, exploitable vulnerabilities.`;

  // Per-file audit loop (#285). When `perItemOrchestration` is on, walk the
  // package's source files and invoke the audit agent once per file with
  // a focused per-file system prompt. Replaces the prior "dump all 50
  // files into one prompt" single-shot fallback at audit.ts:388.
  if (agentFeatures.perItemOrchestration) {
    const sourceFiles = collectScopeFiles(pkg.path);
    if (sourceFiles.length > 0) {
      return runPerFileAudit({
        pkg,
        files: sourceFiles,
        semgrepFindings,
        npmAuditFindings,
        targetLabel,
        advisoryLabel,
        invoke: ({ systemPrompt, cliSystemPrompt, directApiPrompt }) =>
          runAnalysisAgent({
            role: "audit",
            scopePath: pkg.path,
            target: `${pkg.ecosystem}:${pkg.name}@${pkg.version}`,
            scanId,
            config,
            db,
            emit,
            cliPrompt: buildCliAuditPrompt(pkg, semgrepFindings, npmAuditFindings),
            agentSystemPrompt: systemPrompt,
            cliSystemPrompt,
            directApiPrompt,
          }),
        onFileStart: (fileRel, i, total) => {
          emit({
            type: "stage:start",
            stage: "attack",
            message: `Auditing file ${i + 1}/${total}: ${fileRel}`,
          });
        },
        onFileError: (fileRel, err) => {
          emit({
            type: "error",
            stage: "attack",
            message: `Per-file audit failed (${fileRel}): ${err.message}`,
          });
        },
      });
    }
    // No source files (e.g. a binary OCI layer or empty install). Fall
    // through to the legacy single-shot path so the agent can still do a
    // package-metadata-level pass.
  }

  return runAnalysisAgent({
    role: "audit",
    scopePath: pkg.path,
    target: `${pkg.ecosystem}:${pkg.name}@${pkg.version}`,
    scanId,
    config,
    db,
    emit,
    cliPrompt: buildCliAuditPrompt(pkg, semgrepFindings, npmAuditFindings),
    agentSystemPrompt: auditAgentPrompt(
      pkg.name,
      pkg.version,
      pkg.path,
      semgrepFindings,
      npmAuditFindings,
      targetLabel,
      advisoryLabel,
    ),
    cliSystemPrompt: sharedCliSystemPrompt,
    directApiPrompt: buildDirectApiAuditPrompt(pkg, semgrepFindings, npmAuditFindings),
  });
}

/**
 * Transitive supply-chain pass (issue #565). npm-only — walks the resolved
 * `node_modules` tree, runs the deterministic malicious-package oracles over
 * each transitive dependency (budget-bounded, deduped, attributed), and runs a
 * dependency-confusion check over the audited root + any dependency whose name
 * matches the configured internal scopes/names.
 *
 * Findings are run through the same package-audit suppressor as agent findings
 * so benign install hooks / known binary-bootstrap deps (esbuild &c.) don't
 * flood the report once the whole tree is in scope.
 */
export async function runSupplyChainScan(
  pkg: InstalledPackage,
  config: AuditConfig,
  emit: ScanListener,
): Promise<Finding[]> {
  if (pkg.ecosystem !== "npm") return [];

  const findings: Finding[] = [];
  const internalScopes = config.internalScopes ?? [];
  const internalPackages = config.internalPackages ?? [];

  // 1. Transitive source-audit of the resolved dependency tree.
  const budget = config.transitiveAuditBudget ?? undefined; // undefined → module default
  if (budget === undefined || budget > 0) {
    emit({
      type: "stage:start",
      stage: "discovery",
      message: "Walking resolved dependency tree for transitive supply-chain audit...",
    });
    const tree = walkInstalledNpmTree(pkg.tempDir, pkg.name);
    const result = scanTransitiveDependencies({
      rootName: pkg.name,
      packages: tree,
      maxPackages: budget,
    });
    const cleaned = postProcessPackageAuditFindings(result.findings);
    findings.push(...cleaned);
    emit({
      type: "stage:end",
      stage: "discovery",
      message:
        `Transitive supply-chain audit: ${cleaned.length} finding${cleaned.length === 1 ? "" : "s"} ` +
        `across ${result.scanned} transitive package${result.scanned === 1 ? "" : "s"}` +
        (result.skipped > 0 ? ` (${result.skipped} skipped — budget exhausted)` : ""),
    });

    // 2. Dependency-confusion: probe the public registry for internal names.
    if (internalScopes.length > 0 || internalPackages.length > 0) {
      // Candidate set: the audited root + every distinct transitive dep whose
      // name the org claims as internal. Cheap allow-list filter first so we
      // only hit the network for the handful of internal names.
      const candidates = new Map<string, { name: string; version: string }>();
      const consider = (name: string, version: string) => {
        if (isInternalPackageName(name, internalScopes, internalPackages)) {
          candidates.set(name, { name, version });
        }
      };
      consider(pkg.name, pkg.version);
      for (const dep of tree) consider(dep.name, dep.version);

      if (candidates.size > 0) {
        emit({
          type: "stage:start",
          stage: "discovery",
          message: `Dependency-confusion check for ${candidates.size} internal package name${candidates.size === 1 ? "" : "s"}...`,
        });
        const confusionFindings = (
          await Promise.all(
            [...candidates.values()].map((c) =>
              checkDependencyConfusion({
                packageName: c.name,
                version: c.version,
                internalScopes,
                internalPackages,
                probe: (name) => probePublicNpmRegistry(name),
                attribution:
                  c.name === pkg.name
                    ? { relation: "direct", package: `${pkg.name}@${pkg.version}`, depth: 0 }
                    : { relation: "transitive", package: `${c.name}@${c.version}` },
              }),
            ),
          )
        ).filter((f): f is Finding => f !== null);
        findings.push(...confusionFindings);
        emit({
          type: "stage:end",
          stage: "discovery",
          message: `Dependency-confusion check: ${confusionFindings.length} risk${confusionFindings.length === 1 ? "" : "s"} flagged`,
        });
      }
    }
  }

  return findings;
}

/**
 * Main entry point: audit an npm package for security vulnerabilities.
 *
 * Pipeline:
 * 1. npm install <package>@latest in a temp dir
 * 2. Run static scanner with security rules
 * 3. AI agent analyzes static scanner findings + hunts for additional vulns
 * 4. Generate report with severity and PoC suggestions
 * 5. Persist to pwnkit DB
 */
export async function packageAudit(
  opts: PackageAuditOptions,
): Promise<AuditReport & { usage?: { inputTokens: number; outputTokens: number }; estimatedCostUsd?: number }> {
  const { config, onEvent } = opts;
  const emit: ScanListener = onEvent ?? (() => {});
  const startTime = Date.now();
  const ecosystem = config.ecosystem ?? "npm";

  // Step 1: Install package
  const pkg = installPackageForEcosystem(ecosystem, config.package, config.version, emit);

  // Initialize DB and create scan record
  const db = await (async () => { try { const { pwnkitDB } = await import("@pwnkit/db"); return new pwnkitDB(config.dbPath); } catch { return null as any; } })() as any;
  const scanConfig: ScanConfig = {
    target: `${pkg.ecosystem}:${pkg.name}@${pkg.version}`,
    depth: config.depth,
    format: config.format,
    runtime: config.runtime ?? "api",
    mode: "deep",
  };
  const scanId = db?.createScan(scanConfig) ?? "no-db";

  try {
    // Step 2: dependency audit + static scanner scan
    const npmAuditFindings = mergeAdvisories(
      runDependencyAuditForEcosystem(pkg.ecosystem, pkg.tempDir, emit, {
        name: pkg.name,
        version: pkg.version,
      }),
      await queryOsvAdvisories(pkg.name, pkg.version, pkg.ecosystem, emit),
    );
    const staticScannerName = selectedStaticScanner() === "foxguard" ? "foxguard" : "semgrep";
    const semgrepFindings = runSelectedStaticScan(pkg.path, emit, { noGitIgnore: true });
    const advisoryFinding = summarizeKnownAdvisoriesFinding(pkg, npmAuditFindings);

    // Step 2.5: Deterministic malicious-package oracles. These run before
    // the LLM, do not depend on the model, and catch the supply-chain
    // attack patterns the LLM prompt is structurally blind to: typosquats,
    // install-script payloads, credential-theft hooks. Their findings are
    // appended to the report alongside the agent findings.
    const maliciousFindings =
      pkg.ecosystem === "npm"
        ? (() => {
            emit({
              type: "stage:start",
              stage: "discovery",
              message: "Running deterministic malicious-package oracles...",
            });
            const findings = scanForMaliciousPatterns({
              packageName: pkg.name,
              packagePath: pkg.path,
            });
            emit({
              type: "stage:end",
              stage: "discovery",
              message: `Malicious-package oracles: ${findings.length} finding${findings.length === 1 ? "" : "s"}`,
            });
            return findings;
          })()
        : [];

    // Step 2.6: Transitive supply-chain audit + dependency-confusion (#565).
    // Walks the resolved dependency tree and source-audits transitive deps —
    // the event-stream class of attack the root-only scan is blind to — plus a
    // namespace-substitution check for configured internal scopes/names.
    const supplyChainFindings = await runSupplyChainScan(pkg, config, emit);

    // Step 3: AI agent analysis
    const agentResult = await runAuditAgent(
      pkg,
      semgrepFindings,
      npmAuditFindings,
      db,
      scanId,
      config,
      emit,
    );
    const agentFindings = postProcessPackageAuditFindings(agentResult.findings);

    // Combine deterministic + LLM findings into the final report set.
    // Deterministic findings come FIRST so they're prominent in the
    // report ordering — they're higher confidence than LLM output.
    const findings = [
      ...(advisoryFinding ? [advisoryFinding] : []),
      ...maliciousFindings,
      ...supplyChainFindings,
      ...agentFindings,
    ];

    // Step 4: Build report
    const durationMs = Date.now() - startTime;
    const summary = {
      totalAttacks: semgrepFindings.length + npmAuditFindings.length,
      totalFindings: findings.length,
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      info: findings.filter((f) => f.severity === "info").length,
    };

    db?.completeScan(scanId, summary);

    emit({
      type: "stage:end",
      stage: "report",
      message: `Audit complete: ${summary.totalFindings} findings (${npmAuditFindings.length} dependency advisories, ${semgrepFindings.length} ${staticScannerName} static findings)`,
    });

    const report: AuditReport & { usage?: { inputTokens: number; outputTokens: number }; estimatedCostUsd?: number } = {
      package: pkg.name,
      version: pkg.version,
      ecosystem: pkg.ecosystem,
      startedAt: new Date(startTime).toISOString(),
      completedAt: new Date().toISOString(),
      durationMs,
      semgrepFindings: semgrepFindings.length,
      npmAuditFindings,
      summary,
      findings,
      usage: agentResult.usage,
      estimatedCostUsd: agentResult.estimatedCostUsd,
    };

    return report;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    db?.failScan(scanId, msg);
    throw err;
  } finally {
    db?.close();
    // Clean up temp directory
    try {
      rmSync(pkg.tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  }
}
