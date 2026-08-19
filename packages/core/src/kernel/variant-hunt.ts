import { execFile } from "node:child_process";
import { randomUUID, createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { promises as fsp } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { promisify } from "node:util";
import type { AttackCategory, Finding, ScanWarning, Severity } from "@0sec/shared";
import {
  detectFoxguard,
  inferCategoryFromRule,
  parseFoxguardSarif,
  type FoxguardFinding,
} from "../triage/multi-modal.js";
import { SUBSYSTEM_PATTERNS } from "../ingest/kernel-crash.js";
import {
  matchPatternByRuleId,
  matchPatternsBySourceHints,
  type DirtyFragPattern,
} from "./dirty-frag-patterns.js";

const execFileAsync = promisify(execFile);

export interface KernelVariantHuntOptions {
  /** Linux source tree to scan. */
  tree: string;
  /** Advisory URL or local advisory path. Kept as provenance, not parsed yet. */
  advisory?: string;
  /** Optional foxguard rule directory, for example rules/kernel/dirty-frag-class. */
  rules?: string;
  /** Override foxguard binary path. */
  foxguardPath?: string;
  /** Read pre-produced SARIF instead of invoking foxguard. Useful for tests and cached runs. */
  sarifPath?: string;
  /** Override the execFile runner for tests. */
  runner?: (
    file: string,
    args: string[],
  ) => Promise<{ stdout: string; stderr: string }>;
  /** Foxguard wall-clock timeout in milliseconds. Default 120s. */
  timeoutMs?: number;
}

export interface KernelVariantHuntReport {
  tree: string;
  advisory?: string;
  rules?: string;
  foxguardPath?: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  foxguardFindings: FoxguardFinding[];
  findings: Finding[];
  warnings: ScanWarning[];
}

function advisorySlug(advisory?: string): string {
  if (!advisory) return "kernel-variant";
  const base = basename(advisory.replace(/[?#].*$/, "")).replace(/\.[^.]+$/, "");
  const slug = base
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug || "kernel-variant";
}

function normaliseRuleId(ruleId: string): string {
  return ruleId
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, "-")
    .replace(/^-+|-+$/g, "") || "unknown-rule";
}

function shortHash(input: string): string {
  return createHash("sha256").update(input).digest("hex").slice(0, 16);
}

function inferSubsystem(file: string, message: string): string {
  const lower = `${file} ${message}`.toLowerCase();
  if (lower.includes("net/tcp") || lower.includes("net/ipv4/tcp")) return "net/tcp";
  if (lower.includes("net/udp") || lower.includes("net/ipv4/udp")) return "net/udp";
  if (lower.includes("net/ipv4/") || lower.includes("net/ipv6/")) return "net/ip";
  if (lower.includes("net/netfilter/")) return "net/netfilter";
  if (lower.includes("net/sctp/")) return "net/sctp";
  if (lower.includes("net/wireless/")) return "net/wireless";
  if (lower.includes("net/") || lower.includes("rxrpc") || lower.includes("macsec")) return "net/core";
  if (lower.includes("crypto/")) return "crypto";
  if (lower.includes("drivers/usb/")) return "drivers/usb";
  if (lower.includes("drivers/bluetooth/")) return "drivers/bluetooth";
  if (lower.includes("drivers/gpu/")) return "drivers/gpu";
  if (lower.includes("fs/nfsd/")) return "fs/nfsd";
  if (lower.includes("fs/ext4/")) return "fs/ext4";
  if (lower.includes("fs/btrfs/")) return "fs/btrfs";
  if (lower.includes("fs/xfs/")) return "fs/xfs";
  if (lower.includes("io_uring/")) return "io_uring";
  if (lower.includes("kernel/sched/")) return "kernel/sched";
  if (lower.includes("kernel/cgroup/")) return "kernel/cgroup";
  if (lower.includes("mm/")) return "mm";
  if (lower.includes("block/")) return "block";
  if (lower.includes("security/")) return "security";
  for (const [pattern, subsystem] of SUBSYSTEM_PATTERNS) {
    if (pattern.test(lower)) return subsystem;
  }
  return "unknown";
}

function isPageCacheWritePrimitive(input: string): boolean {
  const text = input.toLowerCase();
  const hasPageCacheSource =
    /page[-_ ]?cache|copy[-_ ]?fail|dirty[-_ ]?pipe|dirty[-_ ]?cow/.test(text) ||
    /find_get_page|filemap_get_folio|grab_cache_page|read_mapping_page|pagecache_get_page/.test(text) ||
    /pipe_buffer\.?page|\bsplice\b|struct page|struct folio/.test(text);
  const hasWriteSink =
    /write|corrupt|memcpy|memset|kmap|kmap_local_page|sg_set_page|dma|crypto|in[-_ ]?place/.test(text);
  const hasMissingProof =
    /without|missing|lack|no ownership|no cow|exclusive|page_count|page_ref_count|folio_ref_count|folio_lock|folio_test_uptodate|pageprivate|pagewriteback|page_mkwrite|copy_highpage|copy_user_highpage/.test(text);

  return hasPageCacheSource && hasWriteSink && hasMissingProof;
}

function inferVariantCategory(finding: FoxguardFinding): AttackCategory {
  const text = `${finding.ruleId} ${finding.message}`;
  if (isPageCacheWritePrimitive(text)) return "other";

  const inferred = finding.category ?? inferCategoryFromRule(finding.ruleId, finding.message);
  if (inferred) return inferred;

  const lowerText = text.toLowerCase();
  if (
    /dirty[-_ ]?frag|copy[-_ ]?on[-_ ]?write|\bcow\b|shared[-_ ]?frag|in[-_ ]?place/.test(lowerText)
  ) {
    return "information-disclosure";
  }
  if (/uaf|use[-_ ]?after[-_ ]?free/.test(lowerText)) return "use-after-free";
  if (/overflow|oob|out[-_ ]?of[-_ ]?bounds/.test(lowerText)) return "heap-overflow";
  if (/race|toctou/.test(lowerText)) return "race-condition";
  return "information-disclosure";
}

function severityForVariant(finding: FoxguardFinding, subsystem: string): Severity {
  const text = `${finding.ruleId} ${finding.message}`;
  if (finding.level === "error") return "high";
  if (isPageCacheWritePrimitive(text)) return "high";
  if (finding.level === "note") return "low";
  if (subsystem.startsWith("net/") || subsystem === "crypto") return "high";
  return "medium";
}

function commandSummary(tree: string, rules?: string): string {
  const parts = ["foxguard", "scan", tree];
  if (rules) parts.push("--rules", rules);
  parts.push("--format", "sarif");
  return parts.join(" ");
}

/**
 * Build the dirty-frag pattern enrichment section for a finding's analysis.
 * Returns an empty string if no pattern matches.
 */
function dirtyFragPatternAnalysis(pattern: DirtyFragPattern): string {
  const lines = [
    `Dirty-frag pattern: ${pattern.name} (${pattern.id})`,
    `Trigger: ${pattern.triggerConditions.join("; ")}`,
    `Mitigations: ${pattern.mitigations.join(", ")}`,
  ];
  if (pattern.kernelConfigDeps.length > 0) {
    lines.push(`Kernel config deps: ${pattern.kernelConfigDeps.join(", ")}`);
  }
  if (pattern.knownCves.length > 0) {
    lines.push(`Known CVEs: ${pattern.knownCves.join(", ")}`);
  }
  return lines.join("\n");
}

export function foxguardFindingToKernelVariantFinding(args: {
  finding: FoxguardFinding;
  tree: string;
  advisory?: string;
  rules?: string;
}): Finding {
  const { finding, tree, advisory, rules } = args;
  const subsystem = inferSubsystem(finding.file, finding.message);
  const category = inferVariantCategory(finding);
  const line = finding.startLine ? `:${finding.startLine}` : "";
  const advisoryId = advisorySlug(advisory);
  const fingerprint = shortHash([
    advisoryId,
    finding.ruleId,
    finding.file,
    finding.startLine ?? "",
    finding.message,
  ].join("\n"));

  // Try to match a dirty-frag pattern by rule-id first, then by source hints.
  const pattern =
    matchPatternByRuleId(finding.ruleId) ??
    matchPatternsBySourceHints(finding.file, finding.message)[0];

  const patternSection = pattern ? dirtyFragPatternAnalysis(pattern) : "";
  // Boost confidence when a known dirty-frag pattern matches.
  const baseConfidence = subsystem === "unknown" ? 0.4 : 0.5;
  const confidence = pattern ? Math.min(baseConfidence + 0.15, 0.85) : baseConfidence;

  return {
    id: randomUUID(),
    templateId: `kernel-variant-${advisoryId}-${normaliseRuleId(finding.ruleId)}`,
    title: `Linux kernel variant candidate: ${finding.ruleId} in ${subsystem}`,
    description: [
      `Foxguard rule ${finding.ruleId} flagged ${finding.file}${line}.`,
      `Subsystem: ${subsystem}.`,
      pattern ? `Dirty-frag pattern: ${pattern.name}.` : "",
      advisory ? `Advisory provenance: ${advisory}.` : "",
      "This is a structural variant-hunt candidate, not a confirmed kernel crash; queue it for source triage, Coccinelle/CodeQL analysis, or fuzzing.",
    ].filter(Boolean).join("\n"),
    severity: severityForVariant(finding, subsystem),
    category,
    status: "discovered",
    evidence: {
      request: commandSummary(tree, rules),
      response: finding.message || "foxguard SARIF result",
      analysis: [
        "Source: foxguard SARIF",
        `Rule: ${finding.ruleId}`,
        `File: ${finding.file}${line}`,
        `Subsystem: ${subsystem}`,
        `Category: ${category}`,
        `Variant status: suspect`,
        advisory ? `Advisory: ${advisory}` : "",
        rules ? `Rule root: ${rules}` : "",
        patternSection,
      ].filter(Boolean).join("\n"),
    },
    fingerprint,
    triageStatus: "new",
    confidence,
    timestamp: Date.now(),
  };
}

function ensureDirectory(path: string, label: string): string {
  const resolved = resolve(path);
  let stat;
  try {
    stat = statSync(resolved);
  } catch {
    throw new Error(`${label} not found: ${resolved}`);
  }
  if (!stat.isDirectory()) {
    throw new Error(`${label} must be a directory: ${resolved}`);
  }
  return resolved;
}

async function runFoxguardSarifScan(args: {
  tree: string;
  rules?: string;
  foxguardPath?: string;
  runner?: KernelVariantHuntOptions["runner"];
  timeoutMs?: number;
}): Promise<{ sarifText: string; foxguardPath: string }> {
  const foxguardPath = args.foxguardPath ?? (await detectFoxguard());
  if (!foxguardPath) {
    throw new Error("foxguard not found; install foxguard or pass --foxguard <path>");
  }

  if (foxguardPath.includes("/") && !existsSync(foxguardPath)) {
    throw new Error(`foxguard binary not found: ${foxguardPath}`);
  }

  const outPath = join(
    tmpdir(),
    `0sec-kernel-variant-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.sarif`,
  );
  const cmdArgs = ["scan", args.tree];
  if (args.rules) cmdArgs.push("--rules", args.rules);
  cmdArgs.push("--format", "sarif", "--output", outPath);

  const runner =
    args.runner ??
    ((file: string, a: string[]) =>
      execFileAsync(file, a, { timeout: args.timeoutMs ?? 120_000 }));

  try {
    await runner(foxguardPath, cmdArgs);
  } catch (err) {
    if (!existsSync(outPath)) {
      throw new Error(`foxguard failed to run: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  try {
    return { sarifText: readFileSync(outPath, "utf8"), foxguardPath };
  } finally {
    fsp.unlink(outPath).catch(() => {});
  }
}

export async function runKernelVariantHunt(
  options: KernelVariantHuntOptions,
): Promise<KernelVariantHuntReport> {
  const startedAtMs = Date.now();
  const startedAt = new Date(startedAtMs).toISOString();
  const tree = ensureDirectory(options.tree, "kernel tree");
  const rules = options.rules ? ensureDirectory(options.rules, "foxguard rule root") : undefined;

  let sarifText: string;
  let foxguardPath = options.foxguardPath;
  const warnings: ScanWarning[] = [];

  if (options.sarifPath) {
    sarifText = readFileSync(resolve(options.sarifPath), "utf8");
    warnings.push({
      stage: "source-analysis",
      message: "Used pre-produced SARIF; foxguard was not invoked in this run.",
    });
  } else {
    const result = await runFoxguardSarifScan({
      tree,
      rules,
      foxguardPath: options.foxguardPath,
      runner: options.runner,
      timeoutMs: options.timeoutMs,
    });
    sarifText = result.sarifText;
    foxguardPath = result.foxguardPath;
  }

  const foxguardFindings = parseFoxguardSarif(sarifText);
  const findings = foxguardFindings.map((finding) =>
    foxguardFindingToKernelVariantFinding({
      finding,
      tree,
      advisory: options.advisory,
      rules,
    }),
  );

  if (findings.length === 0) {
    warnings.push({
      stage: "source-analysis",
      message: "No foxguard variant candidates found.",
    });
  }

  const completedAtMs = Date.now();
  return {
    tree,
    advisory: options.advisory,
    rules,
    foxguardPath,
    startedAt,
    completedAt: new Date(completedAtMs).toISOString(),
    durationMs: completedAtMs - startedAtMs,
    foxguardFindings,
    findings,
    warnings,
  };
}
