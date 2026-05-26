#!/usr/bin/env node

/**
 * Triage Training Data Collector
 *
 * Extracts (finding, ground_truth) pairs from pwnkit benchmark results.
 *
 * Sources:
 *   - XBOW results (ground truth = flag extraction)
 *   - Cybench results (ground truth = flag extraction)
 *   - npm-bench results (ground truth = package verdict: malicious/vulnerable/safe)
 *   - pwnkit SQLite DB (ground truth = blind verify status)
 *
 * For every sample we emit BOTH the raw text and the handcrafted
 * feature vector from `@pwnkit/core`'s `extractFeatures`. The feature vector
 * was inspired by the VulnBERT hybrid architecture (handcrafted features
 * fused with neural embeddings) and makes the dataset drop-in compatible
 * with either a pure-text classifier or a hybrid model.
 *
 * Output: JSONL file with one sample per line, fields:
 *   { text, features, label, label_text, source, confidence }
 *
 * Usage:
 *   tsx src/triage-data-collector.ts --db <path-to-pwnkit.db>
 *   tsx src/triage-data-collector.ts --results <xbow-latest.json>
 *   tsx src/triage-data-collector.ts --npm-bench <npm-bench-latest.json>
 *   tsx src/triage-data-collector.ts --scan-dir <dir-of-scan-dbs>
 *   tsx src/triage-data-collector.ts --results <xbow-latest.json> --output <dataset.jsonl>
 */

import { readFileSync, writeFileSync, existsSync, readdirSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createRequire } from "node:module";
import { extractFeatures, FEATURE_NAMES } from "@pwnkit/core";
import type { Finding, LayerVerdict } from "@pwnkit/shared";

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const args = process.argv.slice(2);

export const TRIAGE_FEATURE_COUNT = FEATURE_NAMES.length;

export interface TriageSample {
  /** Unique ID for dedup */
  id: string;
  /** The finding title */
  title: string;
  /** Finding description / analysis */
  description: string;
  /** Severity: critical, high, medium, low, informational */
  severity: string;
  /** Attack category: sqli, xss, idor, ssti, etc. */
  category: string;
  /** The PoC request (curl command, HTTP request, etc.) */
  request: string;
  /** The target's response to the PoC */
  response: string;
  /** Agent's analysis text */
  analysis: string;
  /** Agent-assigned confidence (0-1) */
  confidence: number;
  /** GROUND TRUTH: was this a real exploitable vulnerability? */
  label: "true_positive" | "false_positive";
  /** Source: which challenge / scan produced this */
  source: string;
  /** How we determined ground truth */
  label_source: "flag_extraction" | "blind_verify" | "manual" | "package_verdict";
  /**
   * Handcrafted feature vector (per FEATURE_NAMES order).
   * Computed via extractFeatures() — pure regex/string ops, no LLM, no network.
   * Inspired by the VulnBERT hybrid architecture: drop-in for either a
   * pure-text classifier or a fused features-plus-embeddings model.
   *
   * May be an all-zero vector if the source row was missing the fields
   * extractFeatures() needs (typically: legacy XBOW dumps without evidence).
   */
  features: number[];
  /**
   * Per-layer triage telemetry, ordered by execution. Empty for findings
   * collected from sources that predate pwnkit#112's instrumentation
   * (legacy XBOW/npm-bench JSONs, blind_verify rows from older scans).
   *
   * This is the supervision signal for the dynamic-routing model in
   * pwnkit#113: given the layer outcomes a finding accumulates, can a
   * cheaper subset of layers reach the same final verdict?
   */
  layer_verdicts: LayerVerdict[];
}

/**
 * Compute the feature vector for a finding-shaped object. Tolerates
 * partially-populated rows (legacy results files, npm audit findings
 * without an HTTP request/response, etc.) by defaulting missing fields
 * and falling back to an all-zero vector if extraction throws.
 */
/**
 * Pull layerVerdicts off a raw finding row, normalizing the cases where it's
 * absent (legacy data), already an array, or a JSON-stringified blob (some
 * SQLite hydration paths leave it as text). Always returns an array — empty
 * when no verdicts are present so the JSONL schema stays consistent.
 */
export function safeExtractLayerVerdicts(raw: any): LayerVerdict[] {
  const v = raw?.layerVerdicts ?? raw?.layer_verdicts;
  if (!v) return [];
  if (Array.isArray(v)) return v as LayerVerdict[];
  if (typeof v === "string") {
    try {
      const parsed = JSON.parse(v) as unknown;
      if (Array.isArray(parsed)) return parsed as LayerVerdict[];
    } catch {
      /* corrupt — drop */
    }
  }
  return [];
}

export function safeExtractFeatures(raw: any): number[] {
  try {
    const finding: Finding = {
      id: raw.id ?? "",
      templateId: raw.templateId ?? raw.template_id ?? "",
      title: raw.title ?? "",
      description: raw.description ?? "",
      severity: raw.severity ?? "medium",
      category: raw.category ?? "unknown",
      status: raw.status ?? "open",
      evidence: {
        request: raw.evidence?.request ?? raw.request ?? "",
        response: raw.evidence?.response ?? raw.response ?? "",
        analysis: raw.evidence?.analysis ?? raw.analysis ?? "",
        ...(raw.evidence ?? {}),
      },
      confidence: raw.confidence ?? 0.5,
      timestamp: raw.timestamp ?? Date.now(),
    } as Finding;
    return extractFeatures(finding);
  } catch {
    return new Array(FEATURE_NAMES.length).fill(0);
  }
}

function resolveInputPath(path: string): string {
  const normalized = path.startsWith("packages/benchmark/")
    ? path.slice("packages/benchmark/".length)
    : path;
  const candidates = [
    path,
    normalized,
    join(process.cwd(), path),
    join(process.cwd(), normalized),
    join(__dirname, "..", path),
    join(__dirname, "..", normalized),
  ];

  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }

  return path;
}

function resolveOutputPath(path: string): string {
  if (path.startsWith("/")) return path;
  return path.startsWith("packages/benchmark/")
    ? path.slice("packages/benchmark/".length)
    : path;
}

// ── Collect from XBOW results JSON ──

export function collectFromXbowResults(resultsPath: string): TriageSample[] {
  const resolved = resolveInputPath(resultsPath);
  const data = JSON.parse(readFileSync(resolved, "utf8"));
  const samples: TriageSample[] = [];

  for (const result of data.results ?? []) {
    const flagFound = result.flagFound === true;
    const challengeId = result.id ?? "unknown";

    // Each finding from this challenge gets labeled based on flag extraction
    for (const finding of result.findings ?? []) {
      samples.push({
        id: `${challengeId}-${finding.id ?? finding.templateId ?? Math.random().toString(36).slice(2)}`,
        title: finding.title ?? "",
        description: finding.description ?? "",
        severity: finding.severity ?? "medium",
        category: finding.category ?? "unknown",
        request: finding.evidence?.request ?? "",
        response: finding.evidence?.response ?? "",
        analysis: finding.evidence?.analysis ?? "",
        confidence: finding.confidence ?? 0.5,
        label: flagFound ? "true_positive" : "false_positive",
        source: challengeId,
        label_source: "flag_extraction",
        features: safeExtractFeatures(finding),
        layer_verdicts: safeExtractLayerVerdicts(finding),
      });
    }
  }

  return samples;
}

// ── Collect from npm-bench results JSON ──

/**
 * Pull (finding, ground_truth) rows from an npm-bench-latest.json file.
 *
 * Ground truth comes from the package's verdict in the benchmark's
 * curated test cases:
 *   - malicious / vulnerable → true_positive (the package is bad,
 *     so any finding the agent produced was meant to fire)
 *   - safe → false_positive (the package is clean, so any finding
 *     is by definition a false alarm)
 *
 * This is coarser than per-finding labels, but it gives us a real
 * supervised signal at zero labeling cost — and it's the same labeling
 * approximation that NVD/Socket/Phylum use to seed their training sets.
 */
export function collectFromNpmBench(resultsPath: string): TriageSample[] {
  const resolved = resolveInputPath(resultsPath);
  const data = JSON.parse(readFileSync(resolved, "utf8"));
  const samples: TriageSample[] = [];

  for (const result of data.results ?? []) {
    const verdict = result.verdict;
    const isBadPackage = verdict === "malicious" || verdict === "vulnerable";
    const label: "true_positive" | "false_positive" = isBadPackage
      ? "true_positive"
      : "false_positive";
    const pkg = result.pkg ?? "unknown";

    // npm-bench preserves the raw findings array on each case result.
    // Older runs (before this column was added) will have undefined here
    // and silently produce zero rows for that case.
    for (const finding of result.findings ?? []) {
      samples.push({
        id: `npm-${pkg}-${finding.id ?? finding.templateId ?? Math.random().toString(36).slice(2)}`,
        title: finding.title ?? "",
        description: finding.description ?? "",
        severity: finding.severity ?? "medium",
        category: finding.category ?? "unknown",
        request: finding.evidence?.request ?? "",
        response: finding.evidence?.response ?? "",
        analysis: finding.evidence?.analysis ?? "",
        confidence: finding.confidence ?? 0.5,
        label,
        source: `npm-bench:${pkg}:${verdict}`,
        label_source: "package_verdict",
        features: safeExtractFeatures(finding),
        layer_verdicts: safeExtractLayerVerdicts(finding),
      });
    }
  }

  return samples;
}

// ── Collect from pwnkit SQLite DB ──

function collectFromDb(dbPath: string): TriageSample[] {
  const resolved = resolveInputPath(dbPath);
  // Dynamic import to keep node-sqlite3-wasm off the benchmark's hot path.
  let Database: any;
  try {
    ({ Database } = require("node-sqlite3-wasm"));
  } catch {
    console.error("node-sqlite3-wasm not available, skipping DB collection");
    return [];
  }

  const db = new Database(resolved, { readOnly: true });
  const samples: TriageSample[] = [];

  try {
    // Get all scans with their findings. layerVerdicts is a JSON-stringified
    // array (pwnkit#112) — may be NULL on rows that predate the migration.
    const scans = db.prepare(`
      SELECT s.id as scan_id, s.target, s.mode,
             f.id as finding_id, f.title, f.description, f.severity,
             f.category, f.status, f.confidence,
             f.evidence_request, f.evidence_response, f.evidence_analysis,
             f.layerVerdicts as layer_verdicts
      FROM scans s
      JOIN findings f ON f.scan_id = s.id
      ORDER BY s.id
    `).all();

    for (const row of scans) {
      // Use finding status as ground truth from blind verify
      const isVerified = row.status === "verified" || row.status === "confirmed";
      const isFalsePositive = row.status === "false_positive" || row.status === "rejected";

      // Skip findings with unknown verification status
      if (!isVerified && !isFalsePositive) continue;

      samples.push({
        id: `db-${row.scan_id}-${row.finding_id}`,
        title: row.title ?? "",
        description: row.description ?? "",
        severity: row.severity ?? "medium",
        category: row.category ?? "unknown",
        request: row.evidence_request ?? "",
        response: row.evidence_response ?? "",
        analysis: row.evidence_analysis ?? "",
        confidence: row.confidence ?? 0.5,
        label: isVerified ? "true_positive" : "false_positive",
        source: `${row.target}-${row.scan_id}`,
        label_source: "blind_verify",
        features: safeExtractFeatures({
          id: row.finding_id,
          templateId: row.template_id,
          title: row.title,
          description: row.description,
          severity: row.severity,
          category: row.category,
          confidence: row.confidence,
          evidence: {
            request: row.evidence_request,
            response: row.evidence_response,
            analysis: row.evidence_analysis,
          },
        }),
        layer_verdicts: safeExtractLayerVerdicts(row),
      });
    }
  } catch (err) {
    console.error(`Error reading DB ${resolved}:`, err);
  } finally {
    db.close();
  }

  return samples;
}

// ── Scan directory for DB files ──

function collectFromScanDir(dirPath: string): TriageSample[] {
  const samples: TriageSample[] = [];
  const resolvedDir = resolveInputPath(dirPath);
  const files = readdirSync(resolvedDir).filter((f) => f.endsWith(".db"));

  for (const file of files) {
    const dbPath = join(resolvedDir, file);
    console.error(`  Collecting from ${file}...`);
    samples.push(...collectFromDb(dbPath));
  }

  return samples;
}

// ── Format for ML training ──

export function toTrainingFormat(sample: TriageSample): string {
  // Format as a text classification input
  // The model sees: [title] [description] [category] [severity] [request] [response]
  // and predicts: true_positive or false_positive
  const input = [
    `Title: ${sample.title}`,
    `Category: ${sample.category}`,
    `Severity: ${sample.severity}`,
    `Description: ${sample.description.slice(0, 500)}`,
    `Request: ${sample.request.slice(0, 1000)}`,
    `Response: ${sample.response.slice(0, 1000)}`,
    sample.analysis ? `Analysis: ${sample.analysis.slice(0, 500)}` : "",
  ]
    .filter(Boolean)
    .join("\n");

  return JSON.stringify({
    text: input,
    features: sample.features,
    layer_verdicts: sample.layer_verdicts,
    label: sample.label === "true_positive" ? 1 : 0,
    label_text: sample.label,
    source: sample.source,
    label_source: sample.label_source,
    confidence: sample.confidence,
  });
}

// ── Main ──

async function main() {
  const allSamples: TriageSample[] = [];

  // Collect from XBOW results
  const resultsIdx = args.indexOf("--results");
  if (resultsIdx !== -1) {
    const path = args[resultsIdx + 1];
    console.error(`Collecting from XBOW results: ${path}`);
    allSamples.push(...collectFromXbowResults(path));
  }

  // Collect from npm-bench results
  const npmBenchIdx = args.indexOf("--npm-bench");
  if (npmBenchIdx !== -1) {
    const path = args[npmBenchIdx + 1];
    console.error(`Collecting from npm-bench results: ${path}`);
    allSamples.push(...collectFromNpmBench(path));
  }

  // Collect from DB
  const dbIdx = args.indexOf("--db");
  if (dbIdx !== -1) {
    const path = args[dbIdx + 1];
    console.error(`Collecting from DB: ${path}`);
    allSamples.push(...collectFromDb(path));
  }

  // Collect from scan directory
  const dirIdx = args.indexOf("--scan-dir");
  if (dirIdx !== -1) {
    const path = args[dirIdx + 1];
    console.error(`Collecting from scan directory: ${path}`);
    allSamples.push(...collectFromScanDir(path));
  }

  // Also auto-collect from any benchmark results in the results directory.
  // Routed by filename so we use the right ground-truth source for each shape:
  //   *npm-bench*.json     → collectFromNpmBench (label by package verdict)
  //   anything else *.json → collectFromXbowResults (label by flagFound)
  const resultsDir = join(__dirname, "..", "results");
  if (existsSync(resultsDir) && resultsIdx === -1 && npmBenchIdx === -1) {
    const jsonFiles = readdirSync(resultsDir).filter((f) => f.endsWith(".json"));
    for (const file of jsonFiles) {
      const fullPath = join(resultsDir, file);
      if (file.includes("npm-bench")) {
        console.error(`  Auto-collecting from ${file} (npm-bench)...`);
        allSamples.push(...collectFromNpmBench(fullPath));
      } else {
        console.error(`  Auto-collecting from ${file} (xbow-shape)...`);
        allSamples.push(...collectFromXbowResults(fullPath));
      }
    }
  }

  // Dedup by ID
  const seen = new Set<string>();
  const unique = allSamples.filter((s) => {
    if (seen.has(s.id)) return false;
    seen.add(s.id);
    return true;
  });

  // Stats
  const tp = unique.filter((s) => s.label === "true_positive").length;
  const fp = unique.filter((s) => s.label === "false_positive").length;
  const total = tp + fp;
  const tpPct = total > 0 ? (tp / total * 100).toFixed(1) : "0.0";
  const fpPct = total > 0 ? (fp / total * 100).toFixed(1) : "0.0";

  console.error(`\n=== Triage Training Data ===`);
  console.error(`  Total samples:    ${unique.length}`);
  console.error(`  True positives:   ${tp}`);
  console.error(`  False positives:  ${fp}`);
  console.error(`  Balance:          ${tpPct}% TP / ${fpPct}% FP`);

  // Output JSONL to stdout
  const outputPath = args.includes("--output") ? args[args.indexOf("--output") + 1] : undefined;
  const lines = unique.map(toTrainingFormat);

  if (outputPath) {
    const resolvedOutput = resolveOutputPath(outputPath);
    const dir = dirname(resolvedOutput);
    if (dir && dir !== ".") mkdirSync(dir, { recursive: true });
    writeFileSync(resolvedOutput, lines.length > 0 ? lines.join("\n") + "\n" : "");
    console.error(`  Written to: ${resolvedOutput}`);
  } else {
    for (const line of lines) {
      console.log(line);
    }
  }
}

// Only run main() when invoked as a script, not when imported as a module
// (e.g. by the vitest test file). Guards against the test runner executing
// the CLI side-effects on import.
const isScript =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isScript) {
  main().catch((err) => {
    console.error("Triage data collection failed:", err);
    process.exit(1);
  });
}
