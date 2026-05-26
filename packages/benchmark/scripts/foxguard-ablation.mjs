#!/usr/bin/env node
/**
 * Foxguard ablation harness — pwnkit#254.
 *
 * Runs the same review slice under two static-analyzer profiles and
 * captures the metrics needed for the decision gate documented in
 * `docs/src/content/docs/research/foxguard-ablation/_template.md`:
 *
 *   - Total findings produced by the static stage
 *   - Pre-agent triage value: how many findings the agent confirms
 *     (status === "confirmed" after the verify wave)
 *   - Wall-clock time per slice
 *   - FP rate hand-label hook: emits per-finding JSON the operator can
 *     review and tag by hand
 *
 * This script is **manually triggered**. It does not run in CI. The
 * validation gate in the decision doc is the single source of truth on
 * whether Foxguard stays the default static lead generator; this harness
 * only produces the inputs.
 *
 * Slices (all locally checked-out under `bench-targets/`):
 *
 *   1. self-scan — `pwnkit` repo itself (TS/JS-heavy)
 *   2. xbow-bb-wave — one wave of XBOW BB from
 *      `0ca/xbow-validation-benchmarks-patched` (PHP-heavy)
 *   3. npm-bench-wave — first 9 packages from npm-bench (JS taint focus)
 *
 * Usage:
 *
 *   node packages/benchmark/scripts/foxguard-ablation.mjs \
 *     --slice self-scan \
 *     --xbow-path ../xbow-validation-benchmarks-patched \
 *     --npm-bench-cache /tmp/pwnkit-npm-bench-cache
 *
 *   node packages/benchmark/scripts/foxguard-ablation.mjs --slice all
 *
 * Output:
 *
 *   packages/benchmark/results/foxguard-ablation-YYYY-MM-DD.json
 *
 *   Each row carries:
 *     { slice, static: "semgrep" | "foxguard",
 *       totalFindings, confirmedFindings, wallTimeMs,
 *       perFindingForLabel: [ { ruleId, path, startLine, severity,
 *                                snippet, agentStatus,
 *                                label: "<pending>" } ] }
 */

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..", "..", "..");
const resultsDir = join(repoRoot, "packages", "benchmark", "results");

// ── CLI args ───────────────────────────────────────────────────────────────

const args = process.argv.slice(2);

function getArg(name, fallback = undefined) {
  const idx = args.indexOf(`--${name}`);
  if (idx === -1) return fallback;
  return args[idx + 1];
}

const sliceSel = getArg("slice", "all");
const xbowPath = getArg("xbow-path", null);
const npmCache = getArg("npm-bench-cache", null);
const dryRun = args.includes("--dry-run");
const cliBin = getArg(
  "cli",
  join(repoRoot, "packages", "cli", "dist", "index.js"),
);

const today = new Date().toISOString().slice(0, 10);

// ── Slice definitions ──────────────────────────────────────────────────────

const SLICES = {
  "self-scan": {
    description: "pwnkit's own repo (TS/JS).",
    target: repoRoot,
    targetType: "source-code",
  },
  "xbow-bb-wave": {
    description:
      "One wave of XBOW BB on 0ca/xbow-validation-benchmarks-patched (PHP-heavy).",
    target: xbowPath,
    targetType: "source-code",
    requiresFlag: "--xbow-path",
  },
  "npm-bench-wave": {
    description:
      "First 9 packages from the npm-bench suite (JS taint focus).",
    target: npmCache,
    targetType: "source-code", // already-unpacked tarballs sit on disk
    requiresFlag: "--npm-bench-cache",
  },
};

function selectSlices(sel) {
  if (sel === "all") return Object.keys(SLICES);
  if (!(sel in SLICES)) {
    throw new Error(
      `Unknown slice "${sel}". Known: ${Object.keys(SLICES).join(", ")}`,
    );
  }
  return [sel];
}

// ── Runner ─────────────────────────────────────────────────────────────────

function runOnce({ slice, staticAnalyzer, target }) {
  const env = {
    ...process.env,
    PWNKIT_STATIC: staticAnalyzer,
    // Ablation needs deterministic-ish output; suppress noisy metrics.
    SEMGREP_SEND_METRICS: "off",
  };

  const t0 = Date.now();
  if (dryRun) {
    console.log(
      `[dry-run] PWNKIT_STATIC=${staticAnalyzer} pwnkit review ${target}`,
    );
    return {
      slice,
      static: staticAnalyzer,
      totalFindings: 0,
      confirmedFindings: 0,
      wallTimeMs: 0,
      perFindingForLabel: [],
      raw: null,
    };
  }

  const tmpReport = join(
    resultsDir,
    `foxguard-ablation-${today}-${slice}-${staticAnalyzer}.scan.json`,
  );
  const proc = spawnSync(
    "node",
    [
      cliBin,
      "review",
      target,
      "--format",
      "json",
    ],
    {
      env,
      stdio: ["ignore", "pipe", "inherit"],
      encoding: "utf8",
      timeout: 30 * 60 * 1000, // 30 min per slice
    },
  );

  const wallTimeMs = Date.now() - t0;

  if (proc.stdout && proc.stdout.trim()) {
    writeFileSync(tmpReport, proc.stdout, "utf8");
  }

  if (proc.status !== 0 && !existsSync(tmpReport)) {
    return {
      slice,
      static: staticAnalyzer,
      error: `pwnkit review exited ${proc.status}; no report at ${tmpReport}`,
      wallTimeMs,
    };
  }

  if (!existsSync(tmpReport)) {
    return {
      slice,
      static: staticAnalyzer,
      error: `pwnkit review produced no JSON report on stdout`,
      wallTimeMs,
    };
  }

  let report;
  try {
    report = JSON.parse(readFileSync(tmpReport, "utf-8"));
  } catch (err) {
    return {
      slice,
      static: staticAnalyzer,
      error: `failed to parse pwnkit review JSON at ${tmpReport}: ${err instanceof Error ? err.message : String(err)}`,
      wallTimeMs,
      rawReportPath: tmpReport,
    };
  }
  const findings = report.findings ?? [];
  const confirmed = findings.filter(
    (f) => f.status === "confirmed" || f.status === "verified",
  );

  // Hand-labelling hook: emit a minimal row per finding so the operator
  // can decide FP / TP without re-reading the full report.
  const perFindingForLabel = findings.map((f) => ({
    ruleId: f.ruleId ?? f.templateId ?? null,
    path: f.path ?? f.evidence?.request ?? null,
    startLine: f.startLine ?? null,
    severity: f.severity ?? null,
    snippet: (f.snippet ?? "").slice(0, 240),
    agentStatus: f.status,
    // Operator fills this in. Keep `<pending>` so missing labels are
    // visible in grep.
    label: "<pending>",
  }));

  return {
    slice,
    static: staticAnalyzer,
    totalFindings: findings.length,
    confirmedFindings: confirmed.length,
    wallTimeMs,
    perFindingForLabel,
    rawReportPath: tmpReport,
  };
}

// ── Main ───────────────────────────────────────────────────────────────────

function main() {
  if (!existsSync(resultsDir)) {
    mkdirSync(resultsDir, { recursive: true });
  }

  const slices = selectSlices(sliceSel);
  const rows = [];

  for (const slice of slices) {
    const def = SLICES[slice];
    if (!def.target) {
      console.warn(
        `[skip] ${slice} — required flag ${def.requiresFlag} not provided`,
      );
      continue;
    }
    if (!existsSync(def.target)) {
      console.warn(`[skip] ${slice} — target not found at ${def.target}`);
      continue;
    }

    for (const staticAnalyzer of ["semgrep", "foxguard"]) {
      console.error(
        `\n→ slice=${slice} static=${staticAnalyzer} target=${def.target}`,
      );
      const result = runOnce({
        slice,
        staticAnalyzer,
        target: def.target,
      });
      rows.push(result);
      console.error(
        `   findings=${result.totalFindings ?? "?"} ` +
          `confirmed=${result.confirmedFindings ?? "?"} ` +
          `wallTimeMs=${result.wallTimeMs ?? "?"}`,
      );
    }
  }

  const outputPath = join(resultsDir, `foxguard-ablation-${today}.json`);
  writeFileSync(
    outputPath,
    JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        notes:
          "Manual ablation: PWNKIT_STATIC=semgrep vs PWNKIT_STATIC=foxguard. " +
          "Validation gate: ≥semgrep on confirmed findings AND ≥2x faster " +
          "on the source-code slice. See docs/research/foxguard-ablation/.",
        rows,
      },
      null,
      2,
    ),
  );

  console.error(`\nWrote ${outputPath}`);
  console.error(
    "Hand-label step: open the file, set `label` to one of " +
      "`true-positive`, `false-positive`, `needs-context` per row.",
  );
}

main();
