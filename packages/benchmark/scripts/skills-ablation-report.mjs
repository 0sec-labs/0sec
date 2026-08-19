#!/usr/bin/env node
/**
 * Skills ablation report generator — pwnkit#460.
 *
 * Reads the 3 variant result artifacts from the skills-ablation workflow
 * (or local directories) and produces a markdown summary table with
 * per-variant metrics and deltas against the control.
 *
 * Decision criteria from pwnkit#410:
 *   - >5% finding-rate improvement  OR
 *   - >15% token/cost reduction
 *   to recommend defaulting JIT skills ON.
 *
 * Usage (CI — called by the workflow):
 *
 *   node packages/benchmark/scripts/skills-ablation-report.mjs \
 *     --artifacts /tmp/ablation-artifacts \
 *     --output /tmp/ablation-report.md
 *
 * Usage (local — point at three result files):
 *
 *   node packages/benchmark/scripts/skills-ablation-report.mjs \
 *     --control   results/control.json \
 *     --skills    results/skills-only.json \
 *     --combined  results/skills-plus-playbooks.json \
 *     --output    /tmp/ablation-report.md
 *
 * Output:
 *
 *   Markdown summary to stdout (and --output file if provided).
 */

import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, resolve, basename, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── CLI args ──────────────────────────────────────────────────────────────

const args = process.argv.slice(2);

function getArg(name, fallback = undefined) {
  const idx = args.indexOf(`--${name}`);
  if (idx === -1) return fallback;
  return args[idx + 1];
}

const artifactsDir = getArg("artifacts", null);
const controlPath = getArg("control", null);
const skillsPath = getArg("skills", null);
const combinedPath = getArg("combined", null);
const outputPath = getArg("output", null);

// ── Decision thresholds (from pwnkit#410) ─────────────────────────────────

const FINDING_RATE_THRESHOLD = 0.05; // >5% improvement
const TOKEN_REDUCTION_THRESHOLD = 0.15; // >15% reduction

// ── Load variant results ──────────────────────────────────────────────────

/**
 * Given an artifacts directory (from actions/download-artifact), find and
 * load the three variant result files by matching on the artifact directory
 * name pattern: `skills-ablation-<variant>-<run_id>-<attempt>`.
 */
function loadFromArtifactsDir(dir) {
  const variants = {};
  const entries = readdirSync(dir);

  for (const entry of entries) {
    const entryPath = join(dir, entry);
    // Match skills-ablation-<variant>-... directories
    const match = entry.match(/^skills-ablation-(control|skills-only|skills-plus-playbooks)-/);
    if (!match) continue;

    const variant = match[1];
    // Look for xbow-latest.json inside the artifact directory
    const jsonPath = join(entryPath, "xbow-latest.json");
    if (existsSync(jsonPath)) {
      variants[variant] = loadResult(jsonPath);
    }
  }

  return variants;
}

function loadResult(path) {
  const raw = readFileSync(path, "utf-8");
  return JSON.parse(raw);
}

function loadVariants() {
  // Mode 1: artifacts directory (CI)
  if (artifactsDir && existsSync(artifactsDir)) {
    return loadFromArtifactsDir(artifactsDir);
  }

  // Mode 2: explicit paths (local)
  const variants = {};
  if (controlPath && existsSync(controlPath)) {
    variants["control"] = loadResult(controlPath);
  }
  if (skillsPath && existsSync(skillsPath)) {
    variants["skills-only"] = loadResult(skillsPath);
  }
  if (combinedPath && existsSync(combinedPath)) {
    variants["skills-plus-playbooks"] = loadResult(combinedPath);
  }

  return variants;
}

// ── Metrics computation ───────────────────────────────────────────────────

function computeMetrics(report) {
  const results = report.results ?? [];
  const total = results.length;
  const buildable = results.filter(
    (r) => !r.error || r.error === "",
  ).length;
  const flags = results.filter((r) => r.flagFound === true).length;

  // Finding rate = flags / buildable challenges (excludes Docker failures)
  const findingRate = buildable > 0 ? flags / buildable : 0;

  // Token/cost metrics — use estimatedCostUsd and attackTurns from each result
  const costs = results
    .map((r) => r.estimatedCostUsd ?? 0)
    .filter((c) => c > 0);
  const turns = results
    .map((r) => r.attackTurns ?? 0)
    .filter((t) => t > 0);
  const durations = results
    .map((r) => r.durationMs ?? 0)
    .filter((d) => d > 0);

  const meanCost = costs.length > 0
    ? costs.reduce((a, b) => a + b, 0) / costs.length
    : 0;
  const totalCost = costs.reduce((a, b) => a + b, 0);
  const meanTurns = turns.length > 0
    ? turns.reduce((a, b) => a + b, 0) / turns.length
    : 0;
  const meanDuration = durations.length > 0
    ? durations.reduce((a, b) => a + b, 0) / durations.length
    : 0;

  return {
    total,
    buildable,
    flags,
    findingRate,
    meanCost,
    totalCost,
    meanTurns,
    meanDuration,
    featureFlags: report.featureFlags ?? null,
    variant: report.ablationVariant ?? "unknown",
  };
}

function computeDelta(treatment, control) {
  const findingRateDelta = control.findingRate > 0
    ? (treatment.findingRate - control.findingRate) / control.findingRate
    : treatment.findingRate > 0 ? 1.0 : 0;

  const costDelta = control.meanCost > 0
    ? (treatment.meanCost - control.meanCost) / control.meanCost
    : 0;

  const turnsDelta = control.meanTurns > 0
    ? (treatment.meanTurns - control.meanTurns) / control.meanTurns
    : 0;

  const durationDelta = control.meanDuration > 0
    ? (treatment.meanDuration - control.meanDuration) / control.meanDuration
    : 0;

  // Decision criteria from pwnkit#410:
  // >5% finding-rate improvement OR >15% token/cost reduction
  const findingRatePass = findingRateDelta > FINDING_RATE_THRESHOLD;
  const costReductionPass = costDelta < -TOKEN_REDUCTION_THRESHOLD;
  const recommend = findingRatePass || costReductionPass;

  return {
    findingRateDelta,
    costDelta,
    turnsDelta,
    durationDelta,
    findingRatePass,
    costReductionPass,
    recommend,
  };
}

// ── Markdown report ───────────────────────────────────────────────────────

function pct(v) {
  const sign = v >= 0 ? "+" : "";
  return `${sign}${(v * 100).toFixed(1)}%`;
}

function usd(v) {
  return `$${v.toFixed(4)}`;
}

function dur(ms) {
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60_000).toFixed(1)}m`;
}

function generateReport(variants) {
  const lines = [];

  lines.push("## Skills Ablation Report (pwnkit#460)");
  lines.push("");
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push("");
  lines.push("Decision criteria from pwnkit#410: **>5% finding-rate improvement OR >15% token/cost reduction** to default JIT skills ON.");
  lines.push("");

  // ── Per-variant metrics table ──

  const variantOrder = ["control", "skills-only", "skills-plus-playbooks"];
  const metrics = {};

  for (const name of variantOrder) {
    if (variants[name]) {
      metrics[name] = computeMetrics(variants[name]);
    }
  }

  const availableVariants = variantOrder.filter((v) => metrics[v]);
  if (availableVariants.length === 0) {
    lines.push("**No variant results found.** Check that the artifact paths are correct.");
    return lines.join("\n");
  }

  lines.push("### Per-Variant Metrics");
  lines.push("");
  lines.push("| Metric | " + availableVariants.map((v) => `\`${v}\``).join(" | ") + " |");
  lines.push("| --- | " + availableVariants.map(() => "---").join(" | ") + " |");

  const rows = [
    ["Challenges (total)", (m) => `${m.total}`],
    ["Buildable", (m) => `${m.buildable}`],
    ["Flags extracted", (m) => `${m.flags}`],
    ["**Finding rate**", (m) => `**${(m.findingRate * 100).toFixed(1)}%**`],
    ["Mean cost/challenge", (m) => usd(m.meanCost)],
    ["Total cost", (m) => usd(m.totalCost)],
    ["Mean turns/challenge", (m) => m.meanTurns.toFixed(1)],
    ["Mean duration/challenge", (m) => dur(m.meanDuration)],
  ];

  for (const [label, fn] of rows) {
    const cells = availableVariants.map((v) => fn(metrics[v]));
    lines.push(`| ${label} | ${cells.join(" | ")} |`);
  }

  // ── Delta tables (only if control exists) ──

  if (metrics["control"]) {
    const control = metrics["control"];
    const treatments = availableVariants.filter((v) => v !== "control");

    if (treatments.length > 0) {
      lines.push("");
      lines.push("### Deltas vs Control");
      lines.push("");
      lines.push("| Metric | " + treatments.map((v) => `\`${v}\``).join(" | ") + " |");
      lines.push("| --- | " + treatments.map(() => "---").join(" | ") + " |");

      const deltas = {};
      for (const t of treatments) {
        deltas[t] = computeDelta(metrics[t], control);
      }

      const deltaRows = [
        ["Finding rate delta", (d) => pct(d.findingRateDelta)],
        ["Cost delta", (d) => pct(d.costDelta)],
        ["Turns delta", (d) => pct(d.turnsDelta)],
        ["Duration delta", (d) => pct(d.durationDelta)],
      ];

      for (const [label, fn] of deltaRows) {
        const cells = treatments.map((t) => fn(deltas[t]));
        lines.push(`| ${label} | ${cells.join(" | ")} |`);
      }

      // ── Decision gate ──

      lines.push("");
      lines.push("### Decision Gate");
      lines.push("");
      lines.push("| Criterion | " + treatments.map((v) => `\`${v}\``).join(" | ") + " |");
      lines.push("| --- | " + treatments.map(() => "---").join(" | ") + " |");

      lines.push(
        "| Finding rate >5% improvement | " +
        treatments.map((t) => deltas[t].findingRatePass ? "PASS" : "FAIL").join(" | ") +
        " |"
      );
      lines.push(
        "| Cost >15% reduction | " +
        treatments.map((t) => deltas[t].costReductionPass ? "PASS" : "FAIL").join(" | ") +
        " |"
      );
      lines.push(
        "| **Recommend default ON** | " +
        treatments.map((t) => deltas[t].recommend ? "**YES**" : "**NO**").join(" | ") +
        " |"
      );
    }
  }

  // ── Per-challenge breakdown ──

  lines.push("");
  lines.push("### Per-Challenge Breakdown");
  lines.push("");

  // Collect all challenge IDs across variants
  const allIds = new Set();
  for (const v of availableVariants) {
    for (const r of (variants[v].results ?? [])) {
      allIds.add(r.id);
    }
  }
  const sortedIds = [...allIds].sort();

  if (sortedIds.length > 0) {
    lines.push("| Challenge | " + availableVariants.map((v) => `\`${v}\``).join(" | ") + " |");
    lines.push("| --- | " + availableVariants.map(() => "---").join(" | ") + " |");

    for (const id of sortedIds) {
      const cells = availableVariants.map((v) => {
        const r = (variants[v].results ?? []).find((r) => r.id === id);
        if (!r) return "-";
        if (r.error) return "ERR";
        const flag = r.flagFound ? "FLAG" : "miss";
        const cost = r.estimatedCostUsd != null ? ` ${usd(r.estimatedCostUsd)}` : "";
        const turns = r.attackTurns != null ? ` ${r.attackTurns}t` : "";
        return `${flag}${cost}${turns}`;
      });
      lines.push(`| \`${id}\` | ${cells.join(" | ")} |`);
    }
  }

  // ── Feature flag state ──

  lines.push("");
  lines.push("### Feature Flag Configuration");
  lines.push("");
  lines.push("| Variant | `PWNKIT_FEATURE_JIT_SKILLS` | `PWNKIT_FEATURE_DYNAMIC_PLAYBOOKS` |");
  lines.push("| --- | --- | --- |");
  lines.push("| `control` | `0` | `0` |");
  lines.push("| `skills-only` | `1` | `0` |");
  lines.push("| `skills-plus-playbooks` | `1` | `1` |");

  return lines.join("\n");
}

// ── Main ──────────────────────────────────────────────────────────────────

function main() {
  const variants = loadVariants();
  const variantNames = Object.keys(variants);

  if (variantNames.length === 0) {
    const msg = "No variant results found. Provide --artifacts <dir> or --control/--skills/--combined <file>.";
    console.error(msg);
    if (outputPath) {
      writeFileSync(outputPath, `## Skills Ablation Report\n\n${msg}\n`);
    }
    process.exit(1);
  }

  console.error(`Loaded ${variantNames.length} variant(s): ${variantNames.join(", ")}`);

  const report = generateReport(variants);

  // Always print to stdout
  console.log(report);

  // Optionally write to file
  if (outputPath) {
    writeFileSync(outputPath, report + "\n", "utf-8");
    console.error(`Report written to ${outputPath}`);
  }
}

main();
