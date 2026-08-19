#!/usr/bin/env node
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";

const DEFAULT_CORPUS = "scripts/kernel-validator-batch-corpus.json";
const DEFAULT_OUT_DIR = "kernel-validator-batch-results";
const DEFAULT_CLI = "packages/cli/dist/index.js";

function parseArgs(argv) {
  const args = {
    corpus: process.env.PWNKIT_KERNEL_BATCH_CORPUS || DEFAULT_CORPUS,
    outDir: process.env.PWNKIT_KERNEL_BATCH_OUT_DIR || DEFAULT_OUT_DIR,
    cli: process.env.PWNKIT_KERNEL_BATCH_CLI || DEFAULT_CLI,
    limit: process.env.PWNKIT_KERNEL_BATCH_LIMIT || "",
    dryRun: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      const value = argv[i + 1];
      if (!value || value.startsWith("--")) {
        throw new Error(`${arg} requires a value`);
      }
      i += 1;
      return value;
    };

    if (arg === "--corpus") args.corpus = next();
    else if (arg === "--out-dir") args.outDir = next();
    else if (arg === "--cli") args.cli = next();
    else if (arg === "--limit") args.limit = next();
    else if (arg === "--dry-run") args.dryRun = true;
    else if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  return args;
}

function printHelp() {
  console.log(`Usage: node scripts/kernel-validator-batch.mjs [options]

Options:
  --corpus <path>   Corpus JSON path. Default: ${DEFAULT_CORPUS}
  --out-dir <path>  Result artifact directory. Default: ${DEFAULT_OUT_DIR}
  --cli <path>      Built pwnkit CLI entrypoint. Default: ${DEFAULT_CLI}
  --limit <n>       Run at most n cases from the corpus.
  --dry-run         Validate corpus and write skipped case summaries without QEMU.
`);
}

const ALLOWED_DOWNLOAD_HOSTS = new Set(["syzkaller.appspot.com"]);

function resolveWithinRoot(rootDir, value, label) {
  const resolved = path.resolve(rootDir, value);
  const relative = path.relative(rootDir, resolved);
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`${label} must remain inside ${rootDir}`);
  }
  return resolved;
}

function validateDownloadUrl(value, label) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid URL`);
  }
  if (parsed.protocol !== "https:" || !ALLOWED_DOWNLOAD_HOSTS.has(parsed.hostname)) {
    throw new Error(`${label} must use HTTPS from an allowed host`);
  }
  return parsed.toString();
}

async function loadCorpus(corpusPath) {
  const raw = await readFile(corpusPath, "utf8");
  const corpus = JSON.parse(raw);
  if (corpus.version !== 1) {
    throw new Error(`unsupported corpus version: ${String(corpus.version)}`);
  }
  if (!Array.isArray(corpus.cases) || corpus.cases.length === 0) {
    throw new Error("corpus must contain at least one case");
  }

  const ids = new Set();
  for (const [index, testCase] of corpus.cases.entries()) {
    if (!testCase || typeof testCase !== "object") {
      throw new Error(`case ${index} must be an object`);
    }
    if (!/^[a-z0-9][a-z0-9._-]*$/i.test(testCase.id || "")) {
      throw new Error(`case ${index} has invalid id: ${String(testCase.id)}`);
    }
    if (ids.has(testCase.id)) {
      throw new Error(`duplicate case id: ${testCase.id}`);
    }
    ids.add(testCase.id);
    if (!testCase.reportUrl) {
      throw new Error(`case ${testCase.id} is missing reportUrl`);
    }
    testCase.reportUrl = validateDownloadUrl(testCase.reportUrl, `case ${testCase.id} reportUrl`);
    if (testCase.reproducerUrl) {
      testCase.reproducerUrl = validateDownloadUrl(testCase.reproducerUrl, `case ${testCase.id} reproducerUrl`);
    }
    if (testCase.expected && !["reproduced", "verified", "static-only", "not-reproduced"].includes(testCase.expected)) {
      throw new Error(`case ${testCase.id} has unsupported expected value: ${testCase.expected}`);
    }
  }

  return corpus;
}

function applyLimit(cases, limitValue) {
  if (!limitValue) return cases;
  const limit = Number.parseInt(limitValue, 10);
  if (!Number.isFinite(limit) || limit < 1) {
    throw new Error(`--limit must be a positive integer, got ${limitValue}`);
  }
  return cases.slice(0, limit);
}

async function download(url, dest) {
  // foxguard: ignore[js/no-ssrf] callers pass validateDownloadUrl()-checked HTTPS URLs.
  const response = await fetch(url); // foxguard: ignore[js/no-ssrf]
  if (!response.ok) {
    throw new Error(`download failed for ${url}: HTTP ${response.status}`);
  }
  await writeFile(dest, await response.text(), "utf8");
}

function runNode(args, options) {
  return new Promise((resolve) => {
    // foxguard: ignore[js/no-command-injection] process.execPath is the trusted Node runtime.
    const child = spawn(process.execPath, args, { // foxguard: ignore[js/no-command-injection]
      ...options,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (error) => {
      resolve({ code: 1, stdout, stderr: `${stderr}${error.message}` });
    });
    child.on("close", (code) => {
      resolve({ code: code ?? 1, stdout, stderr });
    });
  });
}

function extractJsonArray(raw) {
  let lastError = null;
  for (let start = raw.indexOf("["); start !== -1; start = raw.indexOf("[", start + 1)) {
    try {
      const parsed = JSON.parse(raw.slice(start));
      if (Array.isArray(parsed)) return parsed;
    } catch (error) {
      lastError = error;
    }
  }

  const detail = lastError instanceof Error ? ` Last parse error: ${lastError.message}.` : "";
  throw new Error(`pwnkit ingest output did not contain a parseable JSON array.${detail} Raw output: ${raw.slice(0, 1000)}`);
}

function classifyResults(results) {
  if (!Array.isArray(results) || results.length === 0) {
    return {
      status: "failed",
      verified: false,
      reproduced: false,
      staticOnly: false,
      reason: "ingest produced no findings",
    };
  }

  const verifications = results
    .map((entry) => entry?.verification)
    .filter(Boolean);
  const reproduced = verifications.some((verification) => verification.reproduced === true);
  const verified = verifications.some((verification) => verification.verified === true);
  const crashMatch = verifications.some((verification) => verification.crashMatch === true);
  const staticOnly = !reproduced && verifications.some((verification) => {
    const reason = String(verification.reason || "");
    return reason.includes("static analysis");
  });
  const reason = verifications
    .map((verification) => verification.reason)
    .find((value) => typeof value === "string" && value.length > 0) || "";

  return {
    status: reproduced ? "reproduced" : staticOnly ? "static-only" : verified ? "verified" : "not-reproduced",
    verified,
    reproduced,
    crashMatch,
    reproducedMismatch: reproduced && !crashMatch,
    staticOnly,
    reason,
  };
}

function expectedSatisfied(expected, classification) {
  if (!expected) return true;
  if (expected === "reproduced") return classification.reproduced && classification.crashMatch;
  if (expected === "verified") return classification.verified;
  if (expected === "static-only") return classification.staticOnly;
  if (expected === "not-reproduced") return !classification.reproduced || !classification.crashMatch;
  return false;
}

async function runCase(testCase, args, rootDir) {
  const caseDir = path.join(args.outDir, "cases", testCase.id);
  const inputDir = path.join(caseDir, "input");
  const artifactDir = path.join(caseDir, "vm-artifacts");
  const rawPath = path.join(caseDir, "raw.txt");
  const resultPath = path.join(caseDir, "result.json");
  const summaryPath = path.join(caseDir, "case-summary.json");
  await mkdir(inputDir, { recursive: true });
  await mkdir(artifactDir, { recursive: true });

  const baseSummary = {
    id: testCase.id,
    title: testCase.title || testCase.id,
    expected: testCase.expected || null,
    reportUrl: testCase.reportUrl,
    reproducerUrl: testCase.reproducerUrl || null,
    paths: {
      raw: path.relative(args.outDir, rawPath),
      result: path.relative(args.outDir, resultPath),
      summary: path.relative(args.outDir, summaryPath),
      artifacts: path.relative(args.outDir, artifactDir),
    },
  };

  try {
    if (args.dryRun) {
      const summary = {
        ...baseSummary,
        status: "skipped",
        verified: false,
        reproduced: false,
        crashMatch: false,
        reproducedMismatch: false,
        staticOnly: false,
        reason: "dry run",
        passed: true,
      };
      await writeFile(resultPath, `${JSON.stringify({ skipped: true, reason: "dry run" }, null, 2)}\n`, "utf8");
      await writeFile(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);
      return summary;
    }

    // testCase.id is constrained by loadCorpus; resolveWithinRoot keeps each downloaded
    // artifact under this case's input directory.
    const reportPath = resolveWithinRoot(inputDir, `${testCase.id}.log`, "report path");
    const reproducerPath = resolveWithinRoot(inputDir, `${testCase.id}.c`, "reproducer path");
    await download(testCase.reportUrl, reportPath); // foxguard: ignore[js/no-path-traversal]
    if (testCase.reproducerUrl) {
      await download(testCase.reproducerUrl, reproducerPath); // foxguard: ignore[js/no-path-traversal]
    }

    const env = {
      ...process.env,
      PWNKIT_KERNEL_QEMU: "1",
      PWNKIT_KERNEL_QEMU_ARTIFACT_DIR: artifactDir,
    };
    const ingest = await runNode(
      [args.cli, "ingest", inputDir, "--verify", "-o", "json"],
      { cwd: rootDir, env },
    );
    await writeFile(rawPath, `${ingest.stdout}${ingest.stderr ? `\n--- stderr ---\n${ingest.stderr}` : ""}`, "utf8");

    if (ingest.code !== 0) {
      throw new Error(`pwnkit ingest exited ${ingest.code}`);
    }

    const results = extractJsonArray(ingest.stdout);
    await writeFile(resultPath, `${JSON.stringify(results, null, 2)}\n`, "utf8");
    const classification = classifyResults(results);
    const passed = expectedSatisfied(testCase.expected, classification);
    const summary = {
      ...baseSummary,
      ...classification,
      passed,
    };
    await writeFile(summaryPath, `${JSON.stringify(summary, null, 2)}\n`, "utf8");
    return summary;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const summary = {
      ...baseSummary,
      status: "errored",
      verified: false,
      reproduced: false,
      crashMatch: false,
      reproducedMismatch: false,
      staticOnly: false,
      reason: message,
      passed: false,
    };
    await writeFile(resultPath, `${JSON.stringify({ error: message }, null, 2)}\n`, "utf8");
    await writeFile(summaryPath, `${JSON.stringify(summary, null, 2)}\n`, "utf8");
    return summary;
  }
}

function countBy(cases, predicate) {
  return cases.filter(predicate).length;
}

function makeSummary(cases, dryRun) {
  return {
    generatedAt: new Date().toISOString(),
    dryRun,
    total: cases.length,
    passed: countBy(cases, (testCase) => testCase.passed),
    verified: countBy(cases, (testCase) => testCase.verified),
    reproduced: countBy(cases, (testCase) => testCase.reproduced),
    crashMatch: countBy(cases, (testCase) => testCase.crashMatch),
    reproducedMismatch: countBy(cases, (testCase) => testCase.reproducedMismatch),
    staticOnly: countBy(cases, (testCase) => testCase.staticOnly),
    failed: countBy(cases, (testCase) => !testCase.passed && testCase.status !== "errored"),
    errored: countBy(cases, (testCase) => testCase.status === "errored"),
    cases,
  };
}

function toMarkdown(summary) {
  const lines = [
    "## Kernel Validator Batch",
    "",
    `- Total: ${summary.total}`,
    `- Passed: ${summary.passed}`,
    `- VM reproduced: ${summary.reproduced}`,
    `- Crash matches: ${summary.crashMatch}`,
    `- Reproduced mismatches: ${summary.reproducedMismatch}`,
    `- Verified: ${summary.verified}`,
    `- Static-only: ${summary.staticOnly}`,
    `- Failed: ${summary.failed}`,
    `- Errored: ${summary.errored}`,
    "",
    "| Case | Status | Expected | Reason |",
    "| --- | --- | --- | --- |",
  ];

  for (const testCase of summary.cases) {
    const reason = String(testCase.reason || "").replaceAll("|", "\\|").replaceAll("\n", " ");
    lines.push(`| ${testCase.id} | ${testCase.status} | ${testCase.expected || "-"} | ${reason || "-"} |`);
  }

  return `${lines.join("\n")}\n`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const rootDir = process.cwd();
  args.outDir = resolveWithinRoot(rootDir, args.outDir, "--out-dir");
  args.corpus = resolveWithinRoot(rootDir, args.corpus, "--corpus");
  args.cli = resolveWithinRoot(rootDir, args.cli, "--cli");
  await mkdir(args.outDir, { recursive: true });

  const corpus = await loadCorpus(args.corpus);
  const cases = applyLimit(corpus.cases, args.limit);
  const caseSummaries = [];
  for (const testCase of cases) {
    console.log(`kernel-validator-batch: ${testCase.id}`);
    caseSummaries.push(await runCase(testCase, args, rootDir));
  }

  const summary = makeSummary(caseSummaries, args.dryRun);
  const summaryPath = path.join(args.outDir, "summary.json");
  await writeFile(summaryPath, `${JSON.stringify(summary, null, 2)}\n`, "utf8");
  const markdown = toMarkdown(summary);
  await writeFile(path.join(args.outDir, "summary.md"), markdown, "utf8");

  if (process.env.GITHUB_STEP_SUMMARY) {
    await writeFile(process.env.GITHUB_STEP_SUMMARY, markdown, { flag: "a" });
  }

  console.log(JSON.stringify(summary, null, 2));
  if (summary.failed > 0 || summary.errored > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exitCode = 1;
});
