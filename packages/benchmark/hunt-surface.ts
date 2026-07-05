/** Generic novel-bug hunt on under-audited surface: enumerate files -> runHuntScan (no seed). */
import { runHuntScan, makeSkepticVerifier } from "@pwnkit/core";
import { execFileSync } from "node:child_process";
import { appendToCorpus, resolveHuntCorpusPath } from "./src/hunt-corpus.js";

const SRC = process.env.HUNT_SRC || "/root/linux-next";
const SUBSYS = process.env.HUNT_SUBSYS || "drivers/staging";
const CONC = Number(process.env.HUNT_CONC || 4);
const MAXC = Number(process.env.HUNT_MAXC || 30);
// The finder model(s) actually in use — was a bare (undefined) `models` reference before, a
// ReferenceError waiting to fire the moment this script ran (never caught: these top-level
// scripts sit outside tsconfig's "include": ["src"], so `tsc` never type-checks them).
const MODELS = (process.env.HUNT_MODELS || "").split(",").map((s) => s.trim()).filter(Boolean);

/** Same parse-guard pattern as `cyberGymBestOfN()`: unset/invalid env falls back to the runHuntScan default. */
function huntBestOfN(): number | undefined {
  const raw = process.env.HUNT_BEST_OF_N;
  if (raw === undefined || raw.trim() === "") return undefined;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 1 ? n : undefined;
}
function huntJudgeTopK(): number | undefined {
  const raw = process.env.HUNT_JUDGE_TOP_K;
  if (raw === undefined || raw.trim() === "") return undefined;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : undefined;
}
const BEST_OF_N = huntBestOfN();
const JUDGE_TOP_K = huntJudgeTopK();
const JUDGE_MODEL = process.env.HUNT_JUDGE_MODEL;

// Enumerate .c files under the (under-audited) subsystem; prefer larger files
// (more surface), sample up to MAXC.
const listing = execFileSync(
  "bash",
  ["-lc", `find '${SRC}/${SUBSYS}' -name '*.c' -printf '%s %p\\n' 2>/dev/null | sort -rn | head -${MAXC} | awk '{print $2}'`],
  { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 },
);
const files = listing.split("\n").map((s) => s.trim()).filter(Boolean);
console.log(`[surface] ${SUBSYS}: hunting ${files.length} largest .c files (generic, no seed), ${CONC}-wide`);

if (files.length === 0) { console.log("[surface] no files"); process.exit(0); }

const res = await runHuntScan({
  sourceRoot: SRC,
  candidates: files.map((path) => ({ path })),   // absolute paths from find
  // no brief -> generic memory-safety hunt
  runtime: "api",
  concurrency: CONC,
  ...(MODELS.length > 0 ? { models: MODELS } : {}),
  ...(BEST_OF_N ? { attemptsPerCandidate: BEST_OF_N } : {}),
  ...(JUDGE_TOP_K ? { judgeTopK: JUDGE_TOP_K } : {}),
  ...(JUDGE_MODEL ? { judgeModel: JUDGE_MODEL } : {}),
  verify: makeSkepticVerifier({ sourceRoot: SRC, runtime: "api", model: process.env.HUNT_SKEPTIC_MODEL || "glm-5.2" }),
  log: (m) => console.log(m),
});

console.log("=== SURFACE HUNT RESULT ===");
console.log(JSON.stringify({
  subsystem: SUBSYS,
  scanned: res.scanned,
  findings: res.findings.length,
  confirmed: res.confirmed.length,
  confirmedTitles: res.confirmed.map((f) => f.title),
  allTitles: res.findings.map((f) => f.title),
  warnings: res.warnings.slice(0, 8),
}, null, 2));

// Full finding bodies (never just titles/a bespoke per-run dump) — the shared corpus is the receipt.
try {
  const corpusPath = resolveHuntCorpusPath();
  appendToCorpus(res.records, corpusPath);
  console.log(`[surface] appended ${res.records.length} full finding record(s) to ${corpusPath}`);
} catch (e) {
  console.log("[surface] failed to persist findings: " + String(e));
}
