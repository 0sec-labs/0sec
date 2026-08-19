/** Generic novel-bug hunt on under-audited surface: enumerate files -> runHuntScan (no seed). */
import { runHuntScan, makeSkepticVerifier, applyReachabilityGate, applySurfaceRanking } from "@pwnkit/core";
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
// kernelCTF-reachability gate for candidate selection (default OFF -> today's
// size-only ranking unchanged). See pwnkit/packages/core/src/stages/hunt-reachability.ts.
const REACHABLE_ONLY = process.env.HUNT_REACHABLE_ONLY === "1";
const REACHABLE_PREFER = process.env.HUNT_REACHABLE_PREFER === "1";
// Surface-desirability ranking (default OFF -> size-only ranking unchanged).
// When ON, re-orders candidates so hard-to-fuzz stateful parsers of untrusted
// input that are NOT recently swept float to the top of the (pre-cap) list,
// where a source-review hunt has an edge over fuzzing. See
// pwnkit/packages/core/src/stages/surface-desirability.ts.
const SURFACE_RANK = process.env.HUNT_SURFACE_RANK === "1";

// Enumerate .c files under the (under-audited) subsystem, largest first. The
// MAXC cap is applied in JS below (not in this shell pipeline) so the
// reachability gate runs BEFORE the cap and reachable files aren't truncated
// away by size-only ranking landing on exotic/unbuilt drivers.
const listing = execFileSync(
  "bash",
  ["-lc", `find '${SRC}/${SUBSYS}' -name '*.c' -printf '%s %p\\n' 2>/dev/null | sort -rn | awk '{print $2}'`],
  { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 },
);
const allFiles = listing.split("\n").map((s) => s.trim()).filter(Boolean);

const gate = REACHABLE_ONLY || REACHABLE_PREFER
  ? applyReachabilityGate(allFiles, { reachableOnly: REACHABLE_ONLY, reachablePrefer: REACHABLE_PREFER })
  : { paths: allFiles, unreachableCount: 0 };
if (gate.unreachableCount > 0) {
  const verb = REACHABLE_ONLY ? "dropped" : "deprioritized";
  console.log(`[surface] ${verb} ${gate.unreachableCount} unreachable candidate(s) (not built/zero-cap on kernelCTF COS)`);
}

// Surface-desirability ranking runs AFTER the reachability gate and BEFORE the
// cap, so the most hunt-worthy surfaces survive truncation (opt-in; default OFF
// -> size-only order preserved). Date.now() is fine here — this is a top-level
// node script, not a resumable workflow.
const ranked = SURFACE_RANK
  ? applySurfaceRanking(gate.paths, { enabled: true, tree: SRC, sourceRoot: SRC, nowMs: Date.now() })
  : { paths: gate.paths, scores: [] };
if (SURFACE_RANK && ranked.scores.length > 0) {
  const top = ranked.scores.slice(0, 5).map((s) => `${s.score} ${s.path.replace(`${SRC}/`, "")}`);
  console.log(`[surface] desirability-ranked ${ranked.scores.length} candidate(s); top: ${top.join(" | ")}`);
}

const files = ranked.paths.slice(0, MAXC);
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
  verify: makeSkepticVerifier({ sourceRoot: SRC, runtime: "api", model: process.env.HUNT_SKEPTIC_MODEL || "glm-5.3" }),
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
