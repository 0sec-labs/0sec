/**
 * Kernel archetype-SWEEP runner: fan `runHuntScan` out across MANY kernel
 * bug-class archetypes (`archetype-catalog.ts`, 34-entry library) in ONE
 * invocation, instead of hand-seeding one bug class at a time like
 * `hunt-run.ts`. Multi-lens seeding: many bug classes, one invocation, over
 * the same reachable surface.
 *
 * Orchestration only — mirrors `hunt-run.ts`'s shape. The parts worth unit
 * testing (the file-size guard, per-archetype aggregation) live in
 * `src/hunt-sweep.ts`, tested in `src/hunt-sweep.test.ts`.
 *
 * Gated by `PWNKIT_ARCHETYPE_SWEEP=1` (via `planArchetypeSweep` ->
 * `archetypeSweepEnabled()`, default OFF) — running this without the env set
 * is a clean, logged no-op, not an error.
 */
import {
  archetypeSweepEnabled,
  filterArchetypes,
  FREEBSD_BARE_KERNEL_WORDS,
  loadFreebsdArchetypes,
  loadKernelArchetypes,
  makeSkepticVerifier,
  planArchetypeSweep,
  type ArchetypeDomain,
  type ArchetypeRoute,
} from "@pwnkit/core";
import { resolveHuntCorpusPath } from "./src/hunt-corpus.js";
import { runArchetypeSweep } from "./src/hunt-sweep.js";

// "kernel" (default) = the 34-entry Linux pack against /root/linux-6.12.93.
// "freebsd" = the FreeBSD-idiom pack (copyout/copyin/malloc/priv_check/sysctl)
// against a FreeBSD source checkout (bench:/root/freebsd-src) — see
// archetype-catalog.ts's data/freebsd-archetypes.json provenance note: no
// FreeBSD kernel-verify (build+boot+KASAN) lane exists yet, so treat any
// "kernel-verify"-route hit as a hypothesis for human/skeptic review.
const DOMAIN = (process.env.HUNT_SWEEP_DOMAIN || "kernel").trim() as ArchetypeDomain;
const SRC = process.env.HUNT_SRC || (DOMAIN === "freebsd" ? "/root/freebsd-src" : "/root/linux-6.12.93");
const CONC = Number(process.env.HUNT_CONC || 3);
const MAX_FILE_LINES = Number(process.env.HUNT_MAX_FILE_LINES || 2000);
const MAX_ARCHETYPES = Number(process.env.HUNT_SWEEP_MAX_ARCHETYPES || 8);
// Default to the grep-visible route: kernel-static archetypes have a
// source-level detection signature (see archetype-catalog.ts's file header on
// why `route` here classifies the fix-lane, not grep-ability, but
// kernel-static is the safest default breadth for a static-only sweep).
const ROUTES = (process.env.HUNT_SWEEP_ROUTES || "kernel-static")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean) as ArchetypeRoute[];
const UIDS = process.env.HUNT_SWEEP_UIDS
  ? process.env.HUNT_SWEEP_UIDS.split(",").map((s) => s.trim()).filter(Boolean)
  : undefined;
// FreeBSD's core copy/alloc primitives (copyout/copyin/malloc) are bare
// words that the default symbol-extraction heuristic misses (see
// symbolsFromDetectionSignature's header) — pass the curated allow-list only
// on the FreeBSD path so the Linux sweep stays byte-for-byte unaffected.
const BARE_WORDS = DOMAIN === "freebsd" ? FREEBSD_BARE_KERNEL_WORDS : undefined;

/** Same parse-guard pattern as `hunt-run.ts`: unset/invalid env falls back to the runHuntScan default. */
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

console.log(
  `[hunt-sweep] domain=${DOMAIN} src=${SRC} conc=${CONC} maxFileLines=${MAX_FILE_LINES} maxArchetypes=${MAX_ARCHETYPES} ` +
    `routes=${ROUTES.join(",")}${UIDS ? ` uids=${UIDS.join(",")}` : ""}`,
);

if (!archetypeSweepEnabled()) {
  console.log(
    "[hunt-sweep] PWNKIT_ARCHETYPE_SWEEP is not set to 1 — sweep disabled (this is the default). " +
      "Set PWNKIT_ARCHETYPE_SWEEP=1 to run. Exiting cleanly.",
  );
  process.exit(0);
}

// 1. Pick the archetype subset: an explicit uid pin wins over the route filter.
const filter = UIDS ? { uids: UIDS } : { routes: ROUTES };
const library = DOMAIN === "freebsd" ? loadFreebsdArchetypes() : loadKernelArchetypes();
const selected = filterArchetypes(library, filter).slice(0, MAX_ARCHETYPES);
console.log(`[hunt-sweep] selected ${selected.length} archetype(s): ${selected.map((a) => a.uid).join(", ")}`);

if (selected.length === 0) {
  console.log("[hunt-sweep] no archetypes matched the filter — nothing to hunt");
  process.exit(0);
}

// 2. Plan: grep the source tree for each archetype's candidate sites.
const { plans, warnings: planWarnings } = planArchetypeSweep({
  sourceRoot: SRC,
  domain: DOMAIN,
  uids: selected.map((a) => a.uid),
  ...(BARE_WORDS ? { bareWords: BARE_WORDS } : {}),
});
if (planWarnings.length) console.log("[hunt-sweep] plan warnings:", JSON.stringify(planWarnings));

if (plans.length === 0) {
  console.log("[hunt-sweep] no archetype plans produced (no candidates matched under the source tree) — nothing to hunt");
  process.exit(0);
}

// 3-5. Run the sweep: per-plan file-size guard -> runHuntScan -> corpus persistence.
const corpusPath = resolveHuntCorpusPath();
const result = await runArchetypeSweep({
  sourceRoot: SRC,
  plans,
  runtime: "api",
  concurrency: CONC,
  maxFileLines: MAX_FILE_LINES,
  ...(BEST_OF_N ? { attemptsPerCandidate: BEST_OF_N } : {}),
  ...(JUDGE_TOP_K ? { judgeTopK: JUDGE_TOP_K } : {}),
  ...(JUDGE_MODEL ? { judgeModel: JUDGE_MODEL } : {}),
  verify: makeSkepticVerifier({ sourceRoot: SRC, runtime: "api" }),
  corpusPath,
  log: (m) => console.log(m),
});

console.log("=== ARCHETYPE SWEEP SUMMARY ===");
console.log(
  ["uid".padEnd(20), "scanned".padStart(8), "findings".padStart(9), "confirmed".padStart(10), "droppedSize".padStart(12)].join(" "),
);
for (const row of result.perArchetype) {
  console.log(
    [
      row.uid.padEnd(20),
      String(row.scanned).padStart(8),
      String(row.findings).padStart(9),
      String(row.confirmed).padStart(10),
      String(row.droppedForSize).padStart(12),
    ].join(" "),
    `— ${row.name}`,
  );
}
console.log("--- TOTALS ---", JSON.stringify(result.totals));

// Full evidence (request/response/analysis) lives in the corpus JSONL —
// this printout is a scan-at-a-glance, never the sole record.
const confirmedTitles = result.perArchetype.flatMap((row) =>
  row.confirmedFindings.map((f) => `[${row.uid}] ${f.title}${f.fileLine ? ` (${f.fileLine})` : ""}`),
);
console.log("confirmedTitles:", JSON.stringify(confirmedTitles, null, 2));
if (result.warnings.length) console.log("[hunt-sweep] warnings:", JSON.stringify(result.warnings.slice(0, 20)));
console.log(`[hunt-sweep] corpus: ${corpusPath}`);
