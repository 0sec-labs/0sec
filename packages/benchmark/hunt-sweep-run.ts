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
  CHROMIUM_BARE_WORDS,
  filterArchetypes,
  FREEBSD_BARE_KERNEL_WORDS,
  loadChromiumArchetypes,
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
// "chromium" = the 12-entry V8/Blink/Mojo/base:: pack (TurboFan/Maglev type
// confusion, Oilpan UAF, Mojo IPC validation gaps, unwrapped raw_ptr UAF)
// against a Chromium source checkout — default path below assumes a fresh
// `/root/chromium-src` clone (being staged separately; not present in this
// repo). Every chromium archetype is `route: "source-static"` (see
// archetype-catalog.ts's data/chromium-archetypes.json provenance note: no
// Chromium build/ASan/libFuzzer lane exists yet either).
const DOMAIN = (process.env.HUNT_SWEEP_DOMAIN || "kernel").trim() as ArchetypeDomain;
const SRC =
  process.env.HUNT_SRC ||
  (DOMAIN === "freebsd" ? "/root/freebsd-src" : DOMAIN === "chromium" ? "/root/chromium-src" : "/root/linux-6.12.93");
const CONC = Number(process.env.HUNT_CONC || 3);
const MAX_FILE_LINES = Number(process.env.HUNT_MAX_FILE_LINES || 2000);
const MAX_ARCHETYPES = Number(process.env.HUNT_SWEEP_MAX_ARCHETYPES || 8);
// Default to the grep-visible route for the domain's own vocabulary: the
// kernel/FreeBSD packs use "kernel-static" (see archetype-catalog.ts's file
// header on why `route` there classifies the fix-lane, not grep-ability),
// while the Chromium pack has only one route value, "source-static" (no
// build/execution lane exists to distinguish a "verify" tier yet).
const ROUTES = (process.env.HUNT_SWEEP_ROUTES || (DOMAIN === "chromium" ? "source-static" : "kernel-static"))
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean) as ArchetypeRoute[];
const UIDS = process.env.HUNT_SWEEP_UIDS
  ? process.env.HUNT_SWEEP_UIDS.split(",").map((s) => s.trim()).filter(Boolean)
  : undefined;
// FreeBSD's core copy/alloc primitives (copyout/copyin/malloc) and Chromium's
// PascalCase/camelCase C++ symbols (TurboFan, Member, Deserialize, ...) are
// bare words that the default snake_case symbol-extraction heuristic misses
// (see symbolsFromDetectionSignature's header) — pass the curated allow-list
// only on the matching path so the Linux sweep stays byte-for-byte unaffected.
const BARE_WORDS =
  DOMAIN === "freebsd" ? FREEBSD_BARE_KERNEL_WORDS : DOMAIN === "chromium" ? CHROMIUM_BARE_WORDS : undefined;
// Chromium source is C++, not C — widen the grep globs beyond the kernel
// packs' *.c/*.h default (archetype-catalog.ts's ArchetypeCandidateOptions
// default) to also cover .cc/.cpp/.mojom/.mm.
const INCLUDE_GLOBS = DOMAIN === "chromium" ? ["*.c", "*.cc", "*.cpp", "*.h", "*.hpp", "*.mojom", "*.mm"] : undefined;

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

// Bench token-contention fix (measured: a single shared Codex/ChatGPT
// subscription token times out ~90% of finder calls under sweep fan-out —
// every archetype plan falls through to the same env-priority provider by
// default). Set HUNT_SWEEP_MODEL_POOL to a comma-separated list (e.g.
// "gpt-5.5,glm-5.2") to round-robin ONE model per archetype plan across
// distinct provider accounts (llm-api.ts's providerForModel() routes gpt-*
// to the Codex subscription, glm-* to the separate Z.ai key) — this SPLITS
// load across accounts rather than adding a second pass on top (that would
// be a genuine diversity fan-out, which costs 2x calls instead). Unset
// (default) reproduces today's behavior exactly: every plan uses the shared
// default provider, byte-for-byte identical to pre-existing behavior.
const MODEL_POOL = (process.env.HUNT_SWEEP_MODEL_POOL ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

console.log(
  `[hunt-sweep] domain=${DOMAIN} src=${SRC} conc=${CONC} maxFileLines=${MAX_FILE_LINES} maxArchetypes=${MAX_ARCHETYPES} ` +
    `routes=${ROUTES.join(",")}${UIDS ? ` uids=${UIDS.join(",")}` : ""}` +
    `${MODEL_POOL.length > 0 ? ` modelPool=${MODEL_POOL.join(",")}` : ""}`,
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
const library =
  DOMAIN === "freebsd" ? loadFreebsdArchetypes() : DOMAIN === "chromium" ? loadChromiumArchetypes() : loadKernelArchetypes();
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
  ...(INCLUDE_GLOBS ? { includeGlobs: INCLUDE_GLOBS } : {}),
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
  ...(MODEL_POOL.length > 0 ? { modelPool: MODEL_POOL } : {}),
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
