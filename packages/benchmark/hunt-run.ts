/** Real novel-vuln variant hunt: seed from a proven fix, fan out finders, skeptic-gate. */
import { generateVariantCandidates, runHuntScan, makeSkepticVerifier } from "@pwnkit/core";
import { readFileSync } from "node:fs";

const SRC = process.env.HUNT_SRC || "/root/linux-6.12.93";
const SEED = process.env.HUNT_SEED || "/root/nfc-seed.patch";
const REF = process.env.HUNT_REF || "nfc-digital-SENSF_RES-length-clamp";
const CONC = Number(process.env.HUNT_CONC || 3);
const MAXC = Number(process.env.HUNT_MAXC || 16);

const seedDiff = readFileSync(SEED, "utf8");

console.log(`[hunt-run] seed=${REF} src=${SRC} conc=${CONC} maxCandidates=${MAXC}`);

// 1. Turn the proven fix into a variant-hunt plan (bug class + grep'd candidate sites).
const plan = await generateVariantCandidates({
  sourceRoot: SRC,
  fix: { diff: seedDiff, reference: REF },
  runtime: "api",
  maxCandidates: MAXC,
  includeGlobs: ["*.c"],
  log: (m) => console.log(m),
});
console.log("[hunt-run] BRIEF:", JSON.stringify(plan.brief));
console.log("[hunt-run] grepPatterns:", JSON.stringify(plan.grepPatterns));
console.log("[hunt-run] candidates:", JSON.stringify(plan.candidates.map((c) => c.path)));
if (plan.warnings.length) console.log("[hunt-run] gen warnings:", JSON.stringify(plan.warnings));

if (plan.candidates.length === 0) {
  console.log("[hunt-run] no candidate sites — nothing to hunt");
  process.exit(0);
}

// Make candidate paths absolute for the finder/skeptic.
const candidates = plan.candidates.map((c) => ({ ...c, path: `${SRC}/${c.path}` }));

// 2. Fan finders out over the variant sites; skeptic-gate each finding.
const res = await runHuntScan({
  sourceRoot: SRC,
  candidates,
  brief: plan.brief,
  runtime: "api",
  concurrency: CONC,
  verify: makeSkepticVerifier({ sourceRoot: SRC, runtime: "api" }),
  log: (m) => console.log(m),
});

console.log("=== HUNT RESULT ===");
console.log(JSON.stringify({
  scanned: res.scanned,
  findings: res.findings.length,
  confirmed: res.confirmed.length,
  confirmedTitles: res.confirmed.map((f) => f.title),
  allTitles: res.findings.map((f) => f.title),
  warnings: res.warnings.slice(0, 8),
}, null, 2));
