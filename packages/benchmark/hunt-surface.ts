/** Generic novel-bug hunt on under-audited surface: enumerate files -> runHuntScan (no seed). */
import { runHuntScan, makeSkepticVerifier } from "@pwnkit/core";
import { execFileSync } from "node:child_process";

const SRC = process.env.HUNT_SRC || "/root/linux-next";
const SUBSYS = process.env.HUNT_SUBSYS || "drivers/staging";
const CONC = Number(process.env.HUNT_CONC || 4);
const MAXC = Number(process.env.HUNT_MAXC || 30);

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
