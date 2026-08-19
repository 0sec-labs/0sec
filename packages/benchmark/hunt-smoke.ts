/** E2E smoke for runHuntScan: fan-out finder + skeptic gate on a tiny C target. */
import { runHuntScan, makeSkepticVerifier } from "@0sec/core";

const ROOT = "/tmp/hunt-smoke/src";
const res = await runHuntScan({
  sourceRoot: ROOT,
  candidates: [{ path: `${ROOT}/parse.c` }],
  brief: {
    bugClass: "missing length check before a TLV copy into a fixed buffer",
    pattern: "memcpy(dst, t->val, t->len) with no bound on attacker-controlled t->len",
  },
  runtime: "api",
  concurrency: 1,
  verify: makeSkepticVerifier({ sourceRoot: ROOT, runtime: "api" }),
  log: (m) => console.log(m),
});
console.log("=== HUNT SMOKE RESULT ===");
console.log(JSON.stringify({
  scanned: res.scanned,
  findings: res.findings.length,
  confirmed: res.confirmed.length,
  findingTitles: res.findings.map((f) => f.title),
  warnings: res.warnings,
}, null, 2));
