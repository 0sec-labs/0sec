import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { it } from "vitest";
import { appendHuntClaim, readHuntLedger } from "./hunt-evidence-ledger.js";
import { loadKnownNegativesFromLedger } from "./hunt-negatives.js";

it("bench", () => {
  const dir = mkdtempSync(join(tmpdir(), "bench-"));
  const ledger = join(dir, "e.jsonl");
  for (const n of [200, 1000, 3000]) {
    while (readHuntLedger(ledger).length < n) {
      const i = readHuntLedger(ledger).length;
      appendHuntClaim(ledger, {
        shape: { path: `drivers/net/site-${i}.c`, bugClass: "CWE-416 use-after-free" },
        statement: `claim ${i}: ctx freed while the retry timer can still dereference it`,
        status: "disproven",
        evidence: [{ stance: "observation", statement: "adversarial refute pass surfaced no reproducible claim", source: "skeptic", locator: `drivers/net/site-${i}.c:41` }],
        worker: "skeptic-1",
      });
    }
    const size = statSync(ledger).size;
    const t0 = performance.now();
    for (let k = 0; k < 5; k++) loadKnownNegativesFromLedger(ledger);
    const per = (performance.now() - t0) / 5;
    console.log(`records=${n} fileKB=${(size / 1024).toFixed(0)} per-verdict-load=${per.toFixed(1)}ms`);
  }
  rmSync(dir, { recursive: true, force: true });
}, 300_000);
