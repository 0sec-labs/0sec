/**
 * kernelCTF patch-gap 1day monitor — CLI runner.
 *
 * Loads the upstream kernel CVE feed (a local `git.kernel.org/pub/scm/linux/
 * security/vulns.git` clone, e.g. bench's `/root/kernel-vulns`), diffs each
 * fix against a target tree (e.g. bench's `/root/linux-6.12-git`, the
 * kernelCTF COS-6.12 ground truth `services/orchestrator/src/
 * kernelctf-config.ts` is grounded in), gates by kernelCTF reachability, and
 * appends the ranked survivors to `results/patch-gap-v1.jsonl`.
 *
 * Gated by `PATCH_GAP_RUN=1` — default is a no-op printing usage, mirroring
 * the other opt-in gates in this package (`HUNT_REACHABLE_ONLY`, etc.) so
 * `tsx` / CI never accidentally shells real git against a hardcoded bench
 * path.
 *
 * Usage (on bench, where both trees live):
 *   PATCH_GAP_RUN=1 \
 *   PATCH_GAP_VULNS_REPO=/root/kernel-vulns \
 *   PATCH_GAP_TARGET_TREE=/root/linux-6.12-git \
 *   PATCH_GAP_SINCE_YEAR=2025 \
 *   tsx patch-gap-run.ts
 *
 * 2026-07-05: default TARGET_TREE moved off `/root/linux-6.12.93` — that path
 * is a broken git worktree on bench (parent repo deleted, every `git -C ...`
 * call there fails) — to `/root/linux-6.12-git`, a full-history clone.
 */
import { loadVulnsFeedFromDir, scanForPatchGapCandidates } from "@pwnkit/core";
import { appendPatchGapCorpus, resolvePatchGapCorpusPath } from "./src/patch-gap-corpus.js";

const RUN = process.env.PATCH_GAP_RUN === "1";

if (!RUN) {
  console.log(
    "[patch-gap-run] no-op (set PATCH_GAP_RUN=1 to execute). " +
      "See the module doc in patch-gap-run.ts for the full env-var usage.",
  );
  process.exit(0);
}

const VULNS_REPO = process.env.PATCH_GAP_VULNS_REPO || "/root/kernel-vulns";
const TARGET_TREE = process.env.PATCH_GAP_TARGET_TREE || "/root/linux-6.12-git";
const SINCE_YEAR = process.env.PATCH_GAP_SINCE_YEAR ? Number.parseInt(process.env.PATCH_GAP_SINCE_YEAR, 10) : undefined;
const LIMIT = process.env.PATCH_GAP_LIMIT ? Number.parseInt(process.env.PATCH_GAP_LIMIT, 10) : undefined;
// Default true (drop unreachable-on-COS candidates) — set to "0" to keep everything for a distro-only audit.
const REACHABLE_ONLY = process.env.PATCH_GAP_REACHABLE_ONLY !== "0";

console.log(
  `[patch-gap-run] vulnsRepo=${VULNS_REPO} targetTree=${TARGET_TREE} ` +
    `sinceYear=${SINCE_YEAR ?? "(none)"} limit=${LIMIT ?? "(none)"} reachableOnly=${REACHABLE_ONLY}`,
);

const entries = loadVulnsFeedFromDir({
  vulnsRepoPath: VULNS_REPO,
  ...(SINCE_YEAR !== undefined ? { sinceYear: SINCE_YEAR } : {}),
  ...(LIMIT !== undefined ? { limit: LIMIT } : {}),
});
console.log(`[patch-gap-run] loaded ${entries.length} upstream fix entries from ${VULNS_REPO}`);

if (entries.length === 0) {
  console.log("[patch-gap-run] no feed entries — nothing to scan (check PATCH_GAP_VULNS_REPO / PATCH_GAP_SINCE_YEAR)");
  process.exit(0);
}

const result = scanForPatchGapCandidates({
  targetTreePath: TARGET_TREE,
  entries,
  reachableOnly: REACHABLE_ONLY,
});

console.log("=== PATCH-GAP RESULT ===");
console.log(
  JSON.stringify(
    {
      total: result.total,
      skippedAlreadyFixed: result.skippedAlreadyFixed,
      skippedUnreachable: result.skippedUnreachable,
      candidates: result.candidates.length,
      candidateCves: result.candidates.map((c) => `${c.cve} (${c.subsystem}, ${c.reachable}, ${c.severity})`),
    },
    null,
    2,
  ),
);

const corpusPath = resolvePatchGapCorpusPath();
appendPatchGapCorpus(result.candidates, TARGET_TREE, corpusPath);
console.log(`[patch-gap-run] appended ${result.candidates.length} candidate(s) to ${corpusPath}`);
