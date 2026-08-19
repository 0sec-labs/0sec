/**
 * Issue #272 v0 — shared types for the autonomous CVE PoC adaptation slice.
 *
 * Split out of `adapt-loop.ts` so the scraper (sibling branch
 * `feat/272-cve-artifact-scraper`) and the loop can share the same
 * `PocCandidate` / `CveArtifacts` shape without a merge-time scramble.
 *
 * Keep this file dependency-free. Anything reaching into Tier-1 plumbing
 * lives in `adapt-loop.ts` so this module can be imported by the scraper
 * (which intentionally has zero runtime deps on `kernel-vm-runner`).
 */

/**
 * One reachable PoC artifact for a CVE, as discovered by the scraper.
 *
 * `source` discriminates how the URL should be fetched:
 *  - `github-raw` / `gist`: fetched verbatim as text (GitHub `raw` host or
 *     the `raw_url` from the Gist API).
 *  - `inline-writeup`: the URL points to an HTML writeup that embeds the
 *     PoC in the first fenced code block. The fetcher extracts that block.
 *
 * `confidence` is the scraper's prior on whether this artifact actually
 * reproduces the CVE; the adapt loop tries candidates highest-first.
 */
export interface PocCandidate {
  url: string;
  source: "github-raw" | "gist" | "inline-writeup";
  language: "c" | "py" | "sh" | "syz";
  confidence: number;
  /** Free-form note from the scraper (e.g. "linked from advisory references"). */
  note?: string;
}

/**
 * Output of the scraper layer. The adapt loop consumes this verbatim;
 * the scraper produces it from NVD / GHSA / kernel.org / distro trackers.
 */
export interface CveArtifacts {
  cveId: string;
  writeupText?: string;
  pocCandidates: PocCandidate[];
  affectedKernelSubsystem?: string;
  expectedSignature?: string;
}

/**
 * Typed seam between the scraper (sibling branch) and the adapt loop
 * (this branch). The default impl in production wires to the scraper;
 * tests pass a stub.
 */
export type CveArtifactProvider = (cveId: string) => Promise<CveArtifacts>;

/**
 * Output of `fetchPoc` — what gets handed to `verifyKernelFinding`.
 */
export interface FetchedPoc {
  local_path: string;
  language: PocCandidate["language"];
  sha256: string;
  source_url: string;
  fetched_at: string;
}
