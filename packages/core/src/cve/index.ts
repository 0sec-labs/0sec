// CVE artifact + adaptation surface. Two related slices live here:
//
//  - #272 v0 part 1: artifact scraping (NVD / GHSA / OSV / distro trackers
//    / GitHub PoC search). Public entry: `findCveArtifacts`.
//  - #272 v0 part 2: autonomous PoC adaptation loop (`adaptAndVerify`,
//    `fetchPoc`). Consumes a `CveArtifactProvider` so the scraper above
//    can feed it.
//
// Note on the type name collision: both slices independently defined
// `CveArtifacts` / `PocCandidate` before merging. They are NOT
// interchangeable — the scraper emits snake_case `cve_id` / `poc_urls`
// objects, while the adapt-loop's typed-seam uses camelCase
// `cveId` / `pocCandidates`. To avoid breaking either consumer, the
// scraper's shapes are re-exported under `Scraped*` aliases and the
// adapt-loop's shapes keep the unprefixed names (they are the typed
// seam intended for cross-module use, per
// `packages/core/src/cve/types.ts`).

// ── #272 v0 part 1 — scraper ────────────────────────────────────────
export {
  findCveArtifacts,
  normaliseCveId,
  classifyReferences,
  parseNvdResponse,
  parseGhsaResponse,
  parseOsvResponse,
  parseUbuntuTracker,
  parseRedHatTracker,
  findUbuntuTrackerUrls,
  findRedHatTrackerUrls,
  scoreRepoCandidate,
  scoreCodeCandidate,
} from "./artifact-scraper.js";
export type {
  CveArtifacts as ScrapedCveArtifacts,
  PocCandidate as ScrapedPocCandidate,
  PocSource,
  PocLanguage,
  AffectedVersionRange,
  SourceFetched,
  FindCveArtifactsOptions,
  FetchLike,
} from "./artifact-scraper.js";

// ── #272 v0 part 2 — adaptation loop ────────────────────────────────
export {
  fetchPoc,
  extractInlineCodeBlock,
  PocFetchError,
  MAX_POC_BYTES,
} from "./poc-fetcher.js";
export type { FetchPocOptions } from "./poc-fetcher.js";

export {
  adaptAndVerify,
  applyUnifiedDiff,
  renderAdaptationPrompt,
} from "./adapt-loop.js";
export type {
  AdaptAndVerifyOptions,
  AdaptationAgent,
  AdaptationAgentInput,
  AdaptationResult,
  AdaptationStatus,
  AttemptRecord,
  VerifyKernelFinding,
} from "./adapt-loop.js";

export type {
  CveArtifactProvider,
  CveArtifacts,
  FetchedPoc,
  PocCandidate,
} from "./types.js";
