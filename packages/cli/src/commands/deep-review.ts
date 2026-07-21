/**
 * `pwnkit deep-review <target>` — the SEEDLESS depth-review scan (G-A).
 *
 * This is the "depth method" (PR #1162: specialized finder lenses × best-of-N +
 * the multi-lens verify quorum) exposed as a dispatchable, seedless product.
 * Unlike `pwnkit hunt` (which REQUIRES a `--seed` fix diff to derive variant
 * candidate sites), deep-review needs no seed: it enumerates candidate files
 * straight from the prepared source tree and re-hunts each through the profile's
 * `*FinderLenses`, gating survivors through the profile's `*VerifyLenses`
 * multi-lens refute quorum.
 *
 *   prepare(target) ─▶ enumerate candidate files (scope-capped, subsystem-scoped)
 *                          │
 *                          ▼
 *     runHuntScan({ candidates, lenses: <p>FinderLenses,
 *                   verify: makeMultiLensVerifier(<p>VerifyLenses) })
 *                          │  confirmed leads
 *                          ▼
 *     leadToCandidateFinding ─▶ CloudSink (same 'discovered' candidate path as hunt)
 *
 * A deep-review finding is a LEAD, not a confirmed bug: the multi-lens quorum
 * filters (each lens re-reads and refutes) but does not PROVE. In cloud mode the
 * leads flow to the orchestrator as `discovered` candidates and enter the
 * cloud's own adversarial verify gate, exactly like `hunt`.
 *
 * Exit codes:
 *   0 → the sweep RAN to completion — a VALID outcome whether or not any lead
 *       survived the quorum. A clean 0-lead hunt is a success, not a failure
 *       (the cloud worker maps a non-zero CLI exit to scan status=failed, so a
 *       completed 0-finding sweep must exit 0 or it is wrongly marked failed —
 *       the CapyFi/Onyx "failed with 0 findings" incident, 2026-07-08).
 *   2 → skipped (no candidate files, or the scope exceeds the review cap)
 *   3 → error (bad flags, unreadable target, or the sweep did NO work at all —
 *       every finder errored/timed out, i.e. an LLM/backend failure)
 */

import type { Command } from "commander";
import { statSync } from "node:fs";
import { resolve, join, sep, relative } from "node:path";
import type { Finding, RuntimeMode } from "@pwnkit/shared";
import type { FinderLens, VerifyLens } from "@pwnkit/core";
// The one non-type value import from the core barrel here: the appsec lens
// registry loader. The barrel is already eagerly loaded at CLI boot
// (packages/cli/src/index.ts imports maybeSubscribeCloudEventSink from it), so
// this adds no new startup cost; it lets `defaultFinderLenses` stay a plain
// module-eval const (its reference identity is relied on by selectProfileLenses
// and its tests) while sourcing the appsec lenses from the data-driven JSON.
import { loadAppsecFinderLenses } from "@pwnkit/core";
import { leadToCandidateFinding, type HuntOutcome } from "./hunt.js";

/** Hard cap mirroring the review pipeline's 5000-source-file scope limit
 *  (see docs / 0cloud review constraints): a whole-monorepo target that
 *  exceeds it must be narrowed with `--subsystem`, exactly like `review`. */
const DEEP_REVIEW_FILE_CAP = 5000;
/**
 * Default candidate files actually hunted, largest-first. This is the PRIMARY
 * fan-out bound: every candidate fans out into `finderLenses × models × attempts`
 * finder runs, then each surfaced finding fans the multi-lens verify quorum.
 *
 * The four specialized finder lenses ARE the depth method, so they are never
 * cut. The three fan-out multipliers we CAN cut without losing lens diversity
 * are candidates, models, and attempts. We keep the 4 lenses and default to a
 * SINGLE model × 1 attempt (see {@link defaultModels} / {@link defaultAttempts}),
 * so the default fan-out is `8 candidates × 4 lenses × 1 model × 1 attempt = 32`
 * finder runs — roughly half the previous 15 × 4 = 60-run sweep (~25 min) and
 * far under the 40 × 4 = 160-run sweep that ran ~56 min and got killed mid-flight
 * (the deep_review "failed with 0 findings" incident, 2026-07-08). At the 8-wide
 * concurrency default that's ~4 sequential finder waves + the verify quorum,
 * landing a typical repo in ~8–12 min. Raise it with `--max-candidates` /
 * `PWNKIT_DEEP_REVIEW_MAX_CANDIDATES` (and/or `--models` / `--attempts`) when a
 * target genuinely warrants a deeper sweep AND the timeout allows.
 */
const DEFAULT_MAX_CANDIDATES = 8;
/** Env override for {@link DEFAULT_MAX_CANDIDATES} so operators can tune the cap
 *  without a code change; the `--max-candidates` flag still overrides this. */
function defaultMaxCandidates(): number {
  const raw = process.env.PWNKIT_DEEP_REVIEW_MAX_CANDIDATES;
  if (!raw) return DEFAULT_MAX_CANDIDATES;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_MAX_CANDIDATES;
}
/** Default finder attempts per (candidate × lens × model). 1 = best-of-1: a pure
 *  cost/latency multiplier that adds LESS value than lens diversity, so the fast
 *  default is a single attempt. Raise with `--attempts` /
 *  `PWNKIT_DEEP_REVIEW_ATTEMPTS` for a deliberate deeper (best-of-N) run. */
const DEFAULT_ATTEMPTS = 1;
/** Env override for {@link DEFAULT_ATTEMPTS}; the `--attempts` flag still wins. */
function defaultAttempts(): number {
  const raw = process.env.PWNKIT_DEEP_REVIEW_ATTEMPTS;
  if (!raw) return DEFAULT_ATTEMPTS;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_ATTEMPTS;
}
/**
 * Default finder models. `undefined` = a SINGLE model (the configured provider
 * default) — multi-model fan-out is a pure duration multiplier that adds less
 * value than the 4 lens angles, so the fast default runs one model. Set a
 * comma-separated `PWNKIT_DEEP_REVIEW_MODELS` (or pass `--models`) for a
 * deliberate multi-model run. The `--models` flag still overrides the env.
 */
function defaultModels(): string[] | undefined {
  const raw = process.env.PWNKIT_DEEP_REVIEW_MODELS;
  if (!raw) return undefined;
  const models = raw.split(",").map((s) => s.trim()).filter(Boolean);
  return models.length > 0 ? models : undefined;
}
/** Default finder concurrency. Finder runs are network/LLM-bound (not CPU), so
 *  the wider default (matching {@link runHuntScan}'s own default) roughly halves
 *  the bounded sweep's wall-clock vs. the previous 4, keeping it inside the
 *  worker timeout. Override with `--concurrency`. */
const DEFAULT_CONCURRENCY = 8;

/**
 * The four broad, always-present generic finder lenses. Language- and domain-
 * agnostic best-of-N sweeps whose findings UNION — the same depth-method shape
 * as the on-chain `*FinderLenses`. These stay a hardcoded const (not data-
 * driven) because they are the deliberately-coarse fallback buckets;
 * {@link defaultFinderLenses} widens them with the data-driven appsec pack.
 */
const genericFinderLenses: FinderLens[] = [
  {
    id: "memory-safety",
    challengeHint:
      "Hunt MEMORY-SAFETY bugs only: out-of-bounds read/write, use-after-free, double-free, uninitialized read, integer overflow feeding an allocation or index, and unchecked length/size arithmetic before a copy. Cite the exact unguarded sink (file:line) and the attacker-controlled path that reaches it.",
  },
  {
    id: "input-validation",
    challengeHint:
      "Hunt INPUT-VALIDATION and injection bugs only: untrusted input reaching a dangerous sink without validation — command/SQL/path/template injection, unsafe deserialization, SSRF, unchecked redirects, or a parser that trusts attacker-supplied structure. Trace the taint from the entry point to the sink.",
  },
  {
    id: "auth-logic",
    challengeHint:
      "Hunt AUTHZ / LOGIC bugs only: a missing or wrong permission/ownership check, a broken state machine, a TOCTOU race, an off-by-one or boundary error in a security-relevant decision, or a check that can be bypassed. Prove the guard is absent or mis-scoped, not merely that the keywords appear.",
  },
  {
    id: "secrets-crypto",
    challengeHint:
      "Hunt SECRETS / CRYPTO misuse only: hardcoded credentials, a weak/predictable RNG used for security, a broken or misused cryptographic primitive (ECB, static IV/nonce, missing MAC verification, non-constant-time compare), or a signature/token check that can be forged or replayed. Cite the exact misuse.",
  },
];

/**
 * Generic finder lenses for profiles without a bespoke on-chain lens set
 * (default / c-library / linux-kernel / cardano-haskell / unknown): the four
 * coarse {@link genericFinderLenses} UNIONED with the data-driven, cross-
 * language appsec lens registry ({@link loadAppsecFinderLenses}, backed by
 * `packages/core/src/stages/data/appsec-archetypes.json`). The appsec lenses
 * ADD coverage — os-command-injection, method-authz-differential, template-
 * xss/SSTI, sso-trust, and resource-exhaustion-DoS — the four generic buckets
 * under-weighted (the Swiss engagement misses). Each appsec lens has a distinct
 * id, so they union with the generics rather than colliding on the best-of-N
 * group key. On-chain profiles keep their bespoke sets and never see these (see
 * {@link selectProfileLenses}); only the default fallback bucket is widened.
 */
export const defaultFinderLenses: FinderLens[] = [...genericFinderLenses, ...loadAppsecFinderLenses()];

/**
 * Generic verify lenses (multi-lens refute quorum) for the default profile
 * fallback. Mirrors the four self-check angles the on-chain profiles use —
 * reachability, completeness, novelty, scope/impact — but domain-agnostic.
 */
export const defaultVerifyLenses: VerifyLens[] = [
  {
    id: "reachability",
    challengeHint:
      "REACHABILITY: is the vulnerable code actually reachable by an attacker from a real entry point (exported/public API, request handler, CLI, parser) with no gate it cannot pass? Trace the concrete path from the entry to the sink. If the path is dead code, disabled, or privileged-only, refute it.",
  },
  {
    id: "completeness",
    challengeHint:
      "COMPLETENESS: is the 'missing' check actually enforced elsewhere on the path — a validation earlier in the flow, a guard in the only caller, a wrapper that sanitizes first? Read the whole call path and the full file/module. If the guard is present AND correctly scoped, refute it; keep it only if genuinely absent or mis-scoped.",
  },
  {
    id: "novelty-known-issue",
    challengeHint:
      "NOVELTY / KNOWN-GUARD: is the standard guard for this class present and correct (a framework escaper, a safe API, a bounds check, a working auth middleware)? Is this a well-known already-mitigated pattern in this codebase or its dependencies? If a correct standard guard covers it, refute it.",
  },
  {
    id: "scope",
    challengeHint:
      "SCOPE / IMPACT: does exploiting this actually corrupt memory, leak secrets, escalate privilege, execute code, or move value / break a security invariant? A cosmetic missing check with no real impact is info/low, not a high-severity finding — refute it as such.",
  },
];

/** The lens-set exports a deep-review draws from (injected for tests). */
export interface ProfileLensSets {
  evmFinderLenses: FinderLens[];
  evmVerifyLenses: VerifyLens[];
  solanaFinderLenses: FinderLens[];
  solanaVerifyLenses: VerifyLens[];
  cardanoFinderLenses: FinderLens[];
  cardanoVerifyLenses: VerifyLens[];
  cairoFinderLenses: FinderLens[];
  cairoVerifyLenses: VerifyLens[];
  moveFinderLenses: FinderLens[];
  moveVerifyLenses: VerifyLens[];
}

export interface SelectedLenses {
  finderLenses: FinderLens[];
  verifyLenses: VerifyLens[];
  /** The profile whose lens set was actually selected ('default' on fallback). */
  matchedProfile: string;
}

/**
 * Pick the finder + verify lens set for a `--profile`. The five on-chain
 * profiles have bespoke lens sets; every other profile (default / c-library /
 * linux-kernel / cardano-haskell / unset / unknown) falls back to the generic
 * {@link defaultFinderLenses} / {@link defaultVerifyLenses}. Pure + testable.
 */
export function selectProfileLenses(profile: string | undefined, sets: ProfileLensSets): SelectedLenses {
  switch ((profile ?? "").trim().toLowerCase()) {
    case "evm-onchain":
      return { finderLenses: sets.evmFinderLenses, verifyLenses: sets.evmVerifyLenses, matchedProfile: "evm-onchain" };
    case "solana-onchain":
      return { finderLenses: sets.solanaFinderLenses, verifyLenses: sets.solanaVerifyLenses, matchedProfile: "solana-onchain" };
    case "cardano-onchain":
      return { finderLenses: sets.cardanoFinderLenses, verifyLenses: sets.cardanoVerifyLenses, matchedProfile: "cardano-onchain" };
    case "cairo-onchain":
      return { finderLenses: sets.cairoFinderLenses, verifyLenses: sets.cairoVerifyLenses, matchedProfile: "cairo-onchain" };
    case "move-onchain":
      return { finderLenses: sets.moveFinderLenses, verifyLenses: sets.moveVerifyLenses, matchedProfile: "move-onchain" };
    default:
      return { finderLenses: defaultFinderLenses, verifyLenses: defaultVerifyLenses, matchedProfile: "default" };
  }
}

/**
 * EVM/Foundry repos vendor their dependencies under `lib/` (forge-std,
 * openzeppelin, solmate, …), keep unit tests as `*.t.sol` under `test/`, and
 * put deploy helpers under `script/` / `scripts/`. NONE of that is protocol
 * source worth spending a finder budget on — and the LARGEST `.sol` files in a
 * Foundry tree are almost always vendored (forge-std's `Vm.sol` /
 * `safeconsole.sol` / `console2.sol`), so the largest-first candidate pick lands
 * the entire finder budget on dependencies and tests and times out. Observed on
 * two real cloud scans (2026-07-08): CapyFi finders timed out on
 * `lib/forge-std/src/Vm.sol`; Onyx had 20/32 finders time out on `.t.sol` files
 * under `test/`, gutting real coverage. These dir segments are the
 * vendored/test/script buckets to skip so the evm-onchain candidate set is
 * scoped to protocol source (`src/`, `contracts/`, root `.sol`, …).
 */
const EVM_EXCLUDE_DIR_SEGMENTS = new Set([
  "test", "tests",
  "mock", "mocks",
  "script", "scripts", // Foundry deploy scripts
  "lib",               // Foundry vendored deps (forge-std / openzeppelin / solmate …)
  "node_modules",      // Hardhat/JS vendored deps (also skipped by the core walker)
]);

/**
 * True when an evm-onchain candidate path is a TEST, VENDORED-LIB, MOCK, or
 * DEPLOY-SCRIPT file rather than protocol source. Matches on path segments
 * relative to the scope root (so a nested `lib/openzeppelin/lib/forge-std/…`
 * vendored tree is caught at any depth) plus Foundry/JS test filename patterns
 * (`Foo.t.sol`, `*.test.*`, `*.spec.*`) regardless of directory. Pure +
 * exported for unit testing. EVM-scoped: only wired for `--profile evm-onchain`.
 */
export function isNonProtocolEvmPath(absPath: string, scopeRoot: string): boolean {
  const rel = relative(scopeRoot, absPath);
  // A path that resolves outside the scope (shouldn't happen) is not excludable
  // on a segment basis — leave it in rather than silently drop it.
  if (rel === "" || rel.startsWith("..")) return false;
  const segments = rel.split(/[/\\]+/).filter(Boolean);
  if (segments.length === 0) return false;
  // Directory segments (everything before the filename): vendored / test / script.
  for (let i = 0; i < segments.length - 1; i++) {
    if (EVM_EXCLUDE_DIR_SEGMENTS.has(segments[i]!.toLowerCase())) return true;
  }
  // Test/spec filenames regardless of directory (Foundry `Foo.t.sol`, JS specs).
  const fileName = segments[segments.length - 1]!.toLowerCase();
  if (fileName.endsWith(".t.sol")) return true;
  if (fileName.includes(".test.") || fileName.includes(".spec.")) return true;
  return false;
}

/** File-walk helpers, injected so the enumeration logic is unit-testable
 *  without a real source tree. Match the `@pwnkit/core` signatures. */
export interface DeepReviewEnumHelpers {
  collectScopeFiles: (dir: string, opts?: { maxFiles?: number; maxFileSize?: number; extensions?: Set<string> }) => string[];
  countScopeFilesUpTo: (dir: string, limit: number, opts?: { maxFileSize?: number; extensions?: Set<string> }) => number;
  /** File size in bytes (defaults to statSync). Injected in tests. */
  fileSize?: (path: string) => number;
}

export interface DeepReviewEnumResult {
  /** Absolute candidate paths, largest-first, capped to `maxCandidates`. */
  candidates: string[];
  /** Source-file count under the scope, short-circuited at `fileCap` (so a
   *  value of `fileCap + 1` means "at least that many" — over the cap). */
  totalFiles: number;
  /** True when the scope exceeds the review file cap (must be narrowed). */
  overCap: boolean;
}

/**
 * Seedless candidate enumeration: count the scope (short-circuit at the cap),
 * then collect and rank source files largest-first, capping to `maxCandidates`.
 * Largest-first prioritizes the densest surface (mirrors the surface-hunt
 * enumeration in `@pwnkit/benchmark`'s hunt-surface.ts). Pure over its injected
 * helpers. Returns absolute paths (as `collectScopeFiles` does).
 */
export function enumerateDeepReviewCandidates(
  scopeRoot: string,
  helpers: DeepReviewEnumHelpers,
  opts: {
    maxCandidates: number;
    fileCap?: number;
    /** Drop candidate paths for which this returns true BEFORE the largest-first
     *  cap — used to keep test/vendored files out of the evm-onchain finder set
     *  so the budget goes to protocol source (see {@link isNonProtocolEvmPath}). */
    exclude?: (absPath: string) => boolean;
  },
): DeepReviewEnumResult {
  const fileCap = opts.fileCap ?? DEEP_REVIEW_FILE_CAP;
  const exclude = opts.exclude ?? (() => false);
  const fileSize = helpers.fileSize ?? ((p: string) => {
    try { return statSync(p).size; } catch { return 0; }
  });
  const totalFiles = helpers.countScopeFilesUpTo(scopeRoot, fileCap);
  const overCap = totalFiles > fileCap;
  const files = helpers.collectScopeFiles(scopeRoot, { maxFiles: fileCap });
  const candidates = files
    .filter((p) => !exclude(p))
    .map((p) => ({ p, size: fileSize(p) }))
    .sort((a, b) => b.size - a.size || a.p.localeCompare(b.p))
    .slice(0, Math.max(1, opts.maxCandidates))
    .map((x) => x.p);
  return { candidates, totalFiles, overCap };
}

export interface RunDeepReviewOptions {
  /** Source tree to review — a local path or a git URL (resolved via prepare). */
  target: string;
  /** Review profile picking the lens set (evm/solana/cardano-onchain; else default). */
  profile?: string;
  /** Narrow the scope to a subdirectory (respects the review file cap). */
  subsystem?: string;
  /** Finder models for diversity (a fan-out axis alongside lenses). Default: a
   *  single provider-default model (or $PWNKIT_DEEP_REVIEW_MODELS). */
  models?: string[];
  /** Finder attempts per (candidate × lens × model). Default 1 (or
   *  $PWNKIT_DEEP_REVIEW_ATTEMPTS) — best-of-N is opt-in. */
  attemptsPerCandidate?: number;
  /** Max finders in flight. Default 8 (matches runHuntScan). */
  concurrency?: number;
  /** Max candidate files hunted (largest-first). Default 8 (or $PWNKIT_DEEP_REVIEW_MAX_CANDIDATES). */
  maxCandidates?: number;
  /** Multi-lens quorum override (default: majority of the verify-lens count). */
  quorum?: number;
  runtime?: RuntimeMode;
  timeoutMs?: number;
  log?: (msg: string) => void;
}

/** Run a seedless, lens-driven deep review and return a JSON-ready outcome. Exposed for testing. */
export async function runDeepReview(opts: RunDeepReviewOptions): Promise<HuntOutcome> {
  const {
    runHuntScan,
    makeMultiLensVerifier,
    prepare,
    collectScopeFiles,
    countScopeFilesUpTo,
    getCloudSinkConfig,
    postFinding,
    evmFinderLenses,
    evmVerifyLenses,
    solanaFinderLenses,
    solanaVerifyLenses,
    cardanoFinderLenses,
    cardanoVerifyLenses,
    cairoFinderLenses,
    cairoVerifyLenses,
    moveFinderLenses,
    moveVerifyLenses,
  } = await import("@pwnkit/core");
  const log = opts.log ?? (() => {});
  const runtime: RuntimeMode = opts.runtime ?? "api";
  const maxCandidates = opts.maxCandidates ?? defaultMaxCandidates();
  // Single-model × 1-attempt by default; both are opt-in deeper knobs (flag > env).
  const models = opts.models ?? defaultModels();
  const attemptsPerCandidate = opts.attemptsPerCandidate ?? defaultAttempts();

  // Resolve a local path or a git URL into a local tree (same prepare() path
  // the hunt + review commands use; a git URL is shallow-cloned).
  const prepared = await prepare(opts.target, "source-code", { ...(opts.timeoutMs ? { timeout: opts.timeoutMs } : {}) }, (e) => {
    if (e.message) log(`[deep-review:source] ${e.message}`);
  });
  const sourceRoot = resolve(prepared.resolvedTarget);

  // Subsystem scoping — must stay inside the prepared tree (no path escape).
  let scopeRoot = sourceRoot;
  if (opts.subsystem && opts.subsystem.trim() !== "") {
    const scoped = resolve(join(sourceRoot, opts.subsystem));
    if (scoped !== sourceRoot && !scoped.startsWith(sourceRoot + sep)) {
      prepared.cleanup();
      throw new Error(`--subsystem '${opts.subsystem}' escapes the source tree`);
    }
    scopeRoot = scoped;
  }

  // Capture the cloud-sink config BEFORE suppressing the env (same reasoning as
  // hunt.ts #1051): the inner finder/skeptic passes would otherwise auto-POST
  // their RAW pre-gate findings as 'confirmed'. We disable that inner auto-post
  // and post ONLY the gated leads ourselves as honest 'discovered' candidates.
  const sinkCfg = getCloudSinkConfig();
  const savedCloudSink = process.env.PWNKIT_CLOUD_SINK;
  if (sinkCfg) delete process.env.PWNKIT_CLOUD_SINK;

  try {
    // EVM-scoped candidate filtering: for the evm-onchain profile, keep the
    // finder budget on protocol source by excluding test / vendored-lib / mock /
    // deploy-script files (the largest .sol files in a Foundry tree are vendored,
    // so largest-first would otherwise spend the whole budget on forge-std/tests
    // and time out). No behavior change for kernel / other profiles.
    const isEvmProfile = (opts.profile ?? "").trim().toLowerCase() === "evm-onchain";
    const { candidates: candidatePaths, totalFiles, overCap } = enumerateDeepReviewCandidates(
      scopeRoot,
      { collectScopeFiles, countScopeFilesUpTo },
      {
        maxCandidates,
        fileCap: DEEP_REVIEW_FILE_CAP,
        ...(isEvmProfile ? { exclude: (p: string) => isNonProtocolEvmPath(p, scopeRoot) } : {}),
      },
    );

    if (overCap) {
      return {
        exitCode: 2,
        result: {
          mode: "deep_review",
          source: sourceRoot,
          subsystem: opts.subsystem ?? null,
          scope_files: totalFiles,
          note: `scope exceeds the ${DEEP_REVIEW_FILE_CAP}-file review cap — narrow it with --subsystem <path> to a specific directory.`,
        },
      };
    }
    if (candidatePaths.length === 0) {
      return {
        exitCode: 2,
        result: {
          mode: "deep_review",
          source: sourceRoot,
          subsystem: opts.subsystem ?? null,
          scope_files: totalFiles,
          candidates: 0,
          note: "no reviewable source files found under the scope (empty tree or all filtered).",
        },
      };
    }

    const { finderLenses, verifyLenses, matchedProfile } = selectProfileLenses(opts.profile, {
      evmFinderLenses,
      evmVerifyLenses,
      solanaFinderLenses,
      solanaVerifyLenses,
      cardanoFinderLenses,
      cardanoVerifyLenses,
      cairoFinderLenses,
      cairoVerifyLenses,
      moveFinderLenses,
      moveVerifyLenses,
    });

    log(
      `[deep-review] ${candidatePaths.length} candidate file(s) (of ${totalFiles}${overCap ? "+" : ""}) ` +
        `× ${finderLenses.length} finder-lens(es); verify quorum over ${verifyLenses.length} lens(es); profile=${matchedProfile}`,
    );

    const verify = makeMultiLensVerifier(verifyLenses, {
      sourceRoot,
      runtime,
      ...(models?.[0] ? { model: models[0] } : {}),
      ...(opts.quorum ? { quorum: opts.quorum } : {}),
    });

    // Post each gated lead to the cloud-sink as a CANDIDATE finding (same path
    // hunt uses): leadToCandidateFinding forces status 'discovered' so leads
    // enter the cloud's adversarial verify gate, never as confirmed/sendable.
    // We post INCREMENTALLY — via runHuntScan's onConfirmed hook, as each lead
    // clears the multi-lens quorum — NOT in one burst after the whole sweep.
    // A long fan-out can outrun the sandbox/agent deadline; posting as-we-go
    // means a mid-sweep kill still lands the leads found so far, so the worker
    // sees findings_count > 0 and marks the scan complete-truncated instead of
    // failed-with-zero-findings. No-op when not in cloud mode (sinkCfg null).
    const postedIds = new Set<string>();
    let ingested = 0;
    const provenance = `deep_review (${matchedProfile} lenses)`;
    const postLead = async (lead: Finding): Promise<void> => {
      if (!sinkCfg || postedIds.has(lead.id)) return;
      postedIds.add(lead.id);
      await postFinding(leadToCandidateFinding(lead, `deep-review:${matchedProfile}`, provenance), sinkCfg);
      ingested++;
    };

    const res = await runHuntScan({
      sourceRoot,
      candidates: candidatePaths.map((path) => ({ path })),
      lenses: finderLenses,
      runtime,
      concurrency: opts.concurrency ?? DEFAULT_CONCURRENCY,
      attemptsPerCandidate,
      ...(models ? { models } : {}),
      verify,
      ...(sinkCfg ? { onConfirmed: postLead } : {}),
      log,
    });

    const leads = res.confirmed;

    // Safety net: post any confirmed lead the incremental hook didn't already
    // stream (deduped by id via postLead). In the normal path onConfirmed has
    // already posted every confirmed lead, so this is a no-op — it only covers
    // a confirmed-but-not-streamed edge (e.g. a future gate that confirms
    // outside the verify pool).
    if (sinkCfg) {
      for (const lead of leads) await postLead(lead);
      log(`[deep-review] posted ${ingested} lead(s) to the cloud-sink as candidate findings (incremental)`);
    }

    // Terminal status. A sweep that RAN is a SUCCESS whether or not any lead
    // survived the quorum — a clean 0-lead hunt is a valid outcome, not a
    // failure (the cloud worker maps a non-zero CLI exit to scan status=failed,
    // which was wrongly failing completed 0-finding sweeps — CapyFi/Onyx,
    // 2026-07-08). We do NOT mask a GENUINE backend failure: if the sweep did no
    // work at all — every finder run errored or timed out, so NONE completed —
    // that's an LLM/backend failure (auth, total stall), reported as exit 3. A
    // PARTIAL subset timing out still produced real coverage and is a success.
    // (`finderCompleted` may be absent from older/mocked results; treat absent
    // as "did work" so we never flip a completed run to failure on missing data.)
    const sweptNothing =
      res.scanned > 0 &&
      typeof res.finderCompleted === "number" &&
      res.finderCompleted === 0;
    if (sweptNothing) {
      return {
        exitCode: 3,
        result: {
          mode: "deep_review",
          profile: matchedProfile,
          source: sourceRoot,
          subsystem: opts.subsystem ?? null,
          scope_files: totalFiles,
          candidates: candidatePaths.length,
          scanned: res.scanned,
          finder_completed: res.finderCompleted,
          finder_timed_out: res.finderTimedOut ?? null,
          finder_errored: res.finderErrored ?? null,
          error:
            "every finder run failed (0 of " +
            `${res.scanned} completed) — no coverage was produced; treating as a backend/LLM failure, not a clean 0-finding result.`,
          warnings: res.warnings.slice(0, 10),
        },
      };
    }

    return {
      exitCode: 0,
      result: {
        mode: "deep_review",
        profile: matchedProfile,
        source: sourceRoot,
        subsystem: opts.subsystem ?? null,
        scope_files: totalFiles,
        candidates: candidatePaths.length,
        finder_lenses: finderLenses.map((l) => l.id),
        verify_lenses: verifyLenses.map((l) => l.id),
        scanned: res.scanned,
        findings: res.findings.length,
        confirmed: leads.length,
        leads: leads.map((f) => ({
          title: f.title,
          severity: f.severity,
          analysis: f.evidence.analysis ?? "",
        })),
        ingested: sinkCfg ? ingested : null,
        warnings: res.warnings.slice(0, 10),
        note: "LEADS, not confirmed bugs. Each survived the multi-lens refute quorum; verify the real sink + impact before disclosure.",
      },
    };
  } finally {
    if (savedCloudSink !== undefined) process.env.PWNKIT_CLOUD_SINK = savedCloudSink;
    prepared.cleanup();
  }
}

interface DeepReviewOpts {
  profile?: string;
  subsystem?: string;
  models?: string;
  attempts?: string;
  concurrency?: string;
  maxCandidates?: string;
  quorum?: string;
  runtime?: string;
  format?: string;
  output?: string;
  timeout?: string;
}

function parsePositive(flag: string, raw: string | undefined, dflt: number): number {
  if (raw === undefined) return dflt;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) throw new Error(`invalid ${flag} '${raw}' (expected positive integer)`);
  return n;
}

async function deepReviewAction(target: string, opts: DeepReviewOpts): Promise<void> {
  if (!target || target.trim() === "") throw new Error("missing required argument: <target> (source tree path or git URL)");

  const { writeFileSync } = await import("node:fs");
  const outcome = await runDeepReview({
    target,
    ...(opts.profile ? { profile: opts.profile } : {}),
    ...(opts.subsystem ? { subsystem: opts.subsystem } : {}),
    // Flag > env > single provider-default model. Only pass `models` when the
    // flag is set; otherwise let runDeepReview resolve $PWNKIT_DEEP_REVIEW_MODELS.
    ...(opts.models ? { models: opts.models.split(",").map((s) => s.trim()).filter(Boolean) } : {}),
    ...(opts.attempts ? { attemptsPerCandidate: parsePositive("--attempts", opts.attempts, defaultAttempts()) } : {}),
    concurrency: parsePositive("--concurrency", opts.concurrency, DEFAULT_CONCURRENCY),
    maxCandidates: parsePositive("--max-candidates", opts.maxCandidates, defaultMaxCandidates()),
    ...(opts.quorum ? { quorum: parsePositive("--quorum", opts.quorum, 1) } : {}),
    ...(opts.runtime ? { runtime: opts.runtime as RuntimeMode } : {}),
    timeoutMs: parsePositive("--timeout", opts.timeout, 600_000),
    log: (m) => process.stderr.write(m + "\n"),
  });

  const json = JSON.stringify(outcome.result, null, 2);
  if (opts.output) writeFileSync(resolve(opts.output), json + "\n", "utf8");
  else process.stdout.write(json + "\n");
  process.exitCode = outcome.exitCode;
}

export function registerDeepReviewCommand(program: Command): void {
  program
    .command("deep-review")
    .description(
      "Seedless DEPTH review of a source tree: enumerate candidate files, re-hunt " +
        "each through the profile's specialized finder lenses, and gate survivors " +
        "through the multi-lens verify quorum. Emits LEADS to verify (not confirmed " +
        "bugs). Exit 0=sweep completed (with or without leads), 2=skipped (no files / " +
        "over the review cap), 3=error (bad flags / unreadable target / all finders failed).",
    )
    .argument("<target>", "Source tree to review (a local path or a git URL)")
    .option("--profile <p>", "Lens profile: evm-onchain | solana-onchain | cardano-onchain | cairo-onchain | move-onchain (else a generic default lens set)")
    .option("--subsystem <path>", "Narrow the review scope to a subdirectory (respects the 5000-file review cap)")
    .option("--models <a,b>", "Comma-separated finder models for diversity (default: single provider model, or $PWNKIT_DEEP_REVIEW_MODELS)")
    .option("--attempts <N>", `Finder attempts per candidate×lens×model, best-of-N (default ${DEFAULT_ATTEMPTS}, or $PWNKIT_DEEP_REVIEW_ATTEMPTS)`)
    .option("--concurrency <N>", `Max finders in flight (default ${DEFAULT_CONCURRENCY})`)
    .option("--max-candidates <N>", `Cap candidate files hunted, largest-first (default ${DEFAULT_MAX_CANDIDATES}, or $PWNKIT_DEEP_REVIEW_MAX_CANDIDATES)`)
    .option("--quorum <N>", "Multi-lens verify quorum (default: majority of the verify-lens count)")
    .option("--format <fmt>", "Output format (json)", "json")
    .option("--output <path>", "Write the result JSON to this path instead of stdout")
    .option("--runtime <mode>", "Engine runtime (default api)")
    .option("--timeout <ms>", "Cloud agent timeout budget in milliseconds", "600000")
    .action(async (target: string, opts: DeepReviewOpts) => {
      try {
        await deepReviewAction(target, opts);
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        const json = JSON.stringify({ mode: "deep_review", error: reason }, null, 2);
        if (opts.output) {
          const { writeFileSync } = await import("node:fs");
          try { writeFileSync(resolve(opts.output), json + "\n", "utf8"); } catch { process.stderr.write(json + "\n"); }
        } else process.stdout.write(json + "\n");
        process.exitCode = 3;
      }
    });
}
