/**
 * EVM on-chain PROVING harness (Tier 3) — the EVM analog of the kernel
 * QEMU/KASAN verify lane (`kernel/exploit/harness.ts`, `c-cpp-tier3.ts`).
 *
 * The on-chain review profiles emit "proof" today as textual `poc_steps` only
 * (`solana-onchain-profile.ts`, `cardano-onchain-profile.ts`). The EVM profile
 * (built in parallel) instead emits a runnable **Foundry test** in `poc_steps`.
 * This module is what RUNS that test against a pinned-block mainnet fork and
 * turns a green exploit test into a `candidate → proven` promotion.
 *
 * Design + full rationale: `docs/design/0contract-proving-harness.md`.
 *
 * ── What is real vs. stubbed in this file ────────────────────────────────────
 * REAL + unit-tested (no forge/anvil/RPC needed):
 *   - `parseForgeOutput`      — pure `forge test --json` → outcomes parser.
 *   - `adjudicateForgeOutcomes` — pure outcomes → proven/not_proven verdict.
 *   - `evmVerifyEnabled` / `evmForkRpc` / `forgeAvailable` — env gate + probes.
 *   - `planEvmVerify`         — assembles the forge invocation WITHOUT executing
 *                               when the gate is OFF (mirrors `planArchetypeSweep`).
 *   - `evmVerifyCacheKey`     — deterministic proof-binding key.
 * STUBBED behind the gate (needs forge + an archive RPC; NOT run in CI):
 *   - `runEvmVerify`          — the child_process `forge test` execution +
 *                               throwaway-project staging. Clearly marked; the
 *                               multi-week build surface (see the design doc's
 *                               phased plan P1+).
 *
 * DEFAULT-SAFE: with `0SEC_EVM_VERIFY` unset (the default), `runEvmVerify` is a
 * no-op that returns `{ status: "skipped", ran: false }` — nothing spawns, no
 * RPC is touched. `0sec review` on an EVM repo is harmless on a box with no
 * foundry toolchain, matching the kernel verify-path gating.
 */

import { createHash } from "node:crypto";

// ── Env gate + probes (default OFF, mirrors archetypeSweepEnabled) ───────────

/**
 * Master opt-in gate. Default OFF — mirrors `archetypeSweepEnabled()` /
 * `0SEC_ARCHETYPE_SWEEP`. When OFF, `planEvmVerify` still plans (returns the
 * invocation + a warning) but never executes, and `runEvmVerify` no-ops.
 */
export function evmVerifyEnabled(): boolean {
  return !["", "0", "false", "no"].includes((process.env["0SEC_EVM_VERIFY"] ?? "").toLowerCase());
}

/** The archive-node fork RPC URL (`0SEC_EVM_FORK_RPC`), or undefined when unset. */
export function evmForkRpc(explicit?: string): string | undefined {
  const v = explicit ?? process.env["0SEC_EVM_FORK_RPC"]?.trim();
  return v && v.length > 0 ? v : undefined;
}

/** Resolved `forge` binary (path override via `0SEC_EVM_FORGE_BIN`, else `forge`). */
export function forgeBin(): string {
  const v = process.env["0SEC_EVM_FORGE_BIN"]?.trim();
  return v && v.length > 0 ? v : "forge";
}

/**
 * Readiness probe: is the harness actually runnable? Requires the master gate
 * ON AND a fork RPC present. Does NOT shell out to check `forge` exists (that
 * belongs in `runEvmVerify` behind the gate) — this is the cheap pre-flight the
 * planner uses to decide plan-only vs. would-execute.
 */
export function forgeAvailable(): boolean {
  return evmVerifyEnabled() && evmForkRpc() !== undefined;
}

// ── Parsed-output types ──────────────────────────────────────────────────────

/** Foundry test kinds, normalized from forge's `kind` tag. */
export type ForgeTestKind = "standard" | "fuzz" | "invariant" | "unknown";

/** Per-test outcome status, normalized from forge's `Success|Failure|Skipped`. */
export type ForgeTestStatus = "pass" | "fail" | "skip";

/** One test result extracted from `forge test --json`. */
export interface ForgeTestOutcome {
  /** Suite key, e.g. "test/osecExploit.t.sol:osecExploit". */
  suite: string;
  /** Test function name, e.g. "testExploit" (parens stripped). */
  name: string;
  status: ForgeTestStatus;
  kind: ForgeTestKind;
  /** Revert / assertion string on failure (the failing-assertion witness). */
  reason?: string;
  /** Minimized breaking call-sequence for fuzz/invariant failures (raw JSON string). */
  counterexample?: string;
  /** `console.log` output — where an exploit prints realized attacker profit. */
  decodedLogs?: string[];
  /** Gas / runs number carried by forge's `kind` payload, when present. */
  gas?: number;
}

/** Result of `parseForgeOutput` — the pure parse layer. */
export interface ParsedForgeOutput {
  /** True when the forge JSON parsed into at least a well-formed shape. */
  ok: boolean;
  outcomes: ForgeTestOutcome[];
  passed: number;
  failed: number;
  skipped: number;
  /** Set (and `ok:false`) when the input was not parseable forge JSON. */
  parseError?: string;
}

// ── Request / result types (the candidate → proven flow) ─────────────────────

export type EvmVerifyStatus =
  /** A proving exploit/invariant test reproduced impact. */
  | "proven"
  /** Tests ran but nothing proved impact (exploit reverted / invariant held). */
  | "not_proven"
  /** The scaffold test failed to compile. */
  | "compile_failed"
  /** Infra failure (no forge, RPC rate-limit, timeout) — inconclusive, NOT a refute. */
  | "harness_failed"
  /** Gate OFF or no RPC — default-safe no-op. */
  | "skipped";

export interface EvmVerifyRequest {
  /** Path to the on-chain Solidity target repo checkout. */
  targetRepo: string;
  /**
   * The Foundry exploit test source the EVM profile emitted in `poc_steps`.
   * Written into the throwaway project's `test/` dir by `runEvmVerify`.
   */
  testSource: string;
  /** Test file basename (default "osecExploit.t.sol"). */
  testFile?: string;
  /** Optional contract filter (`--match-contract`). */
  testContract?: string;
  /** Optional single-test filter (`--match-test`). */
  testFn?: string;
  /** Fork RPC override; falls back to `0SEC_EVM_FORK_RPC`. */
  forkUrl?: string;
  /**
   * Pinned fork block. REQUIRED for a reproducible proof — an unpinned fork
   * drifts every block. Absent ⇒ the harness refuses to prove (see the design
   * doc §4).
   */
  forkBlock?: number;
  /** Chain id the RPC serves (bound into the cache key). Default 1 (mainnet). */
  chainId?: number;
  /** Run against a local anvil fork instead of forge's in-process `--fork-url`. */
  useAnvil?: boolean;
  /** Hard wall-clock ceiling for the whole verify (default 5 min, matches Tier-3). */
  wallClockMs?: number;
  /** git commit of `targetRepo` at verify time (bound into the cache key). */
  targetCommit?: string;
  /** Skip the env gate (tests only — production callers must respect the gate). */
  force?: boolean;
}

/** The assembled forge invocation — planned, not necessarily executed. */
export interface EvmVerifyPlan {
  /** The normalized `forge test …` command line (single string, for audit). */
  command: string;
  /** Argv form of the same command (what `runEvmVerify` would spawn). */
  argv: string[];
  /** Resolved fork RPC (may be undefined when none is configured). */
  forkUrl?: string;
  forkBlock?: number;
  useAnvil: boolean;
  /** Deterministic proof-binding key (see `evmVerifyCacheKey`). */
  cacheKey: string;
  wallClockMs: number;
}

export interface EvmVerifyResult {
  status: EvmVerifyStatus;
  /** Did the harness actually spawn forge? False for skipped/plan-only. */
  ran: boolean;
  outcomes: ForgeTestOutcome[];
  /** The passing exploit test (or broken invariant) that constitutes the proof. */
  provingTest?: ForgeTestOutcome;
  /** The failing-assertion / revert reason when nothing proved impact. */
  failingAssertion?: string;
  /** The plan that was (or would have been) executed. */
  plan?: EvmVerifyPlan;
  cacheKey?: string;
  reason: string;
  warnings: string[];
}

const DEFAULT_WALL_CLOCK_MS = 5 * 60 * 1000;
const DEFAULT_TEST_FILE = "osecExploit.t.sol";

// ── parseForgeOutput — the pure oracle-input parser (REAL, unit-tested) ───────

/**
 * Strip any non-JSON preamble forge may print before the result object
 * (compiler warnings, "Compiling…" lines) and return the JSON substring, or
 * null when no `{…}` object is present.
 */
function extractJsonObject(raw: string): string | null {
  const start = raw.indexOf("{");
  const end = raw.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) return null;
  return raw.slice(start, end + 1);
}

function normalizeStatus(raw: unknown): ForgeTestStatus {
  const s = String(raw).toLowerCase();
  if (s === "success") return "pass";
  if (s === "skipped") return "skip";
  return "fail"; // "Failure" and anything unexpected count as fail (conservative)
}

function normalizeKind(kind: unknown): { kind: ForgeTestKind; gas?: number } {
  // forge's `kind` is a tagged object: {"Standard": <gas>} | {"Fuzz": {…}} |
  // {"Invariant": {…}} — or occasionally a bare string. Read the tag.
  if (typeof kind === "string") {
    const k = kind.toLowerCase();
    if (k === "standard" || k === "fuzz" || k === "invariant") return { kind: k };
    return { kind: "unknown" };
  }
  if (kind && typeof kind === "object") {
    const tag = Object.keys(kind as Record<string, unknown>)[0];
    if (!tag) return { kind: "unknown" };
    const payload = (kind as Record<string, unknown>)[tag];
    const gas = typeof payload === "number" ? payload : undefined;
    const t = tag.toLowerCase();
    if (t === "standard") return gas !== undefined ? { kind: "standard", gas } : { kind: "standard" };
    if (t === "fuzz") return { kind: "fuzz" };
    if (t === "invariant") return { kind: "invariant" };
  }
  return { kind: "unknown" };
}

function stripParens(fnName: string): string {
  return fnName.replace(/\(\)$/, "");
}

/**
 * Parse `forge test --json` output into normalized per-test outcomes. PURE: no
 * I/O, no forge needed. Never throws — malformed input returns
 * `{ ok:false, parseError }` with empty counts, exactly like the kernel
 * sanitizer parser returning null rather than throwing.
 */
export function parseForgeOutput(raw: string): ParsedForgeOutput {
  const empty: ParsedForgeOutput = { ok: false, outcomes: [], passed: 0, failed: 0, skipped: 0 };
  const trimmed = (raw ?? "").trim();
  if (!trimmed) return { ...empty, parseError: "empty forge output" };

  const jsonSlice = extractJsonObject(trimmed);
  if (!jsonSlice) return { ...empty, parseError: "no JSON object found in forge output" };

  let root: unknown;
  try {
    root = JSON.parse(jsonSlice);
  } catch (err) {
    return { ...empty, parseError: `forge JSON parse failed: ${err instanceof Error ? err.message : String(err)}` };
  }
  if (!root || typeof root !== "object") {
    return { ...empty, parseError: "forge JSON root is not an object" };
  }

  const outcomes: ForgeTestOutcome[] = [];
  for (const [suite, suiteVal] of Object.entries(root as Record<string, unknown>)) {
    if (!suiteVal || typeof suiteVal !== "object") continue;
    const results = (suiteVal as Record<string, unknown>).test_results;
    if (!results || typeof results !== "object") continue;
    for (const [fnKey, resVal] of Object.entries(results as Record<string, unknown>)) {
      if (!resVal || typeof resVal !== "object") continue;
      const res = resVal as Record<string, unknown>;
      const status = normalizeStatus(res.status);
      const { kind, gas } = normalizeKind(res.kind);
      const decodedLogs = Array.isArray(res.decoded_logs)
        ? (res.decoded_logs as unknown[]).map((l) => String(l))
        : undefined;
      const reason =
        typeof res.reason === "string" && res.reason.length > 0 ? res.reason : undefined;
      const counterexample =
        res.counterexample != null ? JSON.stringify(res.counterexample) : undefined;

      outcomes.push({
        suite,
        name: stripParens(fnKey),
        status,
        kind,
        ...(reason ? { reason } : {}),
        ...(counterexample ? { counterexample } : {}),
        ...(decodedLogs && decodedLogs.length > 0 ? { decodedLogs } : {}),
        ...(gas !== undefined ? { gas } : {}),
      });
    }
  }

  const passed = outcomes.filter((o) => o.status === "pass").length;
  const failed = outcomes.filter((o) => o.status === "fail").length;
  const skipped = outcomes.filter((o) => o.status === "skip").length;
  return { ok: true, outcomes, passed, failed, skipped };
}

// ── Adjudication — outcomes → proven/not_proven (PURE) ───────────────────────

/**
 * An exploit-shaped POSITIVE test proves impact by PASSING (its own
 * `assertGt(profit,0)` / `assertEq(vault,0)` held). Name heuristic mirrors
 * Tier-3's explicit category mapping: we only treat a green test as proof when
 * it is clearly an exploit assertion, never a vacuous `test_nothing`.
 */
function isExploitTestName(name: string): boolean {
  return /(^test.*(exploit|drain|steal|attack|profit|reentran|overflow|underflow))|(^testexploit$)|(^test_exploit)/i.test(
    name,
  );
}

/** An INVARIANT test proves impact by FAILING with a counterexample (property broke). */
function isInvariantName(name: string): boolean {
  return /^invariant_/i.test(name);
}

export interface ForgeAdjudication {
  status: Extract<EvmVerifyStatus, "proven" | "not_proven">;
  provingTest?: ForgeTestOutcome;
  failingAssertion?: string;
  reason: string;
}

/**
 * Turn parsed outcomes into a proven/not_proven verdict. PURE. Two proof
 * shapes (see design doc §5):
 *   - a PASSING exploit-named/standard test → the exploit reproduced.
 *   - a FAILING invariant test with a counterexample → the property broke.
 * Everything else is `not_proven`, surfacing the most informative failing
 * assertion for the audit trail.
 */
export function adjudicateForgeOutcomes(parsed: ParsedForgeOutput): ForgeAdjudication {
  if (!parsed.ok) {
    return { status: "not_proven", reason: parsed.parseError ?? "forge output did not parse" };
  }

  // Proof shape 1: a broken invariant (fail + counterexample).
  const brokenInvariant = parsed.outcomes.find(
    (o) => isInvariantName(o.name) && o.status === "fail" && o.counterexample,
  );
  if (brokenInvariant) {
    return {
      status: "proven",
      provingTest: brokenInvariant,
      reason: `invariant '${brokenInvariant.name}' broken with a counterexample`,
    };
  }

  // Proof shape 2: a passing exploit-shaped test.
  const exploitPass = parsed.outcomes.find((o) => isExploitTestName(o.name) && o.status === "pass");
  if (exploitPass) {
    return {
      status: "proven",
      provingTest: exploitPass,
      reason: `exploit test '${exploitPass.name}' passed (impact assertion held)`,
    };
  }

  // Nothing proved impact. Surface the most useful failing assertion: prefer an
  // exploit-named test that reverted (tells us WHY the exploit didn't fire).
  const revertedExploit = parsed.outcomes.find(
    (o) => isExploitTestName(o.name) && o.status === "fail",
  );
  const anyFail = revertedExploit ?? parsed.outcomes.find((o) => o.status === "fail");
  const failingAssertion = anyFail?.reason;
  return {
    status: "not_proven",
    ...(failingAssertion ? { failingAssertion } : {}),
    reason:
      parsed.outcomes.length === 0
        ? "no tests ran"
        : revertedExploit
          ? `exploit test '${revertedExploit.name}' did not reproduce impact`
          : "no exploit-shaped test passed and no invariant broke",
  };
}

// ── Cache key — bind a proof to the world it was proven against (PURE) ────────

/**
 * Deterministic proof-binding key over `(targetCommit, chainId, forkBlock,
 * testSource)`. Direct analog of the kernel harness's `bootedCacheKey` — a
 * mainnet-fork proof must never be presented as if it held on a different
 * chain/block/commit. `unpinned` is used when no fork block was given (such a
 * proof is not reproducible and the harness refuses to mark it proven).
 */
export function evmVerifyCacheKey(req: EvmVerifyRequest): string {
  const parts = [
    req.targetCommit ?? "no-commit",
    `chain=${req.chainId ?? 1}`,
    `block=${req.forkBlock ?? "unpinned"}`,
    createHash("sha256").update(req.testSource ?? "").digest("hex").slice(0, 16),
  ];
  return `evm-${createHash("sha256").update(parts.join("|")).digest("hex").slice(0, 24)}`;
}

// ── planEvmVerify — assemble the invocation, do NOT execute when gated OFF ────

/**
 * Assemble the normalized forge invocation for a request. Mirrors
 * `planArchetypeSweep`: when the gate is OFF (and `force` is not set) it returns
 * the plan alongside a warning explaining why nothing will run, rather than
 * silently doing nothing. It NEVER spawns a process — planning is pure.
 *
 * Returns `plan: undefined` only when the request is unforkable (no RPC), with a
 * warning; otherwise a full `EvmVerifyPlan` even in the gated-off case so callers
 * can show the operator exactly what WOULD run.
 */
export function planEvmVerify(req: EvmVerifyRequest): { plan?: EvmVerifyPlan; warnings: string[] } {
  const warnings: string[] = [];
  const enabled = req.force || evmVerifyEnabled();
  if (!enabled) {
    warnings.push("evm verify disabled (set 0SEC_EVM_VERIFY=1 to enable, or pass force:true)");
  }

  const forkUrl = evmForkRpc(req.forkUrl);
  if (!forkUrl) {
    warnings.push("no fork RPC (set 0SEC_EVM_FORK_RPC or pass forkUrl) — cannot fork; plan omitted");
    return { warnings };
  }
  if (req.forkBlock === undefined) {
    warnings.push("no forkBlock pinned — a proof against an unpinned fork is not reproducible");
  }

  const testFile = req.testFile ?? DEFAULT_TEST_FILE;
  const useAnvil = req.useAnvil ?? false;
  // When using a local anvil fork the forge command points at the local node;
  // the real (secret) archive URL only ever reaches anvil, not the test process.
  const effectiveForkUrl = useAnvil ? "http://127.0.0.1:8545" : forkUrl;

  const argv = [
    forgeBin(),
    "test",
    "--root",
    req.targetRepo,
    "--match-path",
    `test/${testFile}`,
    ...(req.testContract ? ["--match-contract", req.testContract] : []),
    ...(req.testFn ? ["--match-test", req.testFn] : []),
    "--fork-url",
    effectiveForkUrl,
    ...(req.forkBlock !== undefined ? ["--fork-block-number", String(req.forkBlock)] : []),
    "--json",
    "-vvv",
  ];

  const plan: EvmVerifyPlan = {
    command: argv.join(" "),
    argv,
    forkUrl: effectiveForkUrl,
    ...(req.forkBlock !== undefined ? { forkBlock: req.forkBlock } : {}),
    useAnvil,
    cacheKey: evmVerifyCacheKey(req),
    wallClockMs: req.wallClockMs ?? DEFAULT_WALL_CLOCK_MS,
  };
  return { plan, warnings };
}

// ── runEvmVerify — GATED child_process exec (STUBBED / un-exercised) ─────────

/**
 * Run the EVM verify lane end-to-end: scaffold a throwaway forge project against
 * `targetRepo`, write the emitted test, spawn `forge test --json`, parse the
 * output, and adjudicate.
 *
 * ⚠️ STUBBED: the actual `child_process` forge execution + throwaway-project
 * staging are NOT implemented here — this is the multi-week P1+ surface in the
 * design doc. Today this function only exercises the DEFAULT-SAFE gate: with the
 * gate OFF (or no RPC) it returns `{ status: "skipped", ran: false }` and never
 * spawns anything. When the gate is ON it returns `harness_failed` with a clear
 * "not implemented" reason rather than pretending to prove — an honest no-op, not
 * a fake green. The parse/adjudicate/plan/cacheKey pieces it WILL call are all
 * real and tested above.
 */
export async function runEvmVerify(req: EvmVerifyRequest): Promise<EvmVerifyResult> {
  const { plan, warnings } = planEvmVerify(req);

  if (!req.force && !evmVerifyEnabled()) {
    return {
      status: "skipped",
      ran: false,
      outcomes: [],
      ...(plan ? { plan, cacheKey: plan.cacheKey } : {}),
      reason: "0SEC_EVM_VERIFY not set — harness is a default-safe no-op",
      warnings,
    };
  }
  if (!plan) {
    return {
      status: "skipped",
      ran: false,
      outcomes: [],
      reason: "no fork RPC configured — cannot fork",
      warnings,
    };
  }

  // ── The un-exercised part. P1 replaces this block with the real scaffold +
  // `spawn(forgeBin(), plan.argv.slice(1))` + `parseForgeOutput(stdout)` +
  // `adjudicateForgeOutcomes(...)`. Kept as an explicit, honest not-implemented
  // return so a gate-ON caller never receives a fabricated "proven".
  return {
    status: "harness_failed",
    ran: false,
    outcomes: [],
    plan,
    cacheKey: plan.cacheKey,
    reason:
      "runEvmVerify execution path is not implemented yet (design doc P1). " +
      "Scaffold + `forge test` exec is the stubbed surface; parse/adjudicate/plan are real.",
    warnings,
  };
}

// ── promoteFindingsWithEvmResult — additive proven-promotion (design §7) ─────
//
// Intentionally NOT implemented here: promotion needs the `Finding` category
// vocabulary the EVM profile defines (built in parallel). Once that lands, this
// mirrors `promoteFindingsWithTier3Result` — additive, only fires on
// `status === "proven"`, sets `status: "proven"`, `confidence: 1.0`, and a
// `triageNote` of `evm:forge:<suite>::<fn>`. Left as a documented seam so the
// two files can be wired together without guessing the contract.
