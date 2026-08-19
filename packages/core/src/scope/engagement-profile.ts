// ── Engagement hardening profile ──
//
// A single opt-in posture that makes the engine behave conservatively on an
// authorized enterprise engagement, instead of asking the operator to remember
// six independent env vars.
//
// The engine is architecturally loud by default. Four behaviours in particular
// read as an attack to a mature SOC:
//
//   1. The password-reset burst probe (`recon/rate-limit.ts`) fires up to 25
//      un-throttled POSTs at a discovered reset endpoint. That is the exact
//      shape of a credential-stuffing alert.
//   2. The deterministic web-recon pre-pass (`stages/web-recon-prepass.ts`)
//      uses raw `fetch` and therefore bypasses the per-host token bucket — and
//      it is default-ON for web scans.
//   3. The WAF-evasion ladder (`scope/waf-detect.ts`, dispatched from
//      `agent/tools.ts`) auto-fires on any blocked response, escalating a
//      routine WAF block into a SOC incident.
//   4. The token bucket is fixed-interval, so request timing is perfectly
//      periodic — arguably a STRONGER automation signal to a behavioural SOC
//      than bursty traffic.
//
// This module resolves ONE posture object describing what to do about all four,
// so the call sites carry a single lookup instead of four scattered
// conditionals. It performs no I/O and holds no global state.
//
// ── Configuration sources & precedence ──
//
// Same three sources and the same precedence as attribution
// (`scope/attribution.ts`): **scope file > env > CLI**. The scope file wins
// because it is the artifact that binds to a specific engagement — if the
// engagement's scope file says "conservative", an operator's ad-hoc CLI flag
// must not quietly loosen it.
//
//   1. Scope file: an optional `engagement` block alongside `in_scope` /
//      `out_of_scope`.
//   2. Env: `PWNKIT_ENGAGEMENT_PROFILE`, `PWNKIT_WAF_EVASION`,
//      `PWNKIT_ENGAGEMENT_RATE_RPS`, `PWNKIT_ENGAGEMENT_JITTER_MS`.
//   3. CLI: `--engagement-profile <name>`, `--no-waf-evasion`.
//
// ── Default is UNCHANGED behaviour ──
//
// Profile `standard` (the default when nothing is configured) reproduces the
// pre-existing engine behaviour exactly: burst probe on, pre-pass on raw fetch,
// evasion ladder on, no jitter, 5 rps/host. Everything here is opt-in.
//
// The one exception is `wafEvasionLadder`, which is independently disableable
// (`--no-waf-evasion` / `PWNKIT_WAF_EVASION=0`) WITHOUT selecting a profile —
// that gap was worth closing on its own.

import type { EngagementPostureRecord } from "@pwnkit/shared";

/** Supported engagement profiles. */
export type EngagementProfileName = "standard" | "conservative";

export const ENGAGEMENT_PROFILE_NAMES: readonly EngagementProfileName[] = [
  "standard",
  "conservative",
];

/** Which configuration source decided a given field. Recorded for the audit. */
export type EngagementSource = "default" | "cli" | "env" | "scope-file";

/**
 * Per-host rps the conservative profile applies when the operator did not pass
 * an explicit `--rate-limit` default. Well under the engine's 5 rps default —
 * one request per second per host, further smeared by jitter.
 */
export const CONSERVATIVE_RPS = 1;

/**
 * Full-jitter base (ms) under the conservative profile. Every acquire sleeps a
 * uniform random `[0, baseMs]` on top of the token-bucket pacing, so the
 * request train stops being periodic.
 */
export const CONSERVATIVE_JITTER_MS = 750;

/** The engine's historical default per-host rps (profile `standard`). */
export const STANDARD_RPS = 5;

/** Full-jitter configuration applied to every per-host token bucket. */
export interface EngagementJitter {
  /** Upper bound of the uniform random delay added per acquire. */
  baseMs: number;
}

/**
 * The resolved posture. One object, read by every call site that would
 * otherwise grow its own conditional.
 */
export interface EngagementPosture {
  /** Resolved profile name. */
  profile: EngagementProfileName;
  /** True for any non-`standard` profile — i.e. the operator opted in. */
  active: boolean;
  /**
   * Fire the bounded password-reset burst probe when a reset endpoint is
   * discovered. False under `conservative`: 15 rapid unauthenticated POSTs is
   * the single loudest thing the pre-pass does.
   */
  resetBurstProbe: boolean;
  /**
   * How the web-recon pre-pass issues HTTP.
   *   - `direct-fetch`: raw `fetch`, no pacing (historical behaviour).
   *   - `rate-limited`: routed through the per-host token bucket.
   *
   * We PACE the pre-pass rather than disable it: it is the highest-signal,
   * lowest-cost stage in the engine (baseline headers, stack fingerprint,
   * source maps, DNS posture), and none of it is inherently loud once the
   * burst probe is off and the requests are paced. Disabling it would cost
   * real findings to solve a problem that pacing solves.
   */
  webReconPrepass: "direct-fetch" | "rate-limited";
  /** Run the adaptive WAF-evasion ladder on a blocked response. */
  wafEvasionLadder: boolean;
  /** Full-jitter config for the token bucket; undefined = fixed-interval. */
  jitter?: EngagementJitter;
  /** Default per-host rps applied when no explicit `--rate-limit` default. */
  rateLimitRps: number;
  /** Which source decided each operator-visible field. */
  sources: {
    profile: EngagementSource;
    wafEvasionLadder: EngagementSource;
    rateLimitRps: EngagementSource;
    jitter: EngagementSource;
    resetBurstProbe: EngagementSource;
  };
}

/** Shape of the optional `engagement` block inside a scope JSON file. */
export interface EngagementScopeBlock {
  profile?: string;
  waf_evasion?: boolean;
  reset_burst_probe?: boolean;
  rate_limit_rps?: number;
  jitter_ms?: number;
}

export interface EngagementProfileInputs {
  /** Already-parsed `engagement` block from the scope file, if any. */
  scopeFileBlock?: EngagementScopeBlock;
  /** Env-var inputs, normally `process.env`. */
  env?: NodeJS.ProcessEnv;
  /** `--engagement-profile <name>`. */
  cliProfile?: string;
  /** `--no-waf-evasion` → false. Undefined when the flag was not passed. */
  cliWafEvasion?: boolean;
}

const ENV_PROFILE_KEY = "PWNKIT_ENGAGEMENT_PROFILE";
const ENV_WAF_EVASION_KEY = "PWNKIT_WAF_EVASION";
const ENV_RATE_RPS_KEY = "PWNKIT_ENGAGEMENT_RATE_RPS";
const ENV_JITTER_MS_KEY = "PWNKIT_ENGAGEMENT_JITTER_MS";

/**
 * Validate a profile name. Throws on anything unknown so a typo
 * (`--engagement-profile conservitive`) fails at start-of-scan rather than
 * silently running the loud default for five hours.
 */
export function parseEngagementProfileName(raw: string): EngagementProfileName {
  const name = raw.trim().toLowerCase();
  if ((ENGAGEMENT_PROFILE_NAMES as readonly string[]).includes(name)) {
    return name as EngagementProfileName;
  }
  throw new Error(
    `Unknown engagement profile '${raw}'. Supported: ${ENGAGEMENT_PROFILE_NAMES.join(", ")}.`,
  );
}

/** The baseline posture for a profile, before per-field overrides. */
function baseFor(profile: EngagementProfileName): Omit<EngagementPosture, "sources"> {
  if (profile === "conservative") {
    return {
      profile,
      active: true,
      resetBurstProbe: false,
      webReconPrepass: "rate-limited",
      wafEvasionLadder: false,
      jitter: { baseMs: CONSERVATIVE_JITTER_MS },
      rateLimitRps: CONSERVATIVE_RPS,
    };
  }
  return {
    profile: "standard",
    active: false,
    resetBurstProbe: true,
    webReconPrepass: "direct-fetch",
    wafEvasionLadder: true,
    jitter: undefined,
    rateLimitRps: STANDARD_RPS,
  };
}

/**
 * Resolve the engagement posture from the three configured sources.
 *
 * Precedence is scope file > env > CLI, matching `resolveAttribution`. Fields
 * are resolved INDEPENDENTLY: a scope file that only pins `waf_evasion: false`
 * leaves the profile itself to env/CLI.
 *
 * Never throws for a missing config; throws only on malformed config (unknown
 * profile name, non-numeric rps), because that is an operator error worth
 * surfacing at boot.
 */
export function resolveEngagementProfile(
  inputs: EngagementProfileInputs = {},
): EngagementPosture {
  const env = inputs.env;
  const block = inputs.scopeFileBlock;

  // ── profile name (scope file > env > CLI) ──
  let profile: EngagementProfileName = "standard";
  let profileSource: EngagementSource = "default";
  const cliProfileRaw = nonEmpty(inputs.cliProfile);
  const envProfileRaw = nonEmpty(env?.[ENV_PROFILE_KEY]);
  const fileProfileRaw = nonEmpty(block?.profile);
  if (fileProfileRaw !== undefined) {
    profile = parseEngagementProfileName(fileProfileRaw);
    profileSource = "scope-file";
  } else if (envProfileRaw !== undefined) {
    profile = parseEngagementProfileName(envProfileRaw);
    profileSource = "env";
  } else if (cliProfileRaw !== undefined) {
    profile = parseEngagementProfileName(cliProfileRaw);
    profileSource = "cli";
  }

  const posture: EngagementPosture = {
    ...baseFor(profile),
    sources: {
      profile: profileSource,
      wafEvasionLadder: profileSource,
      rateLimitRps: profileSource,
      jitter: profileSource,
      resetBurstProbe: profileSource,
    },
  };

  // ── WAF-evasion ladder (independently disableable, no profile required) ──
  const wafOverride = resolveBoolOverride({
    file: block?.waf_evasion,
    env: env?.[ENV_WAF_EVASION_KEY],
    cli: inputs.cliWafEvasion,
    label: ENV_WAF_EVASION_KEY,
  });
  if (wafOverride) {
    posture.wafEvasionLadder = wafOverride.value;
    posture.sources.wafEvasionLadder = wafOverride.source;
  }

  // ── reset-endpoint burst probe (scope-file only; no CLI/env knob today) ──
  if (typeof block?.reset_burst_probe === "boolean") {
    posture.resetBurstProbe = block.reset_burst_probe;
    posture.sources.resetBurstProbe = "scope-file";
  }

  // ── per-host rps ──
  const rpsOverride = resolveNumberOverride({
    file: block?.rate_limit_rps,
    env: env?.[ENV_RATE_RPS_KEY],
    label: ENV_RATE_RPS_KEY,
    validate: (n) => n > 0,
    expectation: "a positive number of requests per second",
  });
  if (rpsOverride) {
    posture.rateLimitRps = rpsOverride.value;
    posture.sources.rateLimitRps = rpsOverride.source;
  }

  // ── jitter base (0 disables jitter) ──
  const jitterOverride = resolveNumberOverride({
    file: block?.jitter_ms,
    env: env?.[ENV_JITTER_MS_KEY],
    label: ENV_JITTER_MS_KEY,
    validate: (n) => n >= 0,
    expectation: "a non-negative number of milliseconds",
  });
  if (jitterOverride) {
    posture.jitter = jitterOverride.value > 0 ? { baseMs: jitterOverride.value } : undefined;
    posture.sources.jitter = jitterOverride.source;
  }

  return posture;
}

/**
 * Should the adaptive WAF-evasion ladder run?
 *
 * Takes the already-resolved posture when the caller has one (the agent tool
 * context does). Falls back to resolving from `process.env` so the standalone
 * `PWNKIT_WAF_EVASION=0` opt-out still works for embedders and tests that never
 * built a posture. Default remains `true` — unchanged behaviour.
 */
export function isWafEvasionLadderEnabled(
  posture?: EngagementPosture,
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  if (posture) return posture.wafEvasionLadder;
  return resolveEngagementProfile({ env }).wafEvasionLadder;
}

/**
 * Default per-host rps to hand the rate limiter, given the mode's own default
 * (5 for normal scans, the worker-supplied value in http_audit).
 *
 * The profile can only ever make the scan QUIETER: we take the minimum, so a
 * worker contract that already pins 0.5 rps is never sped up to the profile's
 * nominal rate. An explicit `--rate-limit` default still wins downstream —
 * `parseRateLimitFlag` only consumes this fallback when the spec carries no
 * default of its own.
 */
export function effectiveFallbackRps(
  posture: EngagementPosture,
  modeDefaultRps: number,
): number {
  return posture.active ? Math.min(modeDefaultRps, posture.rateLimitRps) : modeDefaultRps;
}

/**
 * Pull the `engagement` block out of a scope JSON object, if present. Mirrors
 * `extractAttributionFromScopeJson`: shape violations are a hard error so
 * operators see misconfiguration loudly at scan start.
 */
export function extractEngagementFromScopeJson(json: unknown): EngagementScopeBlock | undefined {
  if (!json || typeof json !== "object" || Array.isArray(json)) return undefined;
  const raw = (json as { engagement?: unknown }).engagement;
  if (raw === undefined) return undefined;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(
      "Scope file `engagement` must be an object with optional `profile` / `waf_evasion` / `reset_burst_probe` / `rate_limit_rps` / `jitter_ms` fields",
    );
  }
  const b = raw as Record<string, unknown>;
  const out: EngagementScopeBlock = {};
  if (b.profile !== undefined) {
    if (typeof b.profile !== "string") {
      throw new Error("Scope file `engagement.profile` must be a string");
    }
    out.profile = b.profile;
  }
  for (const key of ["waf_evasion", "reset_burst_probe"] as const) {
    if (b[key] !== undefined) {
      if (typeof b[key] !== "boolean") {
        throw new Error(`Scope file \`engagement.${key}\` must be a boolean`);
      }
      out[key] = b[key] as boolean;
    }
  }
  for (const key of ["rate_limit_rps", "jitter_ms"] as const) {
    if (b[key] !== undefined) {
      if (typeof b[key] !== "number" || !Number.isFinite(b[key])) {
        throw new Error(`Scope file \`engagement.${key}\` must be a finite number`);
      }
      out[key] = b[key] as number;
    }
  }
  return out;
}

/**
 * Render the posture as the auditable record attached to the scan report.
 *
 * This is the evidence artifact: it states exactly which loud behaviours were
 * suppressed for this run and which configuration source decided each one, so
 * an engagement can be handed to a client with a defensible answer to "how did
 * you actually run this against our estate?".
 *
 * snake_case keys, matching the `enforcement_summary` contract.
 */
export function describeEngagementPosture(
  posture: EngagementPosture,
  appliedAt: Date = new Date(),
): EngagementPostureRecord {
  return {
    profile: posture.profile,
    applied_at: appliedAt.toISOString(),
    reset_endpoint_burst_probe: posture.resetBurstProbe ? "enabled" : "disabled",
    web_recon_prepass: posture.webReconPrepass,
    waf_evasion_ladder: posture.wafEvasionLadder ? "enabled" : "disabled",
    request_jitter: posture.jitter ? "full-jitter" : "none",
    jitter_base_ms: posture.jitter?.baseMs ?? 0,
    per_host_rps: posture.rateLimitRps,
    sources: { ...posture.sources },
  };
}

// ── internals ──

function nonEmpty(value: string | undefined): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/** Parse an env boolean the same way `agent/features.ts` does. */
function envBool(raw: string): boolean {
  return raw !== "0" && raw.toLowerCase() !== "false";
}

function resolveBoolOverride(input: {
  file?: boolean;
  env?: string;
  cli?: boolean;
  label: string;
}): { value: boolean; source: EngagementSource } | undefined {
  if (typeof input.file === "boolean") return { value: input.file, source: "scope-file" };
  const envRaw = nonEmpty(input.env);
  if (envRaw !== undefined) return { value: envBool(envRaw), source: "env" };
  if (typeof input.cli === "boolean") return { value: input.cli, source: "cli" };
  return undefined;
}

function resolveNumberOverride(input: {
  file?: number;
  env?: string;
  label: string;
  validate: (n: number) => boolean;
  expectation: string;
}): { value: number; source: EngagementSource } | undefined {
  if (typeof input.file === "number") {
    if (!Number.isFinite(input.file) || !input.validate(input.file)) {
      throw new Error(`Scope file \`engagement\` value ${input.file} must be ${input.expectation}`);
    }
    return { value: input.file, source: "scope-file" };
  }
  const envRaw = nonEmpty(input.env);
  if (envRaw !== undefined) {
    const parsed = Number(envRaw);
    if (!Number.isFinite(parsed) || !input.validate(parsed)) {
      throw new Error(`${input.label} must be ${input.expectation}, got '${envRaw}'`);
    }
    return { value: parsed, source: "env" };
  }
  return undefined;
}
