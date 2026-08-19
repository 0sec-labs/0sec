/**
 * Scope-guard visibility (pwnkit#133).
 *
 * A family of egress guards in `agent/tools.ts` is nested inside
 * `if (this.ctx.scope) { … }`. `ctx.scope` is `undefined` whenever no
 * `ScopePolicy` was configured — and `--scope` is optional in the CLI and is
 * never emitted by the cloud dispatcher (`services/worker-controller/
 * src/runners/args.ts` in 0sec-labs/0sec pushes no `--scope`). So on every
 * cloud scan mode except `http_audit` (which synthesises a host policy from
 * `httpAuditAllowedHosts`) and on every local run without `--scope`, those
 * guards are inert.
 *
 * That in itself is not automatically a vulnerability — most of those modes
 * (source review, package audit, kernel review) have no live target and no
 * engagement to be out of. The actual defect is that the absence was
 * **invisible**: nothing in the CLI output, the scan event log or the report
 * said the guards had not run, so a reviewer reading the guard block
 * reasonably concluded bash traffic was checked.
 *
 * This module is the small, shared vocabulary for scope enforcement. It is
 * consumed at three sites:
 *
 *   1. `agenticScan()` refuses a live network target before it initializes a
 *      database, model, tool, subprocess, or network client when no scope is
 *      configured.
 *   2. `agenticScan()` emits a structured `scope_guards_inert` event for
 *      unscoped local modes.
 *   3. `ToolExecutor.shellExec()` records egress destinations when a local
 *      mode intentionally runs without a scope.
 *
 * `PWNKIT_REQUIRE_SCOPE` remains available to make every mode fail closed.
 *
 * @see https://github.com/0sec-labs/pwnkit/issues/133
 */

/**
 * The guards in `ToolExecutor.shellExec` that live inside `if (ctx.scope)` and
 * therefore do not run when no `ScopePolicy` is configured. Stable, greppable
 * identifiers — they are written into the scan event log, so a reviewer can
 * answer "which checks did NOT run on this scan?" from the DB.
 *
 * NOTE: bash's *other* guards are deliberately NOT listed, because they are
 * scope-independent and still run: the http_audit no-explicit-URL egress
 * refusal, the per-host rate-limit pacing, the wallclock ceiling and the env
 * sanitiser are all outside the `if (ctx.scope)` block.
 */
export const SCOPE_DEPENDENT_BASH_GUARDS = [
  "bash_out_of_scope_url_refusal",
  "bash_http_audit_path_allowlist",
  "bash_generic_scanner_suppression",
  "bash_auth_header_injection",
] as const;

export interface ScopeGuardStatus {
  /** True when a `ScopePolicy` is configured, i.e. the guards above run. */
  active: boolean;
  /** True when `PWNKIT_REQUIRE_SCOPE` opts this run into fail-closed. */
  required: boolean;
  /** Guard identifiers that are inert. Empty when `active`. */
  inertGuards: readonly string[];
  /** One-line, log-ready summary. Empty string when `active`. */
  message: string;
}

/** Event type written to the scan event log when the guards are inert. */
export const SCOPE_GUARDS_INERT_EVENT = "scope_guards_inert";

/**
 * Opt-in strictness switch. `PWNKIT_REQUIRE_SCOPE=1` turns the missing-scope
 * warning into a hard refusal, at scan boot and at the `bash` tool.
 *
 * Env-var rather than a threaded `ScanConfig` field on purpose: the cloud
 * worker-controller builds its argv from a fixed table and injects
 * configuration through `PWNKIT_*` env vars, so an env knob is the only way
 * the managed service can turn strictness on without an engine release. The
 * CLI flag `--require-scope` sets this variable.
 */
export function isScopeRequired(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = env.PWNKIT_REQUIRE_SCOPE?.trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes" || raw === "on";
}

/** True when this target can cause live network execution. */
export function targetRequiresScope(target: string): boolean {
  try {
    const protocol = new URL(target).protocol;
    return protocol === "http:" || protocol === "https:" || protocol === "mcp:";
  } catch {
    return false;
  }
}

/** Refusal used for an unscoped live network target. */
export function networkScopeRequiredRefusal(target: string): string {
  return (
    `scan refused: live network target '${target}' requires an engagement scope. ` +
    "Pass --scope <file> or use http_audit with an operator-provided host policy."
  );
}

/**
 * Describe the state of the scope-dependent guards for a run.
 *
 * @param scopeConfigured whether a `ScopePolicy` was resolved for the run
 */
export function describeScopeGuards(
  scopeConfigured: boolean,
  env: NodeJS.ProcessEnv = process.env,
): ScopeGuardStatus {
  const required = isScopeRequired(env);
  if (scopeConfigured) {
    return { active: true, required, inertGuards: [], message: "" };
  }
  return {
    active: false,
    required,
    inertGuards: SCOPE_DEPENDENT_BASH_GUARDS,
    message:
      "No engagement scope is configured (no --scope file, and this is not http_audit mode), " +
      `so ${SCOPE_DEPENDENT_BASH_GUARDS.length} bash egress guards are INERT for this run: ` +
      `${SCOPE_DEPENDENT_BASH_GUARDS.join(", ")}. ` +
      "bash commands can reach any host the sandbox can reach. Pass --scope <file> to enable " +
      "them, or PWNKIT_REQUIRE_SCOPE=1 (pwnkit scan --require-scope) to refuse unscoped runs.",
  };
}

/**
 * The refusal message used at both enforcement sites when
 * `PWNKIT_REQUIRE_SCOPE` is set and no scope is configured.
 */
export function scopeRequiredRefusal(site: string): string {
  return (
    `${site} refused: PWNKIT_REQUIRE_SCOPE is set but no engagement scope is configured. ` +
    "The bash egress guards (out-of-scope URL refusal, http_audit path allowlist, " +
    "generic-scanner suppression, auth-header injection) only run with a ScopePolicy. " +
    "Pass --scope <file>, or unset PWNKIT_REQUIRE_SCOPE to run in fail-loud mode."
  );
}
