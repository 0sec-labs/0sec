/**
 * Monotonic, deny-only tool-authorization guards.
 *
 * WHY THIS EXISTS
 * ---------------
 * 0sec already authorizes tool calls through the name-keyed gates in
 * `console/turn-engine.ts` (`NETWORK_CAPABLE_TOOLS`, `LOCAL_SCOPE_TOOLS`,
 * `READ_ONLY_TOOLS`), fed by the single capability translation `gateFlagsFor`
 * in `plugins/manifest.ts`. Those gates decide, per tool NAME, whether a call
 * needs scope resolution, a local-directory prompt, or copilot approval.
 *
 * This module sits BENEATH those gates as an additional, composable floor. It
 * exists because plugins want to contribute policy, and the study of the
 * DeepSeek `dsh` harness surfaced exactly the right primitive and exactly the
 * wrong one:
 *
 *   - RIGHT: `dsh`'s `ctx.tools.guard()` is valuable because "any matching
 *     guard may deny ... no guard can force-allow a call another guard denied."
 *     That is MONOTONIC authorization: composing more guards can only ever
 *     NARROW what is permitted. Adding a plugin cannot loosen policy.
 *
 *   - WRONG: `dsh` also has a `tools/pre-execute` waterfall where a listener
 *     that returns without calling `next()` short-circuits the chain — a plugin
 *     can suppress the whole authorization pipeline. We deliberately do NOT
 *     copy that. Guards here are DENY-ONLY: there is no way to express "allow",
 *     so there is nothing to short-circuit.
 *
 * The two central properties (monotonicity + deny-only) are enforced by the
 * type system and the evaluator below, and proven by `guards.test.ts`.
 */

// ── The deny-only guard type: why "allow" is inexpressible ────────────────────

/**
 * The context a guard inspects. Every field is a already-resolved fact about
 * the call being authorized; a guard NEVER performs I/O to discover more.
 *
 * The three capability flags mirror exactly what `gateFlagsFor` produces and
 * what the console gates consume, so a guard reasons in the same vocabulary as
 * the gates above it. `autonomyMode` and `hasScope` mirror the console's own
 * inputs to `maybeResolveScope` / `maybeApproveTool`.
 *
 * `approvalAvailable` and `capabilitiesResolved` are additions beyond the
 * gates' own inputs, justified because the built-in guards below cannot express
 * their fail-closed conditions without them (see each guard). They are typed as
 * required so a caller must decide them explicitly; the guards nonetheless read
 * them defensively (undefined is treated as the unsafe answer) so a loosely
 * typed JS caller can never widen access by omission.
 */
export interface GuardContext {
  /** The tool being authorized. Used only for human-readable denial reasons. */
  readonly toolName: string;
  /** Capability flags resolved for this tool (see `gateFlagsFor`). */
  readonly networkCapable: boolean;
  readonly localScope: boolean;
  readonly readOnly: boolean;
  /** Autonomy mode in effect for this call. */
  readonly autonomyMode: "standard" | "copilot" | "yolo" | "recon";
  /** True when an engagement scope is configured. */
  readonly hasScope: boolean;
  /** True when an operator-approval mechanism is available for this call. */
  readonly approvalAvailable: boolean;
  /**
   * True only when the capability flags above were resolved from a KNOWN
   * source (a validated manifest / a recognized built-in). False when the tool
   * is unknown or its manifest could not be understood — the danger-by-omission
   * class from the plugin design, which must not be allowed to pass silently.
   */
  readonly capabilitiesResolved: boolean;
  /** Opaque, already-sanitized detail for the denial message. */
  readonly detail?: string;
}

/**
 * A guard returns a denial REASON (a string) or ABSTAINS (`null`/`undefined`).
 *
 * WHY THIS TYPE MAKES "ALLOW" INEXPRESSIBLE: the return type is
 * `string | null | undefined` and nothing else. A string is, by construction, a
 * denial reason (the evaluator treats EVERY string as a denial — even the empty
 * string, which becomes a placeholder denial rather than an allowance). The
 * only non-denial value a guard can produce is the absence of a reason
 * (null/undefined) — i.e. abstention. There is no value in the codomain that
 * means "allow", so a guard cannot vote to allow, and therefore cannot override
 * another guard's denial. Monotonicity falls straight out of this: the set of
 * denial reasons can only grow as guards are added.
 */
export type ToolGuard = (ctx: GuardContext) => string | null | undefined;

/**
 * The verdict of evaluating a set of guards. `allowed` is true iff no guard
 * denied. `reasons` collects EVERY denial reason (never first-wins) so the
 * operator sees the full picture of why a call was blocked.
 */
export interface GuardVerdict {
  readonly allowed: boolean;
  readonly reasons: string[];
}

// ── Reason sanitization: reasons render into a terminal ───────────────────────

/**
 * Maximum length of a single denial reason. Bounded because a reason may
 * originate from plugin-supplied text and is rendered into an operator's
 * terminal; an unbounded string is a display-corruption / log-flood vector.
 */
const MAX_REASON_LENGTH = 200;

/**
 * Collapse an arbitrary (possibly plugin-authored) string into a single-line,
 * control-character-free, length-bounded reason safe to print.
 *
 * Control characters (C0 including CR/LF/TAB, DEL, and the C1 range — which
 * covers the ESC that introduces ANSI escape sequences) are replaced with
 * spaces, then runs of whitespace are collapsed and the result trimmed. This
 * guarantees a single line with no cursor-moving / color-injecting bytes.
 * Finally the reason is truncated with an ellipsis if it exceeds the bound.
 */
export function sanitizeReason(raw: string): string {
  const singleLine = raw
    // eslint-disable-next-line no-control-regex -- stripping control chars is the point
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (singleLine.length <= MAX_REASON_LENGTH) return singleLine;
  // Reserve one char for the ellipsis so the result stays within the bound.
  return singleLine.slice(0, MAX_REASON_LENGTH - 1) + "…";
}

/** Human-readable label for a guard in a denial reason, sanitized and safe. */
function guardLabel(guard: unknown, index: number): string {
  const name =
    typeof guard === "function" && typeof guard.name === "string" && guard.name.length > 0
      ? guard.name
      : "";
  return name ? sanitizeReason(`guard "${name}"`) : `guard #${index}`;
}

/** Best-effort message extraction from an unknown throw value. */
function errorMessage(err: unknown): string {
  if (err instanceof Error && typeof err.message === "string") return err.message;
  if (typeof err === "string") return err;
  try {
    return String(err);
  } catch {
    return "unknown error";
  }
}

// ── evaluateGuards: run every guard, collect every denial, fail closed ────────

/**
 * Evaluate `guards` against `ctx`. Runs EVERY guard — never short-circuits on
 * the first denial — because the operator benefits from seeing all the reasons
 * a call was blocked, and because short-circuiting is exactly the pipeline hole
 * we refuse to reproduce.
 *
 * FAIL-CLOSED DECISIONS (each can only NARROW, never widen):
 *   - A guard that returns any string denies (empty string → placeholder
 *     denial, so "allow" remains inexpressible even via a blank reason).
 *   - A guard that THROWS is treated as a DENIAL, with a reason naming the
 *     failure — a broken guard must never grant access.
 *   - A non-callable entry (a loosely typed caller passing garbage) is treated
 *     as a DENIAL for the same reason.
 *
 * PURITY: `ctx` and `guards` are never mutated; the function performs no I/O,
 * reads no clock, and is deterministic for a given input.
 *
 * MONOTONICITY: `allowed` is `reasons.length === 0`, and `reasons` is built by
 * appending — never removing — across guards. Extending the guard set can only
 * add reasons, so a call that was denied can never become allowed. Proven in
 * `guards.test.ts`.
 *
 * An EMPTY guard list allows (`{ allowed: true, reasons: [] }`). This is
 * CORRECT, not a hole: the guard layer is an ADDITIONAL floor beneath the
 * name-keyed gates in `turn-engine.ts`, which still run independently. An empty
 * floor simply adds no further denials; it does not remove the gates above it.
 */
export function evaluateGuards(guards: readonly ToolGuard[], ctx: GuardContext): GuardVerdict {
  const reasons: string[] = [];

  // Defensive: a non-array `guards` (from an untyped caller) contributes no
  // guards but also cannot widen access — the gates above still apply.
  const list: readonly ToolGuard[] = Array.isArray(guards) ? guards : [];

  for (let i = 0; i < list.length; i++) {
    const guard = list[i];

    if (typeof guard !== "function") {
      // Fail closed: an entry that is not a guard cannot be interpreted as an
      // abstention (that would let junk widen access); it is a denial.
      reasons.push(sanitizeReason(`${guardLabel(guard, i)} is not callable`));
      continue;
    }

    let result: string | null | undefined;
    try {
      result = guard(ctx);
    } catch (err) {
      // Fail closed: a throwing guard denies rather than abstains.
      reasons.push(
        sanitizeReason(`${guardLabel(guard, i)} threw during evaluation: ${errorMessage(err)}`),
      );
      continue;
    }

    // Only a string is a denial; null/undefined (and, defensively, any other
    // non-string a JS caller might return) is abstention. Note that a string
    // is ALWAYS a denial — an empty/whitespace reason becomes a placeholder so
    // "allow" can never be smuggled in as a blank string.
    if (typeof result === "string") {
      const clean = sanitizeReason(result);
      reasons.push(clean.length > 0 ? clean : `${guardLabel(guard, i)} denied without a stated reason`);
    }
  }

  return { allowed: reasons.length === 0, reasons };
}

// ── composeGuards: union of guard groups ──────────────────────────────────────

/**
 * Concatenate several guard groups into one array. Composition is UNION: the
 * combined set denies whenever any member denies, so composing groups inherits
 * monotonicity for free (more guards ⇒ at least as restrictive). Order is
 * preserved for stable, readable reason ordering; order never affects `allowed`.
 *
 * Non-array groups are skipped defensively; this cannot widen access (it only
 * omits things that were never guards). Any non-callable entries that survive
 * are handled — as denials — by `evaluateGuards`.
 */
export function composeGuards(...groups: readonly (readonly ToolGuard[])[]): ToolGuard[] {
  const out: ToolGuard[] = [];
  for (const group of groups) {
    if (!Array.isArray(group)) continue;
    for (const g of group) out.push(g);
  }
  return out;
}

// ── Built-in guards: 0sec's existing invariants, encoded once ─────────────────
//
// Each built-in is DERIVED from a real gate in `turn-engine.ts` — it never
// invents policy that contradicts the gates. They are exported individually so
// the wiring can pick a subset, and as `BUILTIN_GUARDS` for the common case.
// Every built-in reads its context defensively so a missing/loosely typed field
// resolves toward denial, never toward access.

/**
 * RETIRED — kept exported for backward compatibility, but wired NOWHERE.
 *
 * ORIGINAL INTENT: deny a network-capable tool when no scope is configured, in
 * YOLO mode, mirroring an old `maybeResolveScope` hard-deny ("YOLO mode: no
 * scope configured — tool ... cannot run").
 *
 * WHY IT WAS RETIRED: the "network requires a PRECONFIGURED scope" invariant no
 * longer holds in ANY mode, so there is no mode this guard could soundly fire
 * in:
 *   - yolo is anchored to the launch TARGET, not to a scope object. A scopeless
 *     yolo call (even `bash echo hello`) is legitimate; the target anchor is
 *     enforced precisely by `maybeResolveScope` (target-relatedness) plus the
 *     executor's own same-origin/scope boundary and the absolute SSRF rail.
 *     Firing here would wrongly re-deny scopeless yolo.
 *   - standard/recon run scope-on-demand (prompt) or fall through to
 *     same-origin validation — never a blanket "needs a scope" denial.
 *   - copilot auto-expands scope to in-engagement targets; it never requires a
 *     preconfigured scope either.
 * It is therefore fully SUPERSEDED by the executor's same-origin anchoring and
 * is removed from both `BUILTIN_GUARDS` and the console's `WIRED_GUARDS`. The
 * function survives only so external callers and its own unit tests still
 * resolve; do NOT add it to any wired set.
 *
 * Its body is unchanged (a pure predicate over the context) so its existing
 * unit tests stay coherent — retirement is about WIRING, not behaviour.
 */
export function guardNetworkRequiresScope(ctx: GuardContext): string | null | undefined {
  // Fail closed: treat a non-explicit-false networkCapable as capable, and a
  // non-explicit-true hasScope as unscoped.
  const networkCapable = ctx.networkCapable !== false;
  const unscoped = ctx.hasScope !== true;
  if (ctx.autonomyMode === "yolo" && networkCapable && unscoped) {
    return `YOLO mode: tool "${ctx.toolName}" is network-capable but no scope is configured`;
  }
  return null;
}

/**
 * Deny a non-read-only tool in the mode that requires per-action approval when
 * no approval mechanism is available.
 *
 * DERIVED FROM: the per-action approval gate `maybeApproveTool`
 * (`turn-engine.ts`). Under the CURRENT autonomy model `standard` is the mode
 * that puts every non-`READ_ONLY_TOOLS` action to the operator before dispatch
 * (copilot and yolo run prompt-free; recon refuses effectful tools outright via
 * its own capability gate). This guard is re-pointed from the obsolete copilot
 * coupling to `standard` accordingly.
 *
 * HARDENING NOTE (a deliberate, monotonic tightening): the console's gate has a
 * fail-OPEN corner — "when approveTool is absent, always allow." This guard
 * closes it: in standard mode, a non-read-only tool with no approval mechanism
 * available is DENIED rather than run unapproved. Because guards are a deny-only
 * floor, this can only narrow the console's behaviour, never widen it, and it
 * removes a fail-open path the plugin design explicitly wants closed.
 */
export function guardApprovalUnavailable(ctx: GuardContext): string | null | undefined {
  // Fail closed: non-explicit-true readOnly counts as effectful; non-explicit-
  // true approvalAvailable counts as unavailable.
  const effectful = ctx.readOnly !== true;
  const noApproval = ctx.approvalAvailable !== true;
  if (ctx.autonomyMode === "standard" && effectful && noApproval) {
    return `Standard mode: tool "${ctx.toolName}" requires operator approval, but no approval mechanism is available`;
  }
  return null;
}

/**
 * Deny anything whose capability flags are unresolved/unknown.
 *
 * DERIVED FROM: the danger-by-omission problem the plugin design (DESIGN.md
 * §1c/§2) identifies — a tool absent from the gate maps lands in the
 * least-dangerous class by omission, so an unknown tool would be ungated. The
 * gates cannot see this (they only test map membership); the guard layer can.
 * When the capability flags were NOT resolved from a known source, deny.
 */
export function guardUnresolvedCapabilities(ctx: GuardContext): string | null | undefined {
  // Fail closed: only an explicit `true` counts as resolved.
  if (ctx.capabilitiesResolved !== true) {
    return `tool "${ctx.toolName}" has unresolved capability flags — refusing to authorize by omission`;
  }
  return null;
}

/**
 * The default built-in guard set, encoding 0sec's CURRENT invariants so the
 * layer is useful immediately. Frozen so a consumer cannot mutate the shared
 * default (which would silently change policy for everyone).
 *
 * Two invariants remain, both always-correct wherever they are wired:
 *   - `guardUnresolvedCapabilities` — refuse any tool whose capability flags
 *     were not resolved from a known source (danger-by-omission).
 *   - `guardApprovalUnavailable` — in standard mode, refuse an effectful tool
 *     with no approval mechanism (closes the fail-open corner).
 * `guardNetworkRequiresScope` is intentionally ABSENT: it is retired (its
 * "network requires a preconfigured scope" invariant no longer holds in any
 * mode — see that function's doc), so keeping it here would re-introduce a
 * denial the executor's own same-origin anchoring already supersedes.
 */
export const BUILTIN_GUARDS: readonly ToolGuard[] = Object.freeze([
  guardUnresolvedCapabilities,
  guardApprovalUnavailable,
]);
