/**
 * Coordinator rails — guardrails that keep a multi-agent scan healthy.
 *
 * Inspired by s0ld13rr/pentestcode's coordinator harness: when a lead agent
 * fans out concurrent sub-agents (`spawn_agents`, see `agent/tools.ts`), the
 * fleet needs a supervisor that watches each child and intervenes when one
 * goes silent, dies, or tries to eat the whole run. This module is the PURE
 * DECISION LAYER of that supervisor — same shape as `agent-messaging.ts`
 * (policy as code, no I/O, no clock, no globals) so every rule is pinned by a
 * unit test. The impure wiring (eventBus subscription + logging) lives in
 * `native-loop.ts`; it only folds bus events into {@link CoordinatorState} via
 * the pure reducer here and logs whatever {@link superviseCoordinator} returns.
 *
 * Three rails, three signatures:
 *
 *   1. {@link stallWatchdog} — gates on IDLE-SINCE-LAST-OUTPUT, never on
 *      dispatch age. A long-running child that is still emitting output is
 *      healthy; one silent past a threshold is stalled.
 *   2. {@link resolveStallAction} — maps a stalled child's state (idle
 *      duration, retries already spent, whether it holds partial findings) to
 *      a concrete recovery action, so the loop never blindly kills
 *      work-in-progress nor lets a provably-dead child hang forever.
 *   3. {@link takeoverGate} — caps the share of the shared budget any single
 *      child may consume before it must checkpoint/yield, so one agent cannot
 *      monopolize the fleet.
 *
 * CONSERVATIVE BY DESIGN: when uncertain the safe action is always `continue`
 * — real work is never killed on a hunch. The ONE exception is a provably-dead
 * child (long idle AND retries exhausted), which is reaped so a dead agent
 * never hangs the run forever. Reaping never drops findings: a child's saved
 * findings are persisted on the parent's `toolCtx.findings` / the DB
 * independently of the child's liveness, so killing the stalled agent discards
 * only the dead process, never its work.
 */

// ── Thresholds (explicit, documented constants) ─────────────────────────────

/**
 * Stall watchdog escalation ladder, keyed on ms IDLE SINCE LAST OUTPUT.
 * Strictly ordered `WARN < ESCALATE < KILL`; the ordering is what makes the
 * watchdog monotone (more idle can only ever yield an EQUAL-or-MORE severe
 * level), and it is asserted at module load below so a future edit cannot
 * silently break that guarantee.
 */
export const STALL_WARN_IDLE_MS = 60_000; // 1 min silent → nudge/warn
export const STALL_ESCALATE_IDLE_MS = 180_000; // 3 min silent → escalate to policy
export const STALL_KILL_IDLE_MS = 420_000; // 7 min silent → kill candidate

/**
 * How many restarts a single child may burn before it is treated as
 * PROVABLY DEAD. A child that is stalled AND has spent every retry is reaped
 * rather than restarted again — this is the only path to `kill`.
 */
export const MAX_AGENT_RETRIES = 2;

/**
 * Floor below which {@link resolveStallAction} always returns `continue`.
 * Wired to the escalate threshold: the kill/escalate policy only engages once
 * the watchdog itself has reached at least `escalate`, so a merely-`warn`
 * child is never restarted or killed.
 */
export const STALL_ACTION_FLOOR_MS = STALL_ESCALATE_IDLE_MS;

/**
 * Anti-solo-takeover cap: the maximum share of the shared fleet budget one
 * child may consume before it must checkpoint/yield. The gate trips at exactly
 * this share (`>=`), not above it.
 */
export const MAX_SOLO_BUDGET_SHARE = 0.6;

// Fail-fast if a future edit breaks the strict ordering the monotonicity
// guarantee (and its test) depends on. Pure-load assertion, no runtime cost.
if (
  !(
    STALL_WARN_IDLE_MS < STALL_ESCALATE_IDLE_MS &&
    STALL_ESCALATE_IDLE_MS < STALL_KILL_IDLE_MS
  )
) {
  throw new Error(
    "coordinator-rails: stall thresholds must be strictly ordered WARN < ESCALATE < KILL",
  );
}

// ── 1. Stall watchdog ───────────────────────────────────────────────────────

/** Watchdog severity. Ordered `continue < warn < escalate < kill`. */
export type StallLevel = "continue" | "warn" | "escalate" | "kill";

/** Numeric severity rank for the ordered {@link StallLevel} — higher = worse. */
export const STALL_LEVEL_RANK: Readonly<Record<StallLevel, number>> = {
  continue: 0,
  warn: 1,
  escalate: 2,
  kill: 3,
};

export interface StallWatchdogInput {
  /** Epoch ms of the child's most recent OBSERVED output (progress event). */
  lastOutputAt: number;
  /** Epoch ms the child was dispatched. Carried for context only — the
   * watchdog deliberately does NOT gate on dispatch age. */
  startedAt: number;
  /** Current epoch ms. */
  now: number;
  /** Turns the child has completed so far (context only). */
  iterations: number;
}

export interface StallWatchdogDecision {
  level: StallLevel;
  /** ms since last output (clamped to ≥ 0). */
  idleMs: number;
  reason: string;
}

/**
 * Decide whether a child is healthy, warning, escalating, or a kill candidate,
 * based ONLY on how long it has been idle SINCE ITS LAST OUTPUT.
 *
 * This is the load-bearing distinction from a naive dispatch-age timeout: a
 * child that has been running for an hour but emitted a progress event two
 * seconds ago is healthy (`continue`); a child dispatched two minutes ago that
 * has emitted nothing since is stalled. `startedAt` is accepted for context
 * and logging but never enters the decision.
 *
 * A `lastOutputAt` in the future (clock skew) clamps `idleMs` to 0 →
 * `continue`, the conservative direction.
 */
export function stallWatchdog(input: StallWatchdogInput): StallWatchdogDecision {
  const idleMs = Math.max(0, input.now - input.lastOutputAt);
  const secs = Math.round(idleMs / 1000);
  if (idleMs >= STALL_KILL_IDLE_MS) {
    return {
      level: "kill",
      idleMs,
      reason: `silent ${secs}s since last output ≥ kill threshold ${STALL_KILL_IDLE_MS / 1000}s`,
    };
  }
  if (idleMs >= STALL_ESCALATE_IDLE_MS) {
    return {
      level: "escalate",
      idleMs,
      reason: `silent ${secs}s since last output ≥ escalate threshold ${STALL_ESCALATE_IDLE_MS / 1000}s`,
    };
  }
  if (idleMs >= STALL_WARN_IDLE_MS) {
    return {
      level: "warn",
      idleMs,
      reason: `silent ${secs}s since last output ≥ warn threshold ${STALL_WARN_IDLE_MS / 1000}s`,
    };
  }
  return {
    level: "continue",
    idleMs,
    reason: `healthy: ${secs}s idle, within budget (${input.iterations} turn(s) done)`,
  };
}

// ── 2. Kill-vs-escalate policy ──────────────────────────────────────────────

/**
 * Concrete recovery action for a stalled child.
 *   - `continue`             — not stalled enough; leave it alone.
 *   - `restart`             — no work at risk and retries remain; cheapest fix.
 *   - `escalate-to-operator` — holds partial findings; hand to a human rather
 *                              than discard work by restarting/killing.
 *   - `kill`                — provably dead (stalled + retries exhausted); reap.
 */
export type StallAction =
  | "continue"
  | "restart"
  | "escalate-to-operator"
  | "kill";

export interface StallActionInput {
  /** ms the child has been idle (from {@link stallWatchdog}'s `idleMs`). */
  stalledMs: number;
  /** Restarts already attempted on this child. */
  retriesSpent: number;
  /** Whether the child has already saved at least one finding. */
  hasPartialFindings: boolean;
}

export interface StallActionDecision {
  action: StallAction;
  reason: string;
}

/**
 * Map a stalled child's state to a recovery action.
 *
 * Ordering encodes the policy:
 *   1. Below the action floor → `continue` (real work is never killed on a
 *      hunch — this is the conservative default).
 *   2. Stalled AND retries exhausted → `kill`. This is the ONLY kill path and
 *      the one non-`continue` action taken without regard to partial findings:
 *      the child is provably dead and its findings are persisted independently,
 *      so reaping the process discards nothing of value. Letting it hang would
 *      stall the whole run forever.
 *   3. Stalled, retries remain, holds partial findings → `escalate-to-operator`.
 *      Never blindly restart/kill work-in-progress; let a human decide.
 *   4. Stalled, retries remain, no findings yet → `restart`. Cheapest recovery
 *      when nothing is at risk.
 */
export function resolveStallAction(
  input: StallActionInput,
): StallActionDecision {
  const { stalledMs, retriesSpent, hasPartialFindings } = input;
  const secs = Math.round(stalledMs / 1000);

  if (stalledMs < STALL_ACTION_FLOOR_MS) {
    return {
      action: "continue",
      reason: `idle ${secs}s < action floor ${STALL_ACTION_FLOOR_MS / 1000}s; within grace`,
    };
  }
  if (retriesSpent >= MAX_AGENT_RETRIES) {
    return {
      action: "kill",
      reason: `stalled ${secs}s with retries exhausted (${retriesSpent}/${MAX_AGENT_RETRIES}); provably dead, reaping (saved findings are preserved)`,
    };
  }
  if (hasPartialFindings) {
    return {
      action: "escalate-to-operator",
      reason: `stalled ${secs}s holding partial findings; escalating rather than discarding work (${retriesSpent}/${MAX_AGENT_RETRIES} retries spent)`,
    };
  }
  return {
    action: "restart",
    reason: `stalled ${secs}s, no partial findings, ${retriesSpent}/${MAX_AGENT_RETRIES} retries spent; restarting`,
  };
}

// ── 3. Anti-solo-takeover gate ──────────────────────────────────────────────

/** Takeover action: keep going, or force a checkpoint/yield. */
export type TakeoverAction = "continue" | "checkpoint";

export interface TakeoverGateInput {
  /** The agent under consideration. */
  agentId: string;
  /** Iterations (turns) consumed so far, per agent id. */
  iterationsByAgent: Record<string, number>;
  /** Total shared iteration budget across the fleet. */
  totalBudget: number;
}

export interface TakeoverGateDecision {
  action: TakeoverAction;
  /** This agent's share of the total budget, in [0, 1]. */
  share: number;
  reason: string;
}

/**
 * Prevent a single child from monopolizing the fleet by capping the share of
 * the SHARED budget it may consume. Trips at EXACTLY the cap (`share >= cap`),
 * so `mine/total == cap` checkpoints and one iteration less continues.
 *
 * The gate emits a reason on every trip so the loop can log WHY it intervened —
 * there are no silent caps. It reads only its three inputs and is otherwise
 * side-effect free.
 */
export function takeoverGate(input: TakeoverGateInput): TakeoverGateDecision {
  const { agentId, iterationsByAgent, totalBudget } = input;
  const mine = iterationsByAgent[agentId] ?? 0;
  const share = totalBudget > 0 ? mine / totalBudget : 0;
  const siblings = Object.keys(iterationsByAgent).filter(
    (id) => id !== agentId && (iterationsByAgent[id] ?? 0) > 0,
  ).length;
  const pct = Math.round(share * 100);
  const capPct = Math.round(MAX_SOLO_BUDGET_SHARE * 100);

  if (share >= MAX_SOLO_BUDGET_SHARE) {
    return {
      action: "checkpoint",
      share,
      reason: `agent ${agentId} consumed ${mine}/${totalBudget} (${pct}%) of shared budget ≥ cap ${capPct}%, ${siblings} sibling(s) active; must checkpoint/yield`,
    };
  }
  return {
    action: "continue",
    share,
    reason: `agent ${agentId} at ${pct}% of shared budget, under cap ${capPct}%`,
  };
}

// ── 4. Loop / repetition detection ──────────────────────────────────────────
//
// Borrowed from claude-bug-bounty's LoopDetector: an agent stuck re-issuing the
// same tool call is spinning, not working. This rail watches the TAIL of an
// agent's recent-call window for a run of identical (or near-identical, via the
// normalized fingerprint) consecutive calls and asks the loop to intervene
// before the whole budget burns on a no-op.

/** Nudge the agent to change approach at this many consecutive repeats. */
export const LOOP_NUDGE_REPEATS = 3;
/** Force a direction change / escalate at this many consecutive repeats. */
export const LOOP_FORCE_REPEATS = 5;
/**
 * How many recent calls to retain per agent. Must be ≥ {@link LOOP_FORCE_REPEATS}
 * so the force threshold is observable inside the window.
 */
export const LOOP_WINDOW_SIZE = 8;

// Fail-fast: the window must be able to hold a force-length run.
if (LOOP_NUDGE_REPEATS >= LOOP_FORCE_REPEATS || LOOP_WINDOW_SIZE < LOOP_FORCE_REPEATS) {
  throw new Error(
    "coordinator-rails: require LOOP_NUDGE_REPEATS < LOOP_FORCE_REPEATS ≤ LOOP_WINDOW_SIZE",
  );
}

/** Loop-detection verdict. Ordered `continue < nudge < force-pivot`. */
export type LoopAction = "continue" | "nudge" | "force-pivot";

/** Numeric severity rank for the ordered {@link LoopAction} — higher = worse. */
export const LOOP_ACTION_RANK: Readonly<Record<LoopAction, number>> = {
  continue: 0,
  nudge: 1,
  "force-pivot": 2,
};

/** One tool invocation reduced to a comparable signature. */
export interface CallSignature {
  /** Tool name (e.g. `http_request`). */
  tool: string;
  /** Normalized arg fingerprint — "" when args are unavailable (bus progress
   * events carry no args, so a bare tool name still detects a spin). */
  fingerprint: string;
}

export interface LoopDetectionDecision {
  action: LoopAction;
  /** Length of the trailing run of identical calls (≥ 1). */
  repeatCount: number;
  reason: string;
}

/**
 * Normalize a tool call's arguments into a stable, comparable fingerprint:
 * keys sorted, whitespace collapsed, lowercased, bounded. Deterministic so two
 * "near-identical" calls (same intent, cosmetic diffs) collapse to one string.
 * Pure; never throws (an unserializable value falls back to "").
 */
export function fingerprintCall(tool: string, args?: unknown): CallSignature {
  let fingerprint = "";
  try {
    if (args && typeof args === "object") {
      const obj = args as Record<string, unknown>;
      fingerprint = Object.keys(obj)
        .sort()
        .map((k) => `${k}=${String(obj[k])}`)
        .join("&");
    } else if (args !== undefined) {
      fingerprint = String(args);
    }
  } catch {
    fingerprint = "";
  }
  fingerprint = fingerprint.replace(/\s+/g, " ").trim().toLowerCase().slice(0, 300);
  return { tool: tool.trim(), fingerprint };
}

/** Two signatures are "the same call" when tool AND fingerprint match. */
function sameCall(a: CallSignature, b: CallSignature): boolean {
  return a.tool === b.tool && a.fingerprint === b.fingerprint;
}

/**
 * Detect a spin: count the trailing run of identical consecutive calls in the
 * window and map its length to an action. `nudge` at {@link LOOP_NUDGE_REPEATS},
 * `force-pivot` at {@link LOOP_FORCE_REPEATS}. A varied tail (last two calls
 * differ) has a run of 1 → `continue`, so a healthy, exploring agent never
 * trips. Monotone by construction: a longer identical run can only raise the
 * action, never lower it.
 */
export function detectCallRepetition(
  window: readonly CallSignature[],
): LoopDetectionDecision {
  if (window.length === 0) {
    return { action: "continue", repeatCount: 0, reason: "no calls observed" };
  }
  const last = window[window.length - 1];
  let repeatCount = 1;
  for (let i = window.length - 2; i >= 0; i--) {
    if (sameCall(window[i], last)) repeatCount++;
    else break;
  }

  const label = last.fingerprint ? `${last.tool}(${last.fingerprint})` : last.tool;
  if (repeatCount >= LOOP_FORCE_REPEATS) {
    return {
      action: "force-pivot",
      repeatCount,
      reason: `same call ${label} repeated ${repeatCount}× (≥ force ${LOOP_FORCE_REPEATS}); forcing a direction change`,
    };
  }
  if (repeatCount >= LOOP_NUDGE_REPEATS) {
    return {
      action: "nudge",
      repeatCount,
      reason: `same call ${label} repeated ${repeatCount}× (≥ nudge ${LOOP_NUDGE_REPEATS}); nudging a new approach`,
    };
  }
  return {
    action: "continue",
    repeatCount,
    reason: `no spin: trailing run of ${repeatCount} for ${label}`,
  };
}

// ── Pure reducer: fold bus events into per-agent state ───────────────────────

/** Per-agent runtime state accumulated from the eventBus subagent events. */
export interface CoordinatorAgentState {
  agentId: string;
  /** Epoch ms of first observation (dispatch). */
  startedAt: number;
  /** Epoch ms of most recent output (progress / lifecycle transition). */
  lastOutputAt: number;
  /** Turns completed so far. */
  iterations: number;
  /** The child's effective turn budget. */
  maxTurns: number;
  status: "queued" | "running" | "completed" | "failed";
  /** Findings the child has saved so far (partial-findings signal). */
  findings: number;
  /** Restarts attempted on this child (reserved for a restart-capable loop). */
  retriesSpent: number;
  /**
   * Bounded window of this child's most recent calls (newest last), fed to
   * {@link detectCallRepetition}. Populated from `subagent_progress` (tool name
   * + status note; bus progress events deliberately carry no tool args, so the
   * note is the "near-identical" signal). Capped at {@link LOOP_WINDOW_SIZE}.
   */
  recentCalls: CallSignature[];
}

/** Full coordinator view: one record per observed child, keyed by agent id. */
export type CoordinatorState = Readonly<
  Record<string, CoordinatorAgentState>
>;

/** Minimal shape of a bus event this reducer understands. */
export interface CoordinatorEvent {
  type: string;
  payload: Record<string, unknown>;
}

function numOr(v: unknown, fallback: number): number {
  return typeof v === "number" && Number.isFinite(v) ? v : fallback;
}

/**
 * Fold one eventBus emission into a {@link CoordinatorState} snapshot.
 *
 * Mirrors `live-agent-state.ts` semantics: returns the SAME reference when the
 * event is irrelevant (so the caller can cheaply skip a supervise pass), and
 * otherwise returns a new object with only the affected agent replaced. Pure:
 * `now` is passed in, never read from the clock, so tests are deterministic.
 *
 * Recognized events (`agent_id`-keyed):
 *   - `subagent_lifecycle` (queued|running|completed|failed)
 *   - `subagent_progress`  (one per completed child turn — the OUTPUT signal
 *      that resets the stall watchdog)
 * Any other event returns `prev` unchanged.
 */
export function reduceCoordinatorState(
  prev: CoordinatorState,
  event: CoordinatorEvent,
  now: number,
): CoordinatorState {
  if (
    event.type !== "subagent_lifecycle" &&
    event.type !== "subagent_progress"
  ) {
    return prev;
  }
  const agentId =
    typeof event.payload.agent_id === "string"
      ? event.payload.agent_id
      : undefined;
  if (!agentId) return prev;

  const existing = prev[agentId];
  const base: CoordinatorAgentState = existing ?? {
    agentId,
    startedAt: now,
    lastOutputAt: now,
    iterations: 0,
    maxTurns: numOr(event.payload.max_turns, 0),
    status: "queued",
    findings: 0,
    retriesSpent: 0,
    recentCalls: [],
  };

  let next: CoordinatorAgentState;
  if (event.type === "subagent_progress") {
    // A progress event IS output — it resets the idle clock. It also records
    // the call the child just ran (tool + status note) into the bounded loop-
    // detection window. A turn that ran no tool contributes no call.
    const tool = typeof event.payload.tool === "string" ? event.payload.tool : undefined;
    let recentCalls = base.recentCalls;
    if (tool) {
      const note = typeof event.payload.note === "string" ? event.payload.note : undefined;
      const sig = fingerprintCall(tool, note);
      recentCalls = [...base.recentCalls, sig].slice(-LOOP_WINDOW_SIZE);
    }
    next = {
      ...base,
      status: "running",
      iterations: numOr(event.payload.turn, base.iterations),
      maxTurns: numOr(event.payload.max_turns, base.maxTurns),
      lastOutputAt: now,
      recentCalls,
    };
  } else {
    const status = event.payload.status;
    const lifecycleStatus: CoordinatorAgentState["status"] =
      status === "running" ||
      status === "completed" ||
      status === "failed" ||
      status === "queued"
        ? status
        : base.status;
    next = {
      ...base,
      status: lifecycleStatus,
      maxTurns: numOr(event.payload.max_turns, base.maxTurns),
      // `turns` / `findings` ride only on the completed|failed transition.
      iterations: numOr(event.payload.turns, base.iterations),
      findings: numOr(event.payload.findings, base.findings),
      // Every lifecycle transition is a fresh signal of life.
      lastOutputAt: now,
    };
  }

  return { ...prev, [agentId]: next };
}

// ── Supervisor: run all rails across the fleet ──────────────────────────────

/** Which rail produced an intervention. */
export type InterventionKind =
  | "stall-watchdog"
  | "kill-escalate"
  | "anti-takeover"
  | "loop-detection";

/** A single logged intervention emitted by {@link superviseCoordinator}. */
export interface CoordinatorIntervention {
  agentId: string;
  kind: InterventionKind;
  /** The chosen action token (rail-specific). */
  action: string;
  /** Present for stall-watchdog interventions. */
  level?: StallLevel;
  reason: string;
  idleMs?: number;
  share?: number;
  /** Present for loop-detection interventions: trailing identical-call run. */
  repeatCount?: number;
}

export interface SuperviseOptions {
  now: number;
  /**
   * Shared budget for the takeover gate. Defaults to the sum of every observed
   * agent's `maxTurns` (the natural fleet pool). Pass an override to bind the
   * gate to a different budget (e.g. the parent loop's own `maxTurns`).
   */
  totalBudget?: number;
}

/**
 * Run every rail across every ACTIVE (queued|running) child and return the list
 * of interventions to log. Completed/failed children are excluded from
 * intervention (nothing to reap) but still count toward the takeover gate's
 * consumed-budget accounting. Pure: the caller supplies `now` and does all
 * logging/enforcement with the returned list.
 *
 * The two stall rails compose: the watchdog decides severity, and for
 * `escalate`/`kill` severities the kill-vs-escalate policy resolves that into a
 * concrete action. A merely-`warn` child produces only the watchdog note.
 */
export function superviseCoordinator(
  state: CoordinatorState,
  opts: SuperviseOptions,
): CoordinatorIntervention[] {
  const { now } = opts;
  const interventions: CoordinatorIntervention[] = [];

  const agents = Object.values(state);
  const iterationsByAgent: Record<string, number> = {};
  let summedBudget = 0;
  for (const a of agents) {
    iterationsByAgent[a.agentId] = a.iterations;
    summedBudget += a.maxTurns;
  }
  const totalBudget = opts.totalBudget ?? summedBudget;

  for (const agent of agents) {
    if (agent.status !== "queued" && agent.status !== "running") continue;

    // Rail 1: stall watchdog (idle-since-last-output).
    const stall = stallWatchdog({
      lastOutputAt: agent.lastOutputAt,
      startedAt: agent.startedAt,
      now,
      iterations: agent.iterations,
    });
    if (stall.level !== "continue") {
      interventions.push({
        agentId: agent.agentId,
        kind: "stall-watchdog",
        action: stall.level,
        level: stall.level,
        reason: stall.reason,
        idleMs: stall.idleMs,
      });
      // Rail 2: resolve escalate/kill severities into a concrete action.
      if (stall.level === "escalate" || stall.level === "kill") {
        const resolved = resolveStallAction({
          stalledMs: stall.idleMs,
          retriesSpent: agent.retriesSpent,
          hasPartialFindings: agent.findings > 0,
        });
        interventions.push({
          agentId: agent.agentId,
          kind: "kill-escalate",
          action: resolved.action,
          reason: resolved.reason,
          idleMs: stall.idleMs,
        });
      }
    }

    // Rail 3: anti-solo-takeover.
    const takeover = takeoverGate({
      agentId: agent.agentId,
      iterationsByAgent,
      totalBudget,
    });
    if (takeover.action !== "continue") {
      interventions.push({
        agentId: agent.agentId,
        kind: "anti-takeover",
        action: takeover.action,
        reason: takeover.reason,
        share: takeover.share,
      });
    }

    // Rail 4: loop / repetition detection over the child's recent-call window.
    const loop = detectCallRepetition(agent.recentCalls);
    if (loop.action !== "continue") {
      interventions.push({
        agentId: agent.agentId,
        kind: "loop-detection",
        action: loop.action,
        reason: loop.reason,
        repeatCount: loop.repeatCount,
      });
    }
  }

  return interventions;
}

// ── Live findings tail (data path for a `tail -f findings.md` view) ──────────

/** Minimal finding shape the tail formatter reads. */
export interface FindingTailInput {
  id?: string;
  severity?: string;
  title?: string;
  message?: string;
  category?: string;
}

/* eslint-disable no-control-regex */
const RE_TAIL_UNSAFE =
  /[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u2069\uFEFF]/g;
/* eslint-enable no-control-regex */

const TAIL_MAX_LEN = 200;

/**
 * Format one finding as a single, control-character-stripped line suitable for
 * a live `tail -f findings.md`-style view. Pure and side-effect free: the loop
 * calls this on `onFindingSaved` and forwards the line through the existing
 * diagnostics/event channel — it never writes to a file or stdout itself, and
 * never blocks. Returns `""` when nothing printable remains.
 */
export function formatFindingTailLine(finding: FindingTailInput): string {
  const sev = (finding.severity ?? "info").toString().toUpperCase();
  const label =
    finding.title?.toString().trim() ||
    finding.message?.toString().trim() ||
    finding.category?.toString().trim() ||
    "(untitled finding)";
  const line = `[${sev}] ${label}`
    .replace(RE_TAIL_UNSAFE, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!line) return "";
  return line.length > TAIL_MAX_LEN ? line.slice(0, TAIL_MAX_LEN - 1) + "…" : line;
}
