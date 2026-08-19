// Live "what's the agent doing RIGHT NOW" snapshot derived from
// eventBus events. Pure reducer — no I/O, no React, no globals — so
// the CLI's TUI (`renderScan.ts`) and the SDK's hypothetical embedded
// renderers can share the exact same derivation logic and the
// invariants are pinned by unit tests instead of "I tested it once
// against a real scan."
//
// Replace-in-place semantics: each event mutates only the fields
// that changed, leaving everything else untouched. No history is
// accumulated here — terminal real estate is precious and the cloud
// dashboard's full scrollback live-trace serves the "I want every
// word" use case.
//
// The reducer mirrors the cloud worker-controller's
// `parseEventLines` consumer in spirit (both turn the same
// 0SEC_EVENT_* wire shape into structured snapshots), but they
// don't share a representation because the cloud persists every
// event and the CLI panel only ever shows the latest.

/** "What's happening right now" view fed to the CLI's TUI panel. */
export interface LiveAgentState {
  /** 1-indexed turn the agent is currently on. */
  turn?: number;
  /** Configured per-loop max-turns ceiling. */
  maxTurns?: number;
  /** "audit" / "scan" / "attack" — which agent role is talking. */
  role?: string;
  /**
   * Latest reasoning summary from the model. Replaces in-place each
   * turn; we deliberately don't append a history.
   */
  reasoningSummary?: string;
  /**
   * Most-recently-started tool call. Status updates in place when
   * the matching tool_call_completed arrives; cleared at the next
   * agent_turn_started.
   */
  currentTool?: {
    tool: string;
    argsPreview?: string;
    status: "running" | "ok" | "error";
    durationMs?: number;
    error?: string;
  };
  /** Cumulative cost for the run so far (cost_update payload). */
  costUsd?: number;
  inputTokens?: number;
  outputTokens?: number;
}

/**
 * Apply one eventBus emission to a {@link LiveAgentState} snapshot.
 *
 * Returns the SAME reference when nothing changed (useful for the
 * caller's "should we trigger a rerender?" check). When the event
 * is irrelevant to the panel (`delta`, `agent_turn_completed`,
 * `llm_planner_invoked`, `finding_ingested`, `scan_completed`),
 * returns the input snapshot unchanged.
 */
export function reduceLiveAgentState(
  prev: LiveAgentState,
  eventType: string,
  payload: unknown,
): LiveAgentState {
  const p = (payload ?? {}) as Record<string, unknown>;
  switch (eventType) {
    case "agent_turn_started": {
      const turn = typeof p.turn === "number" ? p.turn : prev.turn;
      const maxTurns =
        typeof p.max_turns === "number" ? p.max_turns : prev.maxTurns;
      const role = typeof p.role === "string" ? p.role : prev.role;
      // Drop the previous turn's tool call so a stale "running" badge
      // doesn't hang around after a turn boundary.
      return {
        ...prev,
        turn,
        maxTurns,
        role,
        currentTool: undefined,
      };
    }
    case "tool_call_started": {
      if (typeof p.tool !== "string") return prev;
      return {
        ...prev,
        currentTool: {
          tool: p.tool,
          argsPreview:
            typeof p.args_preview === "string" ? p.args_preview : undefined,
          status: "running",
        },
      };
    }
    case "tool_call_completed": {
      const cur = prev.currentTool;
      if (!cur) return prev;
      // Only update when the completed tool matches the in-flight one.
      // Tool calls can interleave (sub-agent loops, retries) and we
      // don't want a stale completion mutating a fresh `started`
      // we already swapped in.
      if (typeof p.tool === "string" && p.tool !== cur.tool) return prev;
      return {
        ...prev,
        currentTool: {
          ...cur,
          status: p.status === "error" ? "error" : "ok",
          durationMs:
            typeof p.duration_ms === "number" ? p.duration_ms : undefined,
          error: typeof p.error === "string" ? p.error : undefined,
        },
      };
    }
    case "reasoning_summary": {
      if (typeof p.summary !== "string") return prev;
      const summary = p.summary.trim();
      if (summary.length === 0) return prev;
      return { ...prev, reasoningSummary: summary };
    }
    case "cost_update": {
      const costUsd =
        typeof p.cost_usd === "number" ? p.cost_usd : prev.costUsd;
      const inputTokens =
        typeof p.input_tokens === "number" ? p.input_tokens : prev.inputTokens;
      const outputTokens =
        typeof p.output_tokens === "number"
          ? p.output_tokens
          : prev.outputTokens;
      // Avoid forcing a rerender when nothing actually changed —
      // some runtimes emit cost_update on every chunk, and the
      // payload can repeat unchanged values.
      if (
        costUsd === prev.costUsd &&
        inputTokens === prev.inputTokens &&
        outputTokens === prev.outputTokens
      ) {
        return prev;
      }
      return { ...prev, costUsd, inputTokens, outputTokens };
    }
    default:
      return prev;
  }
}

/** Whether a snapshot has anything worth rendering in the panel. */
export function hasLiveAgentState(state: LiveAgentState | undefined): boolean {
  if (!state) return false;
  return Boolean(
    state.turn !== undefined ||
      state.reasoningSummary ||
      state.currentTool ||
      state.costUsd !== undefined ||
      state.inputTokens !== undefined ||
      state.outputTokens !== undefined,
  );
}
