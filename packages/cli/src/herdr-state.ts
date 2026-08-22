/**
 * Bridge between the interactive console's operator gates and the herdr
 * pane-state sink.
 *
 * herdr distinguishes `working` from `blocked`, and `blocked` is the state
 * that actually earns its keep: it is what drives the "this agent needs
 * you" attention queue, the sidebar highlight and the toast. 0sec's event
 * bus has no event meaning "waiting on the operator" — the scope-approval
 * and co-pilot gates resolve their promises inline and emit nothing — so
 * the signal has to come from the surface that owns the prompt.
 *
 * The sink instance is created once at CLI bootstrap and parked here so the
 * TUI can reach it without threading a core object through every screen.
 * Everything is a no-op when 0sec is not running inside herdr.
 */

import type { HerdrEventSink } from "@0sec/core";

let sink: HerdrEventSink | null = null;

/** Called once at bootstrap. Passing null (not under herdr) is fine. */
export function setHerdrSink(next: HerdrEventSink | null): void {
  sink = next;
}

/**
 * Report whether 0sec is currently waiting on a human decision.
 *
 * Never throws: the sink is fail-soft by contract, and an approval prompt
 * must not be able to fail because a pane-decoration socket is unhappy.
 */
export function reportOperatorGate(blocked: boolean): void {
  if (!sink) return;
  try {
    if (blocked) sink.reportBlocked();
    else sink.reportWorking();
  } catch {
    // Telemetry for a pane label must never affect the approval path.
  }
}
