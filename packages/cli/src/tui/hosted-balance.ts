import type { InferenceAccountResponse, HostedAllowanceOverview } from "@0sec/core";

export type HostedBalanceState =
  | { status: "loading" }
  | { status: "unavailable" }
  | { status: "legacy"; remainingPercent: number }
  | { status: "ready"; allowance: HostedAllowanceOverview };

const validPercent = (value: unknown): value is number =>
  typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100;

const WINDOW_LABELS = [["monthly", "M"], ["weekly", "W"], ["five_hour", "5h"]] as const;

/** TUI lifecycle owns account identity and must discard stale responses. */
export function hostedBalanceState(account: InferenceAccountResponse | null | undefined): HostedBalanceState {
  if (account?.allowance !== undefined) {
    const allowance = account.allowance;
    return allowance && allowance.windows.every(window => validPercent(window.remainingPercent))
      ? { status: "ready", allowance }
      : { status: "unavailable" };
  }
  const remainingPercent = account?.credits?.remainingPercent;
  return validPercent(remainingPercent)
    ? { status: "legacy", remainingPercent }
    : { status: "unavailable" };
}

/** Render only for the active Cloud provider, never a pending selection or BYOK. */
export function formatHostedBalance(state: HostedBalanceState): string {
  if (state.status === "loading") return "Cloud: Loading…";
  if (state.status === "unavailable") return "Cloud: Unavailable";
  if (state.status === "legacy") return `Legacy: ${formatPercent(state.remainingPercent)}%`;
  const { allowance } = state;
  const status = allowance.subscription.state === "inactive" ? "Not subscribed"
    : allowance.subscription.state === "unavailable" ? "Subscription unavailable"
    : allowance.admission.allowed ? null
    : allowance.admission.reason === "unresolved" ? "Unresolved"
    : allowance.admission.reason === "allowance_exhausted" ? "Limit reached"
    : "Unavailable";
  const windows = WINDOW_LABELS.map(([kind, label]) => {
    const window = allowance.windows.find(window => window.kind === kind);
    return `${label}:${window ? `${formatPercent(window.remainingPercent)}%` : "—"}`;
  }).join(" ");
  return `Cloud: ${status ? `${status} · ` : ""}${windows}`;
}

function formatPercent(value: number): string {
  if (value > 0 && value < 0.1) return "<0.1";
  if (value > 99.9 && value < 100) return ">99.9";
  if (value === 0) return "0";
  if (value === 100) return "100";
  return String(Number(value.toFixed(1)));
}