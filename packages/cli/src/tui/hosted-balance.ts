import type { InferenceAccountResponse } from "@0sec/core";

export type HostedBalanceState =
  | { status: "loading" }
  | { status: "unavailable" }
  | { status: "ready"; remainingPercent: number };

const validPercent = (value: unknown): value is number =>
  typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100;

/** TUI lifecycle owns account identity and must discard stale responses. */
export function hostedBalanceState(account: InferenceAccountResponse | null | undefined): HostedBalanceState {
  const remainingPercent = account?.credits?.remainingPercent;
  return validPercent(remainingPercent)
    ? { status: "ready", remainingPercent }
    : { status: "unavailable" };
}

/** Render only for the active Cloud provider, never a pending selection or BYOK. */
export function formatHostedBalance(state: HostedBalanceState): string {
  if (state.status === "loading") return "Cloud: Loading…";
  if (state.status !== "ready" || !validPercent(state.remainingPercent)) return "Cloud: Unavailable";
  const percent = state.remainingPercent;
  const label = percent > 0 && percent < 0.1
    ? "<0.1"
    : percent > 99.9 && percent < 100
      ? ">99.9"
      : String(Number(percent.toFixed(1)));
  return `Cloud: ${label}% remaining`;
}
