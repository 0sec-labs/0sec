import { describe, expect, it } from "vitest";
import type { InferenceAccountResponse } from "@0sec/core";
import { formatHostedBalance, hostedBalanceState } from "./hosted-balance.js";

function account(remainingPercent: number | null): InferenceAccountResponse {
  return {
    remainingUsd: 500,
    currency: "USD",
    credits: { featureId: "inference_credits", granted: 100, remaining: 42, remainingPercent, nextResetAt: null },
  };
}

const display = (value: InferenceAccountResponse | null | undefined) => formatHostedBalance(hostedBalanceState(value));

describe("hosted balance presentation", () => {
  it.each([
    [0, "0"], [100, "100"], [0.001, "<0.1"], [0.0999, "<0.1"],
    [0.1, "0.1"], [42.34, "42.3"], [99.9, "99.9"], [99.999, ">99.9"],
  ])("renders authoritative %s without false exhaustion or fullness", (percent, label) => {
    expect(display(account(percent))).toBe(`Cloud: ${label}% remaining`);
  });

  it("distinguishes pending data from unavailable data and exhausted credit", () => {
    expect(formatHostedBalance({ status: "loading" })).toBe("Cloud: Loading…");
    expect(display(null)).toBe("Cloud: Unavailable");
    expect(display(account(0))).toBe("Cloud: 0% remaining");
  });

  it("keeps absent and old-gateway balances unavailable despite a USD balance", () => {
    expect(display(undefined)).toBe("Cloud: Unavailable");
    expect(display({ ...account(42), credits: null })).toBe("Cloud: Unavailable");
    const legacy = { remainingUsd: 500, currency: "USD" } as InferenceAccountResponse;
    expect(display(legacy)).toBe("Cloud: Unavailable");
    expect(display(account(null))).toBe("Cloud: Unavailable");
  });

  it.each([NaN, Infinity, -Infinity, -1, 100.1, "42", undefined])("rejects invalid percentage %s rather than clamping or coercing", (invalid) => {
    const malformed = account(invalid as number);
    expect(display(malformed)).toBe("Cloud: Unavailable");
    expect(formatHostedBalance({ status: "ready", remainingPercent: invalid as number })).toBe("Cloud: Unavailable");
  });

  it("never reconstructs a percentage from grants, credit units, USD, or reset", () => {
    const first = account(37.5);
    const second: InferenceAccountResponse = {
      ...first, remainingUsd: 0,
      credits: { ...first.credits!, granted: null, remaining: 99999, nextResetAt: 1 },
    };
    expect(display(first)).toBe("Cloud: 37.5% remaining");
    expect(display(second)).toBe("Cloud: 37.5% remaining");
  });
});
