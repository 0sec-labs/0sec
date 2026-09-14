import { describe, expect, it } from "vitest";
import type { InferenceAccountResponse, HostedAllowanceWindow } from "@0sec/core";
import { formatHostedBalance, hostedBalanceState } from "./hosted-balance.js";

function account(remainingPercent: number | null): InferenceAccountResponse {
  return {
    remainingUsd: 500,
    currency: "USD",
    credits: { featureId: "inference_credits", granted: 100, remaining: 42, remainingPercent, nextResetAt: null },
  };
}

function window(kind: "monthly" | "weekly" | "five_hour", remainingPercent: number): HostedAllowanceWindow {
  return {
    id: `w-${kind}`,
    kind,
    limitUsd: kind === "monthly" ? 10 : kind === "weekly" ? 5 : 2,
    settledUsd: 0,
    reservedUsd: 0,
    unknownReservedUsd: 0,
    availableUsd: kind === "monthly" ? 10 : kind === "weekly" ? 5 : 2,
    remainingPercent,
    startsAt: "2026-09-01T00:00:00Z",
    endsAt: "2026-10-01T00:00:00Z",
    resetSemantics: kind === "monthly" ? "billing_period" : kind === "weekly" ? "utc_monday" : "first_admission",
  };
}

function allowanceAccount(windows: HostedAllowanceWindow[]): InferenceAccountResponse {
  return {
    remainingUsd: 500,
    currency: "USD",
    credits: { featureId: "inference_credits", granted: 100, remaining: 42, remainingPercent: 55, nextResetAt: null },
    allowance: {
      snapshotAt: "2026-09-14T12:00:00Z",
      policyVersion: "subscription15-supplier-cost-v1",
      basis: "supplier_cost_usd",
      unresolvedReservedUsd: 0,
      subscription: { priceUsd: 15, cadence: "monthly", state: "active", sourceId: "sub_001", periodStart: null, periodEnd: null },
      windows,
      admission: { allowed: true, reason: null },
      purchases: { enabled: false, offer: null },
      models: [],
    },
  };
}

const display = (value: InferenceAccountResponse | null | undefined) => formatHostedBalance(hostedBalanceState(value));

describe("hosted balance presentation", () => {
  describe("legacy credits path", () => {
    it.each([
      [0, "0"], [100, "100"], [0.001, "<0.1"], [0.0999, "<0.1"],
      [0.1, "0.1"], [42.34, "42.3"], [99.9, "99.9"], [99.999, ">99.9"],
    ])("renders authoritative %s without false exhaustion or fullness", (percent, label) => {
      expect(display(account(percent))).toBe(`Legacy: ${label}%`);
    });

    it("distinguishes pending data from unavailable data and exhausted credit", () => {
      expect(formatHostedBalance({ status: "loading" })).toBe("Cloud: Loading…");
      expect(display(null)).toBe("Cloud: Unavailable");
      expect(display(account(0))).toBe("Legacy: 0%");
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
    });

    it("never reconstructs a percentage from grants, credit units, USD, or reset", () => {
      const first = account(37.5);
      const second: InferenceAccountResponse = {
        ...first, remainingUsd: 0,
        credits: { ...first.credits!, granted: null, remaining: 99999, nextResetAt: 1 },
      };
      expect(display(first)).toBe("Legacy: 37.5%");
      expect(display(second)).toBe("Legacy: 37.5%");
    });
  });

  describe("subscription allowance path", () => {
    it("uses each server percentage rather than USD totals or the legacy wallet", () => {
      const text = display(allowanceAccount([
        window("five_hour", 40), window("monthly", 75), window("weekly", 60),
      ]));
      expect(text).toContain("M:75%");
      expect(text).toContain("W:60%");
      expect(text).toContain("5h:40%");
      expect(text).not.toContain("Legacy");
    });

    it("preserves tiny availability, almost-full availability and real exhaustion", () => {
      const text = display(allowanceAccount([
        window("monthly", 0.001), window("weekly", 99.999), window("five_hour", 0),
      ]));
      expect(text).toContain("M:<0.1%");
      expect(text).toContain("W:>99.9%");
      expect(text).toContain("5h:0%");
    });

    it("does not invent percentages or use the legacy wallet before windows exist", () => {
      const text = display(allowanceAccount([]));
      for (const label of ["M:", "W:", "5h:"]) expect(text).toContain(label);
      expect(text).not.toMatch(/\d(?:\.\d+)?%/);
    });

    it("does not replace an unavailable subscription snapshot with legacy credits", () => {
      const acct = allowanceAccount([]);
      acct.allowance = null;
      expect(hostedBalanceState(acct).status).toBe("unavailable");
      expect(display(acct)).not.toMatch(/\d(?:\.\d+)?%/);
    });

    it("rejects an invalid window percentage rather than formatting it", () => {
      expect(hostedBalanceState(allowanceAccount([window("monthly", Infinity)])).status).toBe("unavailable");
    });
  });
});