import { describe, expect, it } from "vitest";

import {
  resolveCompactionThresholds,
  DEFAULT_COMPACTION_THRESHOLD,
  DEFAULT_COMPACTION_REGROW,
} from "./native-loop.js";

describe("resolveCompactionThresholds", () => {
  it("defaults when the env is unset", () => {
    expect(resolveCompactionThresholds({})).toEqual({
      threshold: DEFAULT_COMPACTION_THRESHOLD,
      regrow: DEFAULT_COMPACTION_REGROW,
    });
  });

  it("honors valid env overrides", () => {
    expect(
      resolveCompactionThresholds({
        "0SEC_COMPACTION_THRESHOLD": "120000",
        "0SEC_COMPACTION_REGROW": "40000",
      }),
    ).toEqual({ threshold: 120000, regrow: 40000 });
  });

  it("falls back on malformed or too-small values", () => {
    expect(resolveCompactionThresholds({ "0SEC_COMPACTION_THRESHOLD": "not-a-number" }).threshold).toBe(
      DEFAULT_COMPACTION_THRESHOLD,
    );
    // below the floor → default
    expect(resolveCompactionThresholds({ "0SEC_COMPACTION_THRESHOLD": "10" }).threshold).toBe(
      DEFAULT_COMPACTION_THRESHOLD,
    );
    expect(resolveCompactionThresholds({ "0SEC_COMPACTION_REGROW": "-5" }).regrow).toBe(
      DEFAULT_COMPACTION_REGROW,
    );
  });

  it("floors fractional values", () => {
    expect(resolveCompactionThresholds({ "0SEC_COMPACTION_THRESHOLD": "90000.9" }).threshold).toBe(90000);
  });
});
