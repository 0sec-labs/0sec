import { describe, it, expect } from "vitest";
import {
  resolveEngagementProfile,
  parseEngagementProfileName,
  extractEngagementFromScopeJson,
  describeEngagementPosture,
  effectiveFallbackRps,
  isWafEvasionLadderEnabled,
  CONSERVATIVE_RPS,
  CONSERVATIVE_JITTER_MS,
  STANDARD_RPS,
} from "./engagement-profile.js";

describe("resolveEngagementProfile — default (profile off)", () => {
  it("reproduces the historical engine behaviour with no config at all", () => {
    const p = resolveEngagementProfile();
    expect(p.profile).toBe("standard");
    expect(p.active).toBe(false);
    // Every loud behaviour stays exactly as it was.
    expect(p.resetBurstProbe).toBe(true);
    expect(p.webReconPrepass).toBe("direct-fetch");
    expect(p.wafEvasionLadder).toBe(true);
    expect(p.jitter).toBeUndefined();
    expect(p.rateLimitRps).toBe(STANDARD_RPS);
    expect(p.sources.profile).toBe("default");
  });

  it("is unaffected by unrelated env vars", () => {
    const p = resolveEngagementProfile({ env: { "0SEC_FEATURE_WEB_RECON": "1" } });
    expect(p.active).toBe(false);
    expect(p.wafEvasionLadder).toBe(true);
    expect(p.rateLimitRps).toBe(STANDARD_RPS);
  });

  it("explicit standard is still the unchanged posture", () => {
    const p = resolveEngagementProfile({ cliProfile: "standard" });
    expect(p.active).toBe(false);
    expect(p.resetBurstProbe).toBe(true);
    expect(p.jitter).toBeUndefined();
  });
});

describe("resolveEngagementProfile — conservative (profile on)", () => {
  it("disables the burst probe and the evasion ladder, adds jitter, cuts the rate", () => {
    const p = resolveEngagementProfile({ cliProfile: "conservative" });
    expect(p.active).toBe(true);
    expect(p.resetBurstProbe).toBe(false);
    expect(p.wafEvasionLadder).toBe(false);
    expect(p.webReconPrepass).toBe("rate-limited");
    expect(p.jitter).toEqual({ baseMs: CONSERVATIVE_JITTER_MS });
    expect(p.rateLimitRps).toBe(CONSERVATIVE_RPS);
    // …and the conservative rate really is well under the engine default.
    expect(p.rateLimitRps).toBeLessThan(STANDARD_RPS);
  });

  it("is selectable from env and from the scope file", () => {
    expect(
      resolveEngagementProfile({ env: { "0SEC_ENGAGEMENT_PROFILE": "conservative" } }).active,
    ).toBe(true);
    expect(
      resolveEngagementProfile({ scopeFileBlock: { profile: "conservative" } }).active,
    ).toBe(true);
  });

  it("accepts case / whitespace variants of the name", () => {
    expect(resolveEngagementProfile({ cliProfile: "  Conservative " }).profile).toBe(
      "conservative",
    );
  });
});

describe("resolveEngagementProfile — precedence (scope file > env > CLI)", () => {
  it("scope file wins over env and CLI", () => {
    const p = resolveEngagementProfile({
      scopeFileBlock: { profile: "conservative" },
      env: { "0SEC_ENGAGEMENT_PROFILE": "standard" },
      cliProfile: "standard",
    });
    expect(p.profile).toBe("conservative");
    expect(p.sources.profile).toBe("scope-file");
  });

  it("env wins over CLI", () => {
    const p = resolveEngagementProfile({
      env: { "0SEC_ENGAGEMENT_PROFILE": "conservative" },
      cliProfile: "standard",
    });
    expect(p.profile).toBe("conservative");
    expect(p.sources.profile).toBe("env");
  });

  it("an engagement scope file cannot be loosened by a CLI flag", () => {
    // The whole point of scope-file-wins: the engagement artifact pins the
    // posture, an ad-hoc flag can't quietly turn the ladder back on.
    const p = resolveEngagementProfile({
      scopeFileBlock: { waf_evasion: false },
      env: { "0SEC_WAF_EVASION": "1" },
      cliWafEvasion: true,
    });
    expect(p.wafEvasionLadder).toBe(false);
    expect(p.sources.wafEvasionLadder).toBe("scope-file");
  });
});

describe("WAF-evasion ladder — disableable independently of the profile", () => {
  it("0SEC_WAF_EVASION=0 disables the ladder with no profile selected", () => {
    const p = resolveEngagementProfile({ env: { "0SEC_WAF_EVASION": "0" } });
    expect(p.profile).toBe("standard");
    expect(p.active).toBe(false);
    expect(p.wafEvasionLadder).toBe(false);
    expect(p.sources.wafEvasionLadder).toBe("env");
    // Nothing ELSE changed — this is a single-knob opt-out.
    expect(p.resetBurstProbe).toBe(true);
    expect(p.rateLimitRps).toBe(STANDARD_RPS);
    expect(p.jitter).toBeUndefined();
  });

  it("`false` is accepted as well as `0`", () => {
    expect(
      resolveEngagementProfile({ env: { "0SEC_WAF_EVASION": "false" } }).wafEvasionLadder,
    ).toBe(false);
    expect(
      resolveEngagementProfile({ env: { "0SEC_WAF_EVASION": "FALSE" } }).wafEvasionLadder,
    ).toBe(false);
  });

  it("--no-waf-evasion (cliWafEvasion=false) disables the ladder", () => {
    const p = resolveEngagementProfile({ cliWafEvasion: false });
    expect(p.wafEvasionLadder).toBe(false);
    expect(p.sources.wafEvasionLadder).toBe("cli");
  });

  it("the scope file can re-enable the ladder under a conservative profile", () => {
    const p = resolveEngagementProfile({
      scopeFileBlock: { profile: "conservative", waf_evasion: true },
    });
    expect(p.active).toBe(true);
    expect(p.wafEvasionLadder).toBe(true);
    // The rest of the conservative posture is untouched.
    expect(p.resetBurstProbe).toBe(false);
  });

  it("isWafEvasionLadderEnabled defaults to true and honours a posture", () => {
    expect(isWafEvasionLadderEnabled(undefined, {})).toBe(true);
    expect(isWafEvasionLadderEnabled(undefined, { "0SEC_WAF_EVASION": "0" })).toBe(false);
    expect(
      isWafEvasionLadderEnabled(resolveEngagementProfile({ cliProfile: "conservative" })),
    ).toBe(false);
    expect(isWafEvasionLadderEnabled(resolveEngagementProfile())).toBe(true);
  });
});

describe("per-field overrides", () => {
  it("rate + jitter can be tuned per engagement", () => {
    const p = resolveEngagementProfile({
      cliProfile: "conservative",
      scopeFileBlock: { rate_limit_rps: 0.5, jitter_ms: 2000 },
    });
    expect(p.rateLimitRps).toBe(0.5);
    expect(p.jitter).toEqual({ baseMs: 2000 });
    expect(p.sources.rateLimitRps).toBe("scope-file");
  });

  it("jitter_ms = 0 turns jitter off", () => {
    const p = resolveEngagementProfile({
      cliProfile: "conservative",
      scopeFileBlock: { jitter_ms: 0 },
    });
    expect(p.jitter).toBeUndefined();
  });

  it("the burst probe can be re-enabled explicitly from the scope file", () => {
    const p = resolveEngagementProfile({
      cliProfile: "conservative",
      scopeFileBlock: { reset_burst_probe: true },
    });
    expect(p.resetBurstProbe).toBe(true);
    expect(p.sources.resetBurstProbe).toBe("scope-file");
  });

  it("env can set the rate without selecting a profile", () => {
    const p = resolveEngagementProfile({ env: { "0SEC_ENGAGEMENT_RATE_RPS": "2" } });
    expect(p.rateLimitRps).toBe(2);
    expect(p.sources.rateLimitRps).toBe("env");
  });
});

describe("effectiveFallbackRps", () => {
  it("leaves the mode default alone when no profile is active", () => {
    expect(effectiveFallbackRps(resolveEngagementProfile(), 5)).toBe(5);
    expect(effectiveFallbackRps(resolveEngagementProfile(), 20)).toBe(20);
  });

  it("cuts the rate under a conservative profile", () => {
    const p = resolveEngagementProfile({ cliProfile: "conservative" });
    expect(effectiveFallbackRps(p, 5)).toBe(CONSERVATIVE_RPS);
    expect(effectiveFallbackRps(p, 5)).toBeLessThan(5);
  });

  it("never speeds a scan UP — an already-slower mode default wins", () => {
    const p = resolveEngagementProfile({ cliProfile: "conservative" });
    // e.g. an http_audit worker contract pinning 0.5 rps.
    expect(effectiveFallbackRps(p, 0.5)).toBe(0.5);
  });
});

describe("validation", () => {
  it("rejects an unknown profile name loudly", () => {
    expect(() => parseEngagementProfileName("conservitive")).toThrow(/Unknown engagement profile/);
    expect(() => resolveEngagementProfile({ cliProfile: "quiet" })).toThrow(
      /Unknown engagement profile/,
    );
    expect(() =>
      resolveEngagementProfile({ env: { "0SEC_ENGAGEMENT_PROFILE": "stealth" } }),
    ).toThrow(/Unknown engagement profile/);
  });

  it("rejects a non-positive / non-numeric rate", () => {
    expect(() =>
      resolveEngagementProfile({ env: { "0SEC_ENGAGEMENT_RATE_RPS": "0" } }),
    ).toThrow(/positive number/);
    expect(() =>
      resolveEngagementProfile({ env: { "0SEC_ENGAGEMENT_RATE_RPS": "fast" } }),
    ).toThrow(/positive number/);
    expect(() =>
      resolveEngagementProfile({ scopeFileBlock: { rate_limit_rps: -1 } }),
    ).toThrow(/positive number/);
  });

  it("rejects a negative jitter", () => {
    expect(() =>
      resolveEngagementProfile({ env: { "0SEC_ENGAGEMENT_JITTER_MS": "-5" } }),
    ).toThrow(/non-negative/);
  });

  it("empty-string env values fall through instead of erroring", () => {
    const p = resolveEngagementProfile({
      env: { "0SEC_ENGAGEMENT_PROFILE": "", "0SEC_ENGAGEMENT_RATE_RPS": "  " },
      cliProfile: "conservative",
    });
    expect(p.profile).toBe("conservative");
    expect(p.rateLimitRps).toBe(CONSERVATIVE_RPS);
  });
});

describe("extractEngagementFromScopeJson", () => {
  it("returns undefined when the block is absent", () => {
    expect(extractEngagementFromScopeJson({ in_scope: ["example.com"] })).toBeUndefined();
    expect(extractEngagementFromScopeJson(null)).toBeUndefined();
    expect(extractEngagementFromScopeJson("nope")).toBeUndefined();
  });

  it("parses a full block", () => {
    expect(
      extractEngagementFromScopeJson({
        in_scope: ["example.com"],
        engagement: {
          profile: "conservative",
          waf_evasion: false,
          reset_burst_probe: false,
          rate_limit_rps: 1,
          jitter_ms: 500,
        },
      }),
    ).toEqual({
      profile: "conservative",
      waf_evasion: false,
      reset_burst_probe: false,
      rate_limit_rps: 1,
      jitter_ms: 500,
    });
  });

  it("throws on a malformed block so misconfiguration surfaces at boot", () => {
    expect(() => extractEngagementFromScopeJson({ engagement: [] })).toThrow(/must be an object/);
    expect(() => extractEngagementFromScopeJson({ engagement: { profile: 3 } })).toThrow(
      /must be a string/,
    );
    expect(() =>
      extractEngagementFromScopeJson({ engagement: { waf_evasion: "no" } }),
    ).toThrow(/must be a boolean/);
    expect(() =>
      extractEngagementFromScopeJson({ engagement: { rate_limit_rps: "5" } }),
    ).toThrow(/must be a finite number/);
  });
});

describe("describeEngagementPosture — the auditable record", () => {
  it("reflects the posture that was actually applied", () => {
    const posture = resolveEngagementProfile({
      scopeFileBlock: { profile: "conservative" },
      env: { "0SEC_WAF_EVASION": "1" },
    });
    const record = describeEngagementPosture(posture, new Date("2026-07-28T10:00:00.000Z"));
    expect(record).toEqual({
      profile: "conservative",
      applied_at: "2026-07-28T10:00:00.000Z",
      reset_endpoint_burst_probe: "disabled",
      web_recon_prepass: "rate-limited",
      // The env re-enabled the ladder — the record must say so rather than
      // parroting the profile's nominal posture.
      waf_evasion_ladder: "enabled",
      request_jitter: "full-jitter",
      jitter_base_ms: CONSERVATIVE_JITTER_MS,
      per_host_rps: CONSERVATIVE_RPS,
      sources: {
        profile: "scope-file",
        wafEvasionLadder: "env",
        rateLimitRps: "scope-file",
        jitter: "scope-file",
        resetBurstProbe: "scope-file",
      },
    });
  });

  it("records the standard posture faithfully too", () => {
    const record = describeEngagementPosture(resolveEngagementProfile());
    expect(record.profile).toBe("standard");
    expect(record.reset_endpoint_burst_probe).toBe("enabled");
    expect(record.waf_evasion_ladder).toBe("enabled");
    expect(record.request_jitter).toBe("none");
    expect(record.jitter_base_ms).toBe(0);
    expect(record.per_host_rps).toBe(STANDARD_RPS);
  });

  it("does not alias the posture's source map", () => {
    const posture = resolveEngagementProfile({ cliProfile: "conservative" });
    const record = describeEngagementPosture(posture);
    posture.sources.profile = "default";
    expect(record.sources.profile).toBe("cli");
  });
});
