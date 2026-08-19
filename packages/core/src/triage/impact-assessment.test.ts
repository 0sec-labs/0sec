import { describe, expect, it } from "vitest";
import type { Finding } from "@0sec/shared";
import type { NativeRuntime, NativeRuntimeResult } from "../runtime/types.js";
import {
  assessImpact,
  heuristicImpact,
  parseImpactAssessment,
  impactAssessmentToColumn,
  businessImpactOf,
  impactRank,
  compareByImpactDesc,
  BUSINESS_IMPACT_RANK,
} from "./impact-assessment.js";

// ── Fixtures ────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f-1",
    templateId: "manual",
    title: "Some bug",
    description: "a bug",
    severity: "high",
    category: "information-disclosure",
    status: "discovered",
    evidence: { request: "", response: "", analysis: "" },
    timestamp: 0,
    ...overrides,
  };
}

// The two canonical opposites from the issue: a "critical" bug walled behind
// host migration (noise) vs a "high" bug that hits every device (headline).
const FS_IMAGE_UAF = makeFinding({
  id: "uaf",
  title: "UAF mounting crafted squashfs image",
  category: "unsafe-deserialization",
  severity: "critical",
  description: "Use-after-free when the kernel mounts an attacker-crafted FS image.",
});

const NFC_CRASH = makeFinding({
  id: "nfc",
  title: "Remote NFC LLCP parse crash",
  category: "regex-dos",
  severity: "high",
  description: "Malformed NFC LLCP frame crashes the stack on any device with the radio on.",
});

/** A NativeRuntime stub that returns one fixed text block (or an error). */
function stubRuntime(reply: string, error?: string): NativeRuntime {
  return {
    type: "api",
    async isAvailable() {
      return true;
    },
    async executeNative(): Promise<NativeRuntimeResult> {
      return {
        content: error ? [] : [{ type: "text", text: reply }],
        stopReason: error ? "error" : "end_turn",
        durationMs: 1,
        ...(error ? { error } : {}),
      };
    },
  };
}

// ── parseImpactAssessment ───────────────────────────────────────────

describe("parseImpactAssessment", () => {
  it("parses a clean JSON object", () => {
    const a = parseImpactAssessment(
      JSON.stringify({
        reachability_tier: "remote-unauth",
        blast_radius: "every device with NFC",
        weaponizability: "dos-crash",
        business_impact: "headline",
        rationale: "reachable over RF, broad fleet",
      }),
    );
    expect(a?.reachability_tier).toBe("remote-unauth");
    expect(a?.business_impact).toBe("headline");
  });

  it("tolerates markdown code fences and surrounding prose", () => {
    const a = parseImpactAssessment(
      "Here is my assessment:\n```json\n" +
        JSON.stringify({
          reachability_tier: "needs-host-migration",
          blast_radius: "hosts that mount attacker images",
          weaponizability: "lpe-to-root",
          business_impact: "noise",
          rationale: "needs host migration",
        }) +
        "\n```\nHope that helps.",
    );
    expect(a?.business_impact).toBe("noise");
    expect(a?.reachability_tier).toBe("needs-host-migration");
  });

  it("rejects an out-of-vocabulary enum value", () => {
    expect(
      parseImpactAssessment(
        JSON.stringify({
          reachability_tier: "from-mars",
          blast_radius: "x",
          weaponizability: "rce",
          business_impact: "headline",
          rationale: "y",
        }),
      ),
    ).toBeNull();
  });

  it("rejects an empty blast_radius and non-JSON", () => {
    expect(
      parseImpactAssessment(
        JSON.stringify({
          reachability_tier: "remote-unauth",
          blast_radius: "   ",
          weaponizability: "rce",
          business_impact: "headline",
          rationale: "y",
        }),
      ),
    ).toBeNull();
    expect(parseImpactAssessment("not json at all")).toBeNull();
  });
});

// ── heuristicImpact ─────────────────────────────────────────────────

describe("heuristicImpact", () => {
  it("maps severity → business_impact and category → weaponizability", () => {
    const a = heuristicImpact(makeFinding({ severity: "critical", category: "sql-injection" }));
    expect(a.business_impact).toBe("headline");
    expect(a.weaponizability).toBe("rce");
  });

  it("treats low/info severity as noise", () => {
    expect(heuristicImpact(makeFinding({ severity: "low" })).business_impact).toBe("noise");
    expect(heuristicImpact(makeFinding({ severity: "info" })).business_impact).toBe("noise");
  });
});

// ── assessImpact (fake model) ───────────────────────────────────────

describe("assessImpact", () => {
  it("returns the deterministic heuristic when no runtime is injected", async () => {
    const a = await assessImpact(NFC_CRASH);
    expect(a).toEqual(heuristicImpact(NFC_CRASH));
  });

  it("uses the injected model's assessment when it parses", async () => {
    const runtime = stubRuntime(
      JSON.stringify({
        reachability_tier: "proximity-rf",
        blast_radius: "every device with the NFC radio enabled",
        weaponizability: "dos-crash",
        business_impact: "headline",
        rationale: "no auth, RF-reachable, whole fleet",
      }),
    );
    const a = await assessImpact(NFC_CRASH, { runtime });
    expect(a.reachability_tier).toBe("proximity-rf");
    expect(a.business_impact).toBe("headline");
  });

  it("qualifies a nominally-critical FS-image UAF down to noise", async () => {
    const runtime = stubRuntime(
      JSON.stringify({
        reachability_tier: "needs-host-migration",
        blast_radius: "only hosts that mount an attacker-supplied image",
        weaponizability: "lpe-to-root",
        business_impact: "noise",
        rationale: "requires the victim to mount a crafted image first",
      }),
    );
    const a = await assessImpact(FS_IMAGE_UAF, { runtime });
    // Nominal severity is 'critical' but the real impact is noise.
    expect(FS_IMAGE_UAF.severity).toBe("critical");
    expect(a.business_impact).toBe("noise");
  });

  it("falls back to the heuristic when the model errors", async () => {
    const runtime = stubRuntime("", "model unavailable");
    const a = await assessImpact(FS_IMAGE_UAF, { runtime });
    expect(a).toEqual(heuristicImpact(FS_IMAGE_UAF));
  });

  it("falls back to the heuristic when the model returns garbage", async () => {
    const runtime = stubRuntime("I refuse to answer in JSON");
    const a = await assessImpact(NFC_CRASH, { runtime });
    expect(a).toEqual(heuristicImpact(NFC_CRASH));
  });
});

// ── mapping + ranking ───────────────────────────────────────────────

describe("impact ranking", () => {
  it("orders headline > notable > modest > noise", () => {
    expect(BUSINESS_IMPACT_RANK.headline).toBeGreaterThan(BUSINESS_IMPACT_RANK.notable);
    expect(BUSINESS_IMPACT_RANK.notable).toBeGreaterThan(BUSINESS_IMPACT_RANK.modest);
    expect(BUSINESS_IMPACT_RANK.modest).toBeGreaterThan(BUSINESS_IMPACT_RANK.noise);
  });

  it("ranks an unassessed finding as neutral (modest)", () => {
    expect(businessImpactOf(makeFinding())).toBe("modest");
    expect(impactRank(makeFinding())).toBe(BUSINESS_IMPACT_RANK.modest);
  });

  it("sorts a headline finding above a noise finding regardless of nominal severity", () => {
    const headline = makeFinding({
      id: "h",
      severity: "high",
      impactAssessment: {
        reachability_tier: "remote-unauth",
        blast_radius: "all",
        weaponizability: "rce",
        business_impact: "headline",
        rationale: "",
      },
    });
    const noise = makeFinding({
      id: "n",
      severity: "critical",
      impactAssessment: {
        reachability_tier: "needs-host-migration",
        blast_radius: "few",
        weaponizability: "lpe-to-root",
        business_impact: "noise",
        rationale: "",
      },
    });
    const sorted = [noise, headline].sort(compareByImpactDesc);
    expect(sorted[0].id).toBe("h");
    expect(sorted[1].id).toBe("n");
  });

  it("impactAssessmentToColumn whitelists exactly the five fields", () => {
    const withExtra = {
      reachability_tier: "remote-unauth",
      blast_radius: "all",
      weaponizability: "rce",
      business_impact: "headline",
      rationale: "r",
      // an over-eager model tacked on an extra key
      injected: "should not persist",
    } as unknown as Parameters<typeof impactAssessmentToColumn>[0];
    const col = impactAssessmentToColumn(withExtra);
    expect(Object.keys(col).sort()).toEqual(
      [
        "blast_radius",
        "business_impact",
        "rationale",
        "reachability_tier",
        "weaponizability",
      ].sort(),
    );
    expect((col as Record<string, unknown>).injected).toBeUndefined();
  });
});
