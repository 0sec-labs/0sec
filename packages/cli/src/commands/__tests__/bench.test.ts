import { describe, expect, it } from "vitest";
import {
  parseAttemptPolicy,
  parseTournamentSchedule,
  resolveManifestPath,
} from "../bench.js";

describe("resolveManifestPath", () => {
  it("uses an explicit manifest when no bundled corpus is present", () => {
    expect(resolveManifestPath("/tmp/public-manifest.json", "/missing-corpus.json"))
      .toBe("/tmp/public-manifest.json");
  });

  it("fails clearly when a public source export has no bundled corpus", () => {
    expect(() => resolveManifestPath(undefined, "/missing-corpus.json"))
      .toThrow(/No bundled benchmark corpus/);
  });
});

describe("benchmark protocol options", () => {
  it("accepts the explicit independent-repeat and blocked schedule modes", () => {
    expect(parseAttemptPolicy("independent-repeat")).toBe("independent-repeat");
    expect(parseTournamentSchedule("case-major")).toBe("case-major");
  });

  it("fails closed on unknown protocol modes", () => {
    expect(() => parseAttemptPolicy("retry-until-pass")).toThrow(/attempt-policy/);
    expect(() => parseTournamentSchedule("parallel")).toThrow(/schedule/);
  });
});
