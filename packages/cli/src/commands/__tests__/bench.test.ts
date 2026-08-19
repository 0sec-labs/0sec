import { describe, expect, it } from "vitest";
import { resolveManifestPath } from "../bench.js";

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
