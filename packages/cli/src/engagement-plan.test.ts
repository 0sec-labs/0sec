import { describe, expect, it } from "vitest";

import { resolveEngagement } from "./engagement-plan.js";

describe("resolveEngagement", () => {
  it("plans explicit web targets without a separate scan mode", () => {
    expect(resolveEngagement("https://app.example.test")).toEqual({
      ok: true,
      plan: {
        kind: "web",
        target: "https://app.example.test",
        targetType: "url",
        label: "web target https://app.example.test",
      },
    });
  });

  it("routes bare repository URLs to source review before generic web scanning", () => {
    for (const target of [
      "https://github.com/0sec-labs/0sec",
      "https://example.test/repository.git",
      "git://example.test/repository.git",
      "git@example.test:group/repository.git",
    ]) {
      expect(resolveEngagement(target)).toMatchObject({
        ok: true,
        plan: {
          kind: "source",
          target,
          targetType: "source-code",
          reviewStrategy: "lenses",
        },
      });
    }
  });

  it("plans source targets through the validated-lens review strategy", () => {
    expect(resolveEngagement("source:./repo")).toEqual({
      ok: true,
      plan: {
        kind: "source",
        target: "./repo",
        targetType: "source-code",
        reviewStrategy: "lenses",
        label: "source review ./repo",
      },
    });
  });

  it("requires an explicit ecosystem prefix for a package", () => {
    expect(resolveEngagement("npm:express")).toEqual({
      ok: true,
      plan: {
        kind: "package",
        target: "express",
        targetType: "npm-package",
        ecosystem: "npm",
        label: "npm package express",
      },
    });
    expect(resolveEngagement("express")).toMatchObject({
      ok: false,
      message: expect.stringContaining("Ambiguous target"),
    });
  });

  it("rejects a missing explicit payload before any runner is selected", () => {
    expect(resolveEngagement("cargo:")).toEqual({
      ok: false,
      message: "cargo: requires a package name.",
    });
  });
});
