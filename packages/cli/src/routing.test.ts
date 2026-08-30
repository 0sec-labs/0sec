import { describe, expect, it } from "vitest";

import { detectAndRoute } from "./routing.js";

describe("detectAndRoute", () => {
  it("routes explicit target plans through the corresponding compatibility adapter", () => {
    expect(detectAndRoute("https://app.example.test")).toEqual([
      "scan",
      "--target",
      "https://app.example.test",
    ]);
    expect(detectAndRoute("source:./repo")).toEqual([
      "review",
      "./repo",
      "--depth",
      "deep",
    ]);
    expect(detectAndRoute("pypi:requests")).toEqual([
      "audit",
      "requests",
      "--ecosystem",
      "pypi",
    ]);
  });

  it("refuses an ambiguous bare token instead of silently starting an audit", () => {
    expect(detectAndRoute("express")).toBeNull();
  });
});
