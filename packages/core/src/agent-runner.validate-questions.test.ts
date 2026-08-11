import { describe, it, expect } from "vitest";
import { validateQuestions } from "./agent-runner.js";

describe("validateQuestions", () => {
  it("keeps valid string questions", () => {
    const result = validateQuestions(["What deployment model is used?", "Is there a WAF in front?"]);
    expect(result).toEqual(["What deployment model is used?", "Is there a WAF in front?"]);
  });

  it("truncates entries exceeding 500 characters", () => {
    const long = "a".repeat(600);
    const result = validateQuestions([long]);
    expect(result[0]).toHaveLength(500);
    expect(result[0]).toBe("a".repeat(500));
  });

  it("limits to 10 entries max", () => {
    const raw = Array.from({ length: 15 }, (_, i) => `Question ${i + 1}`);
    const result = validateQuestions(raw);
    expect(result).toHaveLength(10);
    expect(result[9]).toBe("Question 10");
  });

  it("drops invalid types (numbers, objects, null, undefined)", () => {
    const raw = ["valid question", 42, { text: "invalid" }, null, undefined, "also valid"];
    const result = validateQuestions(raw);
    expect(result).toEqual(["valid question", "also valid"]);
  });

  it("drops empty or whitespace-only strings", () => {
    const raw = ["valid", "", "   ", "also valid"];
    const result = validateQuestions(raw);
    expect(result).toEqual(["valid", "also valid"]);
  });

  it("returns empty array when all entries are invalid", () => {
    const raw = [123, null, undefined, "", "   "];
    const result = validateQuestions(raw);
    expect(result).toEqual([]);
  });

  it("returns empty array when input is empty", () => {
    const result = validateQuestions([]);
    expect(result).toEqual([]);
  });
});